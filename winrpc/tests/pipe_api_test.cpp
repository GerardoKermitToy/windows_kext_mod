#include <atomic>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

#include <Windows.h>

#include "duplex_pipe/duplex_pipe_client.h"
#include "duplex_pipe/duplex_pipe_server.h"
#include "pipe_support.h"

static_assert(std::is_nothrow_constructible_v<duplex_pipe::Client>);
static_assert(std::is_nothrow_destructible_v<duplex_pipe::Client>);
static_assert(std::is_nothrow_constructible_v<duplex_pipe::Server>);
static_assert(std::is_nothrow_destructible_v<duplex_pipe::Server>);
static_assert(noexcept(std::declval<duplex_pipe::Client&>().Start()));
static_assert(noexcept(std::declval<duplex_pipe::Client&>().Stop()));
static_assert(noexcept(
    std::declval<duplex_pipe::Client&>().Send(nullptr, 0)));
static_assert(noexcept(std::declval<duplex_pipe::Server&>().Start()));
static_assert(noexcept(std::declval<duplex_pipe::Server&>().Stop()));
static_assert(noexcept(
    std::declval<duplex_pipe::Server&>().Send(nullptr, 0)));

namespace
{
bool WaitSignalled(const HANDLE event) noexcept
{
    return WaitForSingleObject(event, 5000) == WAIT_OBJECT_0;
}
} // namespace

int wmain()
{
    pipe_support::ConfigureUtf8Console();

    try
    {
        std::wstring executablePath;
        if (!pipe_support::CurrentExecutablePath(executablePath))
        {
            return 1;
        }

        const HANDLE connectedEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        const HANDLE disconnectedEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        const HANDLE serverReceivedEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        const HANDLE clientReceivedEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (connectedEvent == nullptr || disconnectedEvent == nullptr ||
            serverReceivedEvent == nullptr || clientReceivedEvent == nullptr)
        {
            if (connectedEvent != nullptr) CloseHandle(connectedEvent);
            if (disconnectedEvent != nullptr) CloseHandle(disconnectedEvent);
            if (serverReceivedEvent != nullptr) CloseHandle(serverReceivedEvent);
            if (clientReceivedEvent != nullptr) CloseHandle(clientReceivedEvent);
            return 2;
        }

        int result = 0;
        {
            std::atomic<int> serverReceiveCount = 0;
            std::atomic<int> clientReceiveCount = 0;

            duplex_pipe::Server server;
            server.SetConnectionCallback(
                [&](const duplex_pipe::ClientConnectionEvent event)
                {
                    SetEvent(
                        event == duplex_pipe::ClientConnectionEvent::Connected
                            ? connectedEvent
                            : disconnectedEvent);
                });
            server.SetReceiveCallback(
                [&](const byte*, const unsigned long)
                {
                    const int count = ++serverReceiveCount;
                    if (count == 1)
                    {
                        throw std::runtime_error("intentional server callback test");
                    }
                    if (count == 2)
                    {
                        server.SetReceiveCallback(
                            [&](const byte*, const unsigned long) noexcept
                            {
                                SetEvent(serverReceivedEvent);
                            });
                    }
                    SetEvent(serverReceivedEvent);
                });

            duplex_pipe::Client client;
            client.SetReceiveCallback(
                [&](const byte*, const unsigned long)
                {
                    const int count = ++clientReceiveCount;
                    if (count == 1)
                    {
                        throw std::runtime_error("intentional client callback test");
                    }
                    if (count == 2)
                    {
                        client.SetReceiveCallback(
                            [&](const byte*, const unsigned long) noexcept
                            {
                                SetEvent(clientReceivedEvent);
                            });
                    }
                    SetEvent(clientReceivedEvent);
                });

            RPC_STATUS status = server.Start(executablePath);
            if (status != ERROR_SUCCESS)
            {
                result = 3;
            }
            if (result == 0)
            {
                status = client.Start(executablePath);
                if (status != ERROR_SUCCESS || !WaitSignalled(connectedEvent))
                {
                    result = 4;
                }
            }

            byte payload[] = {0x10, 0x20, 0x30};
            if (result == 0 &&
                (client.Send(nullptr, 1) != ERROR_INVALID_PARAMETER ||
                 server.Send(nullptr, 1) != ERROR_INVALID_PARAMETER ||
                 client.Send(payload, duplex_pipe::kMaxNoteSize + 1) !=
                     ERROR_FILE_TOO_LARGE ||
                 server.Send(payload, duplex_pipe::kMaxNoteSize + 1) !=
                     ERROR_FILE_TOO_LARGE))
            {
                result = 5;
            }

            if (result == 0)
            {
                if (client.Send(payload, 1) != ERROR_SUCCESS ||
                    client.Send(payload, 2) != ERROR_SUCCESS ||
                    server.Send(payload, 1) != ERROR_SUCCESS ||
                    server.Send(payload, 3) != ERROR_SUCCESS ||
                    !WaitSignalled(serverReceivedEvent) ||
                    !WaitSignalled(clientReceivedEvent))
                {
                    result = 6;
                }
            }

            if (result == 0)
            {
                ResetEvent(serverReceivedEvent);
                ResetEvent(clientReceivedEvent);
                if (client.Send(payload, 3) != ERROR_SUCCESS ||
                    server.Send(payload, 2) != ERROR_SUCCESS ||
                    !WaitSignalled(serverReceivedEvent) ||
                    !WaitSignalled(clientReceivedEvent))
                {
                    result = 9;
                }
            }

            client.Stop();
            if (result == 0 && !WaitSignalled(disconnectedEvent))
            {
                result = 7;
            }
            server.Stop();
        }

        if (result == 0)
        {
            duplex_pipe::Server idleServer;
            const ULONGLONG startedAt = GetTickCount64();
            const RPC_STATUS status = idleServer.Start(executablePath);
            idleServer.Stop();
            if (status != ERROR_SUCCESS ||
                GetTickCount64() - startedAt > 5000)
            {
                result = 8;
            }
        }

        CloseHandle(connectedEvent);
        CloseHandle(disconnectedEvent);
        CloseHandle(serverReceivedEvent);
        CloseHandle(clientReceivedEvent);

        if (result == 0)
        {
            pipe_support::PrintLine(
                L"Named-pipe API no-throw test passed.");
        }
        return result;
    }
    catch (...)
    {
        pipe_support::PrintError(
            L"Test harness caught an unexpected exception.");
        return 100;
    }
}
