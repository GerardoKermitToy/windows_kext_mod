#include <atomic>
#include <iomanip>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <Windows.h>

#include "duplex_pipe/duplex_pipe_server.h"
#include "pipe_support.h"

static_assert(std::is_nothrow_constructible_v<duplex_pipe::Server>);
static_assert(std::is_nothrow_destructible_v<duplex_pipe::Server>);
static_assert(noexcept(std::declval<duplex_pipe::Server&>().Start()));
static_assert(noexcept(std::declval<duplex_pipe::Server&>().Stop()));
static_assert(noexcept(
    std::declval<duplex_pipe::Server&>().Send(nullptr, 0)));
static_assert(noexcept(
    std::declval<duplex_pipe::Server&>().SetReceiveCallback({})));
static_assert(noexcept(
    std::declval<duplex_pipe::Server&>().SetConnectionCallback({})));

namespace
{
constexpr DWORD kSendIntervalMilliseconds = 2000;

HANDLE g_stopEvent = nullptr;
std::atomic<bool> g_clientConnected = false;
std::atomic<bool> g_sendEmptyNote = false;

bool ParseArguments(
    const int argc,
    wchar_t* argv[],
    std::wstring& trustedClientPath) noexcept
{
    try
    {
        trustedClientPath.clear();
        for (int index = 1; index < argc; ++index)
        {
            const std::wstring_view argument(argv[index]);
            if (argument == L"--trusted-client" && index + 1 < argc)
            {
                trustedClientPath = argv[++index];
            }
            else
            {
                pipe_support::PrintError(
                    L"Usage: pipe_server.exe "
                    L"[--trusted-client <full-path>]");
                return false;
            }
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}

BOOL WINAPI ConsoleHandler(const DWORD controlType) noexcept
{
    if (controlType == CTRL_C_EVENT ||
        controlType == CTRL_BREAK_EVENT ||
        controlType == CTRL_CLOSE_EVENT)
    {
        if (g_stopEvent != nullptr)
        {
            SetEvent(g_stopEvent);
        }
        return TRUE;
    }
    return FALSE;
}

void PrintReceivedNote(
    const byte* const note,
    const unsigned long noteSize) noexcept
{
    try
    {
        std::wostringstream output;
        output << L"[client -> server] noteSize=" << noteSize
               << L" bytes, noteHex=";
        if (noteSize == 0)
        {
            output << L"<empty>";
        }
        else
        {
            output << std::hex << std::setfill(L'0');
            for (unsigned long index = 0; index < noteSize; ++index)
            {
                if (index != 0)
                {
                    output << L' ';
                }
                output << std::setw(2)
                       << static_cast<unsigned int>(note[index]);
            }
        }
        pipe_support::PrintLine(output.str());
    }
    catch (...)
    {
        pipe_support::PrintError(L"Cannot print a received client note.");
    }
}

void HandleConnectionEvent(
    const duplex_pipe::ClientConnectionEvent event) noexcept
{
    if (event == duplex_pipe::ClientConnectionEvent::Connected)
    {
        g_clientConnected.store(true);
        g_sendEmptyNote.store(true);
        pipe_support::PrintLine(L"[connection callback] Connected");
    }
    else
    {
        g_clientConnected.store(false);
        g_sendEmptyNote.store(false);
        pipe_support::PrintLine(L"[connection callback] Disconnected");
    }
}
} // namespace

int wmain(int argc, wchar_t* argv[])
{
    pipe_support::ConfigureUtf8Console();

    try
    {
        std::wstring trustedClientPath;
        if (!ParseArguments(argc, argv, trustedClientPath))
        {
            return 2;
        }

        g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (g_stopEvent == nullptr)
        {
            pipe_support::PrintStatus(L"CreateEventW", GetLastError());
            return 1;
        }
        SetConsoleCtrlHandler(ConsoleHandler, TRUE);

        duplex_pipe::Server server;
        server.SetReceiveCallback(PrintReceivedNote);
        server.SetConnectionCallback(HandleConnectionEvent);

        const RPC_STATUS startStatus = server.Start(trustedClientPath);
        if (startStatus != ERROR_SUCCESS)
        {
            pipe_support::PrintStatus(L"Server::Start", startStatus);
            SetConsoleCtrlHandler(ConsoleHandler, FALSE);
            CloseHandle(g_stopEvent);
            g_stopEvent = nullptr;
            return 1;
        }

        pipe_support::PrintLine(
            L"The server remains alive after a client disconnect.");

        std::mt19937 randomGenerator(GetTickCount());
        std::uniform_int_distribution<unsigned long> randomDistribution;
        unsigned long long sequence = 0;

        while (WaitForSingleObject(g_stopEvent, kSendIntervalMilliseconds) ==
               WAIT_TIMEOUT)
        {
            if (!g_clientConnected.load())
            {
                continue;
            }

            const bool sendEmpty = g_sendEmptyNote.exchange(false);
            std::vector<byte> note;
            if (!sendEmpty)
            {
                const size_t noteSize = 12 + (++sequence % 19);
                note.resize(noteSize);
                for (byte& value : note)
                {
                    value = static_cast<byte>(
                        randomDistribution(randomGenerator) & 0xFFU);
                }
            }

            const RPC_STATUS status = server.Send(
                note.empty() ? nullptr : note.data(),
                static_cast<unsigned long>(note.size()));
            if (status == RPC_S_SERVER_UNAVAILABLE)
            {
                continue;
            }
            if (status != ERROR_SUCCESS)
            {
                pipe_support::PrintStatus(L"Server::Send", status);
                continue;
            }

            std::wostringstream output;
            output << L"[server -> client] noteSize=" << note.size()
                   << L" bytes";
            pipe_support::PrintLine(output.str());
        }

        pipe_support::PrintLine(L"Stopping named-pipe server...");
        server.Stop();
        SetConsoleCtrlHandler(ConsoleHandler, FALSE);
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        return 0;
    }
    catch (...)
    {
        pipe_support::PrintError(
            L"Unhandled server application exception was contained.");
        if (g_stopEvent != nullptr)
        {
            CloseHandle(g_stopEvent);
            g_stopEvent = nullptr;
        }
        return 1;
    }
}
