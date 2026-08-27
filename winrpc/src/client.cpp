#include <iomanip>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <Windows.h>

#include "duplex_pipe/duplex_pipe_client.h"
#include "pipe_support.h"

static_assert(std::is_nothrow_constructible_v<duplex_pipe::Client>);
static_assert(std::is_nothrow_destructible_v<duplex_pipe::Client>);
static_assert(noexcept(std::declval<duplex_pipe::Client&>().Start()));
static_assert(noexcept(std::declval<duplex_pipe::Client&>().Stop()));
static_assert(noexcept(
    std::declval<duplex_pipe::Client&>().Send(nullptr, 0)));
static_assert(noexcept(
    std::declval<duplex_pipe::Client&>().SetReceiveCallback({})));

namespace
{
constexpr DWORD kSendIntervalMilliseconds = 3000;

bool ParseArguments(
    const int argc,
    wchar_t* argv[],
    std::wstring& trustedServerPath) noexcept
{
    try
    {
        trustedServerPath.clear();
        for (int index = 1; index < argc; ++index)
        {
            const std::wstring_view argument(argv[index]);
            if (argument == L"--trusted-server" && index + 1 < argc)
            {
                trustedServerPath = argv[++index];
            }
            else
            {
                pipe_support::PrintError(
                    L"Usage: pipe_client.exe "
                    L"[--trusted-server <full-path>]");
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

void PrintReceivedNote(
    const byte* const note,
    const unsigned long noteSize) noexcept
{
    try
    {
        std::wostringstream output;
        output << L"[server -> client] noteSize=" << noteSize
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
        pipe_support::PrintError(L"Cannot print a received server note.");
    }
}
} // namespace

int wmain(int argc, wchar_t* argv[])
{
    pipe_support::ConfigureUtf8Console();

    try
    {
        std::wstring trustedServerPath;
        if (!ParseArguments(argc, argv, trustedServerPath))
        {
            return 2;
        }

        duplex_pipe::Client client;
        client.SetReceiveCallback(PrintReceivedNote);

        RPC_STATUS status = client.Start(trustedServerPath);
        if (status != ERROR_SUCCESS)
        {
            pipe_support::PrintStatus(L"Client::Start", status);
            return 1;
        }

        pipe_support::PrintLine(
            L"Press Ctrl+C or terminate this process to demonstrate disconnect detection.");

        status = client.Send(nullptr, 0);
        if (status != ERROR_SUCCESS)
        {
            pipe_support::PrintStatus(L"Client::Send(empty)", status);
            return 1;
        }
        pipe_support::PrintLine(L"[client -> server] noteSize=0 bytes");

        std::mt19937 randomGenerator(GetTickCount() ^ GetCurrentProcessId());
        std::uniform_int_distribution<unsigned long> randomDistribution;
        unsigned long long sequence = 0;

        for (;;)
        {
            Sleep(kSendIntervalMilliseconds);

            const size_t noteSize = 8 + (++sequence % 17);
            std::vector<byte> note(noteSize);
            for (byte& value : note)
            {
                value = static_cast<byte>(
                    randomDistribution(randomGenerator) & 0xFFU);
            }

            status = client.Send(
                note.data(),
                static_cast<unsigned long>(note.size()));
            if (status != ERROR_SUCCESS)
            {
                pipe_support::PrintStatus(L"Client::Send", status);
                return 1;
            }

            std::wostringstream output;
            output << L"[client -> server] noteSize=" << note.size()
                   << L" bytes";
            pipe_support::PrintLine(output.str());
        }
    }
    catch (...)
    {
        pipe_support::PrintError(
            L"Unhandled client application exception was contained.");
        return 1;
    }
}
