#include "pipe_support.h"

#include <algorithm>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <io.h>
#include <limits>
#include <mutex>
#include <new>
#include <sstream>
#include <vector>

namespace pipe_support
{
namespace
{
std::mutex g_consoleMutex;

bool RemoveExtendedPathPrefix(std::wstring& path) noexcept
{
    try
    {
        constexpr std::wstring_view uncPrefix = L"\\\\?\\UNC\\";
        constexpr std::wstring_view pathPrefix = L"\\\\?\\";

        if (path.starts_with(uncPrefix))
        {
            path.replace(0, uncPrefix.size(), L"\\\\");
        }
        else if (path.starts_with(pathPrefix))
        {
            path.erase(0, pathPrefix.size());
        }
        return true;
    }
    catch (...)
    {
        path.clear();
        return false;
    }
}

bool QueryPathFromProcess(const HANDLE process, std::wstring& path) noexcept
{
    try
    {
        std::vector<wchar_t> buffer(512);
        for (;;)
        {
            DWORD size = static_cast<DWORD>(buffer.size());
            if (QueryFullProcessImageNameW(process, 0, buffer.data(), &size) != FALSE)
            {
                path.assign(buffer.data(), size);
                return true;
            }

            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
                buffer.size() >= 32768)
            {
                path.clear();
                return false;
            }
            buffer.resize(std::min<size_t>(buffer.size() * 2, 32768));
        }
    }
    catch (...)
    {
        path.clear();
        return false;
    }
}
} // namespace

void ConfigureUtf8Console() noexcept
{
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);
}

void PrintLine(const std::wstring_view text) noexcept
{
    try
    {
        const std::scoped_lock lock(g_consoleMutex);
        std::wcout << text << L'\n' << std::flush;
    }
    catch (...)
    {
    }
}

void PrintError(const std::wstring_view text) noexcept
{
    try
    {
        const std::scoped_lock lock(g_consoleMutex);
        std::wcerr << text << L'\n' << std::flush;
    }
    catch (...)
    {
    }
}

void PrintStatus(
    const std::wstring_view operation,
    const DWORD status) noexcept
{
    try
    {
        wchar_t* systemMessage = nullptr;
        const DWORD size = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            status,
            0,
            reinterpret_cast<wchar_t*>(&systemMessage),
            0,
            nullptr);

        std::wostringstream output;
        output << operation << L" failed (status " << status << L")";
        if (size != 0 && systemMessage != nullptr)
        {
            std::wstring message(systemMessage, size);
            while (!message.empty() &&
                   (message.back() == L'\r' || message.back() == L'\n'))
            {
                message.pop_back();
            }
            output << L": " << message;
        }
        if (systemMessage != nullptr)
        {
            LocalFree(systemMessage);
        }
        PrintError(output.str());
    }
    catch (...)
    {
        PrintError(operation);
    }
}

bool NormalizePath(
    const std::wstring_view input,
    std::wstring& path) noexcept
{
    path.clear();
    if (input.empty())
    {
        return false;
    }

    try
    {
        std::wstring mutableInput(input);
        std::replace(mutableInput.begin(), mutableInput.end(), L'/', L'\\');

        const DWORD required = GetFullPathNameW(
            mutableInput.c_str(), 0, nullptr, nullptr);
        if (required == 0)
        {
            return false;
        }

        std::vector<wchar_t> buffer(static_cast<size_t>(required) + 1);
        const DWORD written = GetFullPathNameW(
            mutableInput.c_str(),
            static_cast<DWORD>(buffer.size()),
            buffer.data(),
            nullptr);
        if (written == 0 || written >= buffer.size())
        {
            return false;
        }

        path.assign(buffer.data(), written);
        if (!RemoveExtendedPathPrefix(path))
        {
            return false;
        }
        while (path.size() > 3 && path.back() == L'\\')
        {
            path.pop_back();
        }
        return !path.empty();
    }
    catch (...)
    {
        path.clear();
        return false;
    }
}

bool CurrentExecutablePath(std::wstring& path) noexcept
{
    path.clear();
    try
    {
        std::vector<wchar_t> buffer(512);
        for (;;)
        {
            const DWORD size = GetModuleFileNameW(
                nullptr,
                buffer.data(),
                static_cast<DWORD>(buffer.size()));
            if (size == 0)
            {
                return false;
            }
            if (size < buffer.size() - 1)
            {
                return NormalizePath(
                    std::wstring_view(buffer.data(), size), path);
            }
            if (buffer.size() >= 32768)
            {
                return false;
            }
            buffer.resize(std::min<size_t>(buffer.size() * 2, 32768));
        }
    }
    catch (...)
    {
        path.clear();
        return false;
    }
}

bool SiblingExecutablePath(
    const std::wstring_view fileName,
    std::wstring& path) noexcept
{
    path.clear();
    try
    {
        std::wstring currentPath;
        if (!CurrentExecutablePath(currentPath))
        {
            return false;
        }
        std::filesystem::path sibling(currentPath);
        sibling.replace_filename(fileName);
        return NormalizePath(sibling.wstring(), path);
    }
    catch (...)
    {
        path.clear();
        return false;
    }
}

bool QueryProcessPath(
    const DWORD processId,
    std::wstring& path) noexcept
{
    path.clear();
    const HANDLE process = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        processId);
    if (process == nullptr)
    {
        return false;
    }

    std::wstring rawPath;
    const bool queried = QueryPathFromProcess(process, rawPath);
    CloseHandle(process);
    return queried && NormalizePath(rawPath, path);
}

bool PathsEqual(
    const std::wstring_view left,
    const std::wstring_view right) noexcept
{
    if (left.size() > static_cast<size_t>(std::numeric_limits<int>::max()) ||
        right.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
    {
        return false;
    }

    return CompareStringOrdinal(
               left.data(),
               static_cast<int>(left.size()),
               right.data(),
               static_cast<int>(right.size()),
               TRUE) == CSTR_EQUAL;
}

DWORD AuthorizeProcessPath(
    const DWORD processId,
    const std::wstring& trustedPath,
    const std::wstring_view peerName) noexcept
{
    try
    {
        std::wstring actualPath;
        if (processId == 0 || !QueryProcessPath(processId, actualPath))
        {
            std::wostringstream output;
            output << L"[security] " << peerName
                   << L": cannot identify PID " << processId << L'.';
            PrintError(output.str());
            return ERROR_ACCESS_DENIED;
        }

        if (!PathsEqual(actualPath, trustedPath))
        {
            std::wostringstream output;
            output << L"[security] " << peerName << L": denied PID "
                   << processId << L" from '" << actualPath
                   << L"'; trusted path is '" << trustedPath << L"'.";
            PrintError(output.str());
            return ERROR_ACCESS_DENIED;
        }
        return ERROR_SUCCESS;
    }
    catch (...)
    {
        return ERROR_ACCESS_DENIED;
    }
}
} // namespace pipe_support
