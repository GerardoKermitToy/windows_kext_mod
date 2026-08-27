#pragma once

#include <string>
#include <string_view>

#include <Windows.h>

namespace pipe_support
{
void ConfigureUtf8Console() noexcept;
void PrintLine(std::wstring_view text) noexcept;
void PrintError(std::wstring_view text) noexcept;
void PrintStatus(std::wstring_view operation, DWORD status) noexcept;

bool CurrentExecutablePath(std::wstring& path) noexcept;
bool SiblingExecutablePath(
    std::wstring_view fileName,
    std::wstring& path) noexcept;
bool NormalizePath(std::wstring_view input, std::wstring& path) noexcept;
bool QueryProcessPath(DWORD processId, std::wstring& path) noexcept;
bool PathsEqual(std::wstring_view left, std::wstring_view right) noexcept;
DWORD AuthorizeProcessPath(
    DWORD processId,
    const std::wstring& trustedPath,
    std::wstring_view peerName) noexcept;
} // namespace pipe_support
