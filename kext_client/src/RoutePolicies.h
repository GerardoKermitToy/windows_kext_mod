#pragma once

#include <winsock2.h>
#include <windows.h>
#include <netiodef.h>

#include <string>

namespace pmkext::monitor {

// Confirm active IPv4/IPv6 settings through NSI; enable unconfirmed families through netsh.
bool EnableRoutePolicies(std::string& error);

namespace detail {

// Read-only private NSI ABI, linked through nsi.lib and injectable for tests.
struct NsiOperations {
    using GetAllParameters = DWORD (WINAPI*)(
        DWORD, const NPI_MODULEID*, DWORD, const void*, DWORD,
        void*, DWORD, void*, DWORD, void*, DWORD);
    GetAllParameters get = nullptr;
};

struct NetshOperations {
    decltype(&GetSystemDirectoryW) system_directory;
    decltype(&CreateProcessW) create_process;
    decltype(&WaitForSingleObject) wait;
    decltype(&GetExitCodeProcess) exit_code;
    decltype(&TerminateProcess) terminate;
    decltype(&CloseHandle) close;
    decltype(&GetLastError) last_error;
};

bool EnableRoutePolicies(const NsiOperations& nsi, const NetshOperations& netsh,
                         std::string& error);

} // namespace detail
} // namespace pmkext::monitor
