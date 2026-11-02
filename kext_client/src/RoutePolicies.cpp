#include "RoutePolicies.h"

#include <array>
#include <cstddef>

extern "C" __declspec(dllimport) DWORD WINAPI NsiGetAllParameters(
    DWORD, const NPI_MODULEID*, DWORD, const void*, DWORD,
    void*, DWORD, void*, DWORD, void*, DWORD);

namespace pmkext::monitor {
namespace {

// Windows 11 IP global NSI ABI. An exact-size read must succeed and return
// precisely TRUE before we skip netsh. No configuration is ever written via NSI.
constexpr DWORD kActiveStore = 1;
constexpr DWORD kIpGlobalTable = 6;
constexpr DWORD kIpGlobalRwSize = 0x9c;
constexpr size_t kRoutePoliciesOffset = 0x98;
static_assert(sizeof(NPI_MODULEID) == 24);
static_assert(offsetof(NPI_MODULEID, Guid) == 8);

bool FamilyPoliciesEnabled(const detail::NsiOperations& nsi, bool ipv6) {
    if (nsi.get == nullptr) return false;
    NPI_MODULEID module = {};
    module.Length = sizeof(module);
    module.Type = MIT_GUID;
    module.Guid = {ipv6 ? 0xeb004a01u : 0xeb004a00u, 0x9b1a, 0x11d4,
                   {0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc}};
    std::array<BYTE, kIpGlobalRwSize> globals;
    globals.fill(0xff);
    const DWORD status = nsi.get(
        kActiveStore, &module, kIpGlobalTable, nullptr, 0,
        globals.data(), kIpGlobalRwSize, nullptr, 0, nullptr, 0);
    return status == ERROR_SUCCESS && globals[kRoutePoliciesOffset] == 1;
}

bool EnableFamilyRoutePolicies(const detail::NetshOperations& operations,
                              const wchar_t* family, std::string& error) {
    error.clear();
    wchar_t system_directory[MAX_PATH] = {};
    const UINT length = operations.system_directory(system_directory, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        error = "GetSystemDirectoryW failed: error " +
            std::to_string(length == 0 ? operations.last_error() : ERROR_INSUFFICIENT_BUFFER);
        return false;
    }
    const std::wstring executable = std::wstring(system_directory) + L"\\netsh.exe";
    std::wstring command = L"\"" + executable + L"\" interface " + family +
        L" set global routepolicies=enabled store=active";
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    // No shell, PATH lookup, or inherited handles. Keep localized netsh output
    // out of monitor records, including --process-events-only stdout.
    startup.dwFlags = STARTF_USESTDHANDLES;
    PROCESS_INFORMATION process = {};
    if (!operations.create_process(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                                   CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
        error = "could not start netsh: error " + std::to_string(operations.last_error());
        return false;
    }
    operations.close(process.hThread);
    const DWORD wait = operations.wait(process.hProcess, 10'000);
    if (wait != WAIT_OBJECT_0) {
        const DWORD code = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : operations.last_error();
        operations.terminate(process.hProcess, code);
        operations.wait(process.hProcess, 1'000);
        operations.close(process.hProcess);
        error = "waiting for netsh failed: error " + std::to_string(code);
        return false;
    }
    DWORD exit_code = 0;
    const bool have_exit_code = operations.exit_code(process.hProcess, &exit_code) != FALSE;
    const DWORD code = have_exit_code ? exit_code : operations.last_error();
    operations.close(process.hProcess);
    if (!have_exit_code || exit_code != 0) {
        error = std::string(have_exit_code ? "netsh exited with code " :
                                            "GetExitCodeProcess failed: error ") +
            std::to_string(code);
        return false;
    }
    return true;
}

} // namespace

bool detail::EnableRoutePolicies(const NsiOperations& nsi, const NetshOperations& netsh,
                                 std::string& error) {
    error.clear();
    if (!FamilyPoliciesEnabled(nsi, false) && !EnableFamilyRoutePolicies(netsh, L"ipv4", error)) {
        error = "IPv4: " + error;
        return false;
    }
    if (!FamilyPoliciesEnabled(nsi, true) && !EnableFamilyRoutePolicies(netsh, L"ipv6", error)) {
        error = "IPv6: " + error;
        return false;
    }
    return true;
}

bool EnableRoutePolicies(std::string& error) {
    return detail::EnableRoutePolicies(
        {NsiGetAllParameters},
        {GetSystemDirectoryW, CreateProcessW, WaitForSingleObject, GetExitCodeProcess,
         TerminateProcess, CloseHandle, GetLastError}, error);
}

} // namespace pmkext::monitor
