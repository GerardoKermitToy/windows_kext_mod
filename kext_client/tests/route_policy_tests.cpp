#include "RoutePolicies.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <stdexcept>

namespace {

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct FakeNetsh {
    std::array<BYTE, 2> enabled = {0, 0};
    std::array<DWORD, 2> query_status = {ERROR_SUCCESS, ERROR_SUCCESS};
    std::array<unsigned, 2> queries = {0, 0};
    bool populate_query = true;
    unsigned current_family = 0;
    unsigned command_mask = 0;
    unsigned directories = 0;
    unsigned fail_family = 1;
    bool directory_error = false;
    bool directory_too_long = false;
    bool create_error = false;
    bool exit_error = false;
    DWORD wait_result = WAIT_OBJECT_0;
    DWORD exit_code = 0;
    unsigned creates = 0;
    unsigned waits = 0;
    unsigned child_waits = 0;
    unsigned exits = 0;
    unsigned terminates = 0;
    unsigned closed_threads = 0;
    unsigned closed_processes = 0;
};
FakeNetsh state;
const HANDLE process_handle = reinterpret_cast<HANDLE>(uintptr_t{1});
const HANDLE thread_handle = reinterpret_cast<HANDLE>(uintptr_t{2});

DWORD WINAPI GetGlobals(DWORD store, const NPI_MODULEID* module, DWORD table,
                        const void* key, DWORD key_size, void* rw, DWORD rw_size,
                        void* dynamic, DWORD dynamic_size, void* stat, DWORD stat_size) {
    Check(module != nullptr && module->Length == 24 && module->Type == MIT_GUID,
          "NSI module ABI");
    const unsigned family = module->Guid.Data1 == 0xeb004a00 ? 1u : 2u;
    const GUID expected = {family == 1 ? 0xeb004a00u : 0xeb004a01u, 0x9b1a, 0x11d4,
                           {0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc}};
    Check(IsEqualGUID(module->Guid, expected), "query only the IPv4 or IPv6 module");
    Check(store == 1 && table == 6 && key == nullptr && key_size == 0 &&
          rw != nullptr && rw_size == 0x9c && dynamic == nullptr && dynamic_size == 0 &&
          stat == nullptr && stat_size == 0, "read only active IP global parameters");
    state.current_family = family;
    Check(++state.queries[family - 1] == 1, "one NSI query per family");
    if (state.populate_query) {
        std::memset(rw, 0, rw_size);
        static_cast<BYTE*>(rw)[0x98] = state.enabled[family - 1];
    }
    return state.query_status[family - 1];
}

UINT WINAPI SystemDirectory(LPWSTR buffer, UINT size) {
    ++state.directories;
    if (state.current_family == state.fail_family) {
        if (state.directory_error) return 0;
        if (state.directory_too_long) return size;
    }
    constexpr wchar_t directory[] = L"C:\\Windows Test";
    Check(size >= std::size(directory), "system directory buffer");
    std::wmemcpy(buffer, directory, std::size(directory));
    return static_cast<UINT>(std::size(directory) - 1);
}

BOOL WINAPI Create(LPCWSTR executable, LPWSTR command, LPSECURITY_ATTRIBUTES process_security,
                   LPSECURITY_ATTRIBUTES thread_security, BOOL inherit, DWORD flags,
                   LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup,
                   LPPROCESS_INFORMATION process) {
    ++state.creates;
    state.child_waits = 0;
    Check(state.creates <= 2, "only one command per address family");
    Check(std::wstring(executable) == L"C:\\Windows Test\\netsh.exe", "use the system netsh path");
    Check(state.current_family == 1 || state.current_family == 2, "query before fallback");
    const unsigned family_bit = 1u << (state.current_family - 1);
    Check((state.command_mask & family_bit) == 0, "one netsh command per family");
    state.command_mask |= family_bit;
    const std::wstring family = state.current_family == 1 ? L"ipv4" : L"ipv6";
    Check(std::wstring(command) == L"\"C:\\Windows Test\\netsh.exe\" interface " + family +
          L" set global routepolicies=enabled store=active",
          "enable both address families without changing persistent settings");
    Check(process_security == nullptr && thread_security == nullptr && inherit == FALSE &&
          flags == CREATE_NO_WINDOW && environment == nullptr && directory == nullptr,
          "no shell, console window or inherited handles");
    Check(startup->cb == sizeof(STARTUPINFOW) && startup->dwFlags == STARTF_USESTDHANDLES &&
          startup->hStdInput == nullptr && startup->hStdOutput == nullptr &&
          startup->hStdError == nullptr, "do not mix netsh output into monitor records");
    if (state.current_family == state.fail_family && state.create_error) return FALSE;
    process->hProcess = process_handle;
    process->hThread = thread_handle;
    return TRUE;
}

DWORD WINAPI Wait(HANDLE process, DWORD timeout) {
    Check(process == process_handle, "wait only for the owned child");
    Check(timeout == (state.child_waits == 0 ? 10'000u : 1'000u), "bounded child wait");
    ++state.waits;
    ++state.child_waits;
    return state.current_family == state.fail_family && state.child_waits == 1 ?
        state.wait_result : WAIT_OBJECT_0;
}

BOOL WINAPI ExitCode(HANDLE process, LPDWORD code) {
    Check(process == process_handle, "query only the owned child");
    ++state.exits;
    if (state.current_family == state.fail_family && state.exit_error) return FALSE;
    *code = state.current_family == state.fail_family ? state.exit_code : 0;
    return TRUE;
}

BOOL WINAPI Terminate(HANDLE process, UINT code) {
    Check(process == process_handle, "terminate only the owned child");
    const UINT expected = static_cast<UINT>(
        state.wait_result == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_ACCESS_DENIED);
    Check(code == expected, "preserve wait error during cleanup");
    ++state.terminates;
    return TRUE;
}

BOOL WINAPI Close(HANDLE handle) {
    if (handle == thread_handle) ++state.closed_threads;
    else if (handle == process_handle) ++state.closed_processes;
    else Check(false, "unexpected handle closed");
    return TRUE;
}

DWORD WINAPI LastError() { return ERROR_ACCESS_DENIED; }

bool Enable(std::string& error) {
    return pmkext::monitor::detail::EnableRoutePolicies(
        {GetGlobals},
        {SystemDirectory, Create, Wait, ExitCode, Terminate, Close, LastError}, error);
}

} // namespace

int main() {
    try {
        std::string error = "stale error";
        state = {};
        Check(Enable(error) && error.empty() && state.creates == 2 && state.exits == 2 &&
              state.closed_threads == 2 && state.closed_processes == 2 && state.terminates == 0,
              "both netsh commands must succeed and close their handles");

        state = {};
        state.enabled = {1, 1};
        state.directory_error = true;
        Check(Enable(error) && error.empty() && state.creates == 0 && state.directories == 0 &&
              state.queries[0] == 1 && state.queries[1] == 1,
              "confirmed enabled families must not even look up netsh");

        for (unsigned family : {1u, 2u}) {
            state = {};
            state.enabled = {1, 1};
            state.enabled[family - 1] = 0;
            Check(Enable(error) && state.creates == 1 &&
                  state.command_mask == (1u << (family - 1)),
                  "only a disabled family should invoke netsh");

            for (DWORD status : std::array<DWORD, 3>{ERROR_ACCESS_DENIED, ERROR_NOT_SUPPORTED,
                                                    ERROR_INVALID_PARAMETER}) {
                state = {};
                state.enabled = {1, 1};
                state.query_status[family - 1] = status;
                Check(Enable(error) && state.creates == 1 &&
                      state.command_mask == (1u << (family - 1)) && error.empty(),
                      "query failures must fall back even when the buffer contains TRUE");
            }
            for (BYTE value : {BYTE{2}, BYTE{0xff}}) {
                state = {};
                state.enabled = {1, 1};
                state.enabled[family - 1] = value;
                Check(Enable(error) && state.creates == 1 &&
                      state.command_mask == (1u << (family - 1)),
                      "unexpected NSI values are not confirmation and must invoke netsh");
            }
        }
        state = {};
        state.populate_query = false;
        Check(Enable(error) && state.command_mask == 3,
              "successful queries without a flag value must invoke netsh");

        for (unsigned family : {1u, 2u}) {
            const std::string prefix = family == 1 ? "IPv4: " : "IPv6: ";
            state = {};
            state.fail_family = family;
            state.directory_error = true;
            Check(!Enable(error) && state.creates == family - 1 &&
                  error == prefix + "GetSystemDirectoryW failed: error 5",
                  "system directory failure must identify the family and stop startup");
            state = {};
            state.fail_family = family;
            state.directory_too_long = true;
            Check(!Enable(error) && state.creates == family - 1 && error.find("122") != std::string::npos,
                  "truncated system paths must not be used");
            state = {};
            state.fail_family = family;
            state.create_error = true;
            Check(!Enable(error) && state.creates == family && state.waits == family - 1 &&
                  state.closed_processes == family - 1 && error.find("could not start netsh") != std::string::npos,
                  "child creation failure must stop startup");

            for (DWORD result : {static_cast<DWORD>(WAIT_TIMEOUT), static_cast<DWORD>(WAIT_FAILED)}) {
                state = {};
                state.fail_family = family;
                state.wait_result = result;
                Check(!Enable(error) && state.creates == family && state.terminates == 1 &&
                      state.waits == family + 1 && state.exits == family - 1 &&
                      state.closed_processes == family && state.closed_threads == family &&
                      error.find(result == WAIT_TIMEOUT ? "1460" : "5") != std::string::npos,
                      "wait failures must terminate the child and close its handles");
            }
            state = {};
            state.fail_family = family;
            state.exit_error = true;
            Check(!Enable(error) && state.closed_processes == family &&
                  error.find("GetExitCodeProcess") != std::string::npos, "exit-query failure");
            state = {};
            state.fail_family = family;
            state.exit_code = 7;
            Check(!Enable(error) && state.closed_processes == family &&
                  error == prefix + "netsh exited with code 7", "netsh failure must identify the family");
        }
        state = {};
        state.query_status = {ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED};
        state.fail_family = 2;
        state.exit_code = 7;
        Check(!Enable(error) && state.command_mask == 3 && error == "IPv6: netsh exited with code 7",
              "fallback failures must stop startup when NSI cannot confirm either family");
        std::puts("PASS: read-only NSI checks, per-family netsh fallback, bounded lifecycle and errors");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
