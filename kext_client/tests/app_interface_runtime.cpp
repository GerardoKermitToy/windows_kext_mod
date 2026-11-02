// Administrator-only bounded runtime probe; not part of offline CTest.
#define NTDDI_VERSION 0x0A000010
#include "PortmasterKext.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <stdexcept>
#include <string>
#include <thread>
#include <mutex>
#include <vector>

namespace pmkext {
struct DriverTestAccess {
    static void CloseOwnerWithoutShutdown(Driver& driver) {
        // This probe calls it before Run(), so there are no outstanding IRPs.
        CloseHandle(static_cast<HANDLE>(driver.device_));
        driver.device_ = nullptr;
        CloseHandle(static_cast<HANDLE>(driver.stop_event_));
        driver.stop_event_ = nullptr;
    }
    static bool Raw(Driver& driver, const std::vector<uint8_t>& command, bool via_write,
                    std::string& error) {
        return via_write ? driver.SendCommand(command.data(), command.size(), error) :
            driver.DeviceControl(0x9c40e010, nullptr, 0, error, command.data() + 1,
                                 static_cast<uint32_t>(command.size() - 1));
    }
};
} // namespace pmkext

namespace {
struct RouteObservation { DWORD pid; DWORD source; ULONG interface_index; };
std::mutex observations_mutex;
std::vector<RouteObservation> observations;

void Check(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}

struct TestApp {
    std::wstring original;
    std::wstring directory;
    std::wstring path;
    std::vector<uint8_t> app_id;
    TestApp() {
        wchar_t self[32768] = {}, temp[MAX_PATH] = {};
        Check(GetModuleFileNameW(nullptr, self, 32768) != 0, "self path");
        original = self;
        Check(GetTempPathW(MAX_PATH, temp) != 0, "temp path");
        directory = std::wstring(temp) + L"pmkext-route-" + std::to_wstring(GetCurrentProcessId()) +
            L"-" + std::to_wstring(GetTickCount64()) + L"-Тест-应用";
        Check(CreateDirectoryW(directory.c_str(), nullptr) != 0, "Unicode directory");
        path = directory + L"\\Приложение_é_\U0001f680.exe";
        Check(CopyFileW(original.c_str(), path.c_str(), TRUE) != 0, "Unicode EXE copy");
        FWP_BYTE_BLOB* blob = nullptr;
        Check(FwpmGetAppIdFromFileName0(path.c_str(), &blob) == ERROR_SUCCESS, "Unicode app ID");
        app_id.assign(blob->data, blob->data + blob->size);
        using DowncaseChar = wchar_t (NTAPI*)(wchar_t);
        const auto downcase = reinterpret_cast<DowncaseChar>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlDowncaseUnicodeChar"));
        Check(downcase != nullptr, "Windows native Unicode case mapping");
        for (size_t i = 0; i < app_id.size(); i += 2) {
            const auto unit = static_cast<wchar_t>(app_id[i] | (uint16_t(app_id[i + 1]) << 8));
            const auto lower = static_cast<uint16_t>(downcase(unit));
            app_id[i] = static_cast<uint8_t>(lower);
            app_id[i + 1] = static_cast<uint8_t>(lower >> 8);
        }
        const int count = static_cast<int>(blob->size / 2 - 1);
        std::string utf8(static_cast<size_t>(count) * 4, char{});
        const int used = WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<const wchar_t*>(blob->data), count,
                                             utf8.data(), static_cast<int>(utf8.size()), nullptr, nullptr);
        utf8.resize(used);
        std::printf("requested app ID=%s\n", utf8.c_str());
        FwpmFreeMemory0(reinterpret_cast<void**>(&blob));
    }
    ~TestApp() {
        DeleteFileW(path.c_str());
        RemoveDirectoryW(directory.c_str());
    }
};

struct PolicyInspector {
    HANDLE engine = nullptr;
    PolicyInspector() {
        FWPM_SESSION0 session{};
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        Check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine) == ERROR_SUCCESS,
              "inspection engine");
    }
    ~PolicyInspector() { FwpmEngineClose0(engine); }

    void Expect(const std::vector<uint8_t>& app_id, uint64_t expected_luid) {
        for (const GUID* layer : {&FWPM_LAYER_OUTBOUND_NETWORK_CONNECTION_POLICY_V4,
                                  &FWPM_LAYER_OUTBOUND_NETWORK_CONNECTION_POLICY_V6}) {
            FWPM_FILTER_ENUM_TEMPLATE0 query{};
            query.layerKey = *layer;
            query.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED;
            query.actionMask = 0xffffffff;
            HANDLE enumeration = nullptr;
            Check(FwpmFilterCreateEnumHandle0(engine, &query, &enumeration) == ERROR_SUCCESS,
                  "policy filter enum handle");
            unsigned matches = 0;
            bool settings_ok = true;
            for (;;) {
                FWPM_FILTER0** filters = nullptr;
                UINT32 count = 0;
                const DWORD status = FwpmFilterEnum0(engine, enumeration, 64, &filters, &count);
                if (status != ERROR_SUCCESS) {
                    FwpmFilterDestroyEnumHandle0(engine, enumeration);
                    throw std::runtime_error("policy filter enumeration");
                }
                for (UINT32 i = 0; i < count; ++i) {
                    const auto* filter = filters[i];
                    bool same_app = false;
                    for (UINT32 c = 0; c < filter->numFilterConditions; ++c) {
                        const auto& condition = filter->filterCondition[c];
                        if (IsEqualGUID(condition.fieldKey, FWPM_CONDITION_ALE_APP_ID) &&
                            condition.conditionValue.type == FWP_BYTE_BLOB_TYPE) {
                            const auto* blob = condition.conditionValue.byteBlob;
                            same_app = blob && blob->size == app_id.size() &&
                                std::memcmp(blob->data, app_id.data(), app_id.size()) == 0;
                        }
                    }
                    if (!same_app) continue;
                    ++matches;
                    FWPM_PROVIDER_CONTEXT3* context = nullptr;
                    if (FwpmProviderContextGetByKey3(engine, &filter->providerContextKey, &context) != ERROR_SUCCESS) {
                        settings_ok = false;
                        continue;
                    }
                    const auto* settings = context->networkConnectionPolicy;
                    settings_ok = settings_ok && context->type == FWPM_NETWORK_CONNECTION_POLICY_CONTEXT &&
                        settings && settings->numSettings == 1 &&
                        settings->settings[0].type == FWP_NETWORK_CONNECTION_POLICY_NEXT_HOP_INTERFACE &&
                        settings->settings[0].value.type == FWP_UINT64 &&
                        settings->settings[0].value.uint64 &&
                        *settings->settings[0].value.uint64 == expected_luid;
                    FwpmFreeMemory0(reinterpret_cast<void**>(&context));
                }
                FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
                if (count == 0) break;
            }
            FwpmFilterDestroyEnumHandle0(engine, enumeration);
            Check(matches == (expected_luid == 0 ? 0u : 1u), "exactly one app policy per address family");
            Check(settings_ok, "policy stores requested native interface LUID");
        }
    }
};

DWORD ChildSource(const std::wstring& path, ULONG* interface_index = nullptr) {
    size_t first_observation;
    {
        std::lock_guard<std::mutex> guard(observations_mutex);
        first_observation = observations.size();
    }
    std::wstring args = L"\"" + path + L"\" --route-child";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    Check(CreateProcessW(path.c_str(), args.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr,
                         &startup, &process) != 0, "start Unicode route child");
    CloseHandle(process.hThread);
    const DWORD wait = WaitForSingleObject(process.hProcess, 2500);
    if (wait != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 0xfffffffe);
        WaitForSingleObject(process.hProcess, 1000);
        CloseHandle(process.hProcess);
        throw std::runtime_error("route child exceeded its 2.5-second bound");
    }
    DWORD result = 0;
    GetExitCodeProcess(process.hProcess, &result);
    CloseHandle(process.hProcess);
    Check(result == 0, "route child socket operation");
    const ULONGLONG deadline = GetTickCount64() + 1000;
    do {
        {
            std::lock_guard<std::mutex> guard(observations_mutex);
            for (size_t i = first_observation; i < observations.size(); ++i) {
                const auto& route = observations[i];
                if (route.pid == process.dwProcessId) {
                    if (interface_index) *interface_index = route.interface_index;
                    return route.source;
                }
            }
        }
        Sleep(10);
    } while (GetTickCount64() < deadline);
    throw std::runtime_error("no native WFP route indication for child");
}

int RouteChild() {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return -1;
    SOCKET socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    u_long nonblocking = 1;
    ioctlsocket(socket_handle, FIONBIO, &nonblocking);
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(443);
    InetPtonW(AF_INET, L"1.1.1.1", &remote.sin_addr);
    const int connected = connect(socket_handle, reinterpret_cast<sockaddr*>(&remote), sizeof(remote));
    const int error = connected == 0 ? 0 : WSAGetLastError();
    if (connected == 0 || error == WSAEWOULDBLOCK) {
        fd_set writable;
        FD_ZERO(&writable);
        FD_SET(socket_handle, &writable);
        timeval timeout{0, 250000};
        select(0, nullptr, &writable, nullptr, &timeout);
    }
    closesocket(socket_handle);
    WSACleanup();
    return connected == 0 || error == WSAEWOULDBLOCK ? 0 : 1;
}

struct Runtime {
    pmkext::Driver driver;
    std::thread reader;
    std::atomic<bool> verdict_failed{false};
    ~Runtime() {
        driver.Stop();
        if (reader.joinable()) reader.join();
        driver.Cleanup();
    }
    void StartReader(ULONGLONG deadline) {
        reader = std::thread([this, deadline] {
            pmkext::Handlers handlers;
            handlers.on_connection = [this](const pmkext::Connection& connection) {
                std::string error;
                if (!connection.ipv6 && connection.remote_ip[0] == 1 && connection.remote_ip[1] == 1 &&
                    connection.remote_ip[2] == 1 && connection.remote_ip[3] == 1) {
                    DWORD source = 0;
                    std::memcpy(&source, connection.local_ip, sizeof(source));
                    {
                        std::lock_guard<std::mutex> guard(observations_mutex);
                        observations.push_back({static_cast<DWORD>(connection.process_id), source,
                                                connection.interface_index});
                    }
                    std::printf("WFP connection pid=%llu interface=%u source=%s layer=%u\n",
                        connection.process_id, connection.interface_index,
                        connection.LocalIpString().c_str(), connection.payload_layer);
                }
                if (!driver.SendVerdict(connection.id, pmkext::Verdict::PermanentAccept, error))
                    verdict_failed.store(true);
            };
            handlers.on_warning = [](const std::string& warning) { std::printf("protocol warning: %s\n", warning.c_str()); };
            handlers.on_log = [](const pmkext::LogLine& log) {
                if (log.severity >= pmkext::Severity::Warning) std::printf("driver log: %s\n", log.message.c_str());
            };
            handlers.on_poll = [this, deadline] {
                std::string error;
                driver.RequestLogs(error);
                if (GetTickCount64() >= deadline) driver.Stop();
            };
            driver.Run(handlers, 100);
        });
    }
};
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wcscmp(argv[1], L"--route-child") == 0) return RouteChild();
    if ((argc != 4 && argc != 6) || std::wcscmp(argv[1], L"--duration") != 0 ||
        std::wcscmp(argv[2], L"30") != 0 || (argc == 6 && std::wcscmp(argv[4], L"--interface-address") != 0)) {
        std::fprintf(stderr, "Usage: app_interface_runtime.exe --duration 30 absolute-driver.sys [--interface-address IPv4]\n");
        return 2;
    }
    try {
        const ULONGLONG deadline = GetTickCount64() + 30000;
        TestApp app;
        PolicyInspector inspector;
        Runtime runtime;
        std::string error;
        if (!runtime.driver.Install(argv[3], error) || !runtime.driver.Open(error))
            throw std::runtime_error(error);
        NET_LUID loopback{};
        Check(ConvertInterfaceIndexToLuid(1, &loopback) == NO_ERROR, "loopback interface LUID");
        auto set = [&](uint64_t luid, bool write) {
            if (!runtime.driver.SetAppInterface(app.path, luid, error, write))
                throw std::runtime_error(error);
            inspector.Expect(app.app_id, luid);
        };

        set(loopback.Value, false);
        pmkext::DriverTestAccess::CloseOwnerWithoutShutdown(runtime.driver);
        inspector.Expect(app.app_id, 0);
        if (!runtime.driver.Open(error)) throw std::runtime_error(error);
        std::printf("PASS: IOCTL Unicode app policies and IRP_MJ_CLEANUP\n");
        runtime.StartReader(deadline);

        const DWORD baseline = ChildSource(app.path);
        Check(baseline != 0xffffffff && baseline != 0, "baseline native TCP route");
        SOCKADDR_INET destination{};
        destination.Ipv4.sin_family = AF_INET;
        InetPtonW(AF_INET, L"1.1.1.1", &destination.Ipv4.sin_addr);
        MIB_IPFORWARD_ROW2 best{};
        SOCKADDR_INET source{};
        Check(GetBestRoute2(nullptr, 0, nullptr, &destination, 0, &best, &source) == NO_ERROR,
              "default-route interface LUID");
        const NET_LUID default_luid = best.InterfaceLuid;
        NET_LUID alternate{};
        DWORD alternate_source = 0;
        IN_ADDR requested{};
        if (argc == 6) Check(InetPtonW(AF_INET, argv[5], &requested) == 1, "requested interface address");
        MIB_IPFORWARD_TABLE2* routes = nullptr;
        Check(GetIpForwardTable2(AF_INET, &routes) == NO_ERROR, "available interface routes");
        for (ULONG i = 0; i < routes->NumEntries; ++i) {
            auto luid = routes->Table[i].InterfaceLuid;
            if (luid.Value == default_luid.Value) continue;
            if (GetBestRoute2(&luid, 0, nullptr, &destination, 0, &best, &source) == NO_ERROR &&
                source.Ipv4.sin_addr.s_addr != baseline && source.Ipv4.sin_addr.s_addr != 0 &&
                (requested.s_addr == 0 || source.Ipv4.sin_addr.s_addr == requested.s_addr) &&
                (ntohl(source.Ipv4.sin_addr.s_addr) >> 24) != 127) {
                alternate = luid;
                alternate_source = source.Ipv4.sin_addr.s_addr;
                break;
            }
        }
        FreeMibTable(routes);
        Check(alternate.Value != 0, "live routing test needs a second interface with a route to 1.1.1.1");
        std::printf("default source=0x%08lx alternate source=0x%08lx alternate LUID=%llu\n",
                    baseline, alternate_source, alternate.Value);
        set(alternate.Value, false);
        const DWORD selected = ChildSource(app.path);
        Check(selected == alternate_source, "Unicode executable must use the selected non-default interface");
        Check(ChildSource(app.original) == baseline, "other executable path must keep its default route");
        Check(ChildSource(app.path) == alternate_source, "policy persists across process exit and relaunch");
        std::printf("PASS: actual interface selection and per-path isolation\n");

        set(default_luid.Value, true);
        Check(ChildSource(app.path) == baseline, "WriteFile replaces route policy");
        set(default_luid.Value, true);
        set(0, false);
        set(0, false);
        Check(ChildSource(app.path) == baseline, "IOCTL removal restores default route");
        set(alternate.Value, true);
        Check(ChildSource(app.path) == alternate_source, "WriteFile add selects the alternate interface");
        set(0, true);
        Check(ChildSource(app.path) == baseline, "WriteFile removal restores the default route");
        std::printf("PASS: WriteFile add/update/remove and idempotent commands\n");

        std::vector<uint8_t> malformed(1 + 12, 0);
        malformed[0] = 10;
        malformed[9] = 1; // Odd UTF-16 byte length.
        for (bool write : {false, true}) {
            Check(!pmkext::DriverTestAccess::Raw(runtime.driver, malformed, write, error),
                  "both transports reject malformed UTF-16 lengths");
        }
        inspector.Expect(app.app_id, 0);
        set(loopback.Value, false);
        runtime.driver.Stop();
        runtime.reader.join();
        inspector.Expect(app.app_id, 0);
        for (bool write : {false, true}) {
            Check(!runtime.driver.SetAppInterface(app.path, alternate.Value, error, write),
                  "shutdown rejects policy recreation through both transports");
        }
        inspector.Expect(app.app_id, 0);
        Check(!runtime.verdict_failed.load(), "runtime verdict submissions");
        Check(GetTickCount64() < deadline, "probe stayed within duration bound");
        std::printf("PASS: malformed input rejection and shutdown cleanup\n");
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "FAIL: %s\n", e.what());
        return 1;
    }
}
