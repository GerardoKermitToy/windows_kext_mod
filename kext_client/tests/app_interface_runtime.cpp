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
#include <utility>
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
    struct Snapshot { unsigned matches = 0; bool valid = true; bool contains_target = false; };
    PolicyInspector() {
        FWPM_SESSION0 session{};
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        Check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine) == ERROR_SUCCESS,
              "inspection engine");
    }
    ~PolicyInspector() { FwpmEngineClose0(engine); }

    Snapshot Inspect(const std::vector<uint8_t>& app_id, uint64_t expected_luid,
                     int family, const SOCKADDR_INET* target = nullptr) {
        FWPM_FILTER_ENUM_TEMPLATE0 query{};
        query.layerKey = family == AF_INET ? FWPM_LAYER_OUTBOUND_NETWORK_CONNECTION_POLICY_V4 :
                                            FWPM_LAYER_OUTBOUND_NETWORK_CONNECTION_POLICY_V6;
        query.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED;
        query.actionMask = 0xffffffff;
        HANDLE enumeration = nullptr;
        Check(FwpmFilterCreateEnumHandle0(engine, &query, &enumeration) == ERROR_SUCCESS,
              "policy filter enum handle");
        Snapshot result;
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
                const FWP_RANGE0* range = nullptr;
                for (UINT32 c = 0; c < filter->numFilterConditions; ++c) {
                    const auto& condition = filter->filterCondition[c];
                    if (IsEqualGUID(condition.fieldKey, FWPM_CONDITION_ALE_APP_ID) &&
                        condition.matchType == FWP_MATCH_EQUAL && condition.conditionValue.type == FWP_BYTE_BLOB_TYPE) {
                        const auto* blob = condition.conditionValue.byteBlob;
                        same_app = blob && blob->size == app_id.size() &&
                            std::memcmp(blob->data, app_id.data(), app_id.size()) == 0;
                    }
                    if (IsEqualGUID(condition.fieldKey, FWPM_CONDITION_IP_REMOTE_ADDRESS) &&
                        condition.matchType == FWP_MATCH_RANGE && condition.conditionValue.type == FWP_RANGE_TYPE)
                        range = condition.conditionValue.rangeValue;
                }
                if (!same_app) continue;
                ++result.matches;
                result.valid = result.valid && filter->numFilterConditions == 2 && range;
                if (range && family == AF_INET) {
                    result.valid = result.valid && range->valueLow.type == FWP_UINT32 &&
                        range->valueHigh.type == FWP_UINT32 && range->valueLow.uint32 <= range->valueHigh.uint32 &&
                        (range->valueHigh.uint32 < 0x7f000000 || range->valueLow.uint32 > 0x7fffffff);
                    if (target) {
                        const auto ip = ntohl(target->Ipv4.sin_addr.s_addr);
                        result.contains_target |= range->valueLow.uint32 <= ip && ip <= range->valueHigh.uint32;
                    }
                } else if (range) {
                    const bool valid_types = range->valueLow.type == FWP_BYTE_ARRAY16_TYPE &&
                                             range->valueHigh.type == FWP_BYTE_ARRAY16_TYPE;
                    result.valid = result.valid && valid_types;
                    if (valid_types) {
                        const auto* low = range->valueLow.byteArray16;
                        const auto* high = range->valueHigh.byteArray16;
                        const IN6_ADDR loopback = IN6ADDR_LOOPBACK_INIT;
                        result.valid = result.valid && low && high;
                        if (low && high) {
                            result.valid = result.valid && std::memcmp(low, high, 16) <= 0 &&
                                (std::memcmp(high, &loopback, 16) < 0 || std::memcmp(low, &loopback, 16) > 0);
                            if (target) result.contains_target |=
                                std::memcmp(low, &target->Ipv6.sin6_addr, 16) <= 0 &&
                                std::memcmp(&target->Ipv6.sin6_addr, high, 16) <= 0;
                        }
                    }
                }
                FWPM_PROVIDER_CONTEXT3* context = nullptr;
                if (FwpmProviderContextGetByKey3(engine, &filter->providerContextKey, &context) != ERROR_SUCCESS) {
                    result.valid = false;
                    continue;
                }
                const auto* settings = context->networkConnectionPolicy;
                result.valid = result.valid && context->type == FWPM_NETWORK_CONNECTION_POLICY_CONTEXT &&
                    settings && settings->numSettings == 1 &&
                    settings->settings[0].type == FWP_NETWORK_CONNECTION_POLICY_NEXT_HOP_INTERFACE &&
                    settings->settings[0].value.type == FWP_UINT64 && settings->settings[0].value.uint64 &&
                    *settings->settings[0].value.uint64 == expected_luid;
                FwpmFreeMemory0(reinterpret_cast<void**>(&context));
            }
            FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
            if (count == 0) break;
        }
        FwpmFilterDestroyEnumHandle0(engine, enumeration);
        return result;
    }

    void Expect(const std::vector<uint8_t>& app_id, uint64_t expected_luid) {
        for (int family : {AF_INET, AF_INET6}) {
            const auto result = Inspect(app_id, expected_luid, family);
            Check(expected_luid == 0 ? result.matches == 0 : result.matches > 0,
                  "application range policies for both address families");
            Check(result.valid, "policy ranges exclude loopback and store the requested LUID");
        }
    }

    void ExpectAddress(const std::vector<uint8_t>& app_id, uint64_t luid,
                       const SOCKADDR_INET& address, bool covered) {
        const ULONGLONG deadline = GetTickCount64() + 5000;
        do {
            const auto state = Inspect(app_id, luid, address.si_family, &address);
            if (state.matches && state.valid && state.contains_target == covered) return;
            Sleep(20);
        } while (GetTickCount64() < deadline);
        throw std::runtime_error(covered ? "removed address remained excluded from app policy" :
                                           "local address was not excluded from app policy");
    }
};

struct ChildResult { DWORD pid; DWORD exit_code; };

ChildResult RunChild(const std::wstring& path, const wchar_t* mode, DWORD timeout_ms) {
    std::wstring args = L"\"" + path + L"\" " + mode;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    Check(CreateProcessW(path.c_str(), args.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr,
                         &startup, &process) != 0, "start Unicode test child");
    CloseHandle(process.hThread);
    const DWORD wait = WaitForSingleObject(process.hProcess, timeout_ms);
    if (wait != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 0xfffffffe);
        WaitForSingleObject(process.hProcess, 1000);
        CloseHandle(process.hProcess);
        throw std::runtime_error("test child exceeded its time bound");
    }
    DWORD result = 0;
    const BOOL have_result = GetExitCodeProcess(process.hProcess, &result);
    CloseHandle(process.hProcess);
    Check(have_result != FALSE, "test child exit code");
    return {process.dwProcessId, result};
}

DWORD ChildSource(const std::wstring& path, ULONG* interface_index = nullptr) {
    size_t first_observation;
    {
        std::lock_guard<std::mutex> guard(observations_mutex);
        first_observation = observations.size();
    }
    const auto child = RunChild(path, L"--route-child", 2500);
    Check(child.exit_code == 0, "route child socket operation");
    const ULONGLONG deadline = GetTickCount64() + 1000;
    do {
        {
            std::lock_guard<std::mutex> guard(observations_mutex);
            for (size_t i = first_observation; i < observations.size(); ++i) {
                const auto& route = observations[i];
                if (route.pid == child.pid) {
                    if (interface_index) *interface_index = route.interface_index;
                    return route.source;
                }
            }
        }
        Sleep(10);
    } while (GetTickCount64() < deadline);
    throw std::runtime_error("no native WFP route indication for child");
}

struct TestSocket {
    SOCKET value = INVALID_SOCKET;
    explicit TestSocket(SOCKET socket) : value(socket) {}
    ~TestSocket() { if (value != INVALID_SOCKET) closesocket(value); }
    TestSocket(const TestSocket&) = delete;
    TestSocket& operator=(const TestSocket&) = delete;
};

void SocketCheck(bool ok, const char* operation) {
    if (!ok) throw std::runtime_error(std::string(operation) +
                                      ": WSA error " + std::to_string(WSAGetLastError()));
}

void SocketReady(SOCKET socket, bool write = false) {
    fd_set ready, errors;
    FD_ZERO(&ready);
    FD_ZERO(&errors);
    FD_SET(socket, &ready);
    FD_SET(socket, &errors);
    timeval timeout{0, 700000};
    const int result = select(0, write ? nullptr : &ready, write ? &ready : nullptr,
                              &errors, &timeout);
    if (result == 0) throw std::runtime_error("loopback socket timed out after 700 ms");
    SocketCheck(result > 0, "loopback select");
    int error = 0;
    int size = sizeof(error);
    SocketCheck(getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) == 0,
                "loopback SO_ERROR");
    if (error != 0) throw std::runtime_error("loopback socket: WSA error " + std::to_string(error));
}

void ReceiveExact(SOCKET socket, char* data, int size) {
    int received = 0;
    while (received < size) {
        SocketReady(socket);
        const int count = recv(socket, data + received, size - received, 0);
        SocketCheck(count > 0, "loopback TCP receive");
        received += count;
    }
}

void LoopbackExchange(const wchar_t* address, int family, bool udp, bool require_loopback_source = true) {
    const int type = udp ? SOCK_DGRAM : SOCK_STREAM;
    const int protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;
    TestSocket server(socket(family, type, protocol));
    TestSocket client(socket(family, type, protocol));
    SocketCheck(server.value != INVALID_SOCKET && client.value != INVALID_SOCKET, "loopback sockets");
    SOCKADDR_INET endpoint{};
    endpoint.si_family = static_cast<ADDRESS_FAMILY>(family);
    const int length = family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    void* ip = family == AF_INET ? static_cast<void*>(&endpoint.Ipv4.sin_addr) :
                                  static_cast<void*>(&endpoint.Ipv6.sin6_addr);
    Check(InetPtonW(family, address, ip) == 1, "loopback address");
    SocketCheck(bind(server.value, reinterpret_cast<sockaddr*>(&endpoint), length) == 0, "loopback bind");
    if (!udp) SocketCheck(listen(server.value, 1) == 0, "loopback listen");
    int endpoint_size = length;
    SocketCheck(getsockname(server.value, reinterpret_cast<sockaddr*>(&endpoint), &endpoint_size) == 0,
                "loopback server endpoint");
    u_long nonblocking = 1;
    SocketCheck(ioctlsocket(client.value, FIONBIO, &nonblocking) == 0, "loopback nonblocking client");
    const int connected = connect(client.value, reinterpret_cast<sockaddr*>(&endpoint), length);
    SocketCheck(connected == 0 || WSAGetLastError() == WSAEWOULDBLOCK, "loopback connect");
    if (connected != 0) SocketReady(client.value, true);

    SOCKADDR_INET local{};
    int local_size = sizeof(local);
    SocketCheck(getsockname(client.value, reinterpret_cast<sockaddr*>(&local), &local_size) == 0,
                "loopback client source");
    if (require_loopback_source && family == AF_INET) {
        Check((ntohl(local.Ipv4.sin_addr.s_addr) >> 24) == 127, "loopback must keep a 127/8 source");
    } else if (require_loopback_source) {
        const IN6_ADDR expected = IN6ADDR_LOOPBACK_INIT;
        Check(std::memcmp(&local.Ipv6.sin6_addr, &expected, sizeof(expected)) == 0,
              "IPv6 loopback must keep source ::1");
    }

    constexpr char payload[] = "pmkext-loopback";
    constexpr int payload_size = sizeof(payload);
    SocketCheck(send(client.value, payload, payload_size, 0) == payload_size, "loopback send");
    SocketReady(server.value);
    char received[sizeof(payload)]{};
    if (udp) {
        SOCKADDR_INET peer{};
        int peer_size = sizeof(peer);
        SocketCheck(recvfrom(server.value, received, payload_size, 0,
                             reinterpret_cast<sockaddr*>(&peer), &peer_size) == payload_size,
                    "loopback UDP receive");
        Check(std::memcmp(received, payload, sizeof(payload)) == 0, "loopback UDP payload");
        SocketCheck(sendto(server.value, received, payload_size, 0,
                           reinterpret_cast<sockaddr*>(&peer), peer_size) == payload_size,
                    "loopback UDP reply");
    } else {
        TestSocket accepted(accept(server.value, nullptr, nullptr));
        SocketCheck(accepted.value != INVALID_SOCKET, "loopback accept");
        ReceiveExact(accepted.value, received, payload_size);
        Check(std::memcmp(received, payload, sizeof(payload)) == 0, "loopback TCP payload");
        SocketCheck(send(accepted.value, received, payload_size, 0) == payload_size, "loopback TCP reply");
    }
    if (udp) {
        SocketReady(client.value);
        SocketCheck(recv(client.value, received, payload_size, 0) == payload_size, "loopback UDP echo receive");
    } else {
        ReceiveExact(client.value, received, payload_size);
    }
    Check(std::memcmp(received, payload, sizeof(payload)) == 0, "loopback echo payload");
    std::printf("PASS: %s local %ls round trip%s\n", udp ? "UDP" : "TCP", address,
                require_loopback_source ? " with native loopback source" : "");
}

int LoopbackChild() {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 1;
    int result = 0;
    try {
        for (bool udp : {false, true}) {
            LoopbackExchange(L"127.0.0.1", AF_INET, udp);
            LoopbackExchange(L"127.0.0.2", AF_INET, udp);
            LoopbackExchange(L"::1", AF_INET6, udp);
        }
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        result = 1;
    }
    WSACleanup();
    return result;
}

int LocalAddressChild(const wchar_t* address, int family) {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 1;
    int result = 0;
    try {
        for (bool udp : {false, true}) LoopbackExchange(address, family, udp, false);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        result = 1;
    }
    WSACleanup();
    return result;
}

struct TemporaryAddress {
    MIB_UNICASTIPADDRESS_ROW row{};
    bool installed = false;
    TemporaryAddress(const NET_LUID& interface_luid, const wchar_t* text, int family) {
        InitializeUnicastIpAddressEntry(&row);
        row.InterfaceLuid = interface_luid;
        row.Address.si_family = static_cast<ADDRESS_FAMILY>(family);
        void* ip = family == AF_INET ? static_cast<void*>(&row.Address.Ipv4.sin_addr) :
                                       static_cast<void*>(&row.Address.Ipv6.sin6_addr);
        Check(InetPtonW(family, text, ip) == 1, "temporary IP address");
        row.OnLinkPrefixLength = family == AF_INET ? 32 : 128;
        row.PrefixOrigin = IpPrefixOriginManual;
        row.SuffixOrigin = IpSuffixOriginManual;
    }
    void Add() {
        const DWORD status = CreateUnicastIpAddressEntry(&row);
        if (status != NO_ERROR) throw std::runtime_error("CreateUnicastIpAddressEntry: " + std::to_string(status));
        installed = true;
        const ULONGLONG deadline = GetTickCount64() + 5000;
        do {
            MIB_UNICASTIPADDRESS_ROW current = row;
            if (GetUnicastIpAddressEntry(&current) == NO_ERROR &&
                (current.DadState == IpDadStatePreferred || current.DadState == IpDadStateDeprecated)) return;
            Sleep(25);
        } while (GetTickCount64() < deadline);
        throw std::runtime_error("temporary IP did not become usable");
    }
    void Remove() {
        if (!installed) return;
        const DWORD status = DeleteUnicastIpAddressEntry(&row);
        if (status != NO_ERROR) throw std::runtime_error("DeleteUnicastIpAddressEntry: " + std::to_string(status));
        installed = false;
    }
    ~TemporaryAddress() {
        if (installed) {
            const DWORD status = DeleteUnicastIpAddressEntry(&row);
            if (status != NO_ERROR) std::fprintf(stderr, "ERROR: temporary IP cleanup failed: %lu\n", status);
        }
    }
};

void CheckLocalAddress(const std::wstring& path, const wchar_t* address, int family) {
    const std::wstring mode = std::wstring(L"--local-child ") + (family == AF_INET ? L"4 " : L"6 ") + address;
    Check(RunChild(path, mode.c_str(), 10000).exit_code == 0,
          "selected app must retain TCP/UDP connectivity to a locally assigned address");
}

void CheckLoopback(const std::wstring& path) {
    Check(RunChild(path, L"--loopback-child", 10000).exit_code == 0,
          "selected application must retain IPv4/IPv6 TCP/UDP loopback connectivity");
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
    if (argc == 2 && std::wcscmp(argv[1], L"--loopback-child") == 0) return LoopbackChild();
    if (argc == 4 && std::wcscmp(argv[1], L"--local-child") == 0) {
        const int family = std::wcscmp(argv[2], L"4") == 0 ? AF_INET : AF_INET6;
        return LocalAddressChild(argv[3], family);
    }
    if ((argc != 4 && argc != 6) || std::wcscmp(argv[1], L"--duration") != 0 ||
        (std::wcscmp(argv[2], L"30") != 0 && std::wcscmp(argv[2], L"60") != 0) ||
        (argc == 6 && std::wcscmp(argv[4], L"--interface-address") != 0)) {
        std::fprintf(stderr, "Usage: app_interface_runtime.exe --duration 30|60 absolute-driver.sys [--interface-address IPv4]\n");
        return 2;
    }
    try {
        const ULONGLONG deadline = GetTickCount64() + (std::wcscmp(argv[2], L"60") == 0 ? 60000 : 30000);
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
        CheckLoopback(app.path);
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
        ULONG selected_interface = 0;
        ULONG alternate_interface = 0;
        Check(ConvertInterfaceLuidToIndex(&alternate, &alternate_interface) == NO_ERROR,
              "selected interface index");
        const DWORD selected = ChildSource(app.path, &selected_interface);
        Check(selected == alternate_source && selected_interface == alternate_interface,
              "Unicode executable must use the selected non-default interface and source");
        Check(ChildSource(app.original) == baseline, "other executable path must keep its default route");
        Check(ChildSource(app.path) == alternate_source, "policy persists across process exit and relaunch");
        CheckLoopback(app.path);
        std::printf("PASS: actual interface selection, per-path isolation, and loopback over IOCTL\n");

        MIB_UNICASTIPADDRESS_TABLE* locals = nullptr;
        Check(GetUnicastIpAddressTable(AF_UNSPEC, &locals) == NO_ERROR && locals, "local address snapshot");
        for (ULONG i = 0; i < locals->NumEntries; ++i) {
            const auto& address = locals->Table[i].Address;
            if (address.si_family == AF_INET || address.si_family == AF_INET6)
                inspector.ExpectAddress(app.app_id, alternate.Value, address, false);
        }
        FreeMibTable(locals);
        TestApp second;
        bool second_installed = false;
        for (const auto& spec : {std::pair<const wchar_t*, int>{L"198.18.254.34", AF_INET},
                                 std::pair<const wchar_t*, int>{L"fd00:706d:6b65:7874::34", AF_INET6}}) {
            TemporaryAddress alias(loopback, spec.first, spec.second);
            inspector.ExpectAddress(app.app_id, alternate.Value, alias.row.Address, true);
            alias.Add();
            inspector.ExpectAddress(app.app_id, alternate.Value, alias.row.Address, false);
            if (!second_installed) {
                if (!runtime.driver.SetAppInterface(second.path, default_luid.Value, error, true))
                    throw std::runtime_error(error);
                second_installed = true;
            }
            inspector.ExpectAddress(second.app_id, default_luid.Value, alias.row.Address, false);
            CheckLocalAddress(app.path, spec.first, spec.second);
            alias.Remove();
            inspector.ExpectAddress(app.app_id, alternate.Value, alias.row.Address, true);
            inspector.ExpectAddress(second.app_id, default_luid.Value, alias.row.Address, true);
        }
        if (!runtime.driver.SetAppInterface(second.path, 0, error, false)) throw std::runtime_error(error);
        inspector.Expect(second.app_id, 0);
        std::printf("PASS: automatic IPv4/IPv6 address add/remove updates existing and new app policies\n");

        set(default_luid.Value, true);
        Check(ChildSource(app.path) == baseline, "WriteFile replaces route policy");
        set(default_luid.Value, true);
        set(0, false);
        set(0, false);
        Check(ChildSource(app.path) == baseline, "IOCTL removal restores default route");
        set(alternate.Value, true);
        Check(ChildSource(app.path) == alternate_source, "WriteFile add selects the alternate interface");
        CheckLoopback(app.path);
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
        TemporaryAddress changing(loopback, L"198.18.254.35", AF_INET);
        inspector.ExpectAddress(app.app_id, loopback.Value, changing.row.Address, true);
        std::atomic<bool> changes_started{false};
        std::string change_error;
        std::thread changer([&] {
            try {
                for (int i = 0; i < 8; ++i) {
                    changing.Add();
                    changes_started.store(true);
                    Sleep(5);
                    changing.Remove();
                }
            } catch (const std::exception& ex) {
                change_error = ex.what();
                changes_started.store(true);
            }
        });
        const ULONGLONG changes_deadline = GetTickCount64() + 6000;
        while (!changes_started.load() && GetTickCount64() < changes_deadline) Sleep(1);
        runtime.driver.Stop();
        runtime.reader.join();
        changer.join();
        Check(changes_started.load() && change_error.empty(), "address changes during driver shutdown");
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
