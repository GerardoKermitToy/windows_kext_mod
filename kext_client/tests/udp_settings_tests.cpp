#include "PortmasterKext.h"

#include <windows.h>

#include <cstdio>
#include <stdexcept>
#include <string>
#include <utility>

namespace pmkext {
struct DriverTestAccess {
    static void SetDevice(Driver& driver, HANDLE handle) { driver.device_ = handle; }
};
} // namespace pmkext

namespace {
void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

// Exercise real overlapped WriteFile serialization without loading a driver.
struct FileDevice {
    pmkext::Driver driver;
    HANDLE handle = INVALID_HANDLE_VALUE;

    FileDevice() {
        wchar_t temp[MAX_PATH] = {};
        wchar_t path[MAX_PATH] = {};
        Check(GetTempPathW(MAX_PATH, temp) != 0, "GetTempPathW");
        Check(GetTempFileNameW(temp, L"pmu", 0, path) != 0, "GetTempFileNameW");
        handle = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE |
                             FILE_FLAG_OVERLAPPED, nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            DeleteFileW(path);
            throw std::runtime_error("CreateFileW temporary device");
        }
        pmkext::DriverTestAccess::SetDevice(driver, handle);
    }
    ~FileDevice() {
        pmkext::DriverTestAccess::SetDevice(driver, nullptr);
        CloseHandle(handle);
    }

    void CheckWire(uint8_t command, bool enabled) {
        const uint8_t expected[] = {command, static_cast<uint8_t>(enabled)};
        CheckWireBytes(expected, sizeof(expected), "setting write");
    }

    void CheckWireBytes(const uint8_t* expected, DWORD expected_len, const char* what) {
        uint8_t bytes[64] = {};
        OVERLAPPED ov = {};
        DWORD read = 0;
        const BOOL started = ReadFile(handle, bytes, sizeof(bytes), &read, &ov);
        Check(started || GetLastError() == ERROR_IO_PENDING, "ReadFile wire");
        Check(GetOverlappedResult(handle, &ov, &read, TRUE) != 0, "read wire completion");
        Check(read == expected_len, what);
        for (DWORD i = 0; i < expected_len; ++i) {
            Check(bytes[i] == expected[i], "wire bytes mismatch");
        }
    }
};

using Setter = bool (pmkext::Driver::*)(bool, std::string&, bool);

void TestSettings() {
    static_assert(static_cast<uint8_t>(pmkext::CommandType::SetAuthorizeOutboundUdpAtAle) == 11);
    static_assert(static_cast<uint8_t>(pmkext::CommandType::SetInboundUdpPidFallback) == 12);
    for (const auto& test : {
             std::pair<Setter, uint8_t>{&pmkext::Driver::SetAuthorizeOutboundUdpAtAle, 11},
             std::pair<Setter, uint8_t>{&pmkext::Driver::SetInboundUdpPidFallback, 12}}) {
        for (bool enabled : {false, true}) {
            pmkext::Driver unopened;
            for (bool via_write : {false, true}) {
                std::string error;
                Check(!(unopened.*test.first)(enabled, error, via_write),
                      "unopened setting request must fail");
                Check(error == "device not open", "unopened request diagnostic");
            }
            FileDevice file;
            std::string error;
            const bool sent = (file.driver.*test.first)(enabled, error, true);
            Check(sent, error.c_str());
            file.CheckWire(test.second, enabled);
        }
    }
}

void TestUdpFlowAbortCommands() {
    static_assert(static_cast<uint8_t>(pmkext::CommandType::AbortUdpFlowV4) == 13);
    static_assert(static_cast<uint8_t>(pmkext::CommandType::AbortUdpFlowV6) == 14);

    const uint8_t local_v4[] = {192, 0, 2, 10};
    const uint8_t remote_v4[] = {198, 51, 100, 20};
    const uint8_t expected_v4[] = {
        13, 192, 0, 2, 10, 0x39, 0x30, 198, 51, 100, 20, 0xbb, 0x01,
    };
    {
        pmkext::Driver unopened;
        std::string error;
        Check(!unopened.AbortUdpFlowV4(local_v4, 12'345, remote_v4, 443, error, true),
              "unopened IPv4 flow-abort request must fail");
        Check(error == "device not open", "unopened IPv4 flow-abort diagnostic");
    }
    {
        FileDevice file;
        std::string error;
        Check(file.driver.AbortUdpFlowV4(local_v4, 12'345, remote_v4, 443, error, true),
              error.c_str());
        file.CheckWireBytes(expected_v4, sizeof(expected_v4), "IPv4 flow-abort write size");
    }

    const uint8_t local_v6[] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    };
    const uint8_t remote_v6[] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    };
    const uint8_t expected_v6[] = {
        14,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0x82, 0x9a,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        0x35, 0x00,
    };
    {
        pmkext::Driver unopened;
        std::string error;
        Check(!unopened.AbortUdpFlowV6(local_v6, 39'554, remote_v6, 53, error, true),
              "unopened IPv6 flow-abort request must fail");
        Check(error == "device not open", "unopened IPv6 flow-abort diagnostic");
    }
    {
        FileDevice file;
        std::string error;
        Check(file.driver.AbortUdpFlowV6(local_v6, 39'554, remote_v6, 53, error, true),
              error.c_str());
        file.CheckWireBytes(expected_v6, sizeof(expected_v6), "IPv6 flow-abort write size");
    }
}

} // namespace

int main() {
    try {
        TestSettings();
        TestUdpFlowAbortCommands();
        std::printf("PASS: UDP runtime setting API and WriteFile encoding\n");
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "FAIL: %s\n", e.what());
        return 1;
    }
}
