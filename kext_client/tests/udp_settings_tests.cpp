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
        uint8_t bytes[8] = {};
        OVERLAPPED ov = {};
        DWORD read = 0;
        const BOOL started = ReadFile(handle, bytes, sizeof(bytes), &read, &ov);
        Check(started || GetLastError() == ERROR_IO_PENDING, "ReadFile wire");
        Check(GetOverlappedResult(handle, &ov, &read, TRUE) != 0, "read wire completion");
        Check(read == 2, "setting write must contain exactly two bytes");
        Check(bytes[0] == command, "setting command ID");
        Check(bytes[1] == static_cast<uint8_t>(enabled), "setting boolean encoding");
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
} // namespace

int main() {
    try {
        TestSettings();
        std::printf("PASS: UDP runtime setting API and WriteFile encoding\n");
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "FAIL: %s\n", e.what());
        return 1;
    }
}
