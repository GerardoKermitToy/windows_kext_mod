#include "PortmasterKext.h"

#include <windows.h>
#include <fwpmu.h>

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace pmkext {
struct DriverTestAccess {
    static bool Build(const std::wstring& path, uint64_t luid,
                      std::vector<uint8_t>& command, std::string& error) {
        return Driver::BuildAppInterfaceCommand(path, luid, command, error);
    }
};
} // namespace pmkext

namespace {
void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct TestFile {
    std::wstring directory;
    std::wstring path;

    TestFile() {
        wchar_t temp[MAX_PATH] = {};
        Check(GetTempPathW(MAX_PATH, temp) != 0, "GetTempPathW");
        directory = std::wstring(temp) + L"pmkext-app-" + std::to_wstring(GetCurrentProcessId()) +
            L"-" + std::to_wstring(GetTickCount64()) + L"-\u0422\u0435\u0441\u0442-\u5e94\u7528";
        Check(CreateDirectoryW(directory.c_str(), nullptr) != 0, "CreateDirectoryW Unicode");
        path = directory + L"\\\u041f\u0440\u0438\u043b\u043e\u0436\u0435\u043d\u0438\u0435_\u00e9_\U0001f680.exe";
        HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                  CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            RemoveDirectoryW(directory.c_str());
            throw std::runtime_error("CreateFileW Unicode");
        }
        CloseHandle(file);
    }
    ~TestFile() {
        DeleteFileW(path.c_str());
        RemoveDirectoryW(directory.c_str());
    }
};

void TestUnicodeCanonicalizationAndWire() {
    TestFile file;
    std::string error;
    std::vector<uint8_t> command;
    constexpr uint64_t luid = 0xfedcba9876543210ULL;
    Check(pmkext::DriverTestAccess::Build(file.path, luid, command, error), error.c_str());
    Check(command.size() > 17 && command[0] == 10, "command number and header");
    for (unsigned i = 0; i < 8; ++i) {
        Check(command[1 + i] == static_cast<uint8_t>(luid >> (i * 8)), "full-width LUID LE");
    }
    uint32_t size = 0;
    for (unsigned i = 0; i < 4; ++i) size |= uint32_t(command[9 + i]) << (i * 8);
    Check(command.size() == 13 + size, "explicit app ID byte size");

    FWP_BYTE_BLOB* expected = nullptr;
    Check(FwpmGetAppIdFromFileName0(file.path.c_str(), &expected) == ERROR_SUCCESS,
          "FwpmGetAppIdFromFileName0 Unicode");
    const bool equal = expected && size == expected->size &&
        std::memcmp(command.data() + 13, expected->data, size) == 0;
    FwpmFreeMemory0(reinterpret_cast<void**>(&expected));
    Check(equal, "wire app ID must match the native WFP Unicode blob byte-for-byte");

    std::wstring native(size / sizeof(wchar_t), wchar_t{});
    std::memcpy(native.data(), command.data() + 13, size);
    Check(native.starts_with(L"\\device\\"), "canonical native device path");
    Check(native.find(L"\u5e94\u7528") != std::wstring::npos, "CJK survives canonicalization");
    Check(native.find(L"\u043f\u0440\u0438\u043b") != std::wstring::npos ||
          native.find(L"\u041f\u0440\u0438\u043b") != std::wstring::npos, "Cyrillic survives canonicalization");
    Check(native.find(L"\u00e9") != std::wstring::npos, "accented Latin survives");
    Check(native.find(L"\U0001f680") != std::wstring::npos, "UTF-16 surrogate pair survives");
    Check(native.back() == wchar_t{}, "native app ID has a NUL terminator");

    std::wstring upper = file.path;
    CharUpperBuffW(upper.data(), static_cast<DWORD>(upper.size()));
    std::vector<uint8_t> uppercase;
    Check(pmkext::DriverTestAccess::Build(upper, luid, uppercase, error), error.c_str());
    Check(uppercase == command, "Unicode case variants resolve to the same app ID");

    std::vector<uint8_t> remove;
    Check(pmkext::DriverTestAccess::Build(file.path, 0, remove, error), error.c_str());
    for (unsigned i = 1; i <= 8; ++i) Check(remove[i] == 0, "zero LUID removal");
    Check(std::memcmp(command.data() + 9, remove.data() + 9, command.size() - 9) == 0,
          "removal keeps the same canonical identity");

    pmkext::Driver unopened;
    Check(!unopened.SetAppInterface(file.path, luid, error), "IOCTL must not falsely succeed unopened");
    Check(!unopened.SetAppInterface(file.path, luid, error, true), "WriteFile must not falsely succeed unopened");
}

void TestInvalidPaths() {
    std::string error;
    std::vector<uint8_t> command{1, 2, 3};
    Check(!pmkext::DriverTestAccess::Build(L"", 1, command, error), "reject empty path");
    Check(command.empty(), "clear command after failure");
    std::wstring embedded = L"C:\\valid.exe";
    embedded.push_back(wchar_t{});
    embedded += L"ignored.exe";
    Check(!pmkext::DriverTestAccess::Build(embedded, 1, command, error), "reject embedded NUL");
}
} // namespace

int main() {
    try {
        TestUnicodeCanonicalizationAndWire();
        TestInvalidPaths();
        std::printf("PASS: Unicode app ID and interface command tests\n");
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "FAIL: %s\n", e.what());
        return 1;
    }
}
