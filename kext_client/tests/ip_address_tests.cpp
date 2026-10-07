#include "PortmasterKext.h"

#include <cstdio>
#include <string>

int main() {
    struct ValidCase {
        const wchar_t* literal;
        const char* normalized;
    };
    const ValidCase valid[] = {
        {L"127.0.0.1", "127.0.0.1"},
        {L"192.0.2.1", "192.0.2.1"},
        {L"0.0.0.0", "0.0.0.0"},
        {L"255.255.255.255", "255.255.255.255"},
        {L"::", "0000:0000:0000:0000:0000:0000:0000:0000"},
        {L"::1", "0000:0000:0000:0000:0000:0000:0000:0001"},
        {L"0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001"},
        {L"0000:0000:0000:0000:0000:0000:0000:0001", "0000:0000:0000:0000:0000:0000:0000:0001"},
        {L"2001:db8:85a3::8a2e:370:7334", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
        {L"2001:DB8:85A3::8A2E:370:7334", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
        {L"2001:0DB8:85A3:0:0:8A2E:0370:7334", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
        {L"::ffff:127.0.0.1", "0000:0000:0000:0000:0000:ffff:7f00:0001"},
        {L"::FFFF:7F00:1", "0000:0000:0000:0000:0000:ffff:7f00:0001"},
    };
    const wchar_t* invalid[] = {
        L"", L"localhost", L"127.1", L"127.0.0.256", L"127.0.0.1:53",
        L"[::1]", L"[::1]:53", L"::1/128", L"2001::db8::1", L"gggg::1",
        L" 127.0.0.1", L"::1 ", L"fe80::1%1", L"а::1",
    };

    unsigned checks = 0;
    for (const auto& test : valid) {
        std::string normalized;
        if (!pmkext::NormalizeIpAddress(test.literal, normalized) || normalized != test.normalized) {
            std::fprintf(stderr, "Valid IP case %u failed: got '%s', expected '%s'\n",
                         checks, normalized.c_str(), test.normalized);
            return 1;
        }
        std::string repeated;
        const std::wstring canonical(normalized.begin(), normalized.end());
        if (!pmkext::NormalizeIpAddress(canonical, repeated) || repeated != normalized) {
            std::fprintf(stderr, "IP normalization is not idempotent for case %u\n", checks);
            return 1;
        }
        checks += 2;
    }
    for (const auto* literal : invalid) {
        std::string normalized = "unchanged";
        if (pmkext::NormalizeIpAddress(literal, normalized) || normalized != "unchanged") {
            std::fprintf(stderr, "Invalid IP case %u was accepted or changed the output\n", checks);
            return 1;
        }
        ++checks;
    }
    std::printf("PASS: %u IP normalization checks\n", checks);
    return 0;
}
