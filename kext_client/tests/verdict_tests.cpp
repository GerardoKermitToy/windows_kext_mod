#include "PortmasterKext.h"

#include <cstdio>
#include <cstring>

int main() {
    struct VerdictCase {
        pmkext::Verdict verdict;
        unsigned value;
        const char* name;
    };
    const VerdictCase supported[] = {
        {pmkext::Verdict::Undecided, 0, "Undecided"},
        {pmkext::Verdict::Undeterminable, 1, "Undeterminable"},
        {pmkext::Verdict::Accept, 2, "Accept"},
        {pmkext::Verdict::PermanentAccept, 3, "PermanentAccept"},
        {pmkext::Verdict::Block, 4, "Block"},
        {pmkext::Verdict::PermanentBlock, 5, "PermanentBlock"},
        {pmkext::Verdict::Drop, 6, "Drop"},
        {pmkext::Verdict::PermanentDrop, 7, "PermanentDrop"},
        {pmkext::Verdict::Failed, 10, "Failed"},
    };
    for (const auto& test : supported) {
        if (static_cast<unsigned>(test.verdict) != test.value ||
            std::strcmp(pmkext::ToString(test.verdict), test.name) != 0) {
            std::fprintf(stderr, "Verdict %s changed its wire value or name\n", test.name);
            return 1;
        }
    }
    for (unsigned value = 0; value <= 255; ++value) {
        const char* expected = "Unknown";
        for (const auto& test : supported) {
            if (value == test.value) expected = test.name;
        }
        if (std::strcmp(pmkext::ToString(static_cast<pmkext::Verdict>(value)), expected) != 0) {
            std::fprintf(stderr, "Unexpected name for verdict value %u\n", value);
            return 1;
        }
    }
    std::printf("PASS: verdict wire values and all 256 names\n");
    return 0;
}
