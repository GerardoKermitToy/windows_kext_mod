#include "PortmasterKext.h"

#include <algorithm>
#include <cstdio>
#include <span>
#include <stdexcept>

namespace pmkext {

struct DriverTestAccess {
    static void Feed(Driver& driver, const Handlers& handlers, std::span<const uint8_t> bytes) {
        driver.buffer_.insert(driver.buffer_.end(), bytes.begin(), bytes.end());
        const size_t consumed = driver.Dispatch(handlers);
        driver.buffer_.erase(driver.buffer_.begin(), driver.buffer_.begin() + consumed);
    }

    static size_t Pending(const Driver& driver) {
        return driver.buffer_.size();
    }
};

} // namespace pmkext

namespace {

constexpr size_t kFormerPipeLimit = 64 * 1024 * 1024;
constexpr size_t kRecordHeaderSize = 5;
constexpr size_t kStatsHeaderSize = 5;
constexpr size_t kReadSize = 64 * 1024;
constexpr uint64_t kTxBase = 0x1234567800000000ULL;
constexpr uint64_t kRxBase = 0xabcdef0100000000ULL;

void Check(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void AppendLe(std::vector<uint8_t>& bytes, uint64_t value, unsigned width) {
    for (unsigned i = 0; i < width; ++i) {
        bytes.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
}

uint8_t AddressByte(uint32_t tuple, size_t byte, bool remote) {
    return static_cast<uint8_t>((tuple >> (8 * (byte % 4))) ^ byte ^ (remote ? 0xa0 : 0x20));
}

std::vector<uint8_t> Record(bool ipv6, uint8_t protocol, uint32_t count) {
    const size_t addr_len = ipv6 ? 16 : 4;
    const size_t entry_size = addr_len * 2 + 2 + 2 + 8 + 8;
    const size_t payload_size = kStatsHeaderSize + entry_size * count;
    std::vector<uint8_t> bytes;
    bytes.reserve(kRecordHeaderSize + payload_size);
    bytes.push_back(static_cast<uint8_t>(ipv6 ? pmkext::InfoType::BandwidthStatsV6
                                            : pmkext::InfoType::BandwidthStatsV4));
    AppendLe(bytes, payload_size, 4);
    bytes.push_back(protocol);
    AppendLe(bytes, count, 4);
    for (uint32_t i = 0; i < count; ++i) {
        for (size_t byte = 0; byte < addr_len; ++byte) {
            bytes.push_back(AddressByte(i, byte, false));
        }
        AppendLe(bytes, static_cast<uint16_t>(1000 + i), 2);
        for (size_t byte = 0; byte < addr_len; ++byte) {
            bytes.push_back(AddressByte(i, byte, true));
        }
        AppendLe(bytes, static_cast<uint16_t>(60000 - i), 2);
        AppendLe(bytes, kTxBase + i, 8);
        AppendLe(bytes, kRxBase + 7ULL * i, 8);
    }
    Check(bytes.size() == kRecordHeaderSize + payload_size, "encoded record size");
    return bytes;
}

void CheckStats(const pmkext::BandwidthStats& stats, bool ipv6, uint8_t protocol,
                uint32_t count) {
    Check(stats.protocol == protocol, "bandwidth protocol");
    Check(stats.entries.size() == count, "every tuple must reach the handler");
    const size_t addr_len = ipv6 ? 16 : 4;
    for (uint32_t i = 0; i < count; ++i) {
        const auto& entry = stats.entries[i];
        Check(entry.ipv6 == ipv6, "bandwidth address family");
        for (size_t byte = 0; byte < 16; ++byte) {
            Check(entry.local_ip[byte] == (byte < addr_len ? AddressByte(i, byte, false) : 0),
                  "bandwidth local address");
            Check(entry.remote_ip[byte] == (byte < addr_len ? AddressByte(i, byte, true) : 0),
                  "bandwidth remote address");
        }
        Check(entry.local_port == static_cast<uint16_t>(1000 + i), "bandwidth local port");
        Check(entry.remote_port == static_cast<uint16_t>(60000 - i), "bandwidth remote port");
        Check(entry.transmitted_bytes == kTxBase + i, "64-bit transmitted bytes");
        Check(entry.received_bytes == kRxBase + 7ULL * i, "64-bit received bytes");
    }
}

void TestRecord(bool ipv6, uint8_t protocol, uint32_t count, bool fragmented) {
    pmkext::Driver driver;
    pmkext::Handlers handlers;
    unsigned snapshots = 0;
    unsigned logs = 0;
    unsigned warnings = 0;
    const uint8_t following_protocol = protocol == 6 ? 17 : 6;
    handlers.on_bandwidth = [&](const pmkext::BandwidthStats& stats) {
        Check(snapshots < 2, "snapshot delivered more than once");
        if (snapshots == 0) {
            CheckStats(stats, ipv6, protocol, count);
        } else {
            CheckStats(stats, !ipv6, following_protocol, 2);
        }
        ++snapshots;
    };
    handlers.on_log = [&](const pmkext::LogLine& log) {
        Check(snapshots == 2, "following log arrived before bandwidth snapshots");
        Check(log.severity == pmkext::Severity::Info && log.message == "ok", "following log");
        ++logs;
    };
    handlers.on_warning = [&](const std::string&) { ++warnings; };

    const auto bytes = Record(ipv6, protocol, count);
    const std::span<const uint8_t> wire(bytes);
    if (fragmented) {
        // Split the frame header, then use the same 64-KiB reads as ReaderLoop.
        // Keep the last byte for a read that also contains subsequent records.
        pmkext::DriverTestAccess::Feed(driver, handlers, wire.first(1));
        pmkext::DriverTestAccess::Feed(driver, handlers, wire.subspan(1, 2));
        for (size_t offset = 3; offset < wire.size() - 1;) {
            const size_t length = std::min(kReadSize, wire.size() - 1 - offset);
            pmkext::DriverTestAccess::Feed(driver, handlers, wire.subspan(offset, length));
            offset += length;
            Check(snapshots == 0 && logs == 0, "partial snapshot was dispatched");
        }
        Check(pmkext::DriverTestAccess::Pending(driver) == wire.size() - 1,
              "partial snapshot bytes must remain buffered");
    } else {
        pmkext::DriverTestAccess::Feed(driver, handlers, wire);
        Check(snapshots == 1, "complete snapshot was not delivered");
    }

    auto tail = Record(!ipv6, following_protocol, 2);
    if (fragmented) {
        tail.insert(tail.begin(), bytes.back());
    }
    tail.insert(tail.end(), {static_cast<uint8_t>(pmkext::InfoType::LogLine), 3, 0, 0, 0,
                             static_cast<uint8_t>(pmkext::Severity::Info), 'o', 'k'});
    pmkext::DriverTestAccess::Feed(driver, handlers, tail);
    Check(snapshots == 2 && logs == 1 && warnings == 0,
          "snapshot or following records were lost");
    Check(pmkext::DriverTestAccess::Pending(driver) == 0, "complete records left in buffer");
    pmkext::DriverTestAccess::Feed(driver, handlers, {});
    Check(snapshots == 2 && logs == 1, "records were delivered twice");

    std::printf("PASS: IPv%u protocol=%u tuples=%u wire_bytes=%zu %s\n",
                ipv6 ? 6u : 4u, static_cast<unsigned>(protocol), count, bytes.size(),
                fragmented ? "fragmented" : "complete");
}

void TestLargeRecords() {
    for (const bool ipv6 : {false, true}) {
        const size_t entry_size = ipv6 ? 52 : 28;
        const auto last_under = static_cast<uint32_t>(
            (kFormerPipeLimit - kRecordHeaderSize - kStatsHeaderSize) / entry_size);
        Check(kRecordHeaderSize + kStatsHeaderSize + entry_size * last_under <= kFormerPipeLimit,
              "below-limit test size");
        Check(kRecordHeaderSize + kStatsHeaderSize + entry_size * (last_under + 1) > kFormerPipeLimit,
              "above-limit test size");
        for (const uint8_t protocol : {uint8_t{6}, uint8_t{17}}) {
            TestRecord(ipv6, protocol, last_under, true);
            TestRecord(ipv6, protocol, last_under + 1, true);
        }
    }
}

} // namespace

int main() {
    try {
        for (const bool ipv6 : {false, true}) {
            for (const uint8_t protocol : {uint8_t{6}, uint8_t{17}}) {
                for (const uint32_t count : {0u, 1u, 3u}) {
                    TestRecord(ipv6, protocol, count, false);
                    TestRecord(ipv6, protocol, count, true);
                }
            }
        }
        TestLargeRecords();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
    std::puts("PASS: every bandwidth tuple survives dispatch, including snapshots above 64 MiB");
    return 0;
}
