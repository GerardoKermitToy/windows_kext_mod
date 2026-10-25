#include "PortmasterKext.h"

#include <algorithm>
#include <cstdio>
#include <stdexcept>

namespace pmkext {

struct DriverTestAccess {
    static void Feed(Driver& driver, const Handlers& handlers, const std::vector<uint8_t>& bytes) {
        driver.buffer_.insert(driver.buffer_.end(), bytes.begin(), bytes.end());
        const size_t consumed = driver.Dispatch(handlers);
        driver.buffer_.erase(driver.buffer_.begin(), driver.buffer_.begin() + consumed);
    }
};

} // namespace pmkext

namespace {

void Check(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::vector<uint8_t> Record(bool ipv6, bool empty = false) {
    const uint8_t size = static_cast<uint8_t>((ipv6 ? 79 : 55) + (empty ? 0 : 3));
    std::vector<uint8_t> bytes = {
        static_cast<uint8_t>(ipv6 ? 8 : 7), size, 0, 0, 0,
        8, 7, 6, 5, 4, 3, 2, 1,
        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
        0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
        0x34, 0x33, 0x32, 0x31,
        0x44, 0x43, 0x42, 0x41,
        0x54, 0x53, 0x52, 0x51,
        1, 17,
    };
    const uint8_t addr_len = ipv6 ? 16 : 4;
    for (uint8_t i = 1; i <= addr_len * 2; ++i) {
        bytes.push_back(i);
    }
    bytes.insert(bytes.end(), {0x62, 0x61, 0x72, 0x71, static_cast<uint8_t>(ipv6 ? 4 : 3),
                              static_cast<uint8_t>(empty ? 0 : 3), 0, 0, 0});
    if (!empty) {
        bytes.insert(bytes.end(), {0xaa, 0xbb, 0xcc});
    }
    return bytes;
}

void CheckConnection(const pmkext::Connection& c, bool ipv6, bool empty) {
    Check(c.ipv6 == ipv6, "address family");
    Check(c.id == 0x0102030405060708ULL, "request ID");
    Check(c.process_id == 0x1112131415161718ULL, "process ID");
    Check(c.tid == 0x2122232425262728ULL, "thread ID");
    Check(c.compartment_id == 0x31323334, "compartment ID");
    Check(c.interface_index == 0x41424344, "interface index");
    Check(c.sub_interface_index == 0x51525354, "subinterface index");
    Check(c.direction == 1 && c.protocol == 17, "direction and protocol");
    const size_t addr_len = ipv6 ? 16 : 4;
    for (size_t i = 0; i < 16; ++i) {
        Check(c.local_ip[i] == (i < addr_len ? i + 1 : 0), "local address");
        Check(c.remote_ip[i] == (i < addr_len ? i + 1 + addr_len : 0), "remote address");
    }
    Check(c.local_port == 0x6162 && c.remote_port == 0x7172, "ports");
    Check(c.payload_layer == (ipv6 ? 4 : 3), "payload layer");
    Check(c.payload_size == (empty ? 0 : 3), "payload size");
    Check(c.payload == (empty ? std::vector<uint8_t>{} : std::vector<uint8_t>{0xaa, 0xbb, 0xcc}),
          "payload bytes");
}

void TestRecords() {
    for (const bool ipv6 : {false, true}) {
        for (const bool empty : {false, true}) {
            for (const bool fragmented : {false, true}) {
                pmkext::Driver driver;
                pmkext::Handlers handlers;
                unsigned connections = 0;
                unsigned warnings = 0;
                handlers.on_connection = [&](const pmkext::Connection& c) {
                    ++connections;
                    CheckConnection(c, ipv6, empty);
                };
                handlers.on_warning = [&](const std::string&) { ++warnings; };
                const auto bytes = Record(ipv6, empty);
                if (fragmented) {
                    for (size_t i = 0; i < bytes.size(); ++i) {
                        pmkext::DriverTestAccess::Feed(driver, handlers, {bytes[i]});
                        Check(connections == (i + 1 == bytes.size() ? 1u : 0u), "partial frame");
                    }
                } else {
                    pmkext::DriverTestAccess::Feed(driver, handlers, bytes);
                }
                Check(connections == 1 && warnings == 0, "valid connection record");
            }
        }
    }
}

void TestShortAndLegacyRecords() {
    for (const bool ipv6 : {false, true}) {
        pmkext::Driver driver;
        pmkext::Handlers handlers;
        unsigned connections = 0;
        unsigned warnings = 0;
        handlers.on_connection = [&](const pmkext::Connection&) { ++connections; };
        handlers.on_warning = [&](const std::string&) { ++warnings; };
        const auto valid = Record(ipv6);
        const size_t fixed = ipv6 ? 79 : 55;
        for (size_t length = 0; length < fixed; ++length) {
            auto short_record = valid;
            short_record.resize(5 + length);
            short_record[1] = static_cast<uint8_t>(length);
            pmkext::DriverTestAccess::Feed(driver, handlers, short_record);
        }
        auto legacy = valid;
        legacy[0] = ipv6 ? 2 : 1;
        pmkext::DriverTestAccess::Feed(driver, handlers, legacy);
        Check(connections == 0 && warnings == fixed + 1, "short/legacy record rejection");
        pmkext::DriverTestAccess::Feed(driver, handlers, valid);
        Check(connections == 1 && warnings == fixed + 1, "parser recovery");
    }
}

void TestBatchAndTruncatedPayload() {
    pmkext::Driver driver;
    pmkext::Handlers handlers;
    std::vector<pmkext::Connection> connections;
    unsigned warnings = 0;
    handlers.on_connection = [&](const pmkext::Connection& c) { connections.push_back(c); };
    handlers.on_warning = [&](const std::string&) { ++warnings; };
    auto bytes = Record(false);
    const auto v6 = Record(true);
    bytes.insert(bytes.end(), v6.begin(), v6.end());
    pmkext::DriverTestAccess::Feed(driver, handlers, bytes);
    Check(connections.size() == 2 && warnings == 0, "batched records");
    CheckConnection(connections[0], false, false);
    CheckConnection(connections[1], true, false);

    auto truncated = Record(false);
    truncated.pop_back();
    --truncated[1];
    pmkext::DriverTestAccess::Feed(driver, handlers, truncated);
    Check(connections.size() == 3 && warnings == 1, "truncated payload warning");
    Check(connections.back().payload_size == 3 && connections.back().payload.size() == 2,
          "truncated payload bounds");
}

} // namespace

int main() {
    static_assert(static_cast<uint8_t>(pmkext::InfoType::ConnectionIpv4) == 7);
    static_assert(static_cast<uint8_t>(pmkext::InfoType::ConnectionIpv6) == 8);
    static_assert(static_cast<uint8_t>(pmkext::InfoType::ConnectionEndEventV4) == 3);
    static_assert(static_cast<uint8_t>(pmkext::InfoType::ConnectionEndEventV6) == 4);
    try {
        TestRecords();
        TestShortAndLegacyRecords();
        TestBatchAndTruncatedPayload();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
    std::puts("PASS: connection metadata, framing, bounds and legacy type rejection");
    return 0;
}
