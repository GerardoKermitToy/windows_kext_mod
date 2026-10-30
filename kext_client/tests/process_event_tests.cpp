#include "PortmasterKext.h"

#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <vector>

namespace pmkext {

struct DriverTestAccess {
    static void Feed(Driver& driver, const Handlers& handlers, const std::vector<uint8_t>& bytes) {
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

void Check(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void AppendU32(std::vector<uint8_t>& bytes, uint32_t value) {
    for (unsigned shift = 0; shift != 32; shift += 8) {
        bytes.push_back(static_cast<uint8_t>(value >> shift));
    }
}

void AppendU64(std::vector<uint8_t>& bytes, uint64_t value) {
    for (unsigned shift = 0; shift != 64; shift += 8) {
        bytes.push_back(static_cast<uint8_t>(value >> shift));
    }
}

std::vector<uint8_t> Frame(pmkext::InfoType type, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> bytes;
    bytes.reserve(5 + payload.size());
    bytes.push_back(static_cast<uint8_t>(type));
    AppendU32(bytes, static_cast<uint32_t>(payload.size()));
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<uint8_t> CreatedFrame(
    std::initializer_list<pmkext::ProcessCreated> entries) {
    std::vector<uint8_t> payload;
    payload.reserve(entries.size() * 16);
    for (const auto& entry : entries) {
        AppendU64(payload, entry.pid);
        AppendU64(payload, entry.parent_pid);
    }
    return Frame(pmkext::InfoType::ProcessCreated, payload);
}

std::vector<uint8_t> TerminatedFrame(
    std::initializer_list<pmkext::ProcessTerminated> entries) {
    std::vector<uint8_t> payload;
    payload.reserve(entries.size() * 8);
    for (const auto& entry : entries) {
        AppendU64(payload, entry.pid);
    }
    return Frame(pmkext::InfoType::ProcessTerminated, payload);
}

void TestPackedBatchesAndLittleEndian() {
    pmkext::Driver driver;
    pmkext::Handlers handlers;
    std::vector<std::vector<pmkext::ProcessCreated>> created_batches;
    std::vector<std::vector<pmkext::ProcessTerminated>> terminated_batches;
    unsigned warnings = 0;
    handlers.on_process_created = [&](const std::vector<pmkext::ProcessCreated>& entries) {
        created_batches.push_back(entries);
    };
    handlers.on_process_terminated = [&](const std::vector<pmkext::ProcessTerminated>& entries) {
        terminated_batches.push_back(entries);
    };
    handlers.on_warning = [&](const std::string&) { ++warnings; };

    auto bytes = CreatedFrame({
        {0x0102030405060708ULL, 0x1112131415161718ULL},
        {0xf0e0d0c0b0a09080ULL, 0x8877665544332211ULL},
    });
    const auto terminated = TerminatedFrame({
        {0x1020304050607080ULL},
        {0xdeadbeef01234567ULL},
    });
    bytes.insert(bytes.end(), terminated.begin(), terminated.end());
    pmkext::DriverTestAccess::Feed(driver, handlers, bytes);

    Check(warnings == 0, "packed batches should not warn");
    Check(created_batches.size() == 1 && terminated_batches.size() == 1,
          "one callback per complete frame");
    Check(created_batches[0].size() == 2, "created packed entry count");
    Check(created_batches[0][0].pid == 0x0102030405060708ULL,
          "created PID little-endian decoding");
    Check(created_batches[0][0].parent_pid == 0x1112131415161718ULL,
          "created parent PID little-endian decoding");
    Check(created_batches[0][1].pid == 0xf0e0d0c0b0a09080ULL,
          "second created PID little-endian decoding");
    Check(created_batches[0][1].parent_pid == 0x8877665544332211ULL,
          "second parent PID little-endian decoding");
    Check(terminated_batches[0].size() == 2, "terminated packed entry count");
    Check(terminated_batches[0][0].pid == 0x1020304050607080ULL,
          "terminated PID little-endian decoding");
    Check(terminated_batches[0][1].pid == 0xdeadbeef01234567ULL,
          "second terminated PID little-endian decoding");
    Check(pmkext::DriverTestAccess::Pending(driver) == 0, "all packed frames consumed");
}

void TestEmptyBatches() {
    pmkext::Driver driver;
    pmkext::Handlers handlers;
    std::vector<size_t> created_sizes;
    std::vector<size_t> terminated_sizes;
    handlers.on_process_created = [&](const std::vector<pmkext::ProcessCreated>& entries) {
        created_sizes.push_back(entries.size());
    };
    handlers.on_process_terminated = [&](const std::vector<pmkext::ProcessTerminated>& entries) {
        terminated_sizes.push_back(entries.size());
    };

    auto bytes = CreatedFrame({});
    const auto terminated = TerminatedFrame({});
    bytes.insert(bytes.end(), terminated.begin(), terminated.end());
    pmkext::DriverTestAccess::Feed(driver, handlers, bytes);

    Check(created_sizes == std::vector<size_t>{0}, "empty created batch delivered");
    Check(terminated_sizes == std::vector<size_t>{0}, "empty terminated batch delivered");
    Check(pmkext::DriverTestAccess::Pending(driver) == 0, "empty frames consumed");
}

void TestMalformedSizeRecovery() {
    pmkext::Driver driver;
    pmkext::Handlers handlers;
    std::vector<std::vector<pmkext::ProcessCreated>> created_batches;
    std::vector<std::vector<pmkext::ProcessTerminated>> terminated_batches;
    unsigned warnings = 0;
    handlers.on_process_created = [&](const std::vector<pmkext::ProcessCreated>& entries) {
        created_batches.push_back(entries);
    };
    handlers.on_process_terminated = [&](const std::vector<pmkext::ProcessTerminated>& entries) {
        terminated_batches.push_back(entries);
    };
    handlers.on_warning = [&](const std::string&) { ++warnings; };

    auto bytes = Frame(pmkext::InfoType::ProcessCreated, std::vector<uint8_t>(15, 0xa5));
    const auto valid_terminated = TerminatedFrame({{0x123456789abcdef0ULL}});
    bytes.insert(bytes.end(), valid_terminated.begin(), valid_terminated.end());
    const auto malformed_terminated =
        Frame(pmkext::InfoType::ProcessTerminated, std::vector<uint8_t>(7, 0x5a));
    bytes.insert(bytes.end(), malformed_terminated.begin(), malformed_terminated.end());
    const auto valid_created = CreatedFrame({{0x0123456789abcdefULL, 0xfedcba9876543210ULL}});
    bytes.insert(bytes.end(), valid_created.begin(), valid_created.end());
    pmkext::DriverTestAccess::Feed(driver, handlers, bytes);

    Check(warnings == 2, "one warning per malformed process frame");
    Check(terminated_batches.size() == 1 && terminated_batches[0].size() == 1,
          "valid terminated frame recovered after malformed created frame");
    Check(terminated_batches[0][0].pid == 0x123456789abcdef0ULL,
          "recovered terminated PID");
    Check(created_batches.size() == 1 && created_batches[0].size() == 1,
          "valid created frame recovered after malformed terminated frame");
    Check(created_batches[0][0].pid == 0x0123456789abcdefULL &&
              created_batches[0][0].parent_pid == 0xfedcba9876543210ULL,
          "recovered created entry");
    Check(pmkext::DriverTestAccess::Pending(driver) == 0, "malformed frames consumed");
}

void TestFragmentedStreamDispatchesImmediately() {
    pmkext::Driver driver;
    pmkext::Handlers handlers;
    unsigned created_callbacks = 0;
    unsigned terminated_callbacks = 0;
    handlers.on_process_created = [&](const std::vector<pmkext::ProcessCreated>& entries) {
        ++created_callbacks;
        Check(entries.size() == 1 && entries[0].pid == 42 && entries[0].parent_pid == 7,
              "fragmented created batch contents");
    };
    handlers.on_process_terminated = [&](const std::vector<pmkext::ProcessTerminated>& entries) {
        ++terminated_callbacks;
        Check(entries.size() == 1 && entries[0].pid == 42,
              "fragmented terminated batch contents");
    };

    const auto created = CreatedFrame({{42, 7}});
    const auto terminated = TerminatedFrame({{42}});
    auto stream = created;
    stream.insert(stream.end(), terminated.begin(), terminated.end());
    for (size_t i = 0; i < stream.size(); ++i) {
        pmkext::DriverTestAccess::Feed(driver, handlers, {stream[i]});
        const unsigned expected_created = i + 1 >= created.size() ? 1u : 0u;
        const unsigned expected_terminated = i + 1 == stream.size() ? 1u : 0u;
        Check(created_callbacks == expected_created,
              "created callback must wait for its complete frame and run immediately then");
        Check(terminated_callbacks == expected_terminated,
              "terminated callback must wait for its complete frame and run immediately then");
    }
    Check(pmkext::DriverTestAccess::Pending(driver) == 0, "fragmented stream fully consumed");
}

} // namespace

int main() {
    static_assert(static_cast<uint8_t>(pmkext::InfoType::ProcessCreated) == 9);
    static_assert(static_cast<uint8_t>(pmkext::InfoType::ProcessTerminated) == 10);
    try {
        TestPackedBatchesAndLittleEndian();
        TestEmptyBatches();
        TestMalformedSizeRecovery();
        TestFragmentedStreamDispatchesImmediately();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
    std::puts("PASS: process event framing, little-endian batches, recovery and fragmentation");
    return 0;
}
