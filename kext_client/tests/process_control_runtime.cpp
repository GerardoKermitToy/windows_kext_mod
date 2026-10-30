// Administrator-only runtime probe; deliberately not registered with CTest.
// Driver owns the service lifecycle exactly as it does in kext_monitor.
#include "PortmasterKext.h"

#include <windows.h>

#include <atomic>
#include <cstdio>
#include <cwchar>
#include <string>

int wmain(int argc, wchar_t** argv) {
    if (argc != 4 || std::wcscmp(argv[1], L"--duration") != 0 ||
        std::wcscmp(argv[2], L"8") != 0) {
        std::fprintf(stderr, "Usage: process_control_runtime.exe --duration 8 absolute-driver.sys\n");
        return 2;
    }

    pmkext::Driver driver;
    std::string error;
    if (!driver.Install(argv[3], error) || !driver.Open(error)) {
        std::fprintf(stderr, "FAIL: %s\n", error.c_str());
        return 1;
    }

    const ULONGLONG started = GetTickCount64();
    const ULONGLONG deadline = started + 8000;
    const uint64_t own_pid = GetCurrentProcessId();
    std::atomic<unsigned> process_records{0};
    std::atomic<unsigned> own_snapshots{0};
    std::atomic<unsigned> warnings{0};
    std::atomic<bool> pause_reader{false};
    std::atomic<bool> reader_paused{false};
    std::atomic<bool> verdict_failed{false};
    bool requested = false;
    bool verified = false;
    std::string failure;

    const auto fail = [&](const std::string& message) {
        failure = message;
        pause_reader.store(false);
        driver.Stop();
    };

    pmkext::Handlers handlers;
    handlers.on_connection = [&](const pmkext::Connection& connection) {
        std::string err;
        if (!driver.SendVerdict(connection.id, pmkext::Verdict::PermanentAccept, err)) {
            verdict_failed.store(true);
        }
    };
    handlers.on_warning = [&](const std::string&) { ++warnings; };
    handlers.on_process_created = [&](const std::vector<pmkext::ProcessCreated>& entries) {
        ++process_records;
        if (pause_reader.load()) {
            reader_paused.store(true);
            while (pause_reader.load() && GetTickCount64() < deadline) {
                Sleep(1);
            }
        }
        for (const auto& entry : entries) {
            if (entry.pid == own_pid) {
                ++own_snapshots;
            }
        }
    };
    handlers.on_process_terminated = [&](const std::vector<pmkext::ProcessTerminated>&) {
        ++process_records;
    };
    handlers.on_poll = [&]() {
        if (GetTickCount64() >= deadline) {
            fail("runtime probe timed out");
            return;
        }
        if (!requested && GetTickCount64() >= started + 500) {
            if (process_records.load() != 0) {
                fail("process records arrived before an explicit request");
                return;
            }
            pause_reader.store(true);
            if (!driver.StartProcessMonitoring(error)) {
                fail("initial IOCTL failed: " + error);
                return;
            }
            requested = true;
            const ULONGLONG pause_deadline = GetTickCount64() + 2000;
            while (!reader_paused.load() && GetTickCount64() < pause_deadline) {
                Sleep(1);
            }
            if (!reader_paused.load()) {
                fail("reader did not receive the first snapshot");
                return;
            }
            // The reader is blocked in its first process callback. Neither of the
            // next two inventories can be read before the following restart.
            if (!driver.StartProcessMonitoring(error, true) ||
                !driver.StartProcessMonitoring(error)) {
                fail("repeated WriteFile/IOCTL failed: " + error);
                return;
            }
            pause_reader.store(false);
        }
        if (requested && own_snapshots.load() >= 3) {
            // Permanent shutdown must win over a late request on either path.
            if (!driver.RequestShutdown(error)) {
                fail("shutdown failed: " + error);
                return;
            }
            if (driver.StartProcessMonitoring(error) ||
                driver.StartProcessMonitoring(error, true)) {
                fail("process collection restarted after shutdown");
                return;
            }
            verified = true;
            driver.Stop();
            return;
        }
        // Exercise ordinary commands before and after opting into collection.
        if (!driver.RequestLogs(error) || !driver.RequestBandwidthStats(error)) {
            fail("ordinary write command failed: " + error);
        }
    };

    driver.Run(handlers, 50);
    pause_reader.store(false);
    driver.Cleanup();
    if (!verified || !failure.empty() || warnings.load() != 0 || verdict_failed.load()) {
        std::fprintf(stderr, "FAIL: %s; snapshots=%u warnings=%u verdict_failed=%u\n",
                     failure.empty() ? "incomplete/invalid stream" : failure.c_str(),
                     own_snapshots.load(), warnings.load(), verdict_failed.load() ? 1U : 0U);
        return 1;
    }
    std::printf("PASS: no events before request; 3 complete snapshots preserved across "
                "IOCTL/WriteFile restarts with reader paused; both paths reject after shutdown\n");
    return 0;
}
