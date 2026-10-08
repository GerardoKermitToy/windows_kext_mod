#include "DelayedVerdicts.h"
#include "ProcessSuspensions.h"

#include <windows.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <future>
#include <mutex>
#include <new>
#include <vector>

using namespace std::chrono_literals;
using Token = pmkext::ProcessSuspensions::Token;

struct FakeProcesses {
    unsigned suspends = 0;
    unsigned resumes = 0;
    unsigned closes = 0;
    bool fail_suspend = false;
    bool throw_suspend = false;
    bool fail_resume = false;
    void* dead_handle = nullptr;
    std::vector<void*> resumed_handles;
    std::atomic<bool> written{false};
    std::atomic<bool> resumed_before_write{false};
    bool require_write = false;

    pmkext::ProcessSuspensions::Operations Operations() {
        return {
            [&](uint64_t, uint64_t, std::string& error) -> void* {
                ++suspends;
                if (throw_suspend) {
                    throw std::bad_alloc();
                }
                if (fail_suspend) {
                    error = "suspend failed";
                    return nullptr;
                }
                return reinterpret_cast<void*>(static_cast<uintptr_t>(suspends));
            },
            [&](void* handle, std::string& error) {
                ++resumes;
                if (require_write && !written.load()) {
                    resumed_before_write.store(true);
                }
                if (fail_resume) {
                    error = "resume failed";
                    return false;
                }
                resumed_handles.push_back(handle);
                return true;
            },
            [&](void*) { ++closes; },
            [&](void* handle) { return handle != dead_handle; },
        };
    }
};

const uint64_t kPid = static_cast<uint64_t>(GetCurrentProcessId()) + 100;

bool CheckSharedHold() {
    FakeProcesses fake;
    pmkext::ProcessSuspensions holds(fake.Operations());
    std::string error;
    Token first, second;
    bool resumed = false;
    if (!holds.Acquire(kPid, first, error) || !holds.Acquire(kPid, second, error) ||
        fake.suspends != 1 || first.generation != second.generation) {
        return false;
    }
    if (!holds.Release(first, resumed, error) || resumed || fake.resumes != 0) {
        return false;
    }
    return holds.Release(second, resumed, error) && resumed && fake.resumes == 1 &&
        fake.closes == 1 && fake.resumed_handles[0] == reinterpret_cast<void*>(uintptr_t{1});
}

bool CheckIndependentPids() {
    FakeProcesses fake;
    pmkext::ProcessSuspensions holds(fake.Operations());
    std::string error;
    Token first, second;
    bool resumed = false;
    if (!holds.Acquire(kPid, first, error) || !holds.Acquire(kPid + 1, second, error) ||
        !holds.Release(first, resumed, error) || !resumed || fake.resumes != 1) {
        return false;
    }
    return holds.ResumeAll() && fake.suspends == 2 && fake.resumes == 2 && fake.closes == 2;
}

bool CheckPidReuseGenerations() {
    FakeProcesses fake;
    pmkext::ProcessSuspensions holds(fake.Operations());
    std::string error;
    Token old, fresh, extra;
    bool resumed = false;
    if (!holds.Acquire(kPid, old, error)) {
        return false;
    }
    fake.dead_handle = reinterpret_cast<void*>(uintptr_t{1});
    if (!holds.Acquire(kPid, fresh, error) || old.generation == fresh.generation ||
        fake.suspends != 2) {
        return false;
    }
    if (!holds.Release(old, resumed, error) || !resumed || fake.resumes != 1 ||
        fake.resumed_handles.back() != fake.dead_handle) {
        return false;
    }
    // Releasing the old generation must not forget the new PID index.
    if (!holds.Acquire(kPid, extra, error) || fresh.generation != extra.generation ||
        fake.suspends != 2 || !holds.Release(fresh, resumed, error) || resumed) {
        return false;
    }
    if (!holds.Release(extra, resumed, error) || !resumed || fake.resumes != 2 ||
        fake.resumed_handles.back() != reinterpret_cast<void*>(uintptr_t{2})) {
        return false;
    }
    // A late callback for the retired generation cannot release anything again.
    return holds.Release(old, resumed, error) && !resumed && fake.resumes == 2 && fake.closes == 2;
}

bool CheckResumeAfterWrite() {
    FakeProcesses fake;
    fake.require_write = true;
    pmkext::ProcessSuspensions holds(fake.Operations());
    std::mutex mutex;
    std::condition_variable ready;
    bool done = false;
    bool ok = false;
    pmkext::DelayedVerdicts queue(80);
    std::string error;
    Token token;
    if (!holds.Acquire(kPid, token, error)) {
        return false;
    }
    queue.Schedule([&, token]() {
        fake.written.store(true);
        bool resumed = false;
        std::string err;
        const bool released = holds.Release(token, resumed, err);
        std::lock_guard<std::mutex> guard(mutex);
        ok = released && resumed;
        done = true;
        ready.notify_one();
    });
    std::unique_lock<std::mutex> lock(mutex);
    if (!ready.wait_for(lock, 2s, [&]() { return done; })) {
        return false;
    }
    return ok && fake.written.load() && !fake.resumed_before_write.load() &&
        fake.resumes == 1 && fake.closes == 1;
}

bool CheckCancellationResumesAll() {
    FakeProcesses fake;
    pmkext::ProcessSuspensions holds(fake.Operations());
    pmkext::DelayedVerdicts queue(60'000);
    std::string error;
    Token token;
    if (!holds.Acquire(kPid, token, error) || !holds.Acquire(kPid, token, error) ||
        !holds.Acquire(kPid + 1, token, error)) {
        return false;
    }
    queue.Schedule([&]() { fake.written.store(true); });
    queue.Stop();
    if (fake.written.load() || fake.resumes != 0) {
        return false;
    }
    if (!holds.ResumeAll() || !holds.ResumeAll()) {
        return false;
    }
    return fake.resumes == 2 && fake.closes == 2 && !holds.Acquire(kPid, token, error);
}

bool CheckFailedWriteKeepsHold() {
    FakeProcesses fake;
    pmkext::ProcessSuspensions holds(fake.Operations());
    std::promise<void> attempted;
    auto done = attempted.get_future();
    pmkext::DelayedVerdicts queue(10);
    std::string error;
    Token token;
    if (!holds.Acquire(kPid, token, error)) {
        return false;
    }
    queue.Schedule([&]() { attempted.set_value(); });
    if (done.wait_for(2s) != std::future_status::ready) {
        return false;
    }
    queue.Stop();
    if (fake.resumes != 0 || fake.closes != 0) {
        return false;
    }
    return holds.ResumeAll() && fake.resumes == 1 && fake.closes == 1;
}

bool CheckFailuresCanRetry() {
    FakeProcesses fake;
    pmkext::ProcessSuspensions holds(fake.Operations());
    std::string error;
    Token token;
    fake.fail_suspend = true;
    if (holds.Acquire(kPid, token, error) || fake.resumes != 0 || fake.closes != 0) {
        return false;
    }
    fake.fail_suspend = false;
    if (!holds.Acquire(kPid, token, error)) {
        return false;
    }
    fake.fail_resume = true;
    bool resumed = false;
    if (holds.Release(token, resumed, error) || resumed || fake.closes != 0) {
        return false;
    }
    unsigned reports = 0;
    if (holds.ResumeAll([&](uint64_t pid, bool ok, const std::string& err) {
            if (pid == kPid && !ok && !err.empty()) {
                ++reports;
            }
        }) || reports != 1 || fake.closes != 0) {
        return false;
    }
    fake.fail_resume = false;
    return holds.ResumeAll() && fake.resumes == 3 && fake.closes == 1;
}

bool CheckAcquisitionExceptionRollsBack() {
    FakeProcesses fake;
    pmkext::ProcessSuspensions holds(fake.Operations());
    std::string error;
    Token token;
    fake.throw_suspend = true;
    bool caught = false;
    try {
        holds.Acquire(kPid, token, error);
    } catch (const std::bad_alloc&) {
        caught = true;
    }
    fake.throw_suspend = false;
    if (!caught || !holds.Acquire(kPid, token, error) || fake.suspends != 2) {
        return false;
    }
    return holds.ResumeAll() && fake.resumes == 1 && fake.closes == 1;
}

bool CheckSchedulingExceptionKeepsCleanupHold() {
    struct ThrowOnCopy {
        ThrowOnCopy() = default;
        ThrowOnCopy(const ThrowOnCopy&) { throw std::bad_alloc(); }
        void operator()() const {}
    };
    FakeProcesses fake;
    pmkext::ProcessSuspensions holds(fake.Operations());
    pmkext::DelayedVerdicts queue(60'000);
    std::string error;
    Token token;
    if (!holds.Acquire(kPid, token, error)) {
        return false;
    }
    bool caught = false;
    try {
        queue.Schedule(ThrowOnCopy{});
    } catch (const std::bad_alloc&) {
        caught = true;
    }
    queue.Stop();
    return caught && fake.resumes == 0 && holds.ResumeAll() &&
        fake.resumes == 1 && fake.closes == 1;
}

bool CheckSafePidGuards() {
    FakeProcesses fake;
    pmkext::ProcessSuspensions holds(fake.Operations());
    std::string error;
    Token token;
    const uint64_t skipped[] = {0, 4, GetCurrentProcessId(), uint64_t{MAXDWORD} + 1};
    for (const uint64_t pid : skipped) {
        if (holds.Acquire(pid, token, error) || error.empty() || token.generation != 0) {
            return false;
        }
    }
    return fake.suspends == 0 && fake.resumes == 0 && fake.closes == 0;
}

bool CheckDestructorResumes() {
    FakeProcesses fake;
    {
        pmkext::ProcessSuspensions holds(fake.Operations());
        std::string error;
        Token token;
        if (!holds.Acquire(kPid, token, error)) {
            return false;
        }
    }
    return fake.resumes == 1 && fake.closes == 1;
}

int main() {
    struct Test {
        const char* name;
        bool (*run)();
    };
    const Test tests[] = {
        {"shared process stays held until all verdicts are sent", CheckSharedHold},
        {"different PIDs release independently", CheckIndependentPids},
        {"reused PID generations retain independent handles and holds", CheckPidReuseGenerations},
        {"resume follows delayed write", CheckResumeAfterWrite},
        {"shutdown cancels delays and releases holds", CheckCancellationResumesAll},
        {"failed write keeps its hold until shutdown", CheckFailedWriteKeepsHold},
        {"failed suspend/resume keeps balanced handles and allows retry", CheckFailuresCanRetry},
        {"acquisition exception rolls back empty tracking entries", CheckAcquisitionExceptionRollsBack},
        {"scheduling exception keeps the hold available for shutdown cleanup", CheckSchedulingExceptionKeepsCleanupHold},
        {"system, self and invalid PIDs are skipped", CheckSafePidGuards},
        {"destructor releases outstanding holds", CheckDestructorResumes},
    };
    for (const auto& test : tests) {
        if (!test.run()) {
            std::fprintf(stderr, "FAIL: %s\n", test.name);
            return 1;
        }
        std::printf("PASS: %s\n", test.name);
    }
    return 0;
}
