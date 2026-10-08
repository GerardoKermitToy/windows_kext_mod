#include "ProcessSuspensions.h"

#include <windows.h>

#include <cstdio>
#include <memory>
#include <utility>

namespace pmkext {
namespace {

using ProcessOperation = LONG (NTAPI*)(HANDLE);

uint64_t FileTimeValue(const FILETIME& time) {
    return (static_cast<uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

std::string StatusError(const char* operation, LONG status) {
    char text[96] = {};
    std::snprintf(text, sizeof(text), "%s failed: NTSTATUS(0x%08lx)",
                  operation, static_cast<unsigned long>(status));
    return text;
}

ProcessSuspensions::Operations WindowsOperations() {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto suspend = ntdll == nullptr ? nullptr :
        reinterpret_cast<ProcessOperation>(GetProcAddress(ntdll, "NtSuspendProcess"));
    const auto resume = ntdll == nullptr ? nullptr :
        reinterpret_cast<ProcessOperation>(GetProcAddress(ntdll, "NtResumeProcess"));

    ProcessSuspensions::Operations operations;
    operations.suspend = [suspend, resume](uint64_t pid, uint64_t observed_at,
                                          std::string& error) -> void* {
        if (suspend == nullptr || resume == nullptr) {
            error = "NtSuspendProcess/NtResumeProcess are unavailable";
            return nullptr;
        }

        std::unique_ptr<void, decltype(&CloseHandle)> process(
            OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                        FALSE, static_cast<DWORD>(pid)), &CloseHandle);
        if (!process) {
            error = "OpenProcess failed: error " + std::to_string(GetLastError());
            return nullptr;
        }

        FILETIME created = {}, exited = {}, kernel = {}, user = {};
        if (!GetProcessTimes(process.get(), &created, &exited, &kernel, &user)) {
            error = "GetProcessTimes failed: error " + std::to_string(GetLastError());
            return nullptr;
        }
        if (FileTimeValue(created) > observed_at) {
            error = "process started after this CONN was observed (PID may have been reused)";
            return nullptr;
        }
        if (WaitForSingleObject(process.get(), 0) == WAIT_OBJECT_0) {
            error = "process has exited";
            return nullptr;
        }

        BOOL critical = FALSE;
        if (!IsProcessCritical(process.get(), &critical)) {
            error = "IsProcessCritical failed: error " + std::to_string(GetLastError());
            return nullptr;
        }
        if (critical) {
            error = "critical processes are never suspended";
            return nullptr;
        }

        const LONG status = suspend(process.get());
        if (status < 0) {
            error = StatusError("NtSuspendProcess", status);
            return nullptr;
        }
        return process.release();
    };
    operations.resume = [resume](void* process, std::string& error) {
        if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
            return true;
        }
        if (resume == nullptr) {
            error = "NtResumeProcess is unavailable";
            return false;
        }
        const LONG status = resume(process);
        if (status < 0) {
            error = StatusError("NtResumeProcess", status);
            return false;
        }
        return true;
    };
    operations.close = [](void* process) { CloseHandle(process); };
    operations.is_alive = [](void* process) {
        return WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
    };
    return operations;
}

} // namespace

ProcessSuspensions::ProcessSuspensions() : ProcessSuspensions(WindowsOperations()) {}

ProcessSuspensions::ProcessSuspensions(Operations operations)
    : operations_(std::move(operations)) {}

ProcessSuspensions::~ProcessSuspensions() {
    ResumeAll();
    for (const auto& item : entries_) {
        operations_.close(item.second.handle);
    }
}

uint64_t ProcessSuspensions::ObservationTime() {
    FILETIME time = {};
    GetSystemTimePreciseAsFileTime(&time);
    return FileTimeValue(time);
}

bool ProcessSuspensions::Acquire(uint64_t pid, Token& token, std::string& error,
                                 uint64_t observed_at) {
    token = {};
    if (pid == 0 || pid == 4 || pid > MAXDWORD || pid == GetCurrentProcessId()) {
        error = "unknown/system PID or the monitor itself cannot be suspended";
        return false;
    }

    std::lock_guard<std::mutex> guard(mutex_);
    if (stopping_) {
        error = "monitor is stopping";
        return false;
    }

    const auto current = current_.find(pid);
    if (current != current_.end()) {
        auto& entry = entries_.at(current->second);
        if (!operations_.is_alive || operations_.is_alive(entry.handle)) {
            ++entry.pending;
            token.generation = current->second;
            return true;
        }
        // Keep the old generation for its callbacks, but do not share its hold
        // with a different process that now happens to have the same numeric PID.
        current_.erase(current);
    }

    if (next_generation_ == 0) {
        error = "process suspension generation counter exhausted";
        return false;
    }
    const uint64_t generation = next_generation_++;
    // Allocate both indexes before suspending. Roll back empty entries if either
    // allocation or the backend fails; an exception is handled by the controller.
    const auto it = entries_.try_emplace(generation, Entry{pid}).first;
    try {
        current_.emplace(pid, generation);
        it->second.handle = operations_.suspend(pid, observed_at, error);
    } catch (...) {
        ForgetCurrent(pid, generation);
        entries_.erase(it);
        throw;
    }
    if (it->second.handle == nullptr) {
        ForgetCurrent(pid, generation);
        entries_.erase(it);
        return false;
    }
    it->second.pending = 1;
    token.generation = generation;
    return true;
}

void ProcessSuspensions::ForgetCurrent(uint64_t pid, uint64_t generation) {
    const auto current = current_.find(pid);
    if (current != current_.end() && current->second == generation) {
        current_.erase(current);
    }
}

bool ProcessSuspensions::Release(Token token, bool& resumed, std::string& error) {
    resumed = false;
    std::lock_guard<std::mutex> guard(mutex_);
    const auto it = entries_.find(token.generation);
    if (it == entries_.end()) {
        return true;
    }
    if (it->second.pending > 0) {
        --it->second.pending;
    }
    if (it->second.pending != 0) {
        return true;
    }
    if (!operations_.resume(it->second.handle, error)) {
        return false;
    }
    operations_.close(it->second.handle);
    ForgetCurrent(it->second.pid, token.generation);
    entries_.erase(it);
    resumed = true;
    return true;
}

bool ProcessSuspensions::ResumeAll(const Reporter& report) {
    std::lock_guard<std::mutex> guard(mutex_);
    stopping_ = true;
    bool ok = true;
    for (auto it = entries_.begin(); it != entries_.end();) {
        std::string error;
        const bool resumed = operations_.resume(it->second.handle, error);
        if (report) {
            report(it->second.pid, resumed, error);
        }
        if (!resumed) {
            ok = false;
            ++it;
            continue;
        }
        operations_.close(it->second.handle);
        ForgetCurrent(it->second.pid, it->first);
        it = entries_.erase(it);
    }
    return ok;
}

} // namespace pmkext
