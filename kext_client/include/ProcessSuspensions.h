#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>

namespace pmkext {

// One native suspend per process generation, shared by its delayed verdicts.
// Tokens and retained handles keep old callbacks separate from a reused PID.
class ProcessSuspensions {
public:
    using Handle = void*;
    struct Token {
        uint64_t generation = 0;
    };
    struct Operations {
        std::function<Handle(uint64_t, uint64_t, std::string&)> suspend;
        std::function<bool(Handle, std::string&)> resume;
        std::function<void(Handle)> close;
        std::function<bool(Handle)> is_alive;
    };
    using Reporter = std::function<void(uint64_t, bool, const std::string&)>;

    ProcessSuspensions();
    explicit ProcessSuspensions(Operations operations);
    ~ProcessSuspensions();

    ProcessSuspensions(const ProcessSuspensions&) = delete;
    ProcessSuspensions& operator=(const ProcessSuspensions&) = delete;

    static uint64_t ObservationTime();
    bool Acquire(uint64_t pid, Token& token, std::string& error,
                 uint64_t observed_at = ObservationTime());
    // Release only after the corresponding verdict was successfully written.
    // resumed is false while other verdicts for this process are still pending.
    bool Release(Token token, bool& resumed, std::string& error);
    // Abort outstanding holds during shutdown and prohibit new acquisitions.
    // Failed resumes retain their handles so a later call can retry.
    bool ResumeAll(const Reporter& report = {});

private:
    struct Entry {
        uint64_t pid = 0;
        Handle handle = nullptr;
        size_t pending = 0;
    };
    void ForgetCurrent(uint64_t pid, uint64_t generation);

    Operations operations_;
    std::mutex mutex_;
    std::map<uint64_t, Entry> entries_;       // generation -> retained process
    std::map<uint64_t, uint64_t> current_;    // PID -> latest live generation
    uint64_t next_generation_ = 1;
    bool stopping_ = false;
};

} // namespace pmkext
