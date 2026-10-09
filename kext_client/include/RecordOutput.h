#pragma once

#include <cstdarg>
#include <cstdio>
#include <mutex>

namespace pmkext {

// Keep every part of a record under one lock, including the final flush.
class RecordOutput {
public:
    RecordOutput(FILE* output, std::mutex& mutex)
        : guard_(mutex), output_(output) {}

    ~RecordOutput() {
        if (output_ != nullptr) {
            std::fflush(output_);
        }
    }

    RecordOutput(const RecordOutput&) = delete;
    RecordOutput& operator=(const RecordOutput&) = delete;

    void Write(const char* format, ...) {
        va_list args;
        va_start(args, format);
        WriteV(format, args);
        va_end(args);
    }

    void WriteV(const char* format, va_list args) {
        if (output_ != nullptr) {
            std::vfprintf(output_, format, args);
        }
    }

private:
    std::lock_guard<std::mutex> guard_;
    FILE* output_;
};

} // namespace pmkext
