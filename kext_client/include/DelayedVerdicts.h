#pragma once

#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>

namespace pmkext {

// Each verdict waits from its own enqueue time, not from the previous send.
// Stop discards unsent verdicts and joins any send already in progress.
class DelayedVerdicts {
public:
    explicit DelayedVerdicts(unsigned delay_ms)
        : delay_(delay_ms), worker_([this]() { Run(); }) {}

    ~DelayedVerdicts() {
        Stop();
    }

    DelayedVerdicts(const DelayedVerdicts&) = delete;
    DelayedVerdicts& operator=(const DelayedVerdicts&) = delete;

    bool Schedule(std::function<void()> send) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (stopping_) {
            return false;
        }
        // Take the timestamp under the lock so FIFO order also orders deadlines.
        pending_.push_back({std::chrono::steady_clock::now() + delay_, std::move(send)});
        ready_.notify_one();
        return true;
    }

    void Stop() {
        {
            std::lock_guard<std::mutex> guard(mutex_);
            stopping_ = true;
            pending_.clear();
        }
        ready_.notify_one();
        if (worker_.joinable()) {
            worker_.join();
        }
    }

private:
    struct Pending {
        std::chrono::steady_clock::time_point due;
        std::function<void()> send;
    };

    void Run() {
        std::unique_lock<std::mutex> lock(mutex_);
        for (;;) {
            ready_.wait(lock, [this]() { return stopping_ || !pending_.empty(); });
            if (stopping_) {
                return;
            }

            const auto due = pending_.front().due;
            if (ready_.wait_until(lock, due, [this]() { return stopping_; })) {
                return;
            }

            auto send = std::move(pending_.front().send);
            pending_.pop_front();
            lock.unlock();
            send();
            lock.lock();
        }
    }

    const std::chrono::milliseconds delay_;
    std::mutex mutex_;
    std::condition_variable ready_;
    std::deque<Pending> pending_;
    bool stopping_ = false;
    std::thread worker_;
};

} // namespace pmkext
