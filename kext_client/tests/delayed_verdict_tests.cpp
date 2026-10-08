#include "DelayedVerdicts.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

bool CheckIndependentDeadlines() {
    std::mutex mutex;
    std::condition_variable ready;
    std::vector<unsigned> ids;
    std::vector<Clock::time_point> sent_at;
    std::vector<Clock::duration> waited;
    pmkext::DelayedVerdicts queue(120);
    const auto start = Clock::now();

    for (unsigned id = 0; id < 8; ++id) {
        const auto requested_at = Clock::now();
        if (!queue.Schedule([&, id, requested_at]() {
                std::lock_guard<std::mutex> guard(mutex);
                ids.push_back(id);
                sent_at.push_back(Clock::now());
                waited.push_back(sent_at.back() - requested_at);
                ready.notify_one();
            })) {
            return false;
        }
    }

    {
        std::unique_lock<std::mutex> lock(mutex);
        if (!ready.wait_for(lock, 2s, [&]() { return ids.size() == 8; })) {
            return false;
        }
        for (unsigned id = 0; id < 8; ++id) {
            if (ids[id] != id || waited[id] < 120ms) {
                return false;
            }
        }
        // Eight serial sleeps would take 960 ms. Allow ample scheduling jitter.
        if (sent_at.back() - start >= 600ms) {
            return false;
        }
    }

    // After draining, a new request must get its own full delay and wake the worker.
    const auto next = Clock::now();
    if (!queue.Schedule([&]() {
            std::lock_guard<std::mutex> guard(mutex);
            ids.push_back(8);
            sent_at.push_back(Clock::now());
            ready.notify_one();
        })) {
        return false;
    }
    {
        std::unique_lock<std::mutex> lock(mutex);
        if (!ready.wait_for(lock, 2s, [&]() { return ids.size() == 9; }) ||
            sent_at.back() - next < 120ms) {
            return false;
        }
    }
    return true;
}

bool CheckStopDiscardsPending() {
    std::atomic<unsigned> sends{0};
    pmkext::DelayedVerdicts queue(60'000);
    for (unsigned i = 0; i < 20; ++i) {
        if (!queue.Schedule([&]() { ++sends; })) {
            return false;
        }
    }
    std::this_thread::sleep_for(30ms);
    const auto start = Clock::now();
    queue.Stop();
    queue.Stop();
    return Clock::now() - start < 1s && sends.load() == 0 &&
        !queue.Schedule([&]() { ++sends; });
}

bool CheckStopJoinsActiveSend() {
    std::mutex mutex;
    std::condition_variable ready;
    bool sending = false;
    bool release = false;
    bool finished = false;
    std::atomic<bool> stopped{false};
    pmkext::DelayedVerdicts queue(1);
    queue.Schedule([&]() {
        std::unique_lock<std::mutex> lock(mutex);
        sending = true;
        ready.notify_one();
        ready.wait_for(lock, 2s, [&]() { return release; });
        finished = true;
    });
    {
        std::unique_lock<std::mutex> lock(mutex);
        if (!ready.wait_for(lock, 2s, [&]() { return sending; })) {
            return false;
        }
    }

    std::thread stopper([&]() {
        queue.Stop();
        stopped.store(true);
    });
    std::this_thread::sleep_for(30ms);
    const bool returned_early = stopped.load();
    {
        std::lock_guard<std::mutex> guard(mutex);
        release = true;
    }
    ready.notify_one();
    stopper.join();
    return !returned_early && stopped.load() && finished;
}

bool CheckDestructorStopsWaiting() {
    std::atomic<unsigned> sends{0};
    const auto start = Clock::now();
    {
        pmkext::DelayedVerdicts queue(60'000);
        queue.Schedule([&]() { ++sends; });
    }
    return Clock::now() - start < 1s && sends.load() == 0;
}

int main() {
    struct Test {
        const char* name;
        bool (*run)();
    };
    const Test tests[] = {
        {"independent deadlines and FIFO", CheckIndependentDeadlines},
        {"stop discards pending verdicts", CheckStopDiscardsPending},
        {"stop joins active send", CheckStopJoinsActiveSend},
        {"destructor interrupts long delay", CheckDestructorStopsWaiting},
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
