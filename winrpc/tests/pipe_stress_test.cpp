#include <array>
#include <atomic>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <Windows.h>

#include "duplex_pipe/duplex_pipe_client.h"
#include "duplex_pipe/duplex_pipe_server.h"
#include "pipe_support.h"

namespace
{
constexpr DWORD kProducerCount = 2;
constexpr std::uint32_t kMessagesPerProducer = 25000;
constexpr unsigned long kStressPayloadSize = 64;
constexpr DWORD kWaitMilliseconds = 30000;
constexpr std::uint32_t kClientToServerTag = 0x43545331U;
constexpr std::uint32_t kServerToClientTag = 0x53544331U;

class UniqueHandle final
{
public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(const HANDLE handle) noexcept
        : handle_(handle)
    {
    }

    ~UniqueHandle() noexcept
    {
        Reset();
    }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept
        : handle_(other.Release())
    {
    }

    UniqueHandle& operator=(UniqueHandle&& other) noexcept
    {
        if (this != &other)
        {
            Reset(other.Release());
        }
        return *this;
    }

    [[nodiscard]] HANDLE Get() const noexcept
    {
        return handle_;
    }

    [[nodiscard]] bool IsValid() const noexcept
    {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    HANDLE Release() noexcept
    {
        const HANDLE handle = handle_;
        handle_ = nullptr;
        return handle;
    }

    void Reset(const HANDLE handle = nullptr) noexcept
    {
        if (IsValid())
        {
            CloseHandle(handle_);
        }
        handle_ = handle;
    }

private:
    HANDLE handle_ = nullptr;
};

void StoreUint32(byte* const destination, const std::uint32_t value) noexcept
{
    destination[0] = static_cast<byte>(value & 0xFFU);
    destination[1] = static_cast<byte>((value >> 8U) & 0xFFU);
    destination[2] = static_cast<byte>((value >> 16U) & 0xFFU);
    destination[3] = static_cast<byte>((value >> 24U) & 0xFFU);
}

std::uint32_t LoadUint32(const byte* const source) noexcept
{
    return static_cast<std::uint32_t>(source[0]) |
        (static_cast<std::uint32_t>(source[1]) << 8U) |
        (static_cast<std::uint32_t>(source[2]) << 16U) |
        (static_cast<std::uint32_t>(source[3]) << 24U);
}

byte PayloadByte(
    const std::uint32_t tag,
    const DWORD producer,
    const std::uint32_t sequence,
    const unsigned long index) noexcept
{
    return static_cast<byte>(
        (tag + producer * 17U + sequence * 29U + index * 43U) & 0xFFU);
}

void BuildStressPayload(
    std::array<byte, kStressPayloadSize>& payload,
    const std::uint32_t tag,
    const DWORD producer,
    const std::uint32_t sequence) noexcept
{
    StoreUint32(payload.data(), tag);
    StoreUint32(payload.data() + 4, producer);
    StoreUint32(payload.data() + 8, sequence);
    for (unsigned long index = 12; index < payload.size(); ++index)
    {
        payload[index] = PayloadByte(tag, producer, sequence, index);
    }
}

struct ReceiverState final
{
    explicit ReceiverState(const std::uint32_t expectedTagValue) noexcept
        : expectedTag(expectedTagValue),
          stressComplete(CreateEventW(nullptr, TRUE, FALSE, nullptr)),
          mixedComplete(CreateEventW(nullptr, FALSE, FALSE, nullptr))
    {
    }

    [[nodiscard]] bool IsValid() const noexcept
    {
        return stressComplete.IsValid() && mixedComplete.IsValid();
    }

    void Receive(const byte* const note, const unsigned long noteSize) noexcept
    {
        if (stressPhase.load(std::memory_order_acquire))
        {
            ValidateStressPayload(note, noteSize);
            const unsigned long count =
                received.fetch_add(1, std::memory_order_relaxed) + 1;
            if (count == kProducerCount * kMessagesPerProducer)
            {
                SetEvent(stressComplete.Get());
            }
            return;
        }

        const unsigned long expectedSize =
            mixedSize.load(std::memory_order_acquire);
        const byte expectedValue = mixedValue.load(std::memory_order_relaxed);
        bool valid = noteSize == expectedSize;
        if (valid && noteSize == 0)
        {
            valid = note == nullptr;
        }
        else if (valid && note != nullptr)
        {
            for (unsigned long index = 0; index < noteSize; ++index)
            {
                if (note[index] != expectedValue)
                {
                    valid = false;
                    break;
                }
            }
        }
        else
        {
            valid = false;
        }

        if (!valid)
        {
            invalid.store(true, std::memory_order_relaxed);
        }
        SetEvent(mixedComplete.Get());
    }

    void BeginMixedPhase() noexcept
    {
        stressPhase.store(false, std::memory_order_release);
    }

    void ExpectMixed(
        const unsigned long size,
        const byte value) noexcept
    {
        mixedValue.store(value, std::memory_order_relaxed);
        mixedSize.store(size, std::memory_order_release);
        ResetEvent(mixedComplete.Get());
    }

    [[nodiscard]] bool WaitStress() const noexcept
    {
        return WaitForSingleObject(stressComplete.Get(), kWaitMilliseconds) ==
            WAIT_OBJECT_0;
    }

    [[nodiscard]] bool WaitMixed() const noexcept
    {
        return WaitForSingleObject(mixedComplete.Get(), kWaitMilliseconds) ==
            WAIT_OBJECT_0;
    }

    void ValidateStressPayload(
        const byte* const note,
        const unsigned long noteSize) noexcept
    {
        if (note == nullptr || noteSize != kStressPayloadSize)
        {
            invalid.store(true, std::memory_order_relaxed);
            return;
        }

        const std::uint32_t tag = LoadUint32(note);
        const std::uint32_t producer = LoadUint32(note + 4);
        const std::uint32_t sequence = LoadUint32(note + 8);
        if (tag != expectedTag || producer >= kProducerCount ||
            sequence != nextSequence[producer])
        {
            invalid.store(true, std::memory_order_relaxed);
            return;
        }

        for (unsigned long index = 12; index < noteSize; ++index)
        {
            if (note[index] != PayloadByte(tag, producer, sequence, index))
            {
                invalid.store(true, std::memory_order_relaxed);
                return;
            }
        }
        ++nextSequence[producer];
    }

    std::uint32_t expectedTag = 0;
    std::array<std::uint32_t, kProducerCount> nextSequence{};
    std::atomic<unsigned long> received = 0;
    std::atomic<bool> invalid = false;
    std::atomic<bool> stressPhase = true;
    std::atomic<unsigned long> mixedSize = 0;
    std::atomic<byte> mixedValue = 0;
    UniqueHandle stressComplete;
    UniqueHandle mixedComplete;
};

struct SenderContext final
{
    HANDLE startEvent = nullptr;
    duplex_pipe::Client* client = nullptr;
    duplex_pipe::Server* server = nullptr;
    std::atomic<DWORD>* firstError = nullptr;
    std::uint32_t tag = 0;
    DWORD producer = 0;
};

DWORD WINAPI SenderThread(void* const parameter) noexcept
{
    auto* const context = static_cast<SenderContext*>(parameter);
    if (context == nullptr || context->firstError == nullptr ||
        WaitForSingleObject(context->startEvent, INFINITE) != WAIT_OBJECT_0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    std::array<byte, kStressPayloadSize> payload{};
    for (std::uint32_t sequence = 0;
         sequence < kMessagesPerProducer;
         ++sequence)
    {
        BuildStressPayload(
            payload,
            context->tag,
            context->producer,
            sequence);
        const RPC_STATUS status = context->client != nullptr
            ? context->client->Send(payload.data(), kStressPayloadSize)
            : context->server->Send(payload.data(), kStressPayloadSize);
        if (status != ERROR_SUCCESS)
        {
            DWORD expected = ERROR_SUCCESS;
            context->firstError->compare_exchange_strong(expected, status);
            return status;
        }
    }
    return ERROR_SUCCESS;
}

std::uint64_t FileTimeValue(const FILETIME& value) noexcept
{
    ULARGE_INTEGER result{};
    result.LowPart = value.dwLowDateTime;
    result.HighPart = value.dwHighDateTime;
    return result.QuadPart;
}

struct ProcessUsage final
{
    std::uint64_t cpu100Nanoseconds = 0;
    std::uint64_t cycles = 0;
    DWORD handles = 0;
};

bool CaptureProcessUsage(ProcessUsage& usage) noexcept
{
    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    ULONG64 cycles = 0;
    DWORD handles = 0;
    const HANDLE process = GetCurrentProcess();
    if (GetProcessTimes(process, &creation, &exit, &kernel, &user) == FALSE ||
        QueryProcessCycleTime(process, &cycles) == FALSE ||
        GetProcessHandleCount(process, &handles) == FALSE)
    {
        return false;
    }

    usage.cpu100Nanoseconds = FileTimeValue(kernel) + FileTimeValue(user);
    usage.cycles = cycles;
    usage.handles = handles;
    return true;
}

bool SendMixedPayloads(
    duplex_pipe::Client& client,
    duplex_pipe::Server& server,
    ReceiverState& serverReceiver,
    ReceiverState& clientReceiver) noexcept
{
    try
    {
        constexpr std::array<unsigned long, 8> sizes = {
            0,
            1,
            11,
            12,
            4096,
            64UL * 1024UL - 12UL,
            64UL * 1024UL - 11UL,
            1024UL * 1024UL,
        };

        serverReceiver.BeginMixedPhase();
        clientReceiver.BeginMixedPhase();
        std::vector<byte> payload;
        byte value = 1;
        for (const unsigned long size : sizes)
        {
            payload.assign(size, value);

            serverReceiver.ExpectMixed(size, value);
            RPC_STATUS status = client.Send(
                payload.empty() ? nullptr : payload.data(),
                size);
            if (status != ERROR_SUCCESS || !serverReceiver.WaitMixed())
            {
                return false;
            }

            clientReceiver.ExpectMixed(size, value);
            status = server.Send(
                payload.empty() ? nullptr : payload.data(),
                size);
            if (status != ERROR_SUCCESS || !clientReceiver.WaitMixed())
            {
                return false;
            }
            ++value;
        }
        return !serverReceiver.invalid.load(std::memory_order_relaxed) &&
            !clientReceiver.invalid.load(std::memory_order_relaxed);
    }
    catch (...)
    {
        return false;
    }
}
} // namespace

int wmain()
{
    pipe_support::ConfigureUtf8Console();

    try
    {
        std::wstring executablePath;
        if (!pipe_support::CurrentExecutablePath(executablePath))
        {
            return 1;
        }

        UniqueHandle connectedEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        UniqueHandle disconnectedEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        UniqueHandle startEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        ReceiverState serverReceiver(kClientToServerTag);
        ReceiverState clientReceiver(kServerToClientTag);
        if (!connectedEvent.IsValid() || !disconnectedEvent.IsValid() ||
            !startEvent.IsValid() || !serverReceiver.IsValid() ||
            !clientReceiver.IsValid())
        {
            return 2;
        }

        duplex_pipe::Server server;
        server.SetConnectionCallback(
            [&](const duplex_pipe::ClientConnectionEvent event) noexcept
            {
                SetEvent(
                    event == duplex_pipe::ClientConnectionEvent::Connected
                        ? connectedEvent.Get()
                        : disconnectedEvent.Get());
            });
        server.SetReceiveCallback(
            [&](const byte* const note, const unsigned long noteSize) noexcept
            {
                serverReceiver.Receive(note, noteSize);
            });

        duplex_pipe::Client client;
        client.SetReceiveCallback(
            [&](const byte* const note, const unsigned long noteSize) noexcept
            {
                clientReceiver.Receive(note, noteSize);
            });

        RPC_STATUS status = server.Start(executablePath);
        if (status != ERROR_SUCCESS)
        {
            return 3;
        }
        status = client.Start(executablePath);
        if (status != ERROR_SUCCESS ||
            WaitForSingleObject(connectedEvent.Get(), kWaitMilliseconds) !=
                WAIT_OBJECT_0)
        {
            return 4;
        }

        std::atomic<DWORD> firstError = ERROR_SUCCESS;
        std::array<SenderContext, kProducerCount * 2> contexts{};
        std::array<UniqueHandle, kProducerCount * 2> threads{};
        for (DWORD index = 0; index < kProducerCount; ++index)
        {
            contexts[index] = {
                startEvent.Get(),
                &client,
                nullptr,
                &firstError,
                kClientToServerTag,
                index,
            };
            contexts[kProducerCount + index] = {
                startEvent.Get(),
                nullptr,
                &server,
                &firstError,
                kServerToClientTag,
                index,
            };
        }

        for (size_t index = 0; index < threads.size(); ++index)
        {
            threads[index].Reset(CreateThread(
                nullptr,
                0,
                SenderThread,
                &contexts[index],
                0,
                nullptr));
            if (!threads[index].IsValid())
            {
                SetEvent(startEvent.Get());
                for (UniqueHandle& thread : threads)
                {
                    if (thread.IsValid())
                    {
                        WaitForSingleObject(thread.Get(), INFINITE);
                    }
                }
                client.Stop();
                server.Stop();
                return 5;
            }
        }

        ProcessUsage before{};
        ProcessUsage after{};
        if (!CaptureProcessUsage(before))
        {
            return 6;
        }
        const ULONGLONG startedAt = GetTickCount64();
        SetEvent(startEvent.Get());

        std::array<HANDLE, kProducerCount * 2> threadHandles{};
        for (size_t index = 0; index < threads.size(); ++index)
        {
            threadHandles[index] = threads[index].Get();
        }
        const DWORD waitStatus = WaitForMultipleObjects(
            static_cast<DWORD>(threadHandles.size()),
            threadHandles.data(),
            TRUE,
            kWaitMilliseconds);
        const bool receivedAll = serverReceiver.WaitStress() &&
            clientReceiver.WaitStress();
        const ULONGLONG elapsedMilliseconds = GetTickCount64() - startedAt;
        if (!CaptureProcessUsage(after))
        {
            return 7;
        }

        const unsigned long totalPerDirection =
            kProducerCount * kMessagesPerProducer;
        const unsigned long totalMessages = totalPerDirection * 2;
        if (waitStatus != WAIT_OBJECT_0 || !receivedAll ||
            firstError.load(std::memory_order_relaxed) != ERROR_SUCCESS ||
            serverReceiver.received.load(std::memory_order_relaxed) !=
                totalPerDirection ||
            clientReceiver.received.load(std::memory_order_relaxed) !=
                totalPerDirection ||
            serverReceiver.invalid.load(std::memory_order_relaxed) ||
            clientReceiver.invalid.load(std::memory_order_relaxed))
        {
            client.Stop();
            server.Stop();
            return 8;
        }

        for (UniqueHandle& thread : threads)
        {
            thread.Reset();
        }

        if (!SendMixedPayloads(
                client,
                server,
                serverReceiver,
                clientReceiver))
        {
            client.Stop();
            server.Stop();
            return 9;
        }

        client.Stop();
        if (WaitForSingleObject(disconnectedEvent.Get(), kWaitMilliseconds) !=
            WAIT_OBJECT_0)
        {
            server.Stop();
            return 10;
        }
        server.Stop();

        const double elapsedSeconds =
            static_cast<double>(elapsedMilliseconds) / 1000.0;
        const double messagesPerSecond = elapsedSeconds > 0.0
            ? static_cast<double>(totalMessages) / elapsedSeconds
            : 0.0;
        const double cpuMilliseconds = static_cast<double>(
            after.cpu100Nanoseconds - before.cpu100Nanoseconds) / 10000.0;

        std::wostringstream output;
        output << L"Named-pipe stress test passed: " << totalMessages
               << L" messages, wall=" << elapsedMilliseconds
               << L" ms, CPU=" << std::fixed << std::setprecision(1)
               << cpuMilliseconds << L" ms, rate=" << std::setprecision(0)
               << messagesPerSecond << L" msg/s, cycles="
               << (after.cycles - before.cycles) << L", handles="
               << before.handles << L"->" << after.handles << L'.';
        pipe_support::PrintLine(output.str());
        return 0;
    }
    catch (...)
    {
        pipe_support::PrintError(
            L"Stress test caught an unexpected exception.");
        return 100;
    }
}
