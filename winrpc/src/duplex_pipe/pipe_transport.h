#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include <Windows.h>

#include "duplex_pipe/duplex_pipe_common.h"

namespace pipe_transport
{
constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\WinNamedPipeDuplex.Service";
constexpr DWORD kHandshakeTimeoutMilliseconds = 5000;
constexpr DWORD kPipeBufferSize = 64U * 1024U;
constexpr size_t kFrameHeaderSize = 12;
constexpr size_t kFastFrameBufferSize = 64U * 1024U;
constexpr unsigned long kFastPayloadLimit =
    static_cast<unsigned long>(kFastFrameBufferSize - kFrameHeaderSize);

class UniqueHandle final
{
public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE handle) noexcept;
    ~UniqueHandle() noexcept;

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept;
    UniqueHandle& operator=(UniqueHandle&& other) noexcept;

    [[nodiscard]] HANDLE Get() const noexcept;
    [[nodiscard]] bool IsValid() const noexcept;
    HANDLE Release() noexcept;
    void Reset(HANDLE handle = INVALID_HANDLE_VALUE) noexcept;

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

enum class FrameType : std::uint16_t
{
    Ready = 1,
    Rejected = 2,
    Accepted = 3,
    Data = 4,
};

class Frame final
{
public:
    [[nodiscard]] FrameType Type() const noexcept;
    [[nodiscard]] const byte* Data() const noexcept;
    [[nodiscard]] unsigned long Size() const noexcept;
    [[nodiscard]] bool Empty() const noexcept;

private:
    friend DWORD ReadFrame(
        class Connection& connection,
        Frame& frame,
        DWORD timeoutMilliseconds) noexcept;

    void Reset() noexcept;
    void SetView(
        FrameType type,
        const byte* payload,
        unsigned long payloadSize) noexcept;

    FrameType type_ = FrameType::Data;
    const byte* payload_ = nullptr;
    unsigned long payloadSize_ = 0;
    std::vector<byte> ownedPayload_;
};

class Connection final
{
public:
    explicit Connection(UniqueHandle pipe) noexcept;
    ~Connection() noexcept;

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] bool IsActive() const noexcept;
    [[nodiscard]] DWORD Status() const noexcept;
    [[nodiscard]] HANDLE Pipe() const noexcept;
    [[nodiscard]] HANDLE CancelEvent() const noexcept;
    [[nodiscard]] HANDLE ReadEvent() const noexcept;
    [[nodiscard]] HANDLE WriteEvent() const noexcept;

    void Cancel(DWORD status) noexcept;
    void LockWrites() noexcept;
    void UnlockWrites() noexcept;
    std::array<byte, kFastFrameBufferSize>& ReadBuffer() noexcept;
    size_t& ReadBegin() noexcept;
    size_t& ReadEnd() noexcept;

private:
    friend DWORD ReadFrame(
        Connection& connection,
        Frame& frame,
        DWORD timeoutMilliseconds) noexcept;
    friend DWORD WriteFrame(
        Connection& connection,
        FrameType type,
        const byte* payload,
        unsigned long payloadSize,
        DWORD timeoutMilliseconds) noexcept;

    UniqueHandle pipe_;
    UniqueHandle cancelEvent_;
    UniqueHandle readEvent_;
    UniqueHandle writeEvent_;
    std::atomic<DWORD> status_ = ERROR_SUCCESS;
    SRWLOCK writeLock_ = SRWLOCK_INIT;
    std::array<byte, kFastFrameBufferSize> readBuffer_;
    size_t readBegin_ = 0;
    size_t readEnd_ = 0;
    std::array<byte, kFastFrameBufferSize> writeBuffer_;
};

using ConnectionPtr = std::shared_ptr<Connection>;

ConnectionPtr MakeConnection(UniqueHandle pipe) noexcept;
DWORD ConnectNamedPipeCancelable(HANDLE pipe, HANDLE stopEvent) noexcept;
DWORD ReadFrame(
    Connection& connection,
    Frame& frame,
    DWORD timeoutMilliseconds = INFINITE) noexcept;
DWORD WriteFrame(
    Connection& connection,
    FrameType type,
    const byte* payload,
    unsigned long payloadSize,
    DWORD timeoutMilliseconds = INFINITE) noexcept;
} // namespace pipe_transport
