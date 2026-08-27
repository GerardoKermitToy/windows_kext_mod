#include "duplex_pipe/pipe_transport.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <new>
#include <utility>

namespace pipe_transport
{
namespace
{
constexpr std::uint32_t kFrameMagic = 0x45504950U;
constexpr std::uint16_t kFrameVersion = 1;
constexpr DWORD kTransferChunkSize = 1024U * 1024U;

class Deadline final
{
public:
    explicit Deadline(const DWORD timeoutMilliseconds) noexcept
        : timeoutMilliseconds_(timeoutMilliseconds),
          startedAt_(timeoutMilliseconds == INFINITE ? 0 : GetTickCount64())
    {
    }

    [[nodiscard]] DWORD Remaining() const noexcept
    {
        if (timeoutMilliseconds_ == INFINITE)
        {
            return INFINITE;
        }

        const ULONGLONG elapsed = GetTickCount64() - startedAt_;
        if (elapsed >= timeoutMilliseconds_)
        {
            return 0;
        }
        return timeoutMilliseconds_ - static_cast<DWORD>(elapsed);
    }

    [[nodiscard]] bool IsFinite() const noexcept
    {
        return timeoutMilliseconds_ != INFINITE;
    }

private:
    DWORD timeoutMilliseconds_ = INFINITE;
    ULONGLONG startedAt_ = 0;
};

class WriteLockGuard final
{
public:
    explicit WriteLockGuard(Connection& connection) noexcept
        : connection_(connection)
    {
        connection_.LockWrites();
    }

    ~WriteLockGuard() noexcept
    {
        connection_.UnlockWrites();
    }

    WriteLockGuard(const WriteLockGuard&) = delete;
    WriteLockGuard& operator=(const WriteLockGuard&) = delete;

private:
    Connection& connection_;
};

void StoreUint16(byte* const destination, const std::uint16_t value) noexcept
{
    destination[0] = static_cast<byte>(value & 0xFFU);
    destination[1] = static_cast<byte>((value >> 8U) & 0xFFU);
}

void StoreUint32(byte* const destination, const std::uint32_t value) noexcept
{
    destination[0] = static_cast<byte>(value & 0xFFU);
    destination[1] = static_cast<byte>((value >> 8U) & 0xFFU);
    destination[2] = static_cast<byte>((value >> 16U) & 0xFFU);
    destination[3] = static_cast<byte>((value >> 24U) & 0xFFU);
}

std::uint16_t LoadUint16(const byte* const source) noexcept
{
    return static_cast<std::uint16_t>(source[0]) |
        static_cast<std::uint16_t>(source[1] << 8U);
}

std::uint32_t LoadUint32(const byte* const source) noexcept
{
    return static_cast<std::uint32_t>(source[0]) |
        (static_cast<std::uint32_t>(source[1]) << 8U) |
        (static_cast<std::uint32_t>(source[2]) << 16U) |
        (static_cast<std::uint32_t>(source[3]) << 24U);
}

void BuildHeader(
    byte* const header,
    const FrameType type,
    const unsigned long payloadSize) noexcept
{
    StoreUint32(header, kFrameMagic);
    StoreUint16(header + 4, kFrameVersion);
    StoreUint16(header + 6, static_cast<std::uint16_t>(type));
    StoreUint32(header + 8, payloadSize);
}

DWORD DrainCancelledOperation(
    const HANDLE pipe,
    OVERLAPPED& overlapped,
    const DWORD result) noexcept
{
    CancelIoEx(pipe, &overlapped);
    DWORD transferred = 0;
    GetOverlappedResult(pipe, &overlapped, &transferred, TRUE);
    return result;
}

DWORD TransferOnce(
    Connection& connection,
    byte* const buffer,
    const DWORD size,
    const bool writing,
    const DWORD timeoutMilliseconds,
    DWORD& transferred) noexcept
{
    transferred = 0;
    if (size == 0)
    {
        return ERROR_SUCCESS;
    }
    if (!connection.IsActive())
    {
        return connection.Status();
    }

    const HANDLE operationEvent = writing
        ? connection.WriteEvent()
        : connection.ReadEvent();
    ResetEvent(operationEvent);

    OVERLAPPED overlapped{};
    overlapped.hEvent = operationEvent;
    const BOOL started = writing
        ? WriteFile(
              connection.Pipe(),
              buffer,
              size,
              &transferred,
              &overlapped)
        : ReadFile(
              connection.Pipe(),
              buffer,
              size,
              &transferred,
              &overlapped);

    if (started == FALSE)
    {
        const DWORD startStatus = GetLastError();
        if (startStatus != ERROR_IO_PENDING)
        {
            return startStatus;
        }

        const HANDLE waitHandles[] = {
            operationEvent,
            connection.CancelEvent(),
        };
        const DWORD waitStatus = WaitForMultipleObjects(
            2,
            waitHandles,
            FALSE,
            timeoutMilliseconds);
        if (waitStatus == WAIT_OBJECT_0 + 1)
        {
            const DWORD status = connection.Status();
            return DrainCancelledOperation(
                connection.Pipe(),
                overlapped,
                status == ERROR_SUCCESS ? ERROR_OPERATION_ABORTED : status);
        }
        if (waitStatus == WAIT_TIMEOUT)
        {
            return DrainCancelledOperation(
                connection.Pipe(),
                overlapped,
                ERROR_TIMEOUT);
        }
        if (waitStatus != WAIT_OBJECT_0)
        {
            return DrainCancelledOperation(
                connection.Pipe(),
                overlapped,
                GetLastError());
        }

        if (GetOverlappedResult(
                connection.Pipe(),
                &overlapped,
                &transferred,
                FALSE) == FALSE)
        {
            return GetLastError();
        }
    }

    return transferred == 0 ? ERROR_BROKEN_PIPE : ERROR_SUCCESS;
}

DWORD TransferExact(
    Connection& connection,
    byte* const buffer,
    const unsigned long size,
    const bool writing,
    Deadline& deadline) noexcept
{
    unsigned long offset = 0;
    while (offset < size)
    {
        if (!connection.IsActive())
        {
            return connection.Status();
        }

        const DWORD timeout = deadline.Remaining();
        if (deadline.IsFinite() && timeout == 0)
        {
            return ERROR_TIMEOUT;
        }

        const DWORD chunk = std::min<DWORD>(
            kTransferChunkSize,
            static_cast<DWORD>(size - offset));
        DWORD transferred = 0;
        const DWORD status = TransferOnce(
            connection,
            buffer + offset,
            chunk,
            writing,
            timeout,
            transferred);
        if (status != ERROR_SUCCESS)
        {
            return status;
        }
        if (transferred > chunk)
        {
            return ERROR_INVALID_DATA;
        }
        offset += transferred;
    }
    return ERROR_SUCCESS;
}

DWORD ReadSome(
    Connection& connection,
    byte* const buffer,
    const DWORD capacity,
    Deadline& deadline,
    DWORD& transferred) noexcept
{
    const DWORD timeout = deadline.Remaining();
    if (deadline.IsFinite() && timeout == 0)
    {
        transferred = 0;
        return ERROR_TIMEOUT;
    }
    return TransferOnce(
        connection,
        buffer,
        capacity,
        false,
        timeout,
        transferred);
}

DWORD FillReadBuffer(
    Connection& connection,
    Deadline& deadline) noexcept
{
    auto& buffer = connection.ReadBuffer();
    size_t& begin = connection.ReadBegin();
    size_t& end = connection.ReadEnd();
    if (begin == end)
    {
        begin = 0;
        end = 0;
    }
    else if (begin != 0)
    {
        const size_t available = end - begin;
        std::memmove(
            buffer.data(),
            buffer.data() + begin,
            available);
        begin = 0;
        end = available;
    }

    const size_t freeSpace = buffer.size() - end;
    if (freeSpace == 0)
    {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    DWORD transferred = 0;
    const DWORD status = ReadSome(
        connection,
        buffer.data() + end,
        static_cast<DWORD>(freeSpace),
        deadline,
        transferred);
    if (status == ERROR_SUCCESS)
    {
        end += transferred;
    }
    return status;
}

DWORD EnsureBufferedBytes(
    Connection& connection,
    const size_t required,
    Deadline& deadline) noexcept
{
    while (connection.ReadEnd() - connection.ReadBegin() < required)
    {
        const DWORD status = FillReadBuffer(connection, deadline);
        if (status != ERROR_SUCCESS)
        {
            return status;
        }
    }
    return ERROR_SUCCESS;
}

DWORD WriteFrameLocked(
    Connection& connection,
    byte* const fastBuffer,
    const FrameType type,
    const byte* const payload,
    const unsigned long payloadSize,
    Deadline& deadline) noexcept
{
    const size_t totalSize = kFrameHeaderSize + payloadSize;
    if (totalSize <= kFastFrameBufferSize)
    {
        BuildHeader(fastBuffer, type, payloadSize);
        if (payloadSize != 0)
        {
            std::memcpy(
                fastBuffer + kFrameHeaderSize,
                payload,
                payloadSize);
        }
        return TransferExact(
            connection,
            fastBuffer,
            static_cast<unsigned long>(totalSize),
            true,
            deadline);
    }

    std::array<byte, kFrameHeaderSize> header{};
    BuildHeader(header.data(), type, payloadSize);
    DWORD status = TransferExact(
        connection,
        header.data(),
        static_cast<unsigned long>(header.size()),
        true,
        deadline);
    if (status == ERROR_SUCCESS)
    {
        status = TransferExact(
            connection,
            const_cast<byte*>(payload),
            payloadSize,
            true,
            deadline);
    }
    return status;
}
} // namespace

UniqueHandle::UniqueHandle(const HANDLE handle) noexcept
    : handle_(handle)
{
}

UniqueHandle::~UniqueHandle() noexcept
{
    Reset();
}

UniqueHandle::UniqueHandle(UniqueHandle&& other) noexcept
    : handle_(other.Release())
{
}

UniqueHandle& UniqueHandle::operator=(UniqueHandle&& other) noexcept
{
    if (this != &other)
    {
        Reset(other.Release());
    }
    return *this;
}

HANDLE UniqueHandle::Get() const noexcept
{
    return handle_;
}

bool UniqueHandle::IsValid() const noexcept
{
    return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
}

HANDLE UniqueHandle::Release() noexcept
{
    const HANDLE handle = handle_;
    handle_ = INVALID_HANDLE_VALUE;
    return handle;
}

void UniqueHandle::Reset(const HANDLE handle) noexcept
{
    if (IsValid())
    {
        CloseHandle(handle_);
    }
    handle_ = handle;
}

FrameType Frame::Type() const noexcept
{
    return type_;
}

const byte* Frame::Data() const noexcept
{
    return payloadSize_ == 0 ? nullptr : payload_;
}

unsigned long Frame::Size() const noexcept
{
    return payloadSize_;
}

bool Frame::Empty() const noexcept
{
    return payloadSize_ == 0;
}

void Frame::Reset() noexcept
{
    type_ = FrameType::Data;
    payload_ = nullptr;
    payloadSize_ = 0;
    ownedPayload_.clear();
}

void Frame::SetView(
    const FrameType type,
    const byte* const payload,
    const unsigned long payloadSize) noexcept
{
    type_ = type;
    payload_ = payloadSize == 0 ? nullptr : payload;
    payloadSize_ = payloadSize;
}

Connection::Connection(UniqueHandle pipe) noexcept
    : pipe_(std::move(pipe)),
      cancelEvent_(CreateEventW(nullptr, TRUE, FALSE, nullptr)),
      readEvent_(CreateEventW(nullptr, TRUE, FALSE, nullptr)),
      writeEvent_(CreateEventW(nullptr, TRUE, FALSE, nullptr))
{
    if (pipe_.IsValid())
    {
        SetFileCompletionNotificationModes(
            pipe_.Get(),
            FILE_SKIP_SET_EVENT_ON_HANDLE);
    }
}

Connection::~Connection() noexcept
{
    Cancel(ERROR_OPERATION_ABORTED);
}

bool Connection::IsValid() const noexcept
{
    return pipe_.IsValid() && cancelEvent_.IsValid() &&
        readEvent_.IsValid() && writeEvent_.IsValid();
}

bool Connection::IsActive() const noexcept
{
    return IsValid() &&
        status_.load(std::memory_order_acquire) == ERROR_SUCCESS;
}

DWORD Connection::Status() const noexcept
{
    const DWORD status = status_.load(std::memory_order_acquire);
    return status == ERROR_SUCCESS ? ERROR_PIPE_NOT_CONNECTED : status;
}

HANDLE Connection::Pipe() const noexcept
{
    return pipe_.Get();
}

HANDLE Connection::CancelEvent() const noexcept
{
    return cancelEvent_.Get();
}

HANDLE Connection::ReadEvent() const noexcept
{
    return readEvent_.Get();
}

HANDLE Connection::WriteEvent() const noexcept
{
    return writeEvent_.Get();
}

void Connection::Cancel(DWORD status) noexcept
{
    if (status == ERROR_SUCCESS)
    {
        status = ERROR_OPERATION_ABORTED;
    }

    DWORD expected = ERROR_SUCCESS;
    if (status_.compare_exchange_strong(
            expected,
            status,
            std::memory_order_acq_rel,
            std::memory_order_acquire))
    {
        if (cancelEvent_.IsValid())
        {
            SetEvent(cancelEvent_.Get());
        }
        if (pipe_.IsValid())
        {
            CancelIoEx(pipe_.Get(), nullptr);
        }
    }
}

void Connection::LockWrites() noexcept
{
    AcquireSRWLockExclusive(&writeLock_);
}

void Connection::UnlockWrites() noexcept
{
    ReleaseSRWLockExclusive(&writeLock_);
}

std::array<byte, kFastFrameBufferSize>& Connection::ReadBuffer() noexcept
{
    return readBuffer_;
}

size_t& Connection::ReadBegin() noexcept
{
    return readBegin_;
}

size_t& Connection::ReadEnd() noexcept
{
    return readEnd_;
}

ConnectionPtr MakeConnection(UniqueHandle pipe) noexcept
{
    try
    {
        ConnectionPtr connection =
            std::make_shared<Connection>(std::move(pipe));
        if (!connection->IsValid())
        {
            return {};
        }
        return connection;
    }
    catch (...)
    {
        return {};
    }
}

DWORD ConnectNamedPipeCancelable(
    const HANDLE pipe,
    const HANDLE stopEvent) noexcept
{
    UniqueHandle operationEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!operationEvent.IsValid())
    {
        return GetLastError();
    }

    OVERLAPPED overlapped{};
    overlapped.hEvent = operationEvent.Get();
    if (ConnectNamedPipe(pipe, &overlapped) != FALSE)
    {
        return ERROR_SUCCESS;
    }

    const DWORD startStatus = GetLastError();
    if (startStatus == ERROR_PIPE_CONNECTED)
    {
        return ERROR_SUCCESS;
    }
    if (startStatus != ERROR_IO_PENDING)
    {
        return startStatus;
    }

    const HANDLE waitHandles[] = {operationEvent.Get(), stopEvent};
    const DWORD waitStatus = WaitForMultipleObjects(
        2,
        waitHandles,
        FALSE,
        INFINITE);
    if (waitStatus == WAIT_OBJECT_0 + 1)
    {
        return DrainCancelledOperation(
            pipe,
            overlapped,
            ERROR_OPERATION_ABORTED);
    }
    if (waitStatus != WAIT_OBJECT_0)
    {
        return DrainCancelledOperation(pipe, overlapped, GetLastError());
    }

    DWORD transferred = 0;
    if (GetOverlappedResult(pipe, &overlapped, &transferred, FALSE) == FALSE)
    {
        const DWORD status = GetLastError();
        return status == ERROR_PIPE_CONNECTED ? ERROR_SUCCESS : status;
    }
    return ERROR_SUCCESS;
}

DWORD ReadFrame(
    Connection& connection,
    Frame& frame,
    const DWORD timeoutMilliseconds) noexcept
{
    frame.Reset();
    try
    {
        Deadline deadline(timeoutMilliseconds);
        DWORD status = EnsureBufferedBytes(
            connection,
            kFrameHeaderSize,
            deadline);
        if (status != ERROR_SUCCESS)
        {
            connection.Cancel(status);
            return status;
        }

        const byte* const header =
            connection.readBuffer_.data() + connection.readBegin_;
        const std::uint32_t magic = LoadUint32(header);
        const std::uint16_t version = LoadUint16(header + 4);
        const auto type = static_cast<FrameType>(LoadUint16(header + 6));
        const std::uint32_t payloadSize = LoadUint32(header + 8);
        if (magic != kFrameMagic || version != kFrameVersion ||
            (type != FrameType::Ready &&
             type != FrameType::Rejected &&
             type != FrameType::Accepted &&
             type != FrameType::Data))
        {
            connection.Cancel(ERROR_INVALID_DATA);
            return ERROR_INVALID_DATA;
        }
        if (type != FrameType::Data && payloadSize != 0)
        {
            connection.Cancel(ERROR_INVALID_DATA);
            return ERROR_INVALID_DATA;
        }
        if (payloadSize > duplex_pipe::kMaxNoteSize)
        {
            connection.Cancel(ERROR_FILE_TOO_LARGE);
            return ERROR_FILE_TOO_LARGE;
        }

        const size_t totalSize = kFrameHeaderSize + payloadSize;
        if (totalSize <= connection.readBuffer_.size())
        {
            status = EnsureBufferedBytes(connection, totalSize, deadline);
            if (status != ERROR_SUCCESS)
            {
                connection.Cancel(status);
                return status;
            }

            const byte* const payload = payloadSize == 0
                ? nullptr
                : connection.readBuffer_.data() +
                    connection.readBegin_ + kFrameHeaderSize;
            frame.SetView(type, payload, payloadSize);
            connection.readBegin_ += totalSize;
            if (connection.readBegin_ == connection.readEnd_)
            {
                connection.readBegin_ = 0;
                connection.readEnd_ = 0;
            }
            return ERROR_SUCCESS;
        }

        frame.ownedPayload_.resize(payloadSize);
        const size_t available =
            connection.readEnd_ - connection.readBegin_;
        const size_t bufferedPayload = available - kFrameHeaderSize;
        if (bufferedPayload != 0)
        {
            std::memcpy(
                frame.ownedPayload_.data(),
                connection.readBuffer_.data() +
                    connection.readBegin_ + kFrameHeaderSize,
                bufferedPayload);
        }
        connection.readBegin_ = 0;
        connection.readEnd_ = 0;

        const unsigned long remaining = payloadSize -
            static_cast<unsigned long>(bufferedPayload);
        if (remaining != 0)
        {
            status = TransferExact(
                connection,
                frame.ownedPayload_.data() + bufferedPayload,
                remaining,
                false,
                deadline);
            if (status != ERROR_SUCCESS)
            {
                frame.Reset();
                connection.Cancel(status);
                return status;
            }
        }

        frame.SetView(type, frame.ownedPayload_.data(), payloadSize);
        return ERROR_SUCCESS;
    }
    catch (const std::bad_alloc&)
    {
        frame.Reset();
        connection.Cancel(ERROR_NOT_ENOUGH_MEMORY);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    catch (...)
    {
        frame.Reset();
        connection.Cancel(ERROR_GEN_FAILURE);
        return ERROR_GEN_FAILURE;
    }
}

DWORD WriteFrame(
    Connection& connection,
    const FrameType type,
    const byte* const payload,
    const unsigned long payloadSize,
    const DWORD timeoutMilliseconds) noexcept
{
    if (payload == nullptr && payloadSize != 0)
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (payloadSize > duplex_pipe::kMaxNoteSize)
    {
        return ERROR_FILE_TOO_LARGE;
    }
    if (type != FrameType::Data && payloadSize != 0)
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (!connection.IsActive())
    {
        return connection.Status();
    }

    try
    {
        const WriteLockGuard lock(connection);

        Deadline deadline(timeoutMilliseconds);
        const DWORD status = WriteFrameLocked(
            connection,
            connection.writeBuffer_.data(),
            type,
            payload,
            payloadSize,
            deadline);
        if (status != ERROR_SUCCESS)
        {
            connection.Cancel(status);
        }
        return status;
    }
    catch (...)
    {
        connection.Cancel(ERROR_GEN_FAILURE);
        return ERROR_GEN_FAILURE;
    }
}
} // namespace pipe_transport
