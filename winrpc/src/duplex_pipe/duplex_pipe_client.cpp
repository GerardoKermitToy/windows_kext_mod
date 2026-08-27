#include "duplex_pipe/duplex_pipe_client.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <utility>

#include <Windows.h>

#include "duplex_pipe/pipe_transport.h"
#include "pipe_support.h"

namespace
{
class ClientCore final
{
public:
    void SetReceiveCallback(duplex_pipe::ReceiveCallback callback) noexcept
    {
        try
        {
            std::shared_ptr<const duplex_pipe::ReceiveCallback> stored;
            if (callback)
            {
                stored = std::make_shared<const duplex_pipe::ReceiveCallback>(
                    std::move(callback));
            }
            receiveCallback_.store(
                std::move(stored),
                std::memory_order_release);
            callbackGeneration_.fetch_add(
                1,
                std::memory_order_release);
        }
        catch (...)
        {
            pipe_support::PrintError(
                L"Cannot store the client receive callback.");
        }
    }

    void ReadLoop(
        const pipe_transport::ConnectionPtr& connection) noexcept
    {
        try
        {
            pipe_transport::Frame frame;
            ReceiveCallbackSnapshot callbackSnapshot;
            while (connection->IsActive())
            {
                const DWORD status = pipe_transport::ReadFrame(
                    *connection,
                    frame);
                if (status != ERROR_SUCCESS)
                {
                    if (status != ERROR_OPERATION_ABORTED)
                    {
                        pipe_support::PrintStatus(
                            L"Client pipe reader",
                            status);
                    }
                    break;
                }
                if (frame.Type() != pipe_transport::FrameType::Data)
                {
                    connection->Cancel(ERROR_INVALID_DATA);
                    pipe_support::PrintError(
                        L"Client received an unexpected control frame.");
                    break;
                }

                InvokeReceiveCallback(
                    frame.Data(),
                    frame.Size(),
                    callbackSnapshot);
            }
        }
        catch (...)
        {
            connection->Cancel(ERROR_GEN_FAILURE);
            pipe_support::PrintError(
                L"Unexpected failure in the client reader thread.");
        }
    }

private:
    struct ReceiveCallbackSnapshot final
    {
        std::uint64_t generation = static_cast<std::uint64_t>(-1);
        std::shared_ptr<const duplex_pipe::ReceiveCallback> callback;
    };

    void InvokeReceiveCallback(
        const byte* const note,
        const unsigned long noteSize,
        ReceiveCallbackSnapshot& snapshot) noexcept
    {
        const std::uint64_t generation =
            callbackGeneration_.load(std::memory_order_acquire);
        if (snapshot.generation != generation)
        {
            snapshot.callback =
                receiveCallback_.load(std::memory_order_acquire);
            snapshot.generation = generation;
        }

        if (snapshot.callback == nullptr || !*snapshot.callback)
        {
            return;
        }

        try
        {
            (*snapshot.callback)(note, noteSize);
        }
        catch (...)
        {
            pipe_support::PrintError(
                L"Client receive callback threw an exception.");
        }
    }

    std::atomic<std::shared_ptr<const duplex_pipe::ReceiveCallback>>
        receiveCallback_;
    std::atomic<std::uint64_t> callbackGeneration_ = 0;
};

struct ClientThreadContext final
{
    ClientThreadContext(
        std::shared_ptr<ClientCore> coreValue,
        pipe_transport::ConnectionPtr connectionValue) noexcept
        : core(std::move(coreValue)),
          connection(std::move(connectionValue))
    {
    }

    std::shared_ptr<ClientCore> core;
    pipe_transport::ConnectionPtr connection;
};

DWORD WINAPI ClientReaderThread(void* const parameter) noexcept
{
    std::unique_ptr<ClientThreadContext> context(
        static_cast<ClientThreadContext*>(parameter));
    try
    {
        if (context != nullptr && context->core != nullptr &&
            context->connection != nullptr)
        {
            context->core->ReadLoop(context->connection);
        }
    }
    catch (...)
    {
        if (context != nullptr && context->connection != nullptr)
        {
            context->connection->Cancel(ERROR_GEN_FAILURE);
        }
        pipe_support::PrintError(
            L"Unhandled client reader thread failure was contained.");
    }
    return 0;
}

DWORD OpenServerPipe(pipe_transport::UniqueHandle& pipe) noexcept
{
    pipe.Reset();

    for (int attempt = 0; attempt < 2; ++attempt)
    {
        const HANDLE handle = CreateFileW(
            pipe_transport::kPipeName,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            nullptr);
        if (handle != INVALID_HANDLE_VALUE)
        {
            pipe.Reset(handle);
            return ERROR_SUCCESS;
        }

        const DWORD status = GetLastError();
        if (status != ERROR_PIPE_BUSY)
        {
            return status;
        }
        if (WaitNamedPipeW(
                pipe_transport::kPipeName,
                pipe_transport::kHandshakeTimeoutMilliseconds) == FALSE)
        {
            return GetLastError();
        }
    }

    return ERROR_PIPE_BUSY;
}
} // namespace

namespace duplex_pipe
{
class Client::Impl final
{
public:
    Impl() noexcept
    {
        try
        {
            core_ = std::make_shared<ClientCore>();
        }
        catch (...)
        {
            core_.reset();
        }
    }

    ~Impl() noexcept
    {
        Stop();
    }

    RPC_STATUS Start(const std::wstring_view trustedServerPath) noexcept
    {
        try
        {
            const std::scoped_lock lock(lifecycleMutex_);
            if (core_ == nullptr)
            {
                return ERROR_NOT_ENOUGH_MEMORY;
            }
            if (connection_.load(std::memory_order_acquire) != nullptr ||
                readerThread_.IsValid())
            {
                return ERROR_ALREADY_INITIALIZED;
            }

            std::wstring normalizedTrustedPath;
            const bool pathReady = trustedServerPath.empty()
                ? pipe_support::SiblingExecutablePath(
                      L"pipe_server.exe",
                      normalizedTrustedPath)
                : pipe_support::NormalizePath(
                      trustedServerPath,
                      normalizedTrustedPath);
            if (!pathReady)
            {
                return ERROR_INVALID_NAME;
            }

            pipe_transport::UniqueHandle pipe;
            DWORD status = OpenServerPipe(pipe);
            if (status != ERROR_SUCCESS)
            {
                return status;
            }

            ULONG serverProcessId = 0;
            if (GetNamedPipeServerProcessId(
                    pipe.Get(),
                    &serverProcessId) == FALSE)
            {
                return GetLastError();
            }
            status = pipe_support::AuthorizeProcessPath(
                static_cast<DWORD>(serverProcessId),
                normalizedTrustedPath,
                L"named-pipe server");
            if (status != ERROR_SUCCESS)
            {
                return status;
            }

            pipe_transport::ConnectionPtr connection =
                pipe_transport::MakeConnection(std::move(pipe));
            if (connection == nullptr)
            {
                return ERROR_NOT_ENOUGH_MEMORY;
            }

            pipe_transport::Frame handshake;
            status = pipe_transport::ReadFrame(
                *connection,
                handshake,
                pipe_transport::kHandshakeTimeoutMilliseconds);
            if (status != ERROR_SUCCESS)
            {
                return status;
            }
            if (handshake.Type() == pipe_transport::FrameType::Rejected)
            {
                connection->Cancel(ERROR_ACCESS_DENIED);
                return ERROR_ACCESS_DENIED;
            }
            if (handshake.Type() != pipe_transport::FrameType::Ready ||
                !handshake.Empty())
            {
                connection->Cancel(ERROR_INVALID_DATA);
                return ERROR_INVALID_DATA;
            }

            status = pipe_transport::WriteFrame(
                *connection,
                pipe_transport::FrameType::Accepted,
                nullptr,
                0,
                pipe_transport::kHandshakeTimeoutMilliseconds);
            if (status != ERROR_SUCCESS)
            {
                return status;
            }

            auto* const threadContext = new (std::nothrow) ClientThreadContext(
                core_,
                connection);
            if (threadContext == nullptr)
            {
                connection->Cancel(ERROR_NOT_ENOUGH_MEMORY);
                return ERROR_NOT_ENOUGH_MEMORY;
            }

            DWORD threadId = 0;
            const HANDLE thread = CreateThread(
                nullptr,
                0,
                ClientReaderThread,
                threadContext,
                0,
                &threadId);
            if (thread == nullptr)
            {
                const DWORD createStatus = GetLastError();
                delete threadContext;
                connection->Cancel(createStatus);
                return createStatus;
            }

            readerThread_.Reset(thread);
            readerThreadId_ = threadId;
            connection_.store(
                std::move(connection),
                std::memory_order_release);

            pipe_support::PrintLine(
                L"Named-pipe client connected to the server.");
            pipe_support::PrintLine(
                L"Trusted server: " + normalizedTrustedPath);
            return ERROR_SUCCESS;
        }
        catch (const std::bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        catch (...)
        {
            return ERROR_GEN_FAILURE;
        }
    }

    void Stop() noexcept
    {
        try
        {
            pipe_transport::ConnectionPtr connection;
            pipe_transport::UniqueHandle readerThread;
            DWORD readerThreadId = 0;
            {
                const std::scoped_lock lock(lifecycleMutex_);
                connection = connection_.exchange(
                    {},
                    std::memory_order_acq_rel);
                readerThread = std::move(readerThread_);
                readerThreadId = readerThreadId_;
                readerThreadId_ = 0;
            }

            if (connection != nullptr)
            {
                connection->Cancel(ERROR_OPERATION_ABORTED);
            }
            if (readerThread.IsValid() &&
                readerThreadId != GetCurrentThreadId())
            {
                WaitForSingleObject(readerThread.Get(), INFINITE);
            }
        }
        catch (...)
        {
        }
    }

    RPC_STATUS Send(
        const byte* const note,
        const unsigned long noteSize) noexcept
    {
        if (note == nullptr && noteSize != 0)
        {
            return ERROR_INVALID_PARAMETER;
        }
        if (noteSize > kMaxNoteSize)
        {
            return ERROR_FILE_TOO_LARGE;
        }

        try
        {
            const pipe_transport::ConnectionPtr connection =
                connection_.load(std::memory_order_acquire);
            if (connection == nullptr)
            {
                return RPC_S_INVALID_BINDING;
            }

            return pipe_transport::WriteFrame(
                *connection,
                pipe_transport::FrameType::Data,
                note,
                noteSize);
        }
        catch (const std::bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        catch (...)
        {
            return ERROR_GEN_FAILURE;
        }
    }

    void SetReceiveCallback(ReceiveCallback callback) noexcept
    {
        if (core_ != nullptr)
        {
            core_->SetReceiveCallback(std::move(callback));
        }
    }

private:
    std::mutex lifecycleMutex_;
    std::shared_ptr<ClientCore> core_;
    std::atomic<pipe_transport::ConnectionPtr> connection_;
    pipe_transport::UniqueHandle readerThread_;
    DWORD readerThreadId_ = 0;
};

Client::Client() noexcept
    : impl_(new (std::nothrow) Impl())
{
}

Client::~Client() noexcept = default;

RPC_STATUS Client::Start(
    const std::wstring_view trustedServerPath) noexcept
{
    return impl_ != nullptr
        ? impl_->Start(trustedServerPath)
        : static_cast<RPC_STATUS>(ERROR_NOT_ENOUGH_MEMORY);
}

void Client::Stop() noexcept
{
    if (impl_ != nullptr)
    {
        impl_->Stop();
    }
}

RPC_STATUS Client::Send(
    const byte* const note,
    const unsigned long noteSize) noexcept
{
    return impl_ != nullptr
        ? impl_->Send(note, noteSize)
        : static_cast<RPC_STATUS>(ERROR_NOT_ENOUGH_MEMORY);
}

void Client::SetReceiveCallback(ReceiveCallback callback) noexcept
{
    if (impl_ != nullptr)
    {
        impl_->SetReceiveCallback(std::move(callback));
    }
}
} // namespace duplex_pipe
