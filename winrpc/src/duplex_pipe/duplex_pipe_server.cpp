#include "duplex_pipe/duplex_pipe_server.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <new>
#include <sstream>
#include <string>
#include <utility>

#include <Windows.h>

#include "duplex_pipe/pipe_transport.h"
#include "pipe_support.h"

namespace
{
struct ClientState final
{
    ClientState(
        pipe_transport::ConnectionPtr connectionValue,
        const DWORD processIdValue) noexcept
        : connection(std::move(connectionValue)),
          processId(processIdValue)
    {
    }

    pipe_transport::ConnectionPtr connection;
    DWORD processId = 0;
    std::atomic<bool> ended = false;
    std::atomic<bool> connectedNotified = false;
};

class ServerCore final
{
public:
    ServerCore() noexcept
        : stopEvent_(CreateEventW(nullptr, TRUE, FALSE, nullptr)),
          startupEvent_(CreateEventW(nullptr, TRUE, FALSE, nullptr))
    {
    }

    [[nodiscard]] bool IsValid() const noexcept
    {
        return stopEvent_.IsValid() && startupEvent_.IsValid();
    }

    bool PrepareStart(std::wstring trustedClientPath) noexcept
    {
        if (!IsValid())
        {
            return false;
        }

        try
        {
            trustedClientPath_ = std::move(trustedClientPath);
            activeSession_.store({}, std::memory_order_release);
            startupStatus_.store(
                ERROR_IO_PENDING,
                std::memory_order_relaxed);
            running_.store(true, std::memory_order_release);
            ResetEvent(stopEvent_.Get());
            ResetEvent(startupEvent_.Get());
            return true;
        }
        catch (...)
        {
            running_.store(false, std::memory_order_release);
            return false;
        }
    }

    [[nodiscard]] HANDLE StartupEvent() const noexcept
    {
        return startupEvent_.Get();
    }

    [[nodiscard]] DWORD StartupStatus() const noexcept
    {
        return startupStatus_.load(std::memory_order_acquire);
    }

    void RequestStop() noexcept
    {
        running_.store(false, std::memory_order_release);
        if (stopEvent_.IsValid())
        {
            SetEvent(stopEvent_.Get());
        }

        const std::shared_ptr<ClientState> state = GetAnyActiveSession();
        if (state != nullptr)
        {
            state->connection->Cancel(ERROR_OPERATION_ABORTED);
        }
    }

    void Run() noexcept
    {
        bool startupSignalled = false;
        try
        {
            while (running_.load(std::memory_order_acquire))
            {
                pipe_transport::UniqueHandle pipe(CreateNamedPipeW(
                    pipe_transport::kPipeName,
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
                        PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    pipe_transport::kPipeBufferSize,
                    pipe_transport::kPipeBufferSize,
                    0,
                    nullptr));
                if (!pipe.IsValid())
                {
                    const DWORD status = GetLastError();
                    SignalStartup(status, startupSignalled);
                    if (running_.load(std::memory_order_acquire))
                    {
                        pipe_support::PrintStatus(
                            L"CreateNamedPipeW",
                            status);
                    }
                    break;
                }

                SignalStartup(ERROR_SUCCESS, startupSignalled);
                DWORD status = pipe_transport::ConnectNamedPipeCancelable(
                    pipe.Get(),
                    stopEvent_.Get());
                if (!running_.load(std::memory_order_acquire))
                {
                    break;
                }
                if (status != ERROR_SUCCESS)
                {
                    if (status != ERROR_OPERATION_ABORTED)
                    {
                        pipe_support::PrintStatus(
                            L"ConnectNamedPipe",
                            status);
                    }
                    continue;
                }

                ULONG clientProcessId = 0;
                if (GetNamedPipeClientProcessId(
                        pipe.Get(),
                        &clientProcessId) == FALSE)
                {
                    status = GetLastError();
                }
                else
                {
                    status = ERROR_SUCCESS;
					/*pipe_support::AuthorizeProcessPath(
                        static_cast<DWORD>(clientProcessId),
                        trustedClientPath_,
                        L"named-pipe client");
						*/
                }

                pipe_transport::ConnectionPtr connection =
                    pipe_transport::MakeConnection(std::move(pipe));
                if (connection == nullptr)
                {
                    pipe_support::PrintError(
                        L"Cannot allocate named-pipe connection state.");
                    continue;
                }

                if (status != ERROR_SUCCESS)
                {
                    pipe_transport::WriteFrame(
                        *connection,
                        pipe_transport::FrameType::Rejected,
                        nullptr,
                        0,
                        pipe_transport::kHandshakeTimeoutMilliseconds);
                    connection->Cancel(ERROR_ACCESS_DENIED);
                    DisconnectNamedPipe(connection->Pipe());
                    continue;
                }

                status = pipe_transport::WriteFrame(
                    *connection,
                    pipe_transport::FrameType::Ready,
                    nullptr,
                    0,
                    pipe_transport::kHandshakeTimeoutMilliseconds);
                if (status != ERROR_SUCCESS)
                {
                    DisconnectNamedPipe(connection->Pipe());
                    continue;
                }

                pipe_transport::Frame acknowledgement;
                status = pipe_transport::ReadFrame(
                    *connection,
                    acknowledgement,
                    pipe_transport::kHandshakeTimeoutMilliseconds);
                if (status != ERROR_SUCCESS ||
                    acknowledgement.Type() !=
                        pipe_transport::FrameType::Accepted ||
                    !acknowledgement.Empty())
                {
                    if (status == ERROR_SUCCESS)
                    {
                        connection->Cancel(ERROR_INVALID_DATA);
                    }
                    DisconnectNamedPipe(connection->Pipe());
                    continue;
                }

                std::shared_ptr<ClientState> state;
                try
                {
                    state = std::make_shared<ClientState>(
                        connection,
                        static_cast<DWORD>(clientProcessId));
                }
                catch (...)
                {
                    connection->Cancel(ERROR_NOT_ENOUGH_MEMORY);
                    DisconnectNamedPipe(connection->Pipe());
                    continue;
                }

                if (!SetActiveSession(state))
                {
                    connection->Cancel(ERROR_OPERATION_ABORTED);
                    DisconnectNamedPipe(connection->Pipe());
                    continue;
                }

                state->connectedNotified.store(
                    true,
                    std::memory_order_release);
                InvokeConnectionCallback(
                    duplex_pipe::ClientConnectionEvent::Connected);
                ReadClientFrames(state);
                EndSession(state, connection->Status());
                DisconnectNamedPipe(connection->Pipe());
                state.reset();
                connection.reset();
            }
        }
        catch (...)
        {
            pipe_support::PrintError(
                L"Unhandled server worker failure was contained.");
        }

        if (!startupSignalled)
        {
            SignalStartup(ERROR_GEN_FAILURE, startupSignalled);
        }
        const std::shared_ptr<ClientState> state = GetAnyActiveSession();
        if (state != nullptr)
        {
            EndSession(state, ERROR_OPERATION_ABORTED);
        }
        running_.store(false, std::memory_order_release);
    }

    RPC_STATUS Send(
        const byte* const note,
        const unsigned long noteSize) noexcept
    {
        if (note == nullptr && noteSize != 0)
        {
            return ERROR_INVALID_PARAMETER;
        }
        if (noteSize > duplex_pipe::kMaxNoteSize)
        {
            return ERROR_FILE_TOO_LARGE;
        }

        try
        {
            const std::shared_ptr<ClientState> state = GetActiveSession();
            if (state == nullptr)
            {
                return RPC_S_SERVER_UNAVAILABLE;
            }

            const DWORD status = pipe_transport::WriteFrame(
                *state->connection,
                pipe_transport::FrameType::Data,
                note,
                noteSize);
            if (status != ERROR_SUCCESS)
            {
                EndSession(state, status);
            }
            return status;
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
            receiveCallbackGeneration_.fetch_add(
                1,
                std::memory_order_release);
        }
        catch (...)
        {
            pipe_support::PrintError(
                L"Cannot store the server receive callback.");
        }
    }

    void SetConnectionCallback(
        duplex_pipe::ConnectionCallback callback) noexcept
    {
        try
        {
            std::shared_ptr<const duplex_pipe::ConnectionCallback> stored;
            if (callback)
            {
                stored =
                    std::make_shared<const duplex_pipe::ConnectionCallback>(
                        std::move(callback));
            }
            connectionCallback_.store(
                std::move(stored),
                std::memory_order_release);
        }
        catch (...)
        {
            pipe_support::PrintError(
                L"Cannot store the server connection callback.");
        }
    }

private:
    void SignalStartup(
        const DWORD status,
        bool& startupSignalled) noexcept
    {
        if (!startupSignalled)
        {
            startupStatus_.store(
                status,
                std::memory_order_release);
            SetEvent(startupEvent_.Get());
            startupSignalled = true;
        }
    }

    bool SetActiveSession(
        const std::shared_ptr<ClientState>& state) noexcept
    {
        if (!running_.load(std::memory_order_acquire))
        {
            return false;
        }

        std::shared_ptr<ClientState> expected;
        if (!activeSession_.compare_exchange_strong(
                expected,
                state,
                std::memory_order_acq_rel,
                std::memory_order_acquire))
        {
            return false;
        }

        if (running_.load(std::memory_order_acquire))
        {
            return true;
        }

        expected = state;
        activeSession_.compare_exchange_strong(
            expected,
            {},
            std::memory_order_acq_rel,
            std::memory_order_acquire);
        return false;
    }

    std::shared_ptr<ClientState> GetAnyActiveSession() noexcept
    {
        return activeSession_.load(std::memory_order_acquire);
    }

    std::shared_ptr<ClientState> GetActiveSession() noexcept
    {
        const std::shared_ptr<ClientState> state = GetAnyActiveSession();
        if (!running_.load(std::memory_order_acquire) || state == nullptr ||
            state->ended.load(std::memory_order_acquire) ||
            !state->connectedNotified.load(std::memory_order_acquire) ||
            !state->connection->IsActive())
        {
            return {};
        }
        return state;
    }

    void RemoveActiveSession(
        const std::shared_ptr<ClientState>& state) noexcept
    {
        std::shared_ptr<ClientState> expected = state;
        activeSession_.compare_exchange_strong(
            expected,
            {},
            std::memory_order_acq_rel,
            std::memory_order_acquire);
    }

    void EndSession(
        const std::shared_ptr<ClientState>& state,
        DWORD status) noexcept
    {
        bool expected = false;
        if (!state->ended.compare_exchange_strong(
                expected,
                true,
                std::memory_order_acq_rel,
                std::memory_order_acquire))
        {
            return;
        }
        if (status == ERROR_SUCCESS || status == ERROR_PIPE_NOT_CONNECTED)
        {
            status = ERROR_BROKEN_PIPE;
        }
        state->connection->Cancel(status);
        RemoveActiveSession(state);

        if (state->connectedNotified.load(std::memory_order_acquire))
        {
            InvokeConnectionCallback(
                duplex_pipe::ClientConnectionEvent::Disconnected);
        }
    }

    void ReadClientFrames(
        const std::shared_ptr<ClientState>& state) noexcept
    {
        try
        {
            pipe_transport::Frame frame;
            ReceiveCallbackSnapshot callbackSnapshot;
            while (running_.load(std::memory_order_acquire) &&
                   !state->ended.load(std::memory_order_acquire) &&
                   state->connection->IsActive())
            {
                const DWORD status = pipe_transport::ReadFrame(
                    *state->connection,
                    frame);
                if (status != ERROR_SUCCESS)
                {
                    break;
                }
                if (frame.Type() != pipe_transport::FrameType::Data)
                {
                    state->connection->Cancel(ERROR_INVALID_DATA);
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
            state->connection->Cancel(ERROR_GEN_FAILURE);
            pipe_support::PrintError(
                L"Unexpected failure in the server reader loop.");
        }
    }

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
            receiveCallbackGeneration_.load(std::memory_order_acquire);
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
                L"Server receive callback threw an exception.");
        }
    }

    void InvokeConnectionCallback(
        const duplex_pipe::ClientConnectionEvent event) noexcept
    {
        const std::shared_ptr<const duplex_pipe::ConnectionCallback> callback =
            connectionCallback_.load(std::memory_order_acquire);
        if (callback == nullptr || !*callback)
        {
            return;
        }

        try
        {
            (*callback)(event);
        }
        catch (...)
        {
            pipe_support::PrintError(
                L"Server connection callback threw an exception.");
        }
    }

    pipe_transport::UniqueHandle stopEvent_;
    pipe_transport::UniqueHandle startupEvent_;
    std::atomic<bool> running_ = false;
    std::atomic<DWORD> startupStatus_ = ERROR_IO_PENDING;
    std::atomic<std::shared_ptr<ClientState>> activeSession_;
    std::wstring trustedClientPath_;
    std::atomic<std::shared_ptr<const duplex_pipe::ReceiveCallback>>
        receiveCallback_;
    std::atomic<std::uint64_t> receiveCallbackGeneration_ = 0;
    std::atomic<std::shared_ptr<const duplex_pipe::ConnectionCallback>>
        connectionCallback_;
};

struct ServerThreadContext final
{
    explicit ServerThreadContext(std::shared_ptr<ServerCore> coreValue) noexcept
        : core(std::move(coreValue))
    {
    }

    std::shared_ptr<ServerCore> core;
};

DWORD WINAPI ServerWorkerThread(void* const parameter) noexcept
{
    std::unique_ptr<ServerThreadContext> context(
        static_cast<ServerThreadContext*>(parameter));
    try
    {
        if (context != nullptr && context->core != nullptr)
        {
            context->core->Run();
        }
    }
    catch (...)
    {
        if (context != nullptr && context->core != nullptr)
        {
            context->core->RequestStop();
        }
        pipe_support::PrintError(
            L"Unhandled server worker thread failure was contained.");
    }
    return 0;
}
} // namespace

namespace duplex_pipe
{
class Server::Impl final
{
public:
    Impl() noexcept
    {
        try
        {
            core_ = std::make_shared<ServerCore>();
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

    RPC_STATUS Start(const std::wstring_view trustedClientPath) noexcept
    {
        try
        {
            const std::scoped_lock lock(lifecycleMutex_);
            if (core_ == nullptr || !core_->IsValid())
            {
                return ERROR_NOT_ENOUGH_MEMORY;
            }
            if (workerThread_.IsValid())
            {
                return ERROR_ALREADY_INITIALIZED;
            }

            std::wstring normalizedTrustedPath;
            const bool pathReady = trustedClientPath.empty()
                ? pipe_support::SiblingExecutablePath(
                      L"FirewallX.exe",
                      normalizedTrustedPath)
                : pipe_support::NormalizePath(
                      trustedClientPath,
                      normalizedTrustedPath);
            if (!pathReady)
            {
                return ERROR_INVALID_NAME;
            }
            if (!core_->PrepareStart(std::move(normalizedTrustedPath)))
            {
                return ERROR_GEN_FAILURE;
            }

            auto* const threadContext = new (std::nothrow) ServerThreadContext(
                core_);
            if (threadContext == nullptr)
            {
                core_->RequestStop();
                return ERROR_NOT_ENOUGH_MEMORY;
            }

            DWORD threadId = 0;
            const HANDLE thread = CreateThread(
                nullptr,
                0,
                ServerWorkerThread,
                threadContext,
                0,
                &threadId);
            if (thread == nullptr)
            {
                const DWORD status = GetLastError();
                delete threadContext;
                core_->RequestStop();
                return status;
            }

            workerThread_.Reset(thread);
            workerThreadId_ = threadId;

            const DWORD waitStatus = WaitForSingleObject(
                core_->StartupEvent(),
                pipe_transport::kHandshakeTimeoutMilliseconds);
            if (waitStatus != WAIT_OBJECT_0)
            {
                const DWORD status = waitStatus == WAIT_TIMEOUT
                    ? ERROR_TIMEOUT
                    : GetLastError();
                core_->RequestStop();
                WaitForSingleObject(workerThread_.Get(), INFINITE);
                workerThread_.Reset();
                workerThreadId_ = 0;
                return status;
            }

            const DWORD startupStatus = core_->StartupStatus();
            if (startupStatus != ERROR_SUCCESS)
            {
                core_->RequestStop();
                WaitForSingleObject(workerThread_.Get(), INFINITE);
                workerThread_.Reset();
                workerThreadId_ = 0;
                return startupStatus;
            }

            pipe_support::PrintLine(
                L"Named-pipe server is listening at "
                L"\\\\.\\pipe\\WinNamedPipeDuplex.Service.");
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
            pipe_transport::UniqueHandle workerThread;
            DWORD workerThreadId = 0;
            {
                const std::scoped_lock lock(lifecycleMutex_);
                if (core_ != nullptr)
                {
                    core_->RequestStop();
                }
                workerThread = std::move(workerThread_);
                workerThreadId = workerThreadId_;
                workerThreadId_ = 0;
            }

            if (workerThread.IsValid() &&
                workerThreadId != GetCurrentThreadId())
            {
                WaitForSingleObject(workerThread.Get(), INFINITE);
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
        return core_ != nullptr
            ? core_->Send(note, noteSize)
            : static_cast<RPC_STATUS>(ERROR_NOT_ENOUGH_MEMORY);
    }

    void SetReceiveCallback(ReceiveCallback callback) noexcept
    {
        if (core_ != nullptr)
        {
            core_->SetReceiveCallback(std::move(callback));
        }
    }

    void SetConnectionCallback(ConnectionCallback callback) noexcept
    {
        if (core_ != nullptr)
        {
            core_->SetConnectionCallback(std::move(callback));
        }
    }

private:
    std::mutex lifecycleMutex_;
    std::shared_ptr<ServerCore> core_;
    pipe_transport::UniqueHandle workerThread_;
    DWORD workerThreadId_ = 0;
};

Server::Server() noexcept
    : impl_(new (std::nothrow) Impl())
{
}

Server::~Server() noexcept = default;

RPC_STATUS Server::Start(
    const std::wstring_view trustedClientPath) noexcept
{
    return impl_ != nullptr
        ? impl_->Start(trustedClientPath)
        : static_cast<RPC_STATUS>(ERROR_NOT_ENOUGH_MEMORY);
}

void Server::Stop() noexcept
{
    if (impl_ != nullptr)
    {
        impl_->Stop();
    }
}

RPC_STATUS Server::Send(
    const byte* const note,
    const unsigned long noteSize) noexcept
{
    return impl_ != nullptr
        ? impl_->Send(note, noteSize)
        : static_cast<RPC_STATUS>(ERROR_NOT_ENOUGH_MEMORY);
}

void Server::SetReceiveCallback(ReceiveCallback callback) noexcept
{
    if (impl_ != nullptr)
    {
        impl_->SetReceiveCallback(std::move(callback));
    }
}

void Server::SetConnectionCallback(ConnectionCallback callback) noexcept
{
    if (impl_ != nullptr)
    {
        impl_->SetConnectionCallback(std::move(callback));
    }
}
} // namespace duplex_pipe
