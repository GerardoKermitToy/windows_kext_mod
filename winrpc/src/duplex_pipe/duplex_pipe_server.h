#pragma once

#include <functional>
#include <memory>
#include <string_view>

#include "duplex_pipe/duplex_pipe_common.h"

namespace duplex_pipe
{
enum class ClientConnectionEvent
{
    Connected,
    Disconnected,
};

using ConnectionCallback = std::function<void(ClientConnectionEvent event)>;

class Server final
{
public:
    Server() noexcept;
    ~Server() noexcept;

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    Server(Server&&) = delete;
    Server& operator=(Server&&) = delete;

    RPC_STATUS Start(std::wstring_view trustedClientPath = {}) noexcept;
    void Stop() noexcept;

    RPC_STATUS Send(const byte* note, unsigned long noteSize) noexcept;
    void SetReceiveCallback(ReceiveCallback callback) noexcept;
    void SetConnectionCallback(ConnectionCallback callback) noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace duplex_pipe
