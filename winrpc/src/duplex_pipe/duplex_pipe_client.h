#pragma once

#include <memory>
#include <string_view>

#include "duplex_pipe/duplex_pipe_common.h"

namespace duplex_pipe
{
class Client final
{
public:
    Client() noexcept;
    ~Client() noexcept;

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) = delete;
    Client& operator=(Client&&) = delete;

    RPC_STATUS Start(std::wstring_view trustedServerPath = {}) noexcept;
    void Stop() noexcept;

    RPC_STATUS Send(const byte* note, unsigned long noteSize) noexcept;
    void SetReceiveCallback(ReceiveCallback callback) noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace duplex_pipe
