#pragma once

#include <functional>

#include <rpc.h>
#include <rpcndr.h>

namespace duplex_pipe
{
constexpr unsigned long kMaxNoteSize = 64UL * 1024UL * 1024UL;

using ReceiveCallback = std::function<void(
    const byte* note,
    unsigned long noteSize)>;
} // namespace duplex_pipe
