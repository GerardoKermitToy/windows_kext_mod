// Client library for the Portmaster kernel extension (windows_kext driver).
//
// Wire format is defined by windows_kext/protocol/src/info.rs and
// windows_kext/protocol/src/command.rs. Every field is little-endian.
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace duplex_pipe {
class Server;
}

namespace pmkext {

// InfoType, from protocol/src/info.rs:5
enum class InfoType : uint8_t {
    LogLine              = 0,
    ConnectionIpv4       = 1,
    ConnectionIpv6       = 2,
    ConnectionEndEventV4 = 3,
    ConnectionEndEventV6 = 4,
    BandwidthStatsV4     = 5,
    BandwidthStatsV6     = 6,
};

// CommandType, from protocol/src/command.rs:9
enum class CommandType : uint8_t {
    Shutdown              = 0,
    Verdict               = 1,
    UpdateV4              = 2,
    UpdateV6              = 3,
    ClearCache            = 4,
    GetLogs               = 5,
    GetBandwidthStats     = 6,
    PrintMemoryStats      = 7,
    CleanEndedConnections = 8,
};

// Verdict, from driver/src/connection.rs:22
enum class Verdict : uint8_t {
    Undecided           = 0,
    Undeterminable      = 1,
    Accept              = 2,
    PermanentAccept     = 3,
    Block               = 4,
    PermanentBlock      = 5,
    Drop                = 6,
    PermanentDrop       = 7,
    RedirectNameServer  = 8,
    RedirectTunnel      = 9,
    Failed              = 10,
    RedirectSplitTunnel = 11,
};

// Severity, from protocol/src/info.rs:288
enum class Severity : uint8_t {
    Trace    = 1,
    Debug    = 2,
    Info     = 3,
    Warning  = 4,
    Error    = 5,
    Critical = 6,
    Disabled = 7,
};

const char* ToString(Verdict v);
const char* ToString(Severity s);
const char* ToString(InfoType t);
// payload_layer: 4 = transport (ALE), 3 = network. id_cache.rs:99
const char* PayloadLayerToString(uint8_t layer);
const char* ProtocolToString(uint8_t proto);
const char* DirectionToString(uint8_t dir);

std::string FormatIpv4(const uint8_t ip[4]);
std::string FormatIpv6(const uint8_t ip[16]);

// ---------------------------------------------------------------- event types

struct Connection {
    bool     ipv6 = false;
    uint64_t id = 0;
    uint64_t process_id = 0;
    uint8_t  direction = 0;
    uint8_t  protocol = 0;
    uint8_t  local_ip[16] = {};
    uint8_t  remote_ip[16] = {};
    uint16_t local_port = 0;
    uint16_t remote_port = 0;
    uint8_t  payload_layer = 0;
    // Size the driver reported. This is the length of the captured packet, which
    // can exceed `payload.size()` when the record was truncated in transit, so the
    // two are kept separate rather than collapsed into one field.
    uint32_t payload_size = 0;
    // Raw packet bytes, as many as actually arrived in the record.
    std::vector<uint8_t> payload;

    std::string LocalIpString() const;
    std::string RemoteIpString() const;
    // Payload as one unbroken lowercase hex string, no separators.
    std::string PayloadHexString() const;
};

struct ConnectionEnd {
    bool     ipv6 = false;
    uint64_t process_id = 0;
    uint8_t  direction = 0;
    uint8_t  protocol = 0;
    uint8_t  local_ip[16] = {};
    uint8_t  remote_ip[16] = {};
    uint16_t local_port = 0;
    uint16_t remote_port = 0;

    std::string LocalIpString() const;
    std::string RemoteIpString() const;
};

struct LogLine {
    Severity    severity = Severity::Trace;
    std::string message;
};

struct BandwidthEntry {
    bool     ipv6 = false;
    uint8_t  local_ip[16] = {};
    uint16_t local_port = 0;
    uint8_t  remote_ip[16] = {};
    uint16_t remote_port = 0;
    uint64_t transmitted_bytes = 0;
    uint64_t received_bytes = 0;

    std::string LocalIpString() const;
    std::string RemoteIpString() const;
};

struct BandwidthStats {
    uint8_t                     protocol = 0;
    std::vector<BandwidthEntry> entries;
};

// Callbacks invoked from Run(). All are optional.
struct Handlers {
    std::function<void(const Connection&)>     on_connection;
    std::function<void(const ConnectionEnd&)>  on_connection_end;
    std::function<void(const LogLine&)>        on_log;
    std::function<void(const BandwidthStats&)> on_bandwidth;
    // Reports a protocol desync or an unknown InfoType.
    std::function<void(const std::string&)>    on_warning;
    // Fires every poll_interval_ms from Run()'s own thread, independently of
    // event traffic. Use it to request logs and bandwidth stats.
    std::function<void()>                      on_poll;
};

// Manages the driver service lifetime and the device handle.
//
// Requires Administrator: the device ACL is SDDL_DEVOBJ_SYS_ALL_ADM_ALL
// (c_helper/helper.c:49), and installing a service needs SC_MANAGER_CREATE_SERVICE.
class Driver {
public:
    // service_name is used both as the SCM service name and to derive the
    // device path \\.\<service_name>, matching the driver's own naming
    // (wdk/src/interface.rs:37 builds \Device\PortmasterKext).
    explicit Driver(std::wstring service_name = L"PortmasterKext");
    ~Driver();

    Driver(const Driver&) = delete;
    Driver& operator=(const Driver&) = delete;

    // Installs (if needed) and starts the kernel service, then opens the device.
    // sys_path must be an absolute path to the .sys file.
    bool Install(const std::wstring& sys_path, std::string& error);

    // Opens the device with FILE_FLAG_OVERLAPPED, then starts the named-pipe
    // server. With no explicit Server path override, it trusts pipe_client.exe
    // next to the current executable.
    //
    // Overlapped is mandatory, and not for asynchrony. Windows serialises I/O
    // on a handle opened WITHOUT that flag: the file object is marked
    // FO_SYNCHRONOUS_IO and the I/O manager holds its lock for the duration of
    // each request. Because a read on this device blocks in the driver for as
    // long as no event is queued, that lock is held indefinitely, and every
    // WriteFile from another thread waits behind it. Commands would then only
    // reach the driver after the next event arrived — including the Shutdown
    // command needed to stop.
    //
    // With FILE_FLAG_OVERLAPPED there is no such serialisation, so commands
    // reach the driver while a read is still blocked. Every operation must then
    // supply an OVERLAPPED; passing nullptr fails with ERROR_INVALID_PARAMETER.
    // This mirrors the Go client (interception/windowskext/kext.go:330).
    bool Open(std::string& error);

    // Reads events until Stop() is called, dispatching to handlers.
    //
    // Reads run on a dedicated thread. The driver's read dispatch blocks inside
    // KeRemoveQueue in the caller's thread context (device.rs:102 ->
    // ioqueue.rs:160, null timeout) and never calls IoMarkIrpPending, so the
    // read cannot be cancelled from user space: CancelIoEx has no effect
    // because the driver registers no IRP cancel routine. The only way to
    // release it is to make the driver's own wait return, which the Shutdown
    // command does by running down the event queue. Stop() sends it.
    //
    // on_poll fires on a fixed cadence from Run()'s thread, independently of
    // event traffic. Other handlers are invoked from the reader thread unless
    // a named-pipe client is connected; complete raw records are sent to that
    // client instead.
    void Run(const Handlers& handlers, unsigned poll_interval_ms = 1000);

    // Signals Run() to return, then unblocks the reader by sending Shutdown to
    // the driver (which runs down the event queue and makes the blocked read
    // return EOF). Safe to call from a Ctrl+C handler.
    void Stop();

    // IOCTL_VERSION: returns the 4-byte driver version.
    bool GetVersion(uint8_t out[4], std::string& error);
    // IOCTL_SHUTDOWN_REQUEST: asks the driver to release pending packets.
    bool RequestShutdown(std::string& error);

    // Commands written to the device (protocol/src/command.rs).
    bool SendVerdict(uint64_t id, Verdict verdict, std::string& error);
    bool SendShutdown(std::string& error);
    bool RequestLogs(std::string& error);
    bool RequestBandwidthStats(std::string& error);
    bool RequestMemoryStats(std::string& error);
    bool RequestCleanEndedConnections(std::string& error);
    bool RequestClearCache(std::string& error);

    // Closes the handle, stops the service and deletes it from the SCM.
    void Cleanup();

private:
    bool SendCommand(const uint8_t* data, size_t len, std::string& error);
    bool DeviceControl(uint32_t code, uint8_t* out, uint32_t out_len, std::string& error);
    // Consumes whole records from buffer_, returns bytes consumed.
    size_t Dispatch(const Handlers& handlers);
    void ReaderLoop(const Handlers& handlers);

    std::wstring         service_name_;
    std::unique_ptr<duplex_pipe::Server> server_;
    std::atomic<bool>    client_connected_{false};
    void*                device_ = nullptr;   // HANDLE
    void*                scm_ = nullptr;      // SC_HANDLE
    void*                stop_event_ = nullptr;  // HANDLE, signals Stop()
    bool                 service_created_ = false;
    bool                 service_started_ = false;
    std::vector<uint8_t> buffer_;             // accumulates partial records
    // Serialises writes: the reader thread is blocked inside the driver's read
    // dispatch while the polling thread issues commands on the same handle.
    std::mutex           write_mutex_;
};

} // namespace pmkext
