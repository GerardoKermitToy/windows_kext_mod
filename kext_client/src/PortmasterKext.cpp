#include "PortmasterKext.h"
#include "duplex_pipe/duplex_pipe_server.h"

#include <windows.h>
#include <winsvc.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace pmkext {
namespace {

// ControlCode values, computed the same way as driver/src/common.rs:36.
// CTL_CODE(40000, function, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
constexpr uint32_t kDeviceType = 40000;
constexpr uint32_t kMethodBuffered = 0;
constexpr uint32_t kAccessReadWrite = 0x0001 | 0x0002;

constexpr uint32_t MakeCtlCode(uint32_t function) {
    return (kDeviceType << 16) | (kAccessReadWrite << 14) | (function << 2) | kMethodBuffered;
}

constexpr uint32_t kIoctlVersion = MakeCtlCode(0x800);
constexpr uint32_t kIoctlShutdown = MakeCtlCode(0x801);

// Every record is [InfoType: u8, size: u32 LE, payload: size bytes].
constexpr size_t kRecordHeaderSize = 5;

std::string LastErrorText(DWORD err) {
    char buf[256] = {};
    std::snprintf(buf, sizeof(buf), "error %lu", err);
    return buf;
}

// Little-endian readers. The driver writes all integers via to_le_bytes.
uint16_t ReadU16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t ReadU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t ReadU64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | p[i];
    }
    return v;
}

} // namespace

// ------------------------------------------------------------------- to-string

const char* ToString(Verdict v) {
    switch (v) {
        case Verdict::Undecided:           return "Undecided";
        case Verdict::Undeterminable:      return "Undeterminable";
        case Verdict::Accept:              return "Accept";
        case Verdict::PermanentAccept:     return "PermanentAccept";
        case Verdict::Block:               return "Block";
        case Verdict::PermanentBlock:      return "PermanentBlock";
        case Verdict::Drop:                return "Drop";
        case Verdict::PermanentDrop:       return "PermanentDrop";
        case Verdict::RedirectNameServer:  return "RedirectNameServer";
        case Verdict::RedirectTunnel:      return "RedirectTunnel";
        case Verdict::Failed:              return "Failed";
        case Verdict::RedirectSplitTunnel: return "RedirectSplitTunnel";
    }
    return "Unknown";
}

const char* ToString(Severity s) {
    switch (s) {
        case Severity::Trace:    return "TRACE";
        case Severity::Debug:    return "DEBUG";
        case Severity::Info:     return "INFO";
        case Severity::Warning:  return "WARN";
        case Severity::Error:    return "ERROR";
        case Severity::Critical: return "CRIT";
        case Severity::Disabled: return "OFF";
    }
    return "?";
}

const char* ToString(InfoType t) {
    switch (t) {
        case InfoType::LogLine:              return "LogLine";
        case InfoType::ConnectionIpv4:       return "ConnectionIpv4";
        case InfoType::ConnectionIpv6:       return "ConnectionIpv6";
        case InfoType::ConnectionEndEventV4: return "ConnectionEndV4";
        case InfoType::ConnectionEndEventV6: return "ConnectionEndV6";
        case InfoType::BandwidthStatsV4:     return "BandwidthStatsV4";
        case InfoType::BandwidthStatsV6:     return "BandwidthStatsV6";
    }
    return "Unknown";
}

const char* PayloadLayerToString(uint8_t layer) {
    switch (layer) {
        case 3:  return "network";    // packet layer, id_cache.rs:101
        case 4:  return "transport";  // ALE layer, id_cache.rs:99
        default: return "unknown";
    }
}

const char* ProtocolToString(uint8_t proto) {
    switch (proto) {
        case 1:   return "ICMP";
        case 6:   return "TCP";
        case 17:  return "UDP";
        case 58:  return "ICMPv6";
        default:  return "other";
    }
}

const char* DirectionToString(uint8_t dir) {
    // driver/src/common.rs:14
    return dir == 0 ? "outbound" : "inbound";
}

std::string FormatIpv4(const uint8_t ip[4]) {
    char buf[16] = {};
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buf;
}

std::string FormatIpv6(const uint8_t ip[16]) {
    char buf[64] = {};
    std::snprintf(buf, sizeof(buf),
                  "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                  ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
                  ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
    return buf;
}

std::string Connection::LocalIpString() const {
    return ipv6 ? FormatIpv6(local_ip) : FormatIpv4(local_ip);
}
std::string Connection::RemoteIpString() const {
    return ipv6 ? FormatIpv6(remote_ip) : FormatIpv4(remote_ip);
}
std::string Connection::PayloadHexString() const {
    // Built by hand rather than with a stream: two table lookups per byte, no
    // formatting machinery, and the result is what a hex dump is normally pasted
    // into - one unbroken lowercase string.
    static const char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(payload.size() * 2);
    for (uint8_t b : payload) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 0x0f]);
    }
    return out;
}
std::string ConnectionEnd::LocalIpString() const {
    return ipv6 ? FormatIpv6(local_ip) : FormatIpv4(local_ip);
}
std::string ConnectionEnd::RemoteIpString() const {
    return ipv6 ? FormatIpv6(remote_ip) : FormatIpv4(remote_ip);
}
std::string BandwidthEntry::LocalIpString() const {
    return ipv6 ? FormatIpv6(local_ip) : FormatIpv4(local_ip);
}
std::string BandwidthEntry::RemoteIpString() const {
    return ipv6 ? FormatIpv6(remote_ip) : FormatIpv4(remote_ip);
}

// -------------------------------------------------------------- service setup

Driver::Driver(std::wstring service_name)
    : service_name_(std::move(service_name)),
      server_(std::make_unique<duplex_pipe::Server>()) {
    server_->SetConnectionCallback(
        [this](const duplex_pipe::ClientConnectionEvent event) noexcept {
            client_connected_.store(
                event == duplex_pipe::ClientConnectionEvent::Connected,
                std::memory_order_release);
        });
    server_->SetReceiveCallback(
        [this](const byte* const note, const unsigned long note_size) {
            std::string ignored;
            SendCommand(
                reinterpret_cast<const uint8_t*>(note),
                static_cast<size_t>(note_size),
                ignored);
        });
}

Driver::~Driver() {
    Cleanup();
}

bool Driver::Install(const std::wstring& sys_path, std::string& error) {
    scm_ = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (scm_ == nullptr) {
        error = "OpenSCManager failed (Administrator required): " + LastErrorText(GetLastError());
        return false;
    }

    SC_HANDLE service = CreateServiceW(
        static_cast<SC_HANDLE>(scm_), service_name_.c_str(), service_name_.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, sys_path.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);

    if (service == nullptr) {
        const DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            // A previous run left the service behind. Reuse it rather than
            // failing, but do not claim ownership for deletion.
            service = OpenServiceW(static_cast<SC_HANDLE>(scm_), service_name_.c_str(),
                                   SERVICE_ALL_ACCESS);
            if (service == nullptr) {
                error = "OpenService failed: " + LastErrorText(GetLastError());
                return false;
            }
        } else {
            error = "CreateService failed: " + LastErrorText(err);
            return false;
        }
    }
    service_created_ = true;

    if (StartServiceW(service, 0, nullptr) == 0) {
        const DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            error = "StartService failed: " + LastErrorText(err);
            CloseServiceHandle(service);
            return false;
        }
    }
    service_started_ = true;
    CloseServiceHandle(service);
    return true;
}

bool Driver::Open(std::string& error) {
    const std::wstring path = L"\\\\.\\" + service_name_;
    // FILE_FLAG_OVERLAPPED prevents the I/O manager from serialising requests on
    // this handle. Without it, a blocked read holds the file object lock and
    // every command from another thread queues behind it. See the header.
    device_ = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                          nullptr);
    if (device_ == INVALID_HANDLE_VALUE) {
        device_ = nullptr;
        error = "CreateFile on device failed: " + LastErrorText(GetLastError());
        return false;
    }

    // Manual-reset, initially unsignalled.
    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (stop_event_ == nullptr) {
        error = "CreateEvent failed: " + LastErrorText(GetLastError());
        return false;
    }

    client_connected_.store(false, std::memory_order_release);
    const RPC_STATUS server_status = server_->Start();
    if (server_status != ERROR_SUCCESS) {
        error = "named-pipe Server::Start failed: " + LastErrorText(server_status);
        return false;
    }
    return true;
}

void Driver::Cleanup() {
    if (server_ != nullptr) {
        server_->Stop();
    }
    client_connected_.store(false, std::memory_order_release);

    if (device_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(device_));
        device_ = nullptr;
    }
    if (stop_event_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(stop_event_));
        stop_event_ = nullptr;
    }

    if (scm_ == nullptr) {
        return;
    }

    if (service_created_) {
        SC_HANDLE service = OpenServiceW(static_cast<SC_HANDLE>(scm_), service_name_.c_str(),
                                         SERVICE_ALL_ACCESS);
        if (service != nullptr) {
            if (service_started_) {
                SERVICE_STATUS status = {};
                // Best effort: the driver may already be unloading.
                ControlService(service, SERVICE_CONTROL_STOP, &status);
            }
            DeleteService(service);
            CloseServiceHandle(service);
        }
        service_created_ = false;
        service_started_ = false;
    }

    CloseServiceHandle(static_cast<SC_HANDLE>(scm_));
    scm_ = nullptr;
}

// ------------------------------------------------------------------- commands

namespace {

// Waits for an overlapped operation started on an overlapped handle to finish.
// `started_ok` is the BOOL the initiating call returned.
bool FinishOverlapped(HANDLE device, OVERLAPPED* ov, BOOL started_ok,
                      const char* what, DWORD* transferred, std::string& error) {
    if (started_ok == 0) {
        const DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            error = std::string(what) + " failed: " + LastErrorText(err);
            return false;
        }
    }
    DWORD local = 0;
    DWORD* out = (transferred != nullptr) ? transferred : &local;
    if (GetOverlappedResult(device, ov, out, TRUE) == 0) {
        error = std::string(what) + " failed: " + LastErrorText(GetLastError());
        return false;
    }
    return true;
}

// RAII wrapper for an OVERLAPPED with its own auto-reset event. Each concurrent
// operation needs a distinct event; sharing one would let completions cross.
class Overlap {
public:
    Overlap() {
        std::memset(&ov_, 0, sizeof(ov_));
        ov_.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }
    ~Overlap() {
        if (ov_.hEvent != nullptr) {
            CloseHandle(ov_.hEvent);
        }
    }
    Overlap(const Overlap&) = delete;
    Overlap& operator=(const Overlap&) = delete;

    bool valid() const { return ov_.hEvent != nullptr; }
    OVERLAPPED* get() { return &ov_; }

private:
    OVERLAPPED ov_;
};

} // namespace

bool Driver::DeviceControl(uint32_t code, uint8_t* out, uint32_t out_len, std::string& error) {
    if (device_ == nullptr) {
        error = "device not open";
        return false;
    }
    Overlap ov;
    if (!ov.valid()) {
        error = "CreateEvent failed: " + LastErrorText(GetLastError());
        return false;
    }
    HANDLE device = static_cast<HANDLE>(device_);
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(device, code, nullptr, 0, out, out_len,
                                    &returned, ov.get());
    return FinishOverlapped(device, ov.get(), ok, "DeviceIoControl", nullptr, error);
}

bool Driver::GetVersion(uint8_t out[4], std::string& error) {
    return DeviceControl(kIoctlVersion, out, 4, error);
}

bool Driver::RequestShutdown(std::string& error) {
    return DeviceControl(kIoctlShutdown, nullptr, 0, error);
}

bool Driver::SendCommand(const uint8_t* data, size_t len, std::string& error) {
    if (device_ == nullptr) {
        error = "device not open";
        return false;
    }
    // Writes come from both the polling thread and the Ctrl+C handler while the
    // reader thread sits blocked in the driver. Serialise them so two commands
    // never interleave in the driver's single-command-per-write parser.
    std::lock_guard<std::mutex> guard(write_mutex_);

    Overlap ov;
    if (!ov.valid()) {
        error = "CreateEvent failed: " + LastErrorText(GetLastError());
        return false;
    }
    HANDLE device = static_cast<HANDLE>(device_);
    DWORD written = 0;
    const BOOL ok = WriteFile(device, data, static_cast<DWORD>(len), &written, ov.get());
    return FinishOverlapped(device, ov.get(), ok, "WriteFile", nullptr, error);
}

bool Driver::SendVerdict(uint64_t id, Verdict verdict, std::string& error) {
    // CommandType::Verdict followed by struct Verdict { u64 id; u8 verdict; }
    // packed, from protocol/src/command.rs:29.
    uint8_t buf[1 + 8 + 1] = {};
    buf[0] = static_cast<uint8_t>(CommandType::Verdict);
    for (int i = 0; i < 8; ++i) {
        buf[1 + i] = static_cast<uint8_t>((id >> (i * 8)) & 0xFF);
    }
    buf[9] = static_cast<uint8_t>(verdict);
    return SendCommand(buf, sizeof(buf), error);
}

bool Driver::SendShutdown(std::string& error) {
    const uint8_t buf[1] = {static_cast<uint8_t>(CommandType::Shutdown)};
    return SendCommand(buf, sizeof(buf), error);
}

bool Driver::RequestLogs(std::string& error) {
    const uint8_t buf[1] = {static_cast<uint8_t>(CommandType::GetLogs)};
    return SendCommand(buf, sizeof(buf), error);
}

bool Driver::RequestBandwidthStats(std::string& error) {
    const uint8_t buf[1] = {static_cast<uint8_t>(CommandType::GetBandwidthStats)};
    return SendCommand(buf, sizeof(buf), error);
}

bool Driver::RequestMemoryStats(std::string& error) {
    const uint8_t buf[1] = {static_cast<uint8_t>(CommandType::PrintMemoryStats)};
    return SendCommand(buf, sizeof(buf), error);
}

bool Driver::RequestCleanEndedConnections(std::string& error) {
    const uint8_t buf[1] = {static_cast<uint8_t>(CommandType::CleanEndedConnections)};
    return SendCommand(buf, sizeof(buf), error);
}

bool Driver::RequestClearCache(std::string& error) {
    const uint8_t buf[1] = {static_cast<uint8_t>(CommandType::ClearCache)};
    return SendCommand(buf, sizeof(buf), error);
}

void Driver::Stop() {
    // Order matters: raise the flag first so the reader exits once it wakes.
    if (stop_event_ != nullptr) {
        SetEvent(static_cast<HANDLE>(stop_event_));
    }

    // Then unblock the reader. The Shutdown command makes the driver run down
    // its event queue (device.rs:313), which makes the blocked KeRemoveQueue
    // return STATUS_ABANDONED; the driver then completes the read as EOF
    // (device.rs:114). This is the only mechanism that releases the read, since
    // the IRP is never pending and has no cancel routine.
    std::string ignored;
    SendShutdown(ignored);
}

// -------------------------------------------------------------------- parsing

size_t Driver::Dispatch(const Handlers& handlers) {
    size_t offset = 0;

    for (;;) {
        const size_t available = buffer_.size() - offset;
        if (available < kRecordHeaderSize) {
            break;
        }

        const uint8_t* rec = buffer_.data() + offset;
        const uint32_t size = ReadU32(rec + 1);
        const size_t n = static_cast<size_t>(size);

        if (n > available - kRecordHeaderSize) {
            break; // partial record, wait for more data
        }

        const size_t record_size = kRecordHeaderSize + n;
        if (client_connected_.load(std::memory_order_acquire)) {
            RPC_STATUS status = ERROR_FILE_TOO_LARGE;
            if (record_size <= duplex_pipe::kMaxNoteSize) {
                status = server_->Send(
                    reinterpret_cast<const byte*>(rec),
                    static_cast<unsigned long>(record_size));
            }

            // A successful write belongs exclusively to the client. If sending
            // failed but the connection callback still reports a live client,
            // keep the same exclusive ownership rather than invoking handlers for
            // a record that was selected for remote delivery. Transport failures
            // synchronously end the session and clear the flag, so those records
            // fall through to the original local parser.
            if (status == ERROR_SUCCESS ||
                client_connected_.load(std::memory_order_acquire)) {
                offset += record_size;
                continue;
            }
        }

        const auto type = static_cast<InfoType>(rec[0]);
        const uint8_t* p = rec + kRecordHeaderSize;

        switch (type) {
            case InfoType::LogLine: {
                // log_line() writes severity as the first payload byte
                // (info.rs:313), then log_internal! appends "file:line message".
                if (n < 1) {
                    if (handlers.on_warning) handlers.on_warning("LogLine record too short");
                    break;
                }
                LogLine line;
                line.severity = static_cast<Severity>(p[0]);
                line.message.assign(reinterpret_cast<const char*>(p + 1), n - 1);
                if (handlers.on_log) handlers.on_log(line);
                break;
            }

            case InfoType::ConnectionIpv4:
            case InfoType::ConnectionIpv6: {
                const bool v6 = (type == InfoType::ConnectionIpv6);
                const size_t addr_len = v6 ? 16 : 4;
                // id(8) pid(8) dir(1) proto(1) local_ip remote_ip
                // lport(2) rport(2) layer(1) payload_len(4)
                const size_t fixed = 8 + 8 + 1 + 1 + addr_len * 2 + 2 + 2 + 1 + 4;
                if (n < fixed) {
                    if (handlers.on_warning) handlers.on_warning("Connection record too short");
                    break;
                }
                Connection c;
                c.ipv6 = v6;
                size_t o = 0;
                c.id = ReadU64(p + o);          o += 8;
                c.process_id = ReadU64(p + o);  o += 8;
                c.direction = p[o];             o += 1;
                c.protocol = p[o];              o += 1;
                std::memcpy(c.local_ip, p + o, addr_len);  o += addr_len;
                std::memcpy(c.remote_ip, p + o, addr_len); o += addr_len;
                c.local_port = ReadU16(p + o);  o += 2;
                c.remote_port = ReadU16(p + o); o += 2;
                c.payload_layer = p[o];         o += 1;
                c.payload_size = ReadU32(p + o); o += 4;

                // The payload follows the size field. Copy only what the record
                // actually contains: payload_size is what the driver captured, and
                // trusting it as a length would read past the record if the two
                // ever disagree.
                if (o < n) {
                    const size_t in_record = n - o;
                    const size_t take = (c.payload_size < in_record) ? c.payload_size
                                                                     : in_record;
                    c.payload.assign(p + o, p + o + take);
                    if (take < c.payload_size && handlers.on_warning) {
                        handlers.on_warning("Connection payload truncated: record holds "
                                            + std::to_string(in_record) + " of "
                                            + std::to_string(c.payload_size) + " bytes");
                    }
                }
                if (handlers.on_connection) handlers.on_connection(c);
                break;
            }

            case InfoType::ConnectionEndEventV4:
            case InfoType::ConnectionEndEventV6: {
                const bool v6 = (type == InfoType::ConnectionEndEventV6);
                const size_t addr_len = v6 ? 16 : 4;
                const size_t fixed = 8 + 1 + 1 + addr_len * 2 + 2 + 2;
                if (n < fixed) {
                    if (handlers.on_warning) handlers.on_warning("ConnectionEnd record too short");
                    break;
                }
                ConnectionEnd e;
                e.ipv6 = v6;
                size_t o = 0;
                e.process_id = ReadU64(p + o);  o += 8;
                e.direction = p[o];             o += 1;
                e.protocol = p[o];              o += 1;
                std::memcpy(e.local_ip, p + o, addr_len);  o += addr_len;
                std::memcpy(e.remote_ip, p + o, addr_len); o += addr_len;
                e.local_port = ReadU16(p + o);  o += 2;
                e.remote_port = ReadU16(p + o);
                if (handlers.on_connection_end) handlers.on_connection_end(e);
                break;
            }

            case InfoType::BandwidthStatsV4:
            case InfoType::BandwidthStatsV6: {
                const bool v6 = (type == InfoType::BandwidthStatsV6);
                const size_t addr_len = v6 ? 16 : 4;
                const size_t entry_size = addr_len * 2 + 2 + 2 + 8 + 8;
                if (n < 5) {
                    if (handlers.on_warning) handlers.on_warning("Bandwidth record too short");
                    break;
                }
                BandwidthStats stats;
                stats.protocol = p[0];
                const uint32_t count = ReadU32(p + 1);
                if (n < 5 + entry_size * static_cast<size_t>(count)) {
                    if (handlers.on_warning) {
                        handlers.on_warning("Bandwidth record truncated: count exceeds payload");
                    }
                    break;
                }
                stats.entries.reserve(count);
                size_t o = 5;
                for (uint32_t i = 0; i < count; ++i) {
                    BandwidthEntry e;
                    e.ipv6 = v6;
                    std::memcpy(e.local_ip, p + o, addr_len);  o += addr_len;
                    e.local_port = ReadU16(p + o);  o += 2;
                    std::memcpy(e.remote_ip, p + o, addr_len); o += addr_len;
                    e.remote_port = ReadU16(p + o); o += 2;
                    e.transmitted_bytes = ReadU64(p + o); o += 8;
                    e.received_bytes = ReadU64(p + o);    o += 8;
                    stats.entries.push_back(e);
                }
                if (handlers.on_bandwidth) handlers.on_bandwidth(stats);
                break;
            }

            default: {
                if (handlers.on_warning) {
                    char msg[96] = {};
                    std::snprintf(msg, sizeof(msg),
                                  "unknown InfoType %u, skipping %u bytes",
                                  static_cast<unsigned>(rec[0]), size);
                    handlers.on_warning(msg);
                }
                break;
            }
        }

        offset += record_size;
    }

    return offset;
}

void Driver::ReaderLoop(const Handlers& handlers) {
    // The driver packs as many records as fit into each read (device.rs:121),
    // and splits a record across reads when the buffer fills, saving the
    // remainder (device.rs:83). So partial records must be accumulated.
    std::vector<uint8_t> chunk(64 * 1024);
    HANDLE device = static_cast<HANDLE>(device_);
    HANDLE stop_event = static_cast<HANDLE>(stop_event_);

    while (WaitForSingleObject(stop_event, 0) != WAIT_OBJECT_0) {
        Overlap ov;
        if (!ov.valid()) {
            if (handlers.on_warning) {
                handlers.on_warning("CreateEvent failed: " + LastErrorText(GetLastError()));
            }
            break;
        }

        DWORD read = 0;
        BOOL ok = ReadFile(device, chunk.data(), static_cast<DWORD>(chunk.size()),
                           &read, ov.get());

        if (ok == 0) {
            const DWORD err = GetLastError();
            // ERROR_HANDLE_EOF is the normal end of a run, not a failure: the
            // Shutdown command runs down the driver's event queue, which makes
            // the blocked read complete as EOF (device.rs:114). Reporting it as a
            // warning made every clean stop look like an error.
            if (err == ERROR_OPERATION_ABORTED || err == ERROR_INVALID_HANDLE ||
                err == ERROR_HANDLE_EOF) {
                break;
            }
            if (err != ERROR_IO_PENDING) {
                if (handlers.on_warning) {
                    handlers.on_warning("ReadFile failed: " + LastErrorText(err));
                }
                break;
            }

            // Pending: wait for completion or for Stop(). Stop() sends the
            // Shutdown command, which makes the driver complete this read with
            // EOF, so in practice the read event signals shortly after.
            HANDLE waits[2] = {ov.get()->hEvent, stop_event};
            const DWORD result = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (result == WAIT_OBJECT_0 + 1) {
                // Stop requested. Give the driver a moment to complete the read
                // it is about to release, then reap it so the OVERLAPPED and
                // buffer (this stack frame) are no longer referenced.
                if (WaitForSingleObject(ov.get()->hEvent, 2000) != WAIT_OBJECT_0) {
                    CancelIoEx(device, ov.get());
                }
                DWORD ignored = 0;
                GetOverlappedResult(device, ov.get(), &ignored, TRUE);
                break;
            }
            if (result != WAIT_OBJECT_0) {
                if (handlers.on_warning) {
                    handlers.on_warning("wait failed: " + LastErrorText(GetLastError()));
                }
                break;
            }

            if (GetOverlappedResult(device, ov.get(), &read, TRUE) == 0) {
                const DWORD err2 = GetLastError();
                if (err2 == ERROR_OPERATION_ABORTED || err2 == ERROR_INVALID_HANDLE ||
                    err2 == ERROR_HANDLE_EOF) {
                    break;
                }
                if (handlers.on_warning) {
                    handlers.on_warning("GetOverlappedResult failed: " + LastErrorText(err2));
                }
                break;
            }
        }

        if (read == 0) {
            // EOF: the driver ran down the event queue (device.rs:114). This is
            // what Stop() induces via the Shutdown command.
            break;
        }

        buffer_.insert(buffer_.end(), chunk.begin(), chunk.begin() + read);
        const size_t consumed = Dispatch(handlers);
        if (consumed > 0) {
            buffer_.erase(buffer_.begin(), buffer_.begin() + consumed);
        }
    }
}

void Driver::Run(const Handlers& handlers, unsigned poll_interval_ms) {
    HANDLE stop_event = static_cast<HANDLE>(stop_event_);

    // Reads must live on their own thread: they block inside the driver and
    // cannot be cancelled, so the polling cadence and the Ctrl+C response
    // cannot share that thread.
    std::thread reader([this, &handlers]() { ReaderLoop(handlers); });

    // Poll immediately, then on a fixed cadence. WaitForSingleObject on the
    // stop event doubles as the sleep, so Stop() cuts the wait short.
    for (;;) {
        if (handlers.on_poll) {
            handlers.on_poll();
        }
        if (WaitForSingleObject(stop_event, poll_interval_ms) == WAIT_OBJECT_0) {
            break;
        }
    }

    reader.join();
}

} // namespace pmkext
