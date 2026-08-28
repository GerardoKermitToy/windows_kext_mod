// Console monitor for the Portmaster kernel extension.
//
// Collects driver events (logs, connections, bandwidth) and answers connections
// so traffic is not blocked. Requires Administrator: the device ACL is
// SDDL_DEVOBJ_SYS_ALL_ADM_ALL.
//
// Run `kext_monitor.exe --help` for options. The two that matter most for
// scripted collection:
//   --duration N  stop by itself after N seconds (no Ctrl+C needed)
//   --out FILE    write to FILE, flushed per record so `tail -f` works live
//
// Ctrl+C still works interactively, but it cannot be delivered to a process
// started without a real console (a background job in a shell, for example), so
// --duration is the reliable way to bound an unattended run.
#include "PortmasterKext.h"

#include <windows.h>

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

namespace {

pmkext::Driver* g_driver = nullptr;
std::atomic<bool> g_shutdown_requested{false};

// Output comes from the reader thread and the polling thread, so serialise it
// to keep multi-line records from interleaving.
std::mutex g_print_mutex;

// Destination for all records. stdout unless --out was given.
FILE* g_out = stdout;

struct Options {
    std::wstring sys_path;
    std::wstring out_path;
    unsigned duration_s = 0;       // 0 = until Ctrl+C
    unsigned poll_ms = 1000;
    bool show_connections = true;
    bool show_ends = true;
    bool show_logs = true;
    bool show_bandwidth = true;
    bool timestamps = false;
    bool send_verdicts = true;
    bool show_payload = false;     // --payload: dump packet bytes as hex
    bool memory_stats = false;     // --memory-stats: send PrintMemoryStats command
    bool help = false;

    // Alternate verdict for connections matching alt_match_ip / alt_match_port.
    // Everything else keeps getting PermanentAccept.
    //
    // Without --match the verdict applies to every connection instead. That is
    // what the option is for, but it is worth knowing what it costs: a redirect
    // sends all traffic to a local port that is probably not listening, and a
    // block cuts the network - including whatever remote session would be needed
    // to stop this program. Use --duration so the run ends on its own.
    pmkext::Verdict alt_verdict = pmkext::Verdict::PermanentAccept;
    bool has_alt = false;
    bool has_match = false;
    bool has_match_port = false;
    std::string alt_match_ip;      // presentation form, matched as a string
    uint16_t alt_match_port = 0;

    // --filter-ip: display only records involving this IP (connections, ends,
    // bandwidth entries). Other record types (logs, warnings) are always shown.
    bool has_filter_ip = false;
    bool has_filter_port = false;
    std::string filter_ip;
    uint16_t filter_port = 0;
    bool has_filter_pid = false;
    uint64_t filter_pid = 0;
    bool has_filter_protocol = false;
    uint8_t filter_protocol = 0;
};

// The monitor owns the driver's full userspace lifecycle: it loads the service,
// drains a single event queue, and unloads the service when it exits. Letting two
// instances do that independently can unload the WDF control device while the
// other process still has an open file object. Keep the exclusion in userspace so
// a duplicate exits before it touches either the SCM or the device.
class SingleInstanceGuard {
public:
    ~SingleInstanceGuard() {
        if (mutex_ != nullptr) {
            if (owned_) {
                ReleaseMutex(mutex_);
            }
            CloseHandle(mutex_);
        }
    }

    bool Acquire(std::string& error) {
        mutex_ = CreateMutexW(nullptr, TRUE, L"Global\\PortmasterKextMonitor.Singleton");
        if (mutex_ == nullptr) {
            error = "CreateMutexW failed: error " + std::to_string(GetLastError());
            return false;
        }

        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            owned_ = true;
            return true;
        }

        const DWORD wait = WaitForSingleObject(mutex_, 0);
        if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) {
            owned_ = true;
            return true;
        }

        if (wait == WAIT_TIMEOUT) {
            error = "another kext_monitor instance is already running";
        } else {
            error = "WaitForSingleObject failed: error " + std::to_string(GetLastError());
        }
        CloseHandle(mutex_);
        mutex_ = nullptr;
        return false;
    }

private:
    HANDLE mutex_ = nullptr;
    bool owned_ = false;
};

bool ParseUnsignedDecimal(const wchar_t* text, uint64_t maximum, uint64_t& result) {
    if (text == nullptr || *text == L'\0') {
        return false;
    }

    uint64_t value = 0;
    for (const wchar_t* cursor = text; *cursor != L'\0'; ++cursor) {
        if (*cursor < L'0' || *cursor > L'9') {
            return false;
        }
        const uint64_t digit = static_cast<uint64_t>(*cursor - L'0');
        if (value > (maximum - digit) / 10) {
            return false;
        }
        value = value * 10 + digit;
    }

    result = value;
    return true;
}

// Writes a record and flushes it.
//
// Flushing per record is deliberate. A redirected stdout is block-buffered, so
// without it a run that is killed rather than stopped cleanly loses whatever was
// still in the buffer - which is how the previous version could produce an empty
// file despite the driver working.
void Emit(const char* fmt, ...) {
    std::lock_guard<std::mutex> guard(g_print_mutex);

    if (g_out == nullptr) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    std::vfprintf(g_out, fmt, args);
    va_end(args);
    std::fflush(g_out);
}

// Prefix for one record: "HH:MM:SS.mmm " when timestamps are on, else empty.
std::string TimePrefix(bool enabled) {
    if (!enabled) {
        return std::string();
    }
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    char buf[32] = {};
    std::snprintf(buf, sizeof(buf), "%02u:%02u:%02u.%03u ",
                  st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

void PrintUsage() {
    std::printf(
        "Usage: kext_monitor.exe [options] [path\\to\\portmaster-kext.sys]\n"
        "\n"
        "Collection:\n"
        "  --duration N     run for N seconds, then stop and clean up.\n"
        "                   Use this instead of Ctrl+C for unattended runs.\n"
        "  --out FILE       write records to FILE (flushed per record).\n"
        "  --poll N         request logs and bandwidth every N ms (default 1000).\n"
        "  --timestamps     prefix every record with local HH:MM:SS.mmm.\n"
        "  --payload        dump each connection's packet bytes as one hex string.\n"
        "  --memory-stats   request driver memory statistics every poll interval.\n"
        "\n"
        "Filters (all shown by default):\n"
        "  --only-logs      show only driver log lines.\n"
        "  --no-bandwidth   suppress bandwidth records.\n"
        "  --no-conn        suppress connection and connection-end records.\n"
        "  --filter-ip IP[:PORT]\n"
        "                   show only connections, ends and bandwidth entries\n"
        "                   involving this IP. Use [IPv6]:PORT for IPv6.\n"
        "  --filter-pid PID show only connection and end records for this PID.\n"
        "                   Bandwidth records carry no PID and are suppressed.\n"
        "  --filter-protocol N\n"
        "                   show only connection, end and bandwidth records with\n"
        "                   IP protocol number N (0..255; e.g. 1, 6, 17, 58).\n"
        "                   Display filters combine with AND, never affect verdicts,\n"
        "                   and do not suppress logs or warnings.\n"
        "\n"
        "Behaviour:\n"
        "  --no-verdicts    do not answer connections.\n"
        "                   WARNING: the driver blocks pending packets until a\n"
        "                   verdict arrives, so traffic stalls. Diagnostic only.\n"
        "\n"
        "  --verdict V [--match IP[:PORT]]\n"
        "                   answer connections with verdict V.\n"
        "                   V: accept | redirect-tunnel | redirect-split\n"
        "                      | redirect-dns | block | drop\n"
        "                      | permanent-block | permanent-drop\n"
        "\n"
        "                   accept permits the packet without caching the\n"
        "                   verdict, so the connection is indicated again on the\n"
        "                   next packet - unlike the PermanentAccept used for\n"
        "                   everything else.\n"
        "\n"
        "                   With --match only connections to that IP get V. If a\n"
        "                   port is given, both IP and port must match. The rest\n"
        "                   get PermanentAccept. Without --match V applies to\n"
        "                   EVERY connection.\n"
        "\n"
        "                   Applying redirect, block or drop to all traffic can\n"
        "                   take this machine off the network, including the\n"
        "                   session you would need to stop this program. Pair it\n"
        "                   with --duration so the run ends on its own.\n"
        "\n"
        "  --help           this text.\n"
        "\n"
        "Examples:\n"
        "  kext_monitor.exe --duration 10 --only-logs\n"
        "  kext_monitor.exe --duration 30 --out run.log --timestamps\n"
        "  kext_monitor.exe --duration 30 --filter-pid 1234 --filter-protocol 6\n"
        "  kext_monitor.exe --duration 30 --filter-protocol 58\n"
        "  kext_monitor.exe --duration 30 --verdict accept --match 192.168.219.15\n"
        "  kext_monitor.exe --duration 30 --verdict redirect-tunnel \\\n"
        "                   --match 192.168.219.15:9999\n");
}

// Returns false on a malformed argument list.
bool ParseArgs(int argc, wchar_t** argv, Options& opt) {
    for (int i = 1; i < argc; ++i) {
        const std::wstring a = argv[i];

        auto value = [&](unsigned& dest) -> bool {
            if (i + 1 >= argc) {
                std::wprintf(L"ERROR: %s needs a value\n", a.c_str());
                return false;
            }
            dest = static_cast<unsigned>(_wtoi(argv[++i]));
            return true;
        };

        if (a == L"--help" || a == L"-h") {
            opt.help = true;
        } else if (a == L"--duration") {
            if (!value(opt.duration_s)) return false;
        } else if (a == L"--poll") {
            if (!value(opt.poll_ms)) return false;
            if (opt.poll_ms == 0) {
                std::printf("ERROR: --poll must be greater than 0\n");
                return false;
            }
        } else if (a == L"--out") {
            if (i + 1 >= argc) {
                std::printf("ERROR: --out needs a path\n");
                return false;
            }
            opt.out_path = argv[++i];
        } else if (a == L"--timestamps") {
            opt.timestamps = true;
        } else if (a == L"--payload") {
            opt.show_payload = true;
        } else if (a == L"--memory-stats") {
            opt.memory_stats = true;
        } else if (a == L"--only-logs") {
            opt.show_connections = false;
            opt.show_ends = false;
            opt.show_bandwidth = false;
        } else if (a == L"--no-bandwidth") {
            opt.show_bandwidth = false;
        } else if (a == L"--no-conn") {
            opt.show_connections = false;
            opt.show_ends = false;
        } else if (a == L"--no-verdicts") {
            opt.send_verdicts = false;
        } else if (a == L"--verdict") {
            if (i + 1 >= argc) {
                std::printf("ERROR: --verdict needs a value\n");
                return false;
            }
            const std::wstring v = argv[++i];
            if (v == L"accept") {
                // One-shot accept: the driver permits this packet but does not
                // cache the verdict, so the same connection is indicated again.
                // That is the point of having it here - it exercises the
                // re-indication path that PermanentAccept never reaches.
                opt.alt_verdict = pmkext::Verdict::Accept;
            } else if (v == L"redirect-tunnel") {
                opt.alt_verdict = pmkext::Verdict::RedirectTunnel;
            } else if (v == L"redirect-split") {
                opt.alt_verdict = pmkext::Verdict::RedirectSplitTunnel;
            } else if (v == L"redirect-dns") {
                opt.alt_verdict = pmkext::Verdict::RedirectNameServer;
            } else if (v == L"block") {
                opt.alt_verdict = pmkext::Verdict::Block;
            } else if (v == L"drop") {
                opt.alt_verdict = pmkext::Verdict::Drop;
            } else if (v == L"permanent-block") {
                opt.alt_verdict = pmkext::Verdict::PermanentBlock;
            } else if (v == L"permanent-drop") {
                opt.alt_verdict = pmkext::Verdict::PermanentDrop;
            } else {
                std::wprintf(L"ERROR: unknown verdict %s\n", v.c_str());
                return false;
            }
            opt.has_alt = true;
        } else if (a == L"--match") {
            if (i + 1 >= argc) {
                std::printf("ERROR: --match needs IP or IP:PORT\n");
                return false;
            }
            const std::wstring m = argv[++i];
            std::wstring ip;
            std::wstring port;

            // An unbracketed IPv6 address contains multiple colons, so its last
            // component cannot be distinguished from a port. Treat it as an
            // address without a port. Use [IPv6]:PORT when a port is needed.
            if (!m.empty() && m.front() == L'[') {
                const size_t close = m.find(L']');
                if (close == std::wstring::npos) {
                    std::printf("ERROR: --match has an unterminated IPv6 bracket\n");
                    return false;
                }
                ip = m.substr(1, close - 1);
                if (close + 1 < m.size()) {
                    if (m[close + 1] != L':') {
                        std::printf("ERROR: --match [IPv6] must be followed by :PORT or nothing\n");
                        return false;
                    }
                    if (close + 2 >= m.size()) {
                        std::printf("ERROR: --match port after : is empty\n");
                        return false;
                    }
                    port = m.substr(close + 2);
                }
            } else {
                const size_t first_colon = m.find(L':');
                const size_t last_colon = m.find_last_of(L':');
                if (first_colon != std::wstring::npos && first_colon == last_colon) {
                    ip = m.substr(0, first_colon);
                    port = m.substr(first_colon + 1);
                    if (port.empty()) {
                        std::printf("ERROR: --match port is empty\n");
                        return false;
                    }
                } else {
                    ip = m;
                }
            }

            if (ip.empty()) {
                std::printf("ERROR: --match IP is empty\n");
                return false;
            }

            // Narrow explicitly rather than via iterators: an IP literal is ASCII,
            // but an implicit wchar_t->char conversion is lossy in general and the
            // compiler is right to warn about it.
            opt.alt_match_ip.clear();
            opt.alt_match_ip.reserve(ip.size());
            for (const wchar_t ch : ip) {
                if (ch > 0x7F) {
                    std::printf("ERROR: --match IP must be ASCII\n");
                    return false;
                }
                opt.alt_match_ip.push_back(static_cast<char>(ch));
            }

            if (!port.empty()) {
                opt.alt_match_port = static_cast<uint16_t>(_wtoi(port.c_str()));
                if (opt.alt_match_port == 0) {
                    std::printf("ERROR: --match port must be non-zero\n");
                    return false;
                }
                opt.has_match_port = true;
            }
            opt.has_match = true;
        } else if (a == L"--filter-pid") {
            if (i + 1 >= argc) {
                std::printf("ERROR: --filter-pid needs a decimal PID\n");
                return false;
            }
            uint64_t pid = 0;
            if (!ParseUnsignedDecimal(argv[++i], ~uint64_t{0}, pid)) {
                std::printf("ERROR: --filter-pid must be an unsigned decimal value\n");
                return false;
            }
            opt.filter_pid = pid;
            opt.has_filter_pid = true;
        } else if (a == L"--filter-protocol") {
            if (i + 1 >= argc) {
                std::printf("ERROR: --filter-protocol needs a protocol number\n");
                return false;
            }
            uint64_t protocol = 0;
            if (!ParseUnsignedDecimal(argv[++i], 255, protocol)) {
                std::printf("ERROR: --filter-protocol must be a number from 0 to 255\n");
                return false;
            }
            opt.filter_protocol = static_cast<uint8_t>(protocol);
            opt.has_filter_protocol = true;
        } else if (a == L"--filter-ip") {
            if (i + 1 >= argc) {
                std::printf("ERROR: --filter-ip needs IP or IP:PORT\n");
                return false;
            }
            const std::wstring f = argv[++i];
            std::wstring ip;
            std::wstring port;

            if (!f.empty() && f.front() == L'[') {
                const size_t close = f.find(L']');
                if (close == std::wstring::npos) {
                    std::printf("ERROR: --filter-ip has an unterminated IPv6 bracket\n");
                    return false;
                }
                ip = f.substr(1, close - 1);
                if (close + 1 < f.size()) {
                    if (f[close + 1] != L':') {
                        std::printf("ERROR: --filter-ip [IPv6] must be followed by :PORT or nothing\n");
                        return false;
                    }
                    if (close + 2 >= f.size()) {
                        std::printf("ERROR: --filter-ip port after : is empty\n");
                        return false;
                    }
                    port = f.substr(close + 2);
                }
            } else {
                const size_t first_colon = f.find(L':');
                const size_t last_colon = f.find_last_of(L':');
                if (first_colon != std::wstring::npos && first_colon == last_colon) {
                    ip = f.substr(0, first_colon);
                    port = f.substr(first_colon + 1);
                    if (port.empty()) {
                        std::printf("ERROR: --filter-ip port is empty\n");
                        return false;
                    }
                } else {
                    ip = f;
                }
            }

            if (ip.empty()) {
                std::printf("ERROR: --filter-ip IP is empty\n");
                return false;
            }

            opt.filter_ip.clear();
            opt.filter_ip.reserve(ip.size());
            for (const wchar_t ch : ip) {
                if (ch > 0x7F) {
                    std::printf("ERROR: --filter-ip IP must be ASCII\n");
                    return false;
                }
                opt.filter_ip.push_back(static_cast<char>(ch));
            }

            if (!port.empty()) {
                opt.filter_port = static_cast<uint16_t>(_wtoi(port.c_str()));
                if (opt.filter_port == 0) {
                    std::printf("ERROR: --filter-ip port must be non-zero\n");
                    return false;
                }
                opt.has_filter_port = true;
            }
            opt.has_filter_ip = true;
        } else if (!a.empty() && a[0] == L'-') {
            std::wprintf(L"ERROR: unknown option %s\n", a.c_str());
            return false;
        } else {
            opt.sys_path = a;  // positional: the .sys path
        }
    }

    // --match is optional. Without it the verdict applies to every connection,
    // which is a legitimate diagnostic mode but not a harmless one: a redirect
    // sends all traffic to a local port, and a block or drop cuts the network
    // along with any remote session needed to stop this program. The run is
    // allowed, with a warning printed at startup.
    if (!opt.has_alt && opt.has_match) {
        std::printf("ERROR: --match given without --verdict\n");
        return false;
    }

    return true;
}

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT ||
        signal == CTRL_CLOSE_EVENT) {
        g_shutdown_requested.store(true);
        Emit("\nCtrl+C: stopping...\n");
        // Stop() sets the stop flag and sends the Shutdown command, which is
        // what actually releases the blocked read.
        if (g_driver != nullptr) {
            g_driver->Stop();
        }
        return TRUE;
    }
    return FALSE;
}

std::wstring ResolveSysPath(const std::wstring& arg) {
    if (!arg.empty()) {
        wchar_t full[MAX_PATH] = {};
        if (GetFullPathNameW(arg.c_str(), MAX_PATH, full, nullptr) != 0) {
            return full;
        }
        return arg;
    }
    // Default: portmaster-kext.sys next to the executable.
    wchar_t exe[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring path(exe);
    const size_t slash = path.find_last_of(L'\\');
    if (slash != std::wstring::npos) {
        path.resize(slash + 1);
    }
    return path + L"portmaster-kext.sys";
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    Options opt;
    if (!ParseArgs(argc, argv, opt)) {
        return 2;
    }
    if (opt.help) {
        PrintUsage();
        return 0;
    }

    const std::wstring sys_path = ResolveSysPath(opt.sys_path);

    SingleInstanceGuard single_instance;
    std::string instance_error;
    if (!single_instance.Acquire(instance_error)) {
        std::printf("ERROR: %s. No service or device state was changed.\n",
                    instance_error.c_str());
        return 1;
    }

    if (!opt.out_path.empty()) {
        g_out = _wfopen(opt.out_path.c_str(), L"w");
        if (g_out == nullptr) {
            std::wprintf(L"ERROR: cannot open %s for writing\n", opt.out_path.c_str());
            return 1;
        }
        // Progress goes to the console; records go to the file.
        std::wprintf(L"Writing records to %s\n", opt.out_path.c_str());
    }

    std::wprintf(L"Driver file : %s\n", sys_path.c_str());
    std::printf("Service name: PortmasterKext\n");

    if (GetFileAttributesW(sys_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::printf("\nERROR: driver file not found.\n");
        PrintUsage();
        return 1;
    }

    pmkext::Driver driver(L"PortmasterKext");
    g_driver = &driver;
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    std::string error;
    if (!driver.Install(sys_path, error)) {
        std::printf("\nERROR: install failed: %s\n", error.c_str());
        return 1;
    }
    std::printf("Service is available and running.\n");

    if (!driver.Open(error)) {
        std::printf("\nERROR: open device failed: %s\n", error.c_str());
        return 1;
    }

    uint8_t version[4] = {};
    if (driver.GetVersion(version, error)) {
        std::printf("Driver version: %u.%u.%u.%u\n",
                    version[0], version[1], version[2], version[3]);
    } else {
        std::printf("WARN: could not read version: %s\n", error.c_str());
    }

    if (!opt.send_verdicts) {
        std::printf("NOT answering connections (--no-verdicts): traffic will stall.\n");
    } else if (opt.has_alt && opt.has_match) {
        if (opt.has_match_port) {
            std::printf("Answering %s:%u with %s, everything else with PermanentAccept.\n",
                        opt.alt_match_ip.c_str(), static_cast<unsigned>(opt.alt_match_port),
                        pmkext::ToString(opt.alt_verdict));
        } else {
            std::printf("Answering every connection to %s with %s, everything else with PermanentAccept.\n",
                        opt.alt_match_ip.c_str(), pmkext::ToString(opt.alt_verdict));
        }
    } else if (opt.has_alt) {
        // No --match: this hits everything. Say so plainly, because a redirect or
        // a block applied to all traffic can take the machine off the network
        // before the first record is written.
        std::printf("Answering EVERY connection with %s (no --match given).\n",
                    pmkext::ToString(opt.alt_verdict));
        if (opt.alt_verdict != pmkext::Verdict::Accept &&
            opt.alt_verdict != pmkext::Verdict::PermanentAccept) {
            std::printf("WARNING: this applies to all traffic on this machine and may\n"
                        "         cut network access, including remote sessions.\n");
            if (opt.duration_s == 0) {
                std::printf("         No --duration given: the run only ends on Ctrl+C,\n"
                            "         which needs a console that still works.\n");
            }
        }
    } else {
        std::printf("Answering every connection with PermanentAccept.\n");
    }
    if (opt.duration_s > 0) {
        std::printf("Running for %u second(s), then stopping.\n", opt.duration_s);
    } else {
        std::printf("Press Ctrl+C to stop, remove the service and exit.\n");
    }
    std::printf("\n");
    std::fflush(stdout);

    unsigned long long connections = 0;
    unsigned long long verdicts = 0;
    unsigned long long logs = 0;
    unsigned long long ends = 0;
    unsigned long long bandwidth_records = 0;

    pmkext::Handlers handlers;

    handlers.on_connection = [&](const pmkext::Connection& c) {
        ++connections;

        // The verdict is sent whether or not the record is displayed: filtering
        // is about output, and withholding a verdict would block the packet.
        //
        // With --match the alternate verdict applies only to that IP, optionally
        // narrowed to one port. Every other connection gets PermanentAccept, so
        // the machine stays reachable. Without --match it applies to all of them -
        // the caller asked for that explicitly and was warned at startup.
        pmkext::Verdict verdict = pmkext::Verdict::PermanentAccept;
        bool matched = false;
        if (opt.has_alt &&
            (!opt.has_match ||
             (c.RemoteIpString() == opt.alt_match_ip &&
              (!opt.has_match_port || c.remote_port == opt.alt_match_port)))) {
            verdict = opt.alt_verdict;
            matched = true;
        }

        bool verdict_ok = false;
        std::string verdict_error;
        const bool needs_verdict = opt.send_verdicts && c.id != 0;
        if (needs_verdict) {
            verdict_ok = driver.SendVerdict(c.id, verdict, verdict_error);
            if (verdict_ok) {
                ++verdicts;
            }
        }

        if (!opt.show_connections) {
            return;
        }
        if (opt.has_filter_pid && c.process_id != opt.filter_pid) {
            return;
        }
        if (opt.has_filter_protocol && c.protocol != opt.filter_protocol) {
            return;
        }

        // --filter-ip: display only connections involving the specified IP.
        if (opt.has_filter_ip) {
            const std::string remote = c.RemoteIpString();
            const std::string local = c.LocalIpString();
            const bool ip_matches = (remote == opt.filter_ip || local == opt.filter_ip);
            if (!ip_matches) {
                return;
            }
            if (opt.has_filter_port) {
                const bool port_matches = (c.remote_port == opt.filter_port || c.local_port == opt.filter_port);
                if (!port_matches) {
                    return;
                }
            }
        }

        Emit("%s[CONN %s] id=%llu pid=%llu %s proto=%u(%s) layer=%u(%s)\n"
             "          %s:%u -> %s:%u  payload=%u bytes\n",
             TimePrefix(opt.timestamps).c_str(),
             c.ipv6 ? "v6" : "v4",
             static_cast<unsigned long long>(c.id),
             static_cast<unsigned long long>(c.process_id),
             pmkext::DirectionToString(c.direction),
             static_cast<unsigned>(c.protocol), pmkext::ProtocolToString(c.protocol),
             static_cast<unsigned>(c.payload_layer),
             pmkext::PayloadLayerToString(c.payload_layer),
             c.LocalIpString().c_str(), static_cast<unsigned>(c.local_port),
             c.RemoteIpString().c_str(), static_cast<unsigned>(c.remote_port),
             static_cast<unsigned>(c.payload_size));

        if (opt.show_payload) {
            if (c.payload.empty()) {
                Emit("          payload: (none)\n");
            } else {
                // One unbroken line: it is meant to be pasted into a decoder, and
                // wrapping would have to be undone by hand. The byte count is
                // printed when it differs from payload_size, so a truncated record
                // is not mistaken for a short packet.
                if (c.payload.size() == c.payload_size) {
                    Emit("          payload: %s\n", c.PayloadHexString().c_str());
                } else {
                    Emit("          payload (%zu of %u bytes): %s\n",
                         c.payload.size(), static_cast<unsigned>(c.payload_size),
                         c.PayloadHexString().c_str());
                }
            }
        }

        // id 0 is never a valid pending packet (id_cache.rs:26 starts at 1).
        if (c.id == 0) {
            Emit("          (no pending packet, no verdict needed)\n");
        } else if (!opt.send_verdicts) {
            Emit("          -> no verdict sent (--no-verdicts)\n");
        } else if (verdict_ok) {
            // The marker only means something when --match narrowed the target.
            // Without it every connection matches, so flagging them all would be
            // noise.
            Emit("          -> verdict %s sent%s\n", pmkext::ToString(verdict),
                 (matched && opt.has_match) ? "  <== MATCHED" : "");
        } else {
            Emit("          -> verdict FAILED: %s\n", verdict_error.c_str());
        }
    };

    handlers.on_connection_end = [&](const pmkext::ConnectionEnd& e) {
        ++ends;
        if (!opt.show_ends) {
            return;
        }
        if (opt.has_filter_pid && e.process_id != opt.filter_pid) {
            return;
        }
        if (opt.has_filter_protocol && e.protocol != opt.filter_protocol) {
            return;
        }

        // --filter-ip: display only connection ends involving the specified IP.
        if (opt.has_filter_ip) {
            const std::string remote = e.RemoteIpString();
            const std::string local = e.LocalIpString();
            const bool ip_matches = (remote == opt.filter_ip || local == opt.filter_ip);
            if (!ip_matches) {
                return;
            }
            if (opt.has_filter_port) {
                const bool port_matches = (e.remote_port == opt.filter_port || e.local_port == opt.filter_port);
                if (!port_matches) {
                    return;
                }
            }
        }

        Emit("%s[END  %s] pid=%llu %s proto=%u(%s) %s:%u -> %s:%u\n",
             TimePrefix(opt.timestamps).c_str(),
             e.ipv6 ? "v6" : "v4",
             static_cast<unsigned long long>(e.process_id),
             pmkext::DirectionToString(e.direction),
             static_cast<unsigned>(e.protocol),
             pmkext::ProtocolToString(e.protocol),
             e.LocalIpString().c_str(), static_cast<unsigned>(e.local_port),
             e.RemoteIpString().c_str(), static_cast<unsigned>(e.remote_port));
    };

    handlers.on_log = [&](const pmkext::LogLine& line) {
        ++logs;
        if (!opt.show_logs) {
            return;
        }
        Emit("%s[LOG %-5s] %s\n", TimePrefix(opt.timestamps).c_str(),
             pmkext::ToString(line.severity), line.message.c_str());
    };

    handlers.on_bandwidth = [&](const pmkext::BandwidthStats& stats) {
        ++bandwidth_records;
        if (!opt.show_bandwidth) {
            return;
        }
        // Bandwidth wire records are aggregated by tuple and protocol and contain
        // no PID, so they cannot satisfy a PID display filter.
        if (opt.has_filter_pid) {
            return;
        }
        if (opt.has_filter_protocol && stats.protocol != opt.filter_protocol) {
            return;
        }

        // --filter-ip: keep only entries involving the specified IP. Counted in
        // a first pass so the header reports the number of rows that follow
        // rather than the number the driver sent.
        auto keep = [&](const auto& e) {
            if (!opt.has_filter_ip) {
                return true;
            }
            if (e.RemoteIpString() != opt.filter_ip &&
                e.LocalIpString() != opt.filter_ip) {
                return false;
            }
            if (opt.has_filter_port && e.remote_port != opt.filter_port &&
                e.local_port != opt.filter_port) {
                return false;
            }
            return true;
        };

        size_t shown = 0;
        for (const auto& e : stats.entries) {
            if (keep(e)) {
                ++shown;
            }
        }
        // A record whose every entry was filtered out carries no information, so
        // it is dropped entirely. Without a filter an empty record is still
        // printed - that is the driver reporting no traffic, which is a fact.
        if (opt.has_filter_ip && shown == 0) {
            return;
        }

        Emit("%s[BANDWIDTH] proto=%u(%s) entries=%zu\n",
             TimePrefix(opt.timestamps).c_str(),
             static_cast<unsigned>(stats.protocol),
             pmkext::ProtocolToString(stats.protocol),
             shown);
        for (const auto& e : stats.entries) {
            if (!keep(e)) {
                continue;
            }
            Emit("            %s:%u <-> %s:%u  tx=%llu rx=%llu\n",
                 e.LocalIpString().c_str(), static_cast<unsigned>(e.local_port),
                 e.RemoteIpString().c_str(), static_cast<unsigned>(e.remote_port),
                 static_cast<unsigned long long>(e.transmitted_bytes),
                 static_cast<unsigned long long>(e.received_bytes));
        }
    };

    handlers.on_warning = [](const std::string& message) {
        Emit("[WARN] %s\n", message.c_str());
    };

    // Deadline for --duration, evaluated from the poll callback. Run() has no
    // timeout of its own, and the reader thread is blocked inside the driver, so
    // the poll cadence is the only place that reliably regains control.
    const ULONGLONG deadline =
        (opt.duration_s > 0) ? GetTickCount64() + opt.duration_s * 1000ULL : 0;

    // Match the production Portmaster worker: stale connection, ICMP and endpoint
    // observations are swept by a userspace command every 30 seconds. Without this,
    // a standalone kext_monitor stress run never asks the driver to clean anything,
    // so ConnectionCache entries remain allocated regardless of their age.
    constexpr ULONGLONG kCleanupIntervalMs = 30'000;
    ULONGLONG next_cleanup_at = GetTickCount64() + kCleanupIntervalMs;

    // The driver only emits logs and bandwidth stats when asked. Run() invokes
    // this once per poll interval from its own thread, so no extra thread touches
    // the device and the cadence is independent of event traffic.
    handlers.on_poll = [&]() {
        // Skip once shutdown is under way: the driver has run down its queue and
        // further commands would only produce noise.
        if (g_shutdown_requested.load()) {
            return;
        }

        std::string err;
        const ULONGLONG now = GetTickCount64();
        if (now >= next_cleanup_at) {
            if (!driver.RequestCleanEndedConnections(err)) {
                Emit("[WARN] CleanEndedConnections failed: %s\n", err.c_str());
            }
            next_cleanup_at = now + kCleanupIntervalMs;
        }

        // Run cleanup first so memory statistics from the same poll show the
        // post-sweep cache sizes.
        if (opt.memory_stats && !driver.RequestMemoryStats(err)) {
            Emit("[WARN] PrintMemoryStats failed: %s\n", err.c_str());
        }
        // Request logs after memory statistics so that the records produced by
        // PrintMemoryStats are included in this same poll.
        if (!driver.RequestLogs(err)) {
            Emit("[WARN] GetLogs failed: %s\n", err.c_str());
        }
        if (!driver.RequestBandwidthStats(err)) {
            Emit("[WARN] GetBandwidthStats failed: %s\n", err.c_str());
        }

        if (deadline != 0 && GetTickCount64() >= deadline) {
            // Give the driver a moment to answer the requests just issued, so the
            // final poll's logs and stats are not lost to the shutdown.
            Sleep(300);
            g_shutdown_requested.store(true);
            Emit("\nDuration elapsed, stopping...\n");
            driver.Stop();
        }
    };

    driver.Run(handlers, opt.poll_ms);

    g_shutdown_requested.store(true);

    std::printf("\nShutting down.\n");
    std::printf("Connections: %llu (verdicts sent: %llu), ends: %llu, "
                "log lines: %llu, bandwidth records: %llu\n",
                connections, verdicts, ends, logs, bandwidth_records);

    // Stop() already sent the Shutdown command, which is what released the
    // reader; the driver has resolved its pending packets by now
    // (device.rs:312). No second shutdown is needed here.

    // Cleanup() closes the handle, stops the service and deletes it. It also
    // runs from the destructor, but call it here so the result is visible
    // before the process exits.
    driver.Cleanup();
    g_driver = nullptr;
    std::printf("Device closed; owned service state cleaned up.\n");

    if (g_out != nullptr && g_out != stdout) {
        std::fclose(g_out);
    }
    return 0;
}
