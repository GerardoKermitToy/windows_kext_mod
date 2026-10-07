"""Bounded local TCP/UDP regression for monitor --match and --filter-ip.

Requires Windows Administrator. Each monitor exits via --duration; subsequent
cases are not started if delivery, the selected verdict, or driver logs fail.
"""
import argparse
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
DURATION = 10
CONNECTION = re.compile(
    r"\[CONN (v[46])\] id=(\d+) pid=(\d+) (\w+) proto=(\d+)\([^)]*\) layer=\d+\([^)]*\)\r?\n"
    r"\s+(\S+):(\d+) -> (\S+):(\d+)\s+payload=\d+ bytes\r?\n"
    r"\s+-> verdict (\w+) sent([^\r\n]*)"
)


def owners():
    check = subprocess.run([
        "powershell.exe", "-NoProfile", "-Command",
        "Get-Process | Where-Object ProcessName -eq kext_monitor | ForEach-Object { 'monitor=' + $_.Id }; "
        "[System.ServiceProcess.ServiceController]::GetServices() | Where-Object ServiceName -eq PortmasterKext | "
        "ForEach-Object { 'service=' + $_.Status }; exit 0",
    ], capture_output=True, text=True, timeout=20)
    if check.returncode:
        raise RuntimeError(f"driver ownership check failed: {check.stderr}")
    return check.stdout.strip()


def exchange(server, family, ip, protocol):
    errors = []
    payloads = [b"ip-match-regression" * 4, bytes(range(256))]

    def serve():
        try:
            if protocol == 6:
                with server.accept()[0] as peer:
                    peer.settimeout(3)
                    while data := peer.recv(4096):
                        peer.sendall(data)
            else:
                for payload in payloads:
                    data, peer = server.recvfrom(4096)
                    assert data == payload, "server received incorrect UDP payload"
                    server.sendto(data, peer)
        except Exception:
            errors.append(traceback.format_exc())

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        kind = socket.SOCK_STREAM if protocol == 6 else socket.SOCK_DGRAM
        with socket.socket(family, kind) as client:
            client.settimeout(3)
            client.bind((ip, 0))
            client_port = client.getsockname()[1]
            destination = (ip, server.getsockname()[1])
            if protocol == 6:
                client.connect(destination)
            for payload in payloads:
                if protocol == 6:
                    client.sendall(payload)
                    received = bytearray()
                    while len(received) < len(payload):
                        chunk = client.recv(len(payload) - len(received))
                        assert chunk, "unexpected TCP EOF"
                        received.extend(chunk)
                else:
                    assert client.sendto(payload, destination) == len(payload)
                    received, peer = client.recvfrom(4096)
                    assert ipaddress.ip_address(peer[0]) == ipaddress.ip_address(ip)
                    assert peer[1] == destination[1]
                assert received == payload, "echo payload mismatch"
            if protocol == 6:
                client.shutdown(socket.SHUT_WR)
                assert client.recv(1) == b"", "missing graceful TCP EOF"
        worker.join(4)
        assert not worker.is_alive() and not errors, f"echo worker failed: {errors}"
        return client_port
    finally:
        if worker.is_alive():
            server.close()
            worker.join(4)


def verify(records, ip, protocol, client_port, server_port, address_matches, port_match):
    data = records.read_text(encoding="utf-8", errors="replace")
    problems = [line for line in data.splitlines()
                if re.search(r"\[LOG\s+(?:ERROR|WARN|CRIT)|\[WARN\]|verdict FAILED", line)]
    assert not problems, f"driver diagnostics: {problems}"
    selected = []
    for event in CONNECTION.finditer(data):
        family, request, pid, direction, proto, local, lp, remote, rp, verdict, marker = event.groups()
        if int(proto) != protocol or {int(lp), int(rp)} != {client_port, server_port}:
            continue
        assert int(pid) == os.getpid() and int(request) > 0, "incorrect event PID or request ID"
        assert ipaddress.ip_address(local) == ipaddress.ip_address(ip)
        assert ipaddress.ip_address(remote) == ipaddress.ip_address(ip)
        matched = address_matches and (not port_match or int(rp) == server_port)
        expected = "Accept" if matched else "PermanentAccept"
        assert verdict == expected, f"id={request}: expected {expected}, got {verdict}"
        assert ("MATCHED" in marker) == matched, f"id={request}: incorrect match marker"
        selected.append(dict(id=int(request), direction=direction, verdict=verdict, matched=matched))
    assert any(e["direction"] == "outbound" for e in selected), "missing outbound connection record"
    assert any(e["direction"] == "inbound" for e in selected), "missing inbound connection record"
    return selected


def run_case(args, name, family, ip, match, display_filter, address_matches=True, port_match=False):
    folder = args.output / name
    folder.mkdir(parents=True)
    console = folder / "console.log"
    records = folder / "records.log"
    tcp = socket.socket(family, socket.SOCK_STREAM)
    udp = socket.socket(family, socket.SOCK_DGRAM)
    monitor = None
    failure = None
    checks = []
    command = []
    code = None
    try:
        tcp.bind((ip, 0))
        port = tcp.getsockname()[1]
        tcp.listen(1)
        tcp.settimeout(3)
        udp.bind((ip, port))
        udp.settimeout(3)
        command = [str(args.monitor.resolve()), "--duration", str(DURATION), "--poll", "200",
                   "--timestamps", "--no-bandwidth", "--filter-pid", str(os.getpid()),
                   "--filter-ip", display_filter.format(port=port), "--out", str(records.resolve()),
                   "--verdict", "accept", "--match", match.format(port=port), str(args.driver.resolve())]
        with console.open("w", encoding="utf-8") as output:
            monitor = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 6
                while f"Running for {DURATION} second(s)" not in console.read_text(errors="replace"):
                    if monitor.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("monitor did not start: " + console.read_text(errors="replace"))
                    time.sleep(0.1)
                for server, protocol in ((tcp, 6), (udp, 17)):
                    assert monitor.poll() is None, "monitor ended before next protocol test"
                    client_port = exchange(server, family, ip, protocol)
                    time.sleep(0.2)
                    events = verify(records, ip, protocol, client_port, port, address_matches, port_match)
                    checks.append(dict(protocol=protocol, client_port=client_port, server_port=port, events=events))
            except Exception:
                failure = traceback.format_exc()
            finally:
                tcp.close()
                udp.close()
                code = monitor.wait(timeout=DURATION + 30)
        assert code == 0, f"monitor exited with {code}"
        if not failure:
            for check in checks:
                verify(records, ip, check["protocol"], check["client_port"], check["server_port"],
                       address_matches, port_match)
    except Exception:
        failure = failure or traceback.format_exc()
    finally:
        tcp.close()
        udp.close()
    remaining = owners()
    failure = failure or (f"driver owner remains: {remaining}" if remaining else None)
    result = dict(name=name, command=command, monitor_exit=code, checks=checks, failure=failure,
                  owners_after=remaining)
    (folder / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    if failure:
        raise RuntimeError(f"STOP: {name}; no further test cases.\n{failure}\nEvidence: {folder}")
    print(f"PASS: {name}; TCP/UDP delivery, selected verdicts and display filter verified", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--monitor", type=Path, default=ROOT / "kext_client/build/kext_monitor.exe")
    parser.add_argument("--driver", type=Path, default=ROOT / "windows_kext/portmaster-kext.sys")
    parser.add_argument("--output", type=Path,
                        default=ROOT / "windows_kext/test/_out" / ("ip_match_fix_" + datetime.now().strftime("%Y%m%d_%H%M%S")))
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("requires Windows")
    for binary in (args.monitor, args.driver):
        if not binary.is_file():
            parser.error(f"missing binary: {binary}")
    existing = owners()
    if existing:
        raise RuntimeError(f"refusing to interfere with existing driver owner: {existing}")
    args.output.mkdir(parents=True, exist_ok=False)
    cases = [
        ("ipv6_compressed", socket.AF_INET6, "::1", "::1", "::1"),
        ("ipv6_expanded", socket.AF_INET6, "::1", "0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:1"),
        ("ipv6_port", socket.AF_INET6, "::1", "[::1]:{port}", "[::1]:{port}", True, True),
        ("ipv6_nonmatching", socket.AF_INET6, "::1", "::2", "::1", False),
        ("ipv4", socket.AF_INET, "127.0.0.1", "127.0.0.1", "127.0.0.1"),
        ("ipv4_port", socket.AF_INET, "127.0.0.1", "127.0.0.1:{port}", "127.0.0.1:{port}", True, True),
    ]
    results = []
    for case in cases:
        print(f"START: {case[0]}", flush=True)
        results.append(run_case(args, *case))
    (args.output / "result.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"PASS: {len(cases)} cases / {len(cases) * 2} TCP/UDP exchanges. Evidence: {args.output}", flush=True)


if __name__ == "__main__":
    main()
