"""Bounded Windows UDP ALE lifecycle regression (requires Administrator).

Keeps an isolated loopback listener open after short-lived client processes exit,
observes native idle cleanup, reuses an exact tuple, and finally closes only its
own listener. Native idle expiry is deliberately not treated as a precise timer.
"""

import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
import time


ROOT = Path(__file__).resolve().parents[2]
CLIENT = """
import json, os, socket, sys
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(('127.0.0.1', int(sys.argv[2])))
    sock.settimeout(5)
    payload = b'udp-idle-lifecycle-regression'
    sock.sendto(payload, ('127.0.0.2', int(sys.argv[1])))
    assert sock.recvfrom(1024)[0] == payload
    print(json.dumps({'pid': os.getpid(), 'port': sock.getsockname()[1]}))
"""


def driver_owners():
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command",
         "$ErrorActionPreference = 'Stop'; "
         "Get-Process | Where-Object ProcessName -eq kext_monitor | "
         "ForEach-Object { 'monitor=' + $_.Id }; "
         "[System.ServiceProcess.ServiceController]::GetServices() | "
         "Where-Object ServiceName -eq PortmasterKext | "
         "ForEach-Object { 'service=' + $_.Status }; exit 0"],
        capture_output=True, timeout=30,
    )
    if result.returncode:
        raise RuntimeError(f"could not inspect driver ownership: {result.stderr.decode(errors='replace')}")
    return result.stdout.decode(errors="replace").strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--monitor", type=Path,
                        default=ROOT / "kext_client/build/kext_monitor.exe")
    parser.add_argument("--driver", type=Path,
                        default=ROOT / "windows_kext/portmaster-kext.sys")
    parser.add_argument("--idle-seconds", type=int, default=90)
    parser.add_argument("--verdict", choices=("accept",),
                        help="use temporary Accept only for the test endpoint")
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).parent / "_out/udp_flow_idle")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("this test requires Windows")
    if not 65 <= args.idle_seconds <= 300:
        parser.error("--idle-seconds must be between 65 and 300")
    for binary in (args.monitor, args.driver):
        if not binary.is_file():
            parser.error(f"binary does not exist: {binary}")
    owners = driver_owners()
    if owners:
        raise RuntimeError(f"refusing to interfere with an existing driver owner: {owners}")

    args.output.mkdir(parents=True, exist_ok=True)
    records = args.output / "records.log"
    console = args.output / "console.log"
    result_path = args.output / "result.json"
    # Leave prior evidence intact rather than silently overwriting it.
    for path in (records, console, result_path):
        if path.exists():
            raise RuntimeError(f"choose a fresh --output directory: {path}")

    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.2", 0))
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    stopped = threading.Event()
    server_errors = []

    def serve():
        while not stopped.is_set():
            try:
                payload, peer = listener.recvfrom(1024)
                listener.sendto(payload, peer)
            except socket.timeout:
                continue
            except OSError as error:
                if not stopped.is_set():
                    server_errors.append(str(error))
                return

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    monitor = None
    clients = []
    phases = []
    started = time.monotonic()
    endpoint = f"127.0.0.2:{port}"
    server_pid = os.getpid()

    def text():
        return records.read_text(encoding="utf-8", errors="replace") if records.exists() else ""

    def observe(label):
        data = text()
        ends = re.findall(
            rf"\[END\s+v4\] pid={server_pid} inbound proto=17\(UDP\) "
            rf"{re.escape(endpoint)} -> 127\.0\.0\.1:(\d+)", data,
        )
        connections = re.findall(
            rf"\[CONN v4\].*pid={server_pid} inbound proto=17\(UDP\).*\r?\n"
            rf"\s+{re.escape(endpoint)} -> 127\.0\.0\.1:(\d+)", data,
        )
        phase = {"phase": label, "seconds": round(time.monotonic() - started, 2),
                 "server_connections": connections, "server_ends": ends}
        phases.append(phase)
        print(json.dumps(phase), flush=True)
        return phase

    def send(local_port=0):
        process = subprocess.run(
            [sys.executable, "-c", CLIENT, str(port), str(local_port)],
            capture_output=True, text=True, timeout=12,
        )
        if process.returncode:
            raise RuntimeError(f"UDP child failed: {process.stdout}\n{process.stderr}")
        client = json.loads(process.stdout)
        clients.append(client)
        return client

    def close_listener():
        stopped.set()
        worker.join(timeout=2)
        listener.close()
        if worker.is_alive():
            raise RuntimeError("UDP listener thread did not stop")

    try:
        with console.open("w", encoding="utf-8") as output:
            duration = args.idle_seconds + 110
            command = [str(args.monitor.resolve()), "--duration", str(duration),
                       "--poll", "1000", "--timestamps", "--memory-stats",
                       "--no-bandwidth", "--filter-ip", endpoint,
                       "--out", str(records.resolve())]
            if args.verdict:
                command += ["--verdict", args.verdict, "--match", endpoint]
            command.append(str(args.driver.resolve()))
            monitor = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
            try:
                time.sleep(4)
                if monitor.poll() is not None:
                    raise RuntimeError(f"monitor exited early: {console.read_text(errors='replace')}")
                initial = [send() for _ in range(4)]
                time.sleep(2)
                first = observe("clients_exited")
                assert set(first["server_connections"]) == {str(client["port"]) for client in initial}, first

                time.sleep(args.idle_seconds)
                observe("idle_no_new_traffic")
                reused_client = send(initial[0]["port"])
                time.sleep(2)
                observe("exact_tuple_reused")
                if args.verdict == "accept":
                    # Require the new client's decision, not a new server ALE
                    # authorization: the server flow may survive the idle period
                    # and our loopback reinjection has its own inbound fast path.
                    assert re.search(
                        rf"\[CONN v4\].*pid={reused_client['pid']} outbound proto=17\(UDP\).*\r?\n"
                        rf"\s+127\.0\.0\.1:{reused_client['port']} -> {re.escape(endpoint)}", text(),
                    ), reused_client
                for _ in range(12):
                    send()
                time.sleep(2)
                observe("fresh_peer_probe")
                close_listener()
                time.sleep(2)
                observe("listener_closed")
            finally:
                # Never terminate a monitor with an open driver handle. Its own
                # --duration closes the handle and unloads the owned service.
                code = monitor.wait(timeout=duration + 60)
                if code:
                    raise RuntimeError(f"monitor failed ({code}): {console.read_text(errors='replace')}")
    finally:
        close_listener()

    final = observe("post_grace_cleanup")
    assert not server_errors, server_errors
    assert set(final["server_ends"]) == {str(client["port"]) for client in clients}, final
    data = text()
    for client in clients:
        assert re.search(
            rf"\[END\s+v4\] pid={client['pid']} outbound proto=17\(UDP\) "
            rf"127\.0\.0\.1:{client['port']} -> {re.escape(endpoint)}", data,
        ), client
    for marker in ("Verdict invalid id", "failed to inject", "injection failed",
                   "UDP idle delete rejected", "failed to associate UDP flow"):
        assert marker not in data, marker
    owners = driver_owners()
    assert not owners, f"monitor did not release its driver: {owners}"
    result_path.write_text(json.dumps({"listener": endpoint, "server_pid": server_pid,
                                      "clients": clients, "phases": phases}, indent=2),
                           encoding="utf-8")
    print(f"PASS: {len(clients)} request/reply cycles; client and server lifecycle verified.")
    print(f"Records: {records}")


if __name__ == "__main__":
    main()
