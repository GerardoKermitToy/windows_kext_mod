"""Bounded local UDP burst/completion regression (requires Administrator).

Checks every datagram, PID/tuple/END records and delayed injection diagnostics.
The monitor always owns its service and exits through --duration, even on failure.
"""
import argparse
import ctypes
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
CLIENT = r'''
import json, os, socket, sys, time
c = json.loads(sys.argv[1])
f = socket.AF_INET6 if c['ipv6'] else socket.AF_INET
with socket.socket(f, socket.SOCK_DGRAM) as s:
    s.settimeout(5)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
    if c['reuse']:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((c['local'], c['port']))
    meta = dict(pid=os.getpid(), port=s.getsockname()[1], iteration=c['iteration'])
    peer = (c['remote'], c['server_port'])
    payloads = [c['iteration'].to_bytes(4, 'big') + i.to_bytes(4, 'big')
                + bytes([i % 251]) * 248 for i in range(c['count'])]
    for start in range(0, c['count'], 32):
        batch = payloads[start:start + 32]
        for payload in batch:
            assert s.sendto(payload, peer) == len(payload)
        received = []
        for _ in batch:
            data, source = s.recvfrom(65535)
            assert source[1] == c['server_port'], source
            received.append(data)
        assert sorted(received) == sorted(batch), 'lost, duplicated or changed datagram'
    if c['close_delay']:
        s.settimeout(c['close_delay'])
        try:
            extra = s.recvfrom(65535)
        except socket.timeout:
            pass
        else:
            raise AssertionError('unexpected extra datagram: ' + repr(extra))
print(json.dumps(meta), flush=True)
'''
CONN = re.compile(
    r'\[CONN v[46]\] id=(\d+) pid=(\d+) (\w+) proto=17\(UDP\) layer=\d+\([^)]*\)\r?\n'
    r'\s+(\S+):(\d+) -> (\S+):(\d+)\s+payload=\d+ bytes\r?\n'
    r'(?:\s+payload: (?:[0-9a-f]+|\(none\))\r?\n)?'
    r'\s+-> verdict (\w+) sent'
)
END = re.compile(r'\[END\s+v[46]\] pid=(\d+) (\w+) proto=17\(UDP\) (\S+):(\d+) -> (\S+):(\d+)')


def owners():
    result = subprocess.run([
        'powershell.exe', '-NoProfile', '-Command',
        "Get-Process | Where-Object ProcessName -eq kext_monitor | ForEach-Object { 'monitor=' + $_.Id }; "
        "([System.ServiceProcess.ServiceController]::GetServices() + "
        "[System.ServiceProcess.ServiceController]::GetDevices()) | Where-Object ServiceName -eq PortmasterKext | "
        "ForEach-Object { 'service=' + $_.Status }; exit 0",
    ], capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError('driver ownership check failed: ' + result.stderr)
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ipv6', action='store_true')
    parser.add_argument('--repeats', type=int, default=8)
    parser.add_argument('--count', type=int, choices=(32, 128, 256), default=128)
    parser.add_argument('--reuse-port', action='store_true')
    parser.add_argument('--close-delay', type=float, default=0)
    parser.add_argument('--verdict', choices=('permanent', 'accept-client', 'accept-both'), default='permanent')
    parser.add_argument('--monitor', type=Path, default=ROOT / 'kext_client/build/kext_monitor.exe')
    parser.add_argument('--driver', type=Path, default=ROOT / 'windows_kext/portmaster-kext.sys')
    parser.add_argument('--output', type=Path,
                        default=Path(__file__).parent / '_out' / ('udp_burst_' + datetime.now().strftime('%Y%m%d_%H%M%S')))
    args = parser.parse_args()
    if os.name != 'nt' or not 1 <= args.repeats <= 20 or not 0 <= args.close_delay <= 1:
        parser.error('requires Windows, --repeats between 1 and 20, and --close-delay between 0 and 1')
    if not ctypes.windll.shell32.IsUserAnAdmin():
        parser.error('requires Administrator')
    for binary in (args.monitor, args.driver):
        if not binary.is_file():
            parser.error(f'missing binary: {binary}')
    existing = owners()
    if existing:
        raise RuntimeError('refusing to interfere with driver owner: ' + existing)
    args.output.mkdir(parents=True, exist_ok=False)
    records = args.output / 'records.log'
    console = args.output / 'console.log'
    family = socket.AF_INET6 if args.ipv6 else socket.AF_INET
    local = '::1' if args.ipv6 else '127.0.0.1'
    remote = local if args.verdict == 'accept-both' else ('::1' if args.ipv6 else '127.0.0.2')
    server = socket.socket(family, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
    server.bind((remote, 0))
    server.settimeout(0.1)
    port = server.getsockname()[1]
    stopped = threading.Event()
    deliveries = []
    server_errors = []
    lock = threading.Lock()

    def serve():
        try:
            while not stopped.is_set():
                try:
                    data, peer = server.recvfrom(65535)
                except socket.timeout:
                    continue
                assert len(data) == 256, f'incorrect server datagram length: {len(data)}'
                iteration = int.from_bytes(data[:4], 'big')
                sequence = int.from_bytes(data[4:8], 'big')
                assert data[8:] == bytes([sequence % 251]) * 248, 'incorrect server datagram payload'
                with lock:
                    deliveries.append(dict(iteration=iteration, sequence=sequence, port=peer[1]))
                assert server.sendto(data, peer) == len(data)
        except Exception:
            if not stopped.is_set():
                server_errors.append(traceback.format_exc())

    def text():
        return records.read_text(encoding='utf-8', errors='replace') if records.exists() else ''

    def diagnostics():
        return [line for line in text().splitlines()
                if re.search(r'\[LOG\s+(?:ERROR|WARN|CRIT)|\[WARN\]|verdict FAILED', line)]

    def events(offset=0):
        connections, ends = [], []
        for match in CONN.finditer(text()[offset:]):
            request, pid, direction, lip, lp, rip, rp, verdict = match.groups()
            connections.append(dict(id=int(request), pid=int(pid), direction=direction, verdict=verdict,
                local=str(ipaddress.ip_address(lip)), lp=int(lp), remote=str(ipaddress.ip_address(rip)), rp=int(rp)))
        for match in END.finditer(text()[offset:]):
            pid, direction, lip, lp, rip, rp = match.groups()
            ends.append(dict(pid=int(pid), direction=direction, local=str(ipaddress.ip_address(lip)),
                             lp=int(lp), remote=str(ipaddress.ip_address(rip)), rp=int(rp)))
        return connections, ends

    def matches(event, direction, lip, lp, rip, rp):
        return all(event[key] == value for key, value in dict(direction=direction, local=lip, lp=lp,
                                                             remote=rip, rp=rp).items())

    def verify_client(meta, offset):
        deadline = time.monotonic() + 2.5
        while True:
            connections, ends = events(offset)
            client_ends = [event for event in ends if matches(event, 'outbound', local, meta['port'], remote, port)]
            if client_ends or time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        client_connections = [event for event in connections
                              if matches(event, 'outbound', local, meta['port'], remote, port)]
        assert client_connections and all(event['pid'] == meta['pid'] and event['id'] > 0
                                          for event in client_connections), client_connections
        expected_verdict = 'PermanentAccept' if args.verdict == 'permanent' else 'Accept'
        assert all(event['verdict'] == expected_verdict for event in client_connections), client_connections
        assert len(client_ends) == 1 and client_ends[0]['pid'] == meta['pid'], client_ends
        _, all_ends = events()
        assert not any(matches(event, 'inbound', remote, port, local, meta['port']) for event in all_ends), 'live listener ended'
        return dict(connections=client_connections, ends=client_ends)

    duration = args.repeats * 3 + 10
    command = [str(args.monitor.resolve()), '--duration', str(duration), '--poll', '200', '--timestamps',
               '--payload', '--no-bandwidth', '--filter-ip', remote, '--out', str(records.resolve())]
    if args.verdict != 'permanent':
        endpoint = (f'[{remote}]:{port}' if args.ipv6 else f'{remote}:{port}')
        command += ['--verdict', 'accept', '--match', remote if args.verdict == 'accept-both' else endpoint]
    command.append(str(args.driver.resolve()))
    cases = []
    failure = None
    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    with console.open('w', encoding='utf-8') as output:
        monitor = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 8
            while f'Running for {duration} second(s)' not in console.read_text(errors='replace'):
                if monitor.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('monitor failed to start: ' + console.read_text(errors='replace'))
                time.sleep(0.1)
            local_port = 0
            for index in range(args.repeats):
                assert monitor.poll() is None, 'monitor duration ended during test'
                assert not diagnostics(), diagnostics()
                offset = len(text())
                recipe = dict(ipv6=args.ipv6, local=local, remote=remote, server_port=port,
                              port=local_port if args.reuse_port else 0, reuse=args.reuse_port,
                              iteration=index, count=args.count, close_delay=args.close_delay)
                child = subprocess.run([sys.executable, '-u', '-c', CLIENT, json.dumps(recipe)],
                                       capture_output=True, text=True, timeout=12)
                assert child.returncode == 0, f'client failed: {child.stdout}\n{child.stderr}'
                meta = json.loads(child.stdout)
                local_port = meta['port']
                case = dict(index=index, client=meta)
                cases.append(case)
                # Logs are flushed on poll, not when the kernel status occurs.
                # Wait through two polls before declaring an iteration successful.
                time.sleep(0.45)
                with lock:
                    batch = [item for item in deliveries if item['iteration'] == index]
                assert len(batch) == args.count and sorted(item['sequence'] for item in batch) == list(range(args.count)), batch
                assert all(item['port'] == meta['port'] for item in batch), batch
                assert not server_errors and not diagnostics(), server_errors + diagnostics()
                case.update(verify_client(meta, offset))
                print(f'PASS {index + 1}/{args.repeats}: PID {meta["pid"]}, port {meta["port"]}, '
                      f'{args.count} exact datagrams, correct client END, no injection diagnostics', flush=True)
        except Exception:
            failure = traceback.format_exc()
            print('STOP: first failure, no further clients.\n' + failure, flush=True)
        finally:
            stopped.set()
            worker.join(1)
            server.close()
            worker.join(3)
            code = monitor.wait(timeout=duration + 60)

    if not failure:
        try:
            connections, ends = events()
            for client_port in {case['client']['port'] for case in cases}:
                server_connections = [event for event in connections
                                      if matches(event, 'inbound', remote, port, local, client_port)]
                server_ends = [event for event in ends
                               if matches(event, 'inbound', remote, port, local, client_port)]
                assert server_connections and all(event['pid'] == os.getpid() for event in server_connections), server_connections
                expected_verdict = 'Accept' if args.verdict == 'accept-both' else 'PermanentAccept'
                assert all(event['verdict'] == expected_verdict for event in server_connections), server_connections
                assert len(server_ends) == 1 and server_ends[0]['pid'] == os.getpid(), server_ends
        except Exception:
            failure = traceback.format_exc()
    remaining = owners()
    result = dict(command=command, server_pid=os.getpid(), server_port=port, cases=cases, deliveries=deliveries,
                  failure=failure, monitor_exit=code, owners_after=remaining, driver_diagnostics=diagnostics(),
                  server_errors=server_errors, live_worker=worker.is_alive())
    (args.output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(f'Completed {len(cases)}/{args.repeats}; monitor exit {code}; owners={remaining!r}; '
          f'evidence={args.output}', flush=True)
    if failure:
        print(failure, flush=True)
    return 1 if failure or code or remaining or diagnostics() or server_errors or worker.is_alive() else 0


if __name__ == '__main__':
    sys.exit(main())
