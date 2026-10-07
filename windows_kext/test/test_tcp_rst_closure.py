"""Bounded local TCP abortive-close regression (requires Administrator).

Checks reset delivery, PID/tuple/END records, exact-tuple reuse, and absence of
RST verdict requests. The monitor unloads through --duration even on failure.
"""
import argparse
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
CLIENT = r'''
import json, os, socket, struct, sys, time
c = json.loads(sys.argv[1])
f = socket.AF_INET6 if c['ipv6'] else socket.AF_INET
with socket.socket(f, socket.SOCK_STREAM) as s:
    s.settimeout(4)
    if c['reuse']:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((c['local'], c['port']))
    s.connect((c['remote'], c['server_port']))
    payload = c['tag'].encode()
    s.sendall(struct.pack('!I', len(payload)) + payload)
    received = bytearray()
    while len(received) < len(payload):
        part = s.recv(len(payload) - len(received))
        assert part, 'unexpected EOF before echo'
        received.extend(part)
    assert received == payload, 'echo payload mismatch'
    meta = dict(pid=os.getpid(), port=s.getsockname()[1])
    if c['reset_side'] == 'server':
        s.sendall(b'!')
        try:
            meta['status'] = 'EOF' if not s.recv(1) else 'DATA'
        except ConnectionResetError as error:
            meta.update(status='RESET', winerror=error.winerror)
        meta['reset_at'] = time.monotonic()
    else:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('HH', 1, 0))
        meta['closing'] = time.monotonic()
    print(json.dumps(meta), flush=True)
'''
END = re.compile(r"\[END\s+v[46]\] pid=(\d+) (\w+) proto=6\(TCP\) (\S+):(\d+) -> (\S+):(\d+)")
CONN = re.compile(
    r"\[CONN v[46]\] id=(?P<id>\d+) pid=(?P<pid>\d+) (?P<direction>\w+) proto=6\(TCP\) "
    r"layer=(?P<layer>\d+)\([^)]*\)\r?\n"
    r"\s+(?P<local>\S+):(?P<lp>\d+) -> (?P<remote>\S+):(?P<rp>\d+)\s+payload=\d+ bytes\r?\n"
    r"\s+payload: (?P<payload>[0-9a-f]+|\(none\))\r?\n\s+-> verdict (?P<verdict>\w+) sent"
)


def owners():
    result = subprocess.run([
        'powershell.exe', '-NoProfile', '-Command',
        "Get-Process | Where-Object ProcessName -eq kext_monitor | ForEach-Object { 'monitor=' + $_.Id }; "
        "[System.ServiceProcess.ServiceController]::GetServices() | Where-Object ServiceName -eq PortmasterKext | "
        "ForEach-Object { 'service=' + $_.Status }; exit 0",
    ], capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError('driver ownership check failed: ' + result.stderr)
    return result.stdout.strip()


def receive_exact(peer, count):
    data = bytearray()
    while len(data) < count:
        part = peer.recv(count - len(data))
        if not part:
            raise RuntimeError('unexpected server EOF')
        data.extend(part)
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ipv6', action='store_true')
    parser.add_argument('--repeats', type=int, default=10)
    parser.add_argument('--reuse-port', action='store_true')
    parser.add_argument('--reset-side', choices=('client', 'server'), default='client')
    parser.add_argument('--verdict', choices=('accept-client', 'accept-both', 'permanent'), default='accept-client')
    parser.add_argument('--monitor', type=Path, default=ROOT / 'kext_client/build/kext_monitor.exe')
    parser.add_argument('--driver', type=Path, default=ROOT / 'windows_kext/portmaster-kext.sys')
    parser.add_argument('--output', type=Path,
                        default=Path(__file__).parent / '_out' / ('tcp_rst_' + datetime.now().strftime('%Y%m%d_%H%M%S')))
    args = parser.parse_args()
    if os.name != 'nt' or not 1 <= args.repeats <= 50:
        parser.error('requires Windows and --repeats between 1 and 50')
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
    server = socket.socket(family, socket.SOCK_STREAM)
    server.bind((remote, 0))
    server.listen(8)
    server.settimeout(0.2)
    port = server.getsockname()[1]
    stopped = threading.Event()
    observations = queue.Queue()

    def serve():
        while not stopped.is_set():
            try:
                peer, address = server.accept()
            except socket.timeout:
                continue
            except OSError:
                if stopped.is_set():
                    return
                raise
            observation = dict(local_port=port, remote_port=address[1])
            try:
                with peer:
                    peer.settimeout(3)
                    size = int.from_bytes(receive_exact(peer, 4), 'big')
                    payload = receive_exact(peer, size)
                    observation['tag'] = payload.decode()
                    peer.sendall(payload)
                    if args.reset_side == 'server':
                        assert receive_exact(peer, 1) == b'!'
                        peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('HH', 1, 0))
                        observation.update(status='SENT_RESET', reset_at=time.monotonic())
                    else:
                        try:
                            data = peer.recv(1)
                            observation.update(status='EOF' if not data else 'DATA', reset_at=time.monotonic())
                        except ConnectionResetError as error:
                            observation.update(status='RESET', winerror=error.winerror, reset_at=time.monotonic())
                        except socket.timeout:
                            observation.update(status='TIMEOUT', reset_at=time.monotonic())
            except Exception:
                observation.update(status='ERROR', traceback=traceback.format_exc())
            observations.put(observation)

    def text():
        return records.read_text(encoding='utf-8', errors='replace') if records.exists() else ''

    def verify_events(meta, offset):
        deadline = time.monotonic() + 2.5
        while True:
            data = text()[offset:]
            ends = []
            for event in END.finditer(data):
                pid, direction, lip, lp, rip, rp = event.groups()
                if {int(lp), int(rp)} == {meta['port'], port}:
                    ends.append(dict(pid=int(pid), direction=direction, local=str(ipaddress.ip_address(lip)),
                                     lp=int(lp), remote=str(ipaddress.ip_address(rip)), rp=int(rp)))
            if len(ends) >= 2 or time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        for pid, direction, lip, lp, rip, rp in (
            (meta['pid'], 'outbound', local, meta['port'], remote, port),
            (os.getpid(), 'inbound', remote, port, local, meta['port']),
        ):
            expected = dict(pid=pid, direction=direction, local=lip, lp=lp, remote=rip, rp=rp)
            assert ends.count(expected) == 1, f'incorrect END, expected {expected}, got {ends}'
            connections = [event.groupdict() for event in CONN.finditer(data)
                           if int(event['lp']) == lp and int(event['rp']) == rp
                           and event['direction'] == direction]
            assert connections, f'missing {direction} CONN'
            assert all(int(event['pid']) == pid for event in connections), f'incorrect CONN PID: {connections}'
            assert all(str(ipaddress.ip_address(event['local'])) == lip
                       and str(ipaddress.ip_address(event['remote'])) == rip for event in connections)
        resets = []
        for event in CONN.finditer(data):
            if {int(event['lp']), int(event['rp'])} != {meta['port'], port} or event['payload'] == '(none)':
                continue
            packet = bytes.fromhex(event['payload'])
            tcp_offset = (40 if args.ipv6 else (packet[0] & 15) * 4) if int(event['layer']) == 3 else 0
            assert len(packet) >= tcp_offset + 20, 'truncated TCP packet capture'
            if packet[tcp_offset + 13] & 4:
                resets.append(int(event['id']))
        assert not resets, f'RST was incorrectly submitted for a verdict: {resets}'
        return dict(ends=ends, rst_request_ids=resets)

    duration = args.repeats + 10
    command = [str(args.monitor.resolve()), '--duration', str(duration), '--poll', '200', '--timestamps',
               '--payload', '--no-bandwidth', '--filter-ip', remote, '--out', str(records.resolve())]
    if args.verdict != 'permanent':
        if args.verdict == 'accept-both':
            command += ['--verdict', 'accept', '--match', remote]
        else:
            endpoint = f'[{remote}]:{port}' if args.ipv6 else f'{remote}:{port}'
            command += ['--verdict', 'accept', '--match', endpoint]
    command.append(str(args.driver.resolve()))
    failure = None
    cases = []
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
                offset = len(text())
                recipe = dict(ipv6=args.ipv6, local=local, remote=remote, server_port=port,
                              port=local_port if args.reuse_port else 0, reuse=args.reuse_port,
                              reset_side=args.reset_side, tag=f'tcp-rst-{index}')
                child = subprocess.run([sys.executable, '-u', '-c', CLIENT, json.dumps(recipe)],
                                       capture_output=True, text=True, timeout=8)
                assert child.returncode == 0, f'client failed: {child.stdout}\n{child.stderr}'
                meta = json.loads(child.stdout.splitlines()[0])
                local_port = meta['port']
                observation = observations.get(timeout=5)
                case = dict(index=index, client=meta, server=observation)
                cases.append(case)
                assert observation.get('tag') == recipe['tag'], f'incorrect server exchange: {observation}'
                if args.reset_side == 'server':
                    assert observation['status'] == 'SENT_RESET' and meta['status'] == 'RESET', f'RST not delivered: {case}'
                    case['reset_delay_ms'] = round((meta['reset_at'] - observation['reset_at']) * 1000, 3)
                else:
                    assert observation['status'] == 'RESET', f'RST not delivered: {case}'
                    case['reset_delay_ms'] = round((observation['reset_at'] - meta['closing']) * 1000, 3)
                case.update(verify_events(meta, offset))
                problems = [line for line in text().splitlines()
                            if re.search(r'\[LOG\s+(?:ERROR|WARN|CRIT)|\[WARN\]|verdict FAILED', line)]
                assert not problems, f'driver diagnostics: {problems}'
                print(f"PASS {index + 1}/{args.repeats}: PID {meta['pid']}, port {meta['port']}, "
                      f"RST {case['reset_delay_ms']} ms, both ENDs", flush=True)
        except Exception:
            failure = traceback.format_exc()
            print('STOP: first failure, no further clients.\n' + failure, flush=True)
        finally:
            stopped.set()
            server.close()
            worker.join(5)
            code = monitor.wait(timeout=duration + 45)
    remaining = owners()
    problems = [line for line in text().splitlines()
                if re.search(r'\[LOG\s+(?:ERROR|WARN|CRIT)|\[WARN\]|verdict FAILED', line)]
    result = dict(command=command, server_pid=os.getpid(), server_port=port, cases=cases, failure=failure,
                  monitor_exit=code, owners_after=remaining, driver_diagnostics=problems, live_worker=worker.is_alive())
    (args.output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(f"Completed {len(cases)}/{args.repeats}; monitor exit {code}; owners={remaining!r}; evidence={args.output}", flush=True)
    return 1 if failure or code or remaining or problems or worker.is_alive() else 0


if __name__ == '__main__':
    sys.exit(main())
