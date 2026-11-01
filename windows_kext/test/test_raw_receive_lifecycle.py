"""Bounded SIO_RCVALL/native TCP+UDP ownership regression (Administrator).

Bind the observer and local traffic to a real interface, not 127.0.0.1.
Checks connections opened before/during capture, delivery after observer close,
no observer CONN/END, and exact native END events only after native socket close.
An optional --sniffer runs an existing executable instead of the raw-socket child.
The monitor always unloads through --duration, including on assertion failure.
"""
import argparse
from contextlib import ExitStack
from datetime import datetime
import json
import os
from pathlib import Path
import queue
import re
import socket
import subprocess
import sys
import threading
import time
import traceback

from monitor_window import start_monitor, check_monitor, wait_for_cleanup
from test_tcp_rst_closure import owners, receive_exact

ROOT = Path(__file__).resolve().parents[2]
EVENT = re.compile(
    r'\[(CONN|END\s+) v4\] (?:id=\d+ )?pid=(\d+) (?:tid=\d+ )?'
    r'(inbound|outbound) proto=(6|17)\(\w+\)(?: layer=[^\r\n]+\r?\n\s+| )'
    r'(\S+):(\d+) -> (\S+):(\d+)'
)
RAW = r'''
import json, os, socket, sys, threading
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((sys.argv[1], 0))
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
s.settimeout(0.1)
stop = threading.Event()
counts = {'6': 0, '17': 0}
ports = set(json.loads(sys.argv[2]))
def receive():
    while not stop.is_set():
        try:
            data = s.recv(65535)
        except TimeoutError:
            continue
        offset = (data[0] & 15) * 4 if data else 0
        if len(data) >= offset + 4 and str(data[9]) in counts:
            pair = (int.from_bytes(data[offset:offset+2], 'big'),
                    int.from_bytes(data[offset+2:offset+4], 'big'))
            if not ports or any(port in ports for port in pair):
                counts[str(data[9])] += 1
worker = threading.Thread(target=receive)
worker.start()
print(json.dumps({'pid': os.getpid()}), flush=True)
try:
    sys.stdin.readline()
finally:
    stop.set()
    worker.join(timeout=2)
    assert not worker.is_alive(), 'raw receiver failed to stop'
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    s.close()
print(json.dumps({'captured': counts}), flush=True)
'''


def wait_until(check, timeout=5):
    deadline = time.monotonic() + timeout
    while True:
        result = check()
        if result:
            return result
        if time.monotonic() >= deadline:
            raise AssertionError('timed out waiting for monitor events/readiness')
        time.sleep(0.05)


def read_ready(process):
    result = queue.Queue()
    threading.Thread(target=lambda: result.put(process.stdout.readline()), daemon=True).start()
    return json.loads(result.get(timeout=5))


class NativePairs:
    def __init__(self, address):
        self.stack = ExitStack()
        self.signatures = set()
        try:
            def new(kind):
                s = self.stack.enter_context(socket.socket(socket.AF_INET, kind))
                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                s.settimeout(3)
                s.bind((address, 0))
                return s

            self.udp = (new(socket.SOCK_DGRAM), new(socket.SOCK_DGRAM))
            for index, s in enumerate(self.udp):
                s.connect(self.udp[1 - index].getsockname())
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                listener.settimeout(3)
                listener.bind((address, 0))
                listener.listen(1)
                client = new(socket.SOCK_STREAM)
                client.connect(listener.getsockname())
                server, _ = listener.accept()
                self.stack.enter_context(server)
                server.settimeout(3)
                self.tcp = (client, server)
            for protocol, sockets in ((6, self.tcp), (17, self.udp)):
                for s in sockets:
                    self.signatures.add((protocol, *s.getsockname(), *s.getpeername()))
        except BaseException:
            self.close()
            raise

    def exchange(self, tag):
        payload = tag.encode()
        for sockets in (self.tcp, self.udp):
            for index, sender in enumerate(sockets):
                sender.sendall(payload)
                receiver = sockets[1 - index]
                received = (receive_exact(receiver, len(payload))
                            if sockets is self.tcp else receiver.recv(65535))
                assert received == payload, (tag, received)

    def close(self):
        self.stack.close()


def events(text):
    return [dict(kind=kind.strip(), pid=int(pid), direction=direction,
                 signature=(int(protocol), local, int(lp), remote, int(rp)))
            for kind, pid, direction, protocol, local, lp, remote, rp in EVENT.findall(text)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', default='192.168.3.2')
    parser.add_argument('--preexisting', action='store_true', help='open observer before driver load')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--sniffer', type=Path, help='existing SIO_RCVALL exe, already bound to --interface')
    parser.add_argument('--monitor', type=Path, default=ROOT / 'kext_client/build/kext_monitor.exe')
    parser.add_argument('--driver', type=Path, default=ROOT / 'windows_kext/portmaster-kext.sys')
    parser.add_argument('--output', type=Path, default=Path(__file__).parent / '_out' /
                        ('raw_receive_' + datetime.now().strftime('%Y%m%d_%H%M%S')))
    args = parser.parse_args()
    if os.name != 'nt' or not 1 <= args.repeats <= 10:
        parser.error('requires Windows and --repeats between 1 and 10')
    if socket.inet_aton(args.interface)[0] == 127:
        parser.error('--interface must be a real interface address for SIO_RCVALL')
    for path in (args.monitor, args.driver, args.sniffer):
        if path is not None and not path.is_file():
            parser.error(f'missing binary: {path}')
    existing = owners()
    if existing:
        raise RuntimeError('refusing to interfere with driver owner: ' + existing)
    args.output.mkdir(parents=True, exist_ok=False)
    records = args.output / 'records.log'
    console = args.output / 'console.log'
    result = dict(pid=os.getpid(), interface=args.interface, preexisting=args.preexisting,
                  sniffer=str(args.sniffer) if args.sniffer else 'python SIO_RCVALL', cases=[])
    monitor = None
    raw = None
    raw_log = None

    def text():
        return records.read_text(encoding='utf-8', errors='replace') if records.exists() else ''

    def start_raw(ports):
        nonlocal raw, raw_log
        raw_log = (args.output / f'observer-{len(result["cases"])}.log').open('w')
        if args.sniffer:
            raw = subprocess.Popen([str(args.sniffer.resolve())], stdout=raw_log, stderr=subprocess.STDOUT)
            time.sleep(0.5)
            assert raw.poll() is None, 'sniffer exited before the test'
        else:
            raw = subprocess.Popen([sys.executable, '-I', '-c', RAW, args.interface, json.dumps(ports)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=raw_log, text=True)
            assert read_ready(raw)['pid'] == raw.pid
        return raw.pid

    def stop_raw():
        nonlocal raw, raw_log
        if raw is None:
            return None
        try:
            if args.sniffer:
                # Terminate only the observer we created, never the driver owner.
                raw.terminate()
                raw.wait(timeout=5)
                return None
            output, _ = raw.communicate('close\n', timeout=5)
            assert raw.returncode == 0, 'raw receiver failed: ' + output
            return json.loads(output)['captured']
        finally:
            if raw.poll() is None:
                raw.terminate()
                raw.wait(timeout=5)
            raw = None
            raw_log.close()
            raw_log = None

    failure = None
    duration = 18 + args.repeats * 5
    try:
        if args.preexisting:
            start_raw([])
        with console.open('wb') as log:
            command = [str(args.monitor.resolve()), '--duration', str(duration), '--poll', '100',
                       '--timestamps', '--no-bandwidth', '--out', str(records.resolve()),
                       str(args.driver.resolve())]
            monitor = start_monitor(command, stdout=log, stderr=subprocess.STDOUT)
            try:
                wait_until(lambda: 'Running for ' in console.read_text(errors='replace'))
                for iteration in range(args.repeats):
                    check_monitor(monitor, minimum_seconds=5)
                    assert monitor.poll() is None, 'monitor exited during functional checks'
                    offset = len(text())
                    pairs = []
                    case = dict(iteration=iteration, observer_pid=None)
                    result['cases'].append(case)
                    try:
                        before = NativePairs(args.interface)
                        pairs.append(before)
                        before.exchange(f'{iteration}-before')
                        if raw is None:
                            start_raw([signature[2] for signature in before.signatures])
                        case['observer_pid'] = raw.pid
                        during = NativePairs(args.interface)
                        pairs.append(during)
                        during.exchange(f'{iteration}-during-new')
                        before.exchange(f'{iteration}-during-existing')
                        time.sleep(0.2)
                        case['captured'] = stop_raw()
                        for pair in pairs:
                            pair.exchange(f'{iteration}-after-observer-close')
                        time.sleep(0.4)
                        signatures = before.signatures | during.signatures
                        observed = events(text()[offset:])
                        wrong_owner = [e for e in observed if e['pid'] == case['observer_pid']]
                        premature = [e for e in observed if e['kind'] == 'END' and e['signature'] in signatures]
                        case.update(observer_events=wrong_owner, premature_native_ends=premature)
                        assert not wrong_owner, f'observer claimed native connections: {wrong_owner}'
                        assert not premature, f'observer close ended live native sockets: {premature}'
                        if case['captured'] is not None:
                            assert all(case['captured'][str(p)] > 0 for p in (6, 17)), case['captured']
                        connections = [e for e in observed if e['kind'] == 'CONN' and e['signature'] in signatures]
                        assert {e['signature'] for e in connections} == signatures, connections
                        assert all(e['pid'] == os.getpid() for e in connections), connections
                    finally:
                        for pair in pairs:
                            pair.close()
                    wait_until(lambda: len([e for e in events(text()[offset:])
                                            if e['kind'] == 'END' and e['signature'] in signatures]) >= len(signatures))
                    ended = [e for e in events(text()[offset:])
                             if e['kind'] == 'END' and e['signature'] in signatures]
                    assert len(ended) == len(signatures), ended
                    assert {e['signature'] for e in ended} == signatures, ended
                    assert all(e['pid'] == os.getpid() for e in ended), ended
                    case.update(native_end_count=len(ended), passed=True)
                    print(json.dumps(case), flush=True)
            finally:
                try:
                    stop_raw()
                finally:
                    result['monitor_exit'] = wait_for_cleanup(monitor, timeout=duration + 15)
        errors = [line for line in text().splitlines()
                  if '[LOG ERROR]' in line or '[LOG WARN]' in line or 'verdict FAILED' in line]
        result['driver_errors'] = errors
        assert not errors, errors
        observer_pids = {case['observer_pid'] for case in result['cases']}
        result['observer_events'] = [e for e in events(text()) if e['pid'] in observer_pids]
        assert not result['observer_events'], result['observer_events']
        console_errors = [line for line in console.read_text(errors='replace').splitlines()
                          if re.search(r'\b(?:error|failed|warning)\b', line, re.IGNORECASE)]
        result['console_errors'] = console_errors
        assert not console_errors, console_errors
        assert result['monitor_exit'] == 0, result
        assert not owners(), 'monitor/service still present after cleanup'
        result['passed'] = True
    except BaseException:
        failure = traceback.format_exc()
        result.update(passed=False, failure=failure)
    finally:
        stop_raw()
        (args.output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2), flush=True)
    return 1 if failure else 0


if __name__ == '__main__':
    sys.exit(main())
