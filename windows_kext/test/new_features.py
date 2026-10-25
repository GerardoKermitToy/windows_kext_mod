"""Scoped local regressions for pre-handshake closure, TID, delayed verdicts and PID resume."""
import argparse
import ipaddress
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

from monitor_window import start_monitor, check_monitor, check_active, wait_for_cleanup
from test_udp_flow_idle import driver_owners

PROJECT = Path(__file__).resolve().parents[2]
CONN = re.compile(
    r'\[CONN v[46]\] id=(?P<id>\d+) pid=(?P<pid>\d+) tid=(?P<tid>\d+) '
    r'(?P<direction>\w+) proto=(?P<proto>\d+)\([^)]*\) layer=\d+\([^)]*\)\r?\n'
    r'\s+(?P<local>\S+):(?P<lp>\d+) -> (?P<remote>\S+):(?P<rp>\d+)\s+payload=\d+ bytes\r?\n'
    r'\s+compartment_id=(?P<compartment_id>\d+) interface_index=(?P<interface_index>\d+) '
    r'sub_interface_index=(?P<sub_interface_index>\d+)')
END = re.compile(r'\[END\s+v[46]\] pid=(?P<pid>\d+) (?P<direction>\w+) '
                 r'proto=(?P<proto>\d+)\([^)]*\) (?P<local>\S+):(?P<lp>\d+) -> (?P<remote>\S+):(?P<rp>\d+)')
CHILD = r'''
import ctypes, json, os, socket, sys, threading, time
compartment = ctypes.WinDLL('iphlpapi').GetCurrentThreadCompartmentId
compartment.restype = ctypes.c_uint32
c=json.loads(sys.argv[1]); f=socket.AF_INET6 if c['ipv6'] else socket.AF_INET
kind=socket.SOCK_STREAM if c['proto']==6 else socket.SOCK_DGRAM
s=socket.socket(f,kind);s.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
s.bind((c['ip'],c.get('port',0)));s.settimeout(8)
print(json.dumps(dict(pid=os.getpid(),tid=threading.get_native_id(),port=s.getsockname()[1],compartment_id=compartment())),flush=True)
assert sys.stdin.readline().strip()=='go'
start=time.monotonic(); outcome={}
if c['mode']=='close':
    s.setblocking(False); code=s.connect_ex((c['ip'],c['target']))
    print(json.dumps(dict(connect_ex=code)),flush=True)
    assert sys.stdin.readline().strip()=='close'
    s.close(); print(json.dumps(dict(closed_at=time.monotonic(),alive=True)),flush=True)
else:
    try:
        if c['proto']==6:s.connect((c['ip'],c['target']))
        if c['mode']!='shutdown':
            payload=b'new-feature-exact-payload-'+bytes(range(256))*3
            if c['proto']==6:
                s.sendall(payload); received=bytearray()
                while len(received)<len(payload):
                    part=s.recv(len(payload)-len(received));assert part,'unexpected EOF';received.extend(part)
                assert bytes(received)==payload
                s.shutdown(socket.SHUT_WR);assert s.recv(1)==b''
            else:
                assert s.sendto(payload,(c['ip'],c['target']))==len(payload)
                data,peer=s.recvfrom(4096);assert data==payload and peer[:2]==(c['ip'],c['target'])
            outcome['delivered']=True
        outcome['connected']=True
    except OSError as e:
        outcome.update(error=str(e),winerror=e.winerror)
        if c['mode']!='shutdown':raise
    finally:s.close()
    outcome.update(elapsed=time.monotonic()-start,closed_at=time.monotonic(),alive=True)
    print(json.dumps(outcome),flush=True)
assert sys.stdin.readline().strip()=='quit'
'''


class Child:
    def __init__(self, recipe):
        self.process = subprocess.Popen([sys.executable, '-u', '-c', CHILD, json.dumps(recipe)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.lines = queue.Queue()
        self.all_lines = []
        def read():
            for line in self.process.stdout:
                self.all_lines.append(line)
                self.lines.put(line)
        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()
        self.meta = self.next()
    def next(self, timeout=15):
        try:
            return json.loads(self.lines.get(timeout=timeout))
        except queue.Empty:
            if self.process.poll() is not None:
                raise AssertionError(('child exited without result', self.process.returncode, self.process.stderr.read()))
            raise AssertionError(('live child did not progress', self.process.pid, self.all_lines))
    def send(self, command):
        self.process.stdin.write(command + '\n')
        self.process.stdin.flush()
    def finish(self):
        if self.process.poll() is None:
            self.send('quit')
        code = self.process.wait(timeout=12)
        stderr = self.process.stderr.read()
        assert code == 0, (code, stderr, self.all_lines)
        return dict(pid=self.process.pid, exit_code=code, stdout=self.all_lines, stderr=stderr)


def canonical(value):
    return str(ipaddress.ip_address(value))


def events(text, pattern):
    result = []
    for match in pattern.finditer(text):
        e = match.groupdict()
        for key in ('pid', 'tid', 'proto', 'lp', 'rp', 'id', 'compartment_id', 'interface_index', 'sub_interface_index'):
            if key in e:
                e[key] = int(e[key])
        for key in ('local', 'remote'):
            e[key] = canonical(e[key])
        result.append(e)
    return result


def wait_for(predicate, timeout, explanation, observe_monitor=True):
    deadline = time.monotonic() + timeout
    while True:
        if observe_monitor:
            check_active()
        value = predicate()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(explanation)
        time.sleep(0.025)


def diagnostics(text):
    return [line for line in text.splitlines()
            if re.search(r'\[LOG\s+(?:WARN|ERROR|CRIT)|\[WARN\]|verdict FAILED', line)
            and not re.search(r'\[LOG\s+WARN\s*\].*TCP endpoint timeout t=\d+ i=\d+ p: TCP l: ', line)]


def monitor_command(args, ip, port, records):
    delay = {'close': 1500, 'shutdown': 60000}.get(args.mode, 300)
    duration = {'close': 260, 'shutdown': 7}.get(args.mode, 40)
    match = f'[{ip}]:{port}' if args.ipv6 else f'{ip}:{port}'
    command = [str(args.monitor.resolve()), '--duration', str(duration),
               '--poll', '100', '--timestamps', '--no-bandwidth', '--payload', '--filter-ip', ip,
               '--verdict', args.verdict, '--match', match, '--verdict-delay-ms', str(delay),
               '--out', str(records.resolve())]
    if args.mode in ('suspend', 'shutdown'):
        command.append('--suspend-pid-on-verdict-delay')
    command.append(str(args.driver.resolve()))
    return command, duration, delay


def finish_shutdown(monitor, child, connections, read_records, duration):
    code = wait_for_cleanup(monitor, timeout=duration + 25)
    check_monitor(monitor)
    assert code == 0, ('Monitor failed at shutdown', code)
    resumed = child.next(timeout=12)
    assert child.process.poll() is None and resumed.get('alive'), resumed
    data = read_records()
    pid = child.meta['pid']
    assert f'[SUSPEND] pid={pid} held' in data, 'Owned child was not suspended'
    stopped_at = data.find('Duration elapsed, stopping')
    resumed_at = data.find(f'[RESUME] pid={pid} at monitor shutdown (pending verdicts cancelled)')
    assert 0 <= stopped_at < resumed_at, 'Missing shutdown resume after duration elapsed'
    assert not any(re.search(rf'\[VERDICT\] id={e["id"]}\b', data) for e in connections), \
        'Cancelled delayed verdict was sent'
    return code, resumed


def run(args):
    assert not driver_owners(), 'Existing driver owner; refuse to interfere'
    args.output.mkdir(parents=True, exist_ok=False)
    ip = '::1' if args.ipv6 else '127.0.0.1'
    family = socket.AF_INET6 if args.ipv6 else socket.AF_INET
    tcp = socket.socket(family, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    tcp.bind((ip, 0)); port = tcp.getsockname()[1]; tcp.listen(16); tcp.settimeout(0.1)
    udp = socket.socket(family, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    udp.bind((ip, port)); udp.settimeout(0.1)
    records = args.output / 'records.log'
    console = args.output / 'console.log'
    def text():
        return records.read_text(encoding='utf-8', errors='replace') if records.exists() else ''
    command, duration, delay = monitor_command(args, ip, port, records)
    monitor = None
    children = []
    workers = []
    server_errors = []
    deliveries = []
    stop = threading.Event()
    checks = []
    failure = None
    code = None
    def tcp_server():
        try:
            while not stop.is_set():
                try: peer, address = tcp.accept()
                except socket.timeout: continue
                with peer:
                    peer.settimeout(8)
                    data = bytearray()
                    while chunk := peer.recv(4096):
                        data.extend(chunk); peer.sendall(chunk)
                    deliveries.append(dict(proto=6, peer=address, size=len(data)))
        except Exception:
            if not stop.is_set(): server_errors.append(traceback.format_exc())
    def udp_server():
        try:
            while not stop.is_set():
                try: data, address = udp.recvfrom(4096)
                except socket.timeout: continue
                deliveries.append(dict(proto=17, peer=address, size=len(data)))
                udp.sendto(data, address)
        except Exception:
            if not stop.is_set(): server_errors.append(traceback.format_exc())
    if args.mode not in ('close', 'shutdown'):
        for work in (tcp_server, udp_server):
            thread = threading.Thread(target=work, daemon=True); thread.start(); workers.append(thread)
    def controls():
        # Separate exclusive local targets never match the delayed endpoint.
        for proto, kind in ((6, socket.SOCK_STREAM), (17, socket.SOCK_DGRAM)):
            check_monitor(monitor, minimum_seconds=15)
            errors = []
            with socket.socket(family, kind) as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                server.bind((ip, 0)); target = server.getsockname()[1]; server.settimeout(5)
                if proto == 6: server.listen(1)
                def serve():
                    try:
                        if proto == 6:
                            with server.accept()[0] as peer:
                                peer.settimeout(5); data = peer.recv(256); peer.sendall(data)
                                assert peer.recv(1) == b''
                        else:
                            data, address = server.recvfrom(256); server.sendto(data, address)
                    except Exception: errors.append(traceback.format_exc())
                worker = threading.Thread(target=serve, daemon=True); worker.start()
                with socket.socket(family, kind) as client:
                    client.bind((ip, 0)); client_port = client.getsockname()[1]; client.settimeout(5)
                    payload = b'nonmatching-immediate-control'
                    if proto == 6:
                        client.connect((ip, target)); client.sendall(payload)
                        assert client.recv(256) == payload; client.shutdown(socket.SHUT_WR); assert client.recv(1) == b''
                    else:
                        client.sendto(payload, (ip, target)); data, address = client.recvfrom(256)
                        assert data == payload and address[:2] == (ip, target)
                worker.join(6); assert not worker.is_alive() and not errors, errors
                owned = wait_for(lambda: [e for e in events(text(), CONN) if e['pid'] == os.getpid()
                                         and e['direction'] == 'outbound' and e['proto'] == proto
                                         and e['lp'] == client_port and e['rp'] == target], 4, 'Missing control CONN')
                for event in owned:
                    assert event['tid'] == threading.get_native_id(), ('Wrong control TID', event)
                    block = text()[text().index(f'[CONN v{6 if args.ipv6 else 4}] id={event["id"]}'):]
                    block = '\n'.join(block.splitlines()[:5])
                    assert re.search(r'-> verdict PermanentAccept sent(?:\r?\n|$)', block), ('Control verdict delayed or matched', event, block)
                checks.append(dict(test='nonmatching_immediate_control', pid=os.getpid(), proto=proto,
                                   local_port=client_port, remote_port=target, connections=owned))
    def selected(pattern, child, proto):
        return [e for e in events(text(), pattern) if e['pid'] == child.meta['pid'] and e['proto'] == proto
                and e['direction'] == 'outbound' and e['lp'] == child.meta['port'] and e['rp'] == port
                and e['local'] == ip and e['remote'] == ip]
    def verify_connection(child, proto):
        check_monitor(monitor)
        conn = wait_for(lambda: selected(CONN, child, proto), 6, ('Missing owned CONN', child.meta, proto, text()))
        assert all(e['tid'] == child.meta['tid'] for e in conn), ('Wrong outbound TID', child.meta, conn)
        assert all(e['compartment_id'] == child.meta['compartment_id'] for e in conn), \
            ('Wrong compartment ID', child.meta, conn)
        if proto == 17:
            assert all(e['interface_index'] > 0 for e in conn), ('Missing packet interface', conn)
        return conn
    def verify_end(child, proto):
        check_monitor(monitor)
        wait_for(lambda: selected(END, child, proto), 80 if args.mode == 'close' else 35, ('Missing owned END after cleanup window', child.meta, proto))
        end = selected(END, child, proto)
        assert len(end) == 1 and child.process.poll() is None, ('Wrong END or process lifetime', end, child.meta)
        return end
    try:
        with console.open('w', encoding='utf-8') as output:
            monitor = start_monitor(command, stdout=output, stderr=subprocess.STDOUT)
            try:
                wait_for(lambda: f'Running for {duration} second(s)' in console.read_text(errors='replace'),
                         8, 'Monitor did not start', observe_monitor=False)
                time.sleep(0.5)
                if args.mode == 'close':
                    reused_port = 0
                    for generation in range(3):
                        check_monitor(monitor, minimum_seconds=18)
                        child = Child(dict(ip=ip, ipv6=args.ipv6, proto=6, port=reused_port, target=port, mode='close'))
                        children.append(child); reused_port = child.meta['port']
                        check_monitor(monitor, minimum_seconds=18)
                        child.send('go')
                        opening = child.next()
                        assert opening['connect_ex'] in (10035, 10036, 10037), opening
                        conn = verify_connection(child, 6)
                        child.send('close'); closed = child.next()
                        end = verify_end(child, 6)
                        request_id = conn[0]['id']
                        wait_for(lambda: re.search(rf'\[VERDICT\] id={request_id} -> verdict PermanentAccept sent\s+<== MATCHED', text()),
                                 5, ('Late verdict not written', request_id))
                        try:
                            unexpected, peer = tcp.accept(); unexpected.close()
                            raise AssertionError(('Closed generation reached target after late verdict', generation, peer))
                        except socket.timeout: pass
                        if generation == 0: controls()
                        checks.append(dict(test='close_before_handshake_exact_tuple_reuse', generation=generation,
                                           pid=child.meta['pid'], client=child.meta, connections=conn, ends=end,
                                           opening=opening, closed=closed, target_delivery=False))
                elif args.mode == 'shutdown':
                    check_monitor(monitor)
                    child = Child(dict(ip=ip, ipv6=args.ipv6, proto=6, target=port, mode='shutdown'))
                    children.append(child)
                    child.send('go')
                    conn = verify_connection(child, 6)
                    wait_for(lambda: f'[SUSPEND] pid={child.meta["pid"]} held' in text(),
                             4, 'Owned child not suspended')
                    controls()
                    code, resumed = finish_shutdown(monitor, child, conn, text, duration)
                    checks.append(dict(test='shutdown_resumes_held_child_and_cancels_verdict',
                                       pid=child.meta['pid'], client=child.meta,
                                       connections=conn, resumed=resumed))
                else:
                    for proto in (6, 17):
                        check_monitor(monitor, minimum_seconds=18)
                        child = Child(dict(ip=ip, ipv6=args.ipv6, proto=proto, target=port, mode=args.mode))
                        children.append(child)
                        check_monitor(monitor, minimum_seconds=18)
                        child.send('go'); conn = verify_connection(child, proto)
                        if proto == 6: controls()
                        outcome = child.next(timeout=15)
                        assert outcome.get('delivered') and outcome['elapsed'] >= 0.24, outcome
                        end = verify_end(child, proto)
                        if args.mode == 'suspend':
                            pid = child.meta['pid']
                            assert f'[SUSPEND] pid={pid} held' in text(), text()
                            assert re.search(rf'\[RESUME\] pid={pid} after verdict id=\d+', text()), text()
                        checks.append(dict(test='delayed_exact_echo_tid_and_live_process_end', proto=proto,
                                           pid=child.meta['pid'], client=child.meta, connections=conn, ends=end, outcome=outcome))
                assert not diagnostics(text()), diagnostics(text())
            except Exception:
                failure = traceback.format_exc(); print('STOP: no further traffic.\n' + failure, flush=True)
            finally:
                if code is None: code = wait_for_cleanup(monitor, timeout=duration + 25)
        stop.set()
        for worker in workers:
            worker.join(10)
        assert not server_errors and not any(w.is_alive() for w in workers), server_errors
        if failure is None:
            for child in children:
                if args.mode != 'shutdown':
                    proto = 6 if args.mode == 'close' else next(e['proto'] for e in checks if e['pid'] == child.meta['pid'])
                    assert len(selected(END, child, proto)) == 1, ('Late duplicate END', child.meta, text())
            for check in checks:
                if check['test'] == 'nonmatching_immediate_control': continue
                for event in check['connections']:
                    expected = 'Accept' if args.verdict == 'accept' else 'PermanentAccept'
                    scheduled = rf'\[CONN v[46]\] id={event["id"]} .*?-> verdict {expected} scheduled after {delay} ms\s+<== MATCHED'
                    assert re.search(scheduled, text(), re.S), ('Missing scoped delayed verdict', event)
                    if args.mode != 'shutdown':
                        assert re.search(rf'\[VERDICT\] id={event["id"]} -> verdict {expected} sent\s+<== MATCHED', text()), event
            assert not diagnostics(text()) and not diagnostics(console.read_text(errors='replace')), text()
    except Exception:
        if failure is None: failure = traceback.format_exc(); print(failure, flush=True)
    finally:
        stop.set(); tcp.close(); udp.close()
        child_results = []
        for child in children:
            try: child_results.append(child.finish())
            except Exception:
                if failure is None: failure = traceback.format_exc()
    remaining = driver_owners()
    result = dict(command=command, passed=checks, failure=failure, monitor_exit=code, owners_after=remaining,
                  driver_errors=diagnostics(text()), server_errors=server_errors, deliveries=deliveries,
                  child_results=child_results, pid=os.getpid(), mode=args.mode, ipv6=args.ipv6, verdict=args.verdict)
    (args.output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(dict(passed=len(checks), mode=args.mode, ipv6=args.ipv6, failure=failure,
                          monitor_exit=code, owners_after=remaining)), flush=True)
    return 1 if failure or code != 0 or remaining or result['driver_errors'] else 0


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('close', 'delay', 'suspend', 'shutdown'), required=True)
    parser.add_argument('--ipv6', action='store_true')
    parser.add_argument('--verdict', choices=('accept', 'permanent-accept'), default='permanent-accept')
    parser.add_argument('--monitor', type=Path, default=PROJECT / 'kext_client/build/kext_monitor.exe')
    parser.add_argument('--driver', type=Path, default=PROJECT / 'windows_kext/portmaster-kext.sys')
    parser.add_argument('--output', type=Path, required=True)
    return parser


def main():
    parser = argument_parser()
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('this test requires Windows and Administrator')
    for binary in (args.monitor, args.driver):
        if not binary.is_file():
            parser.error(f'missing binary: {binary}')
    args.output = args.output.resolve()
    return run(args)


if __name__ == '__main__':
    sys.exit(main())
