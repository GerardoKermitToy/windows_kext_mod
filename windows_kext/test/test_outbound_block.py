"""Scoped outbound Block/Drop/Accept and UDP live-unload regressions.

Requires Administrator and existing monitor/SYS binaries. Only dedicated loopback
ports receive alternate verdicts; every monitor exits normally through --duration.
"""
import argparse
import ctypes
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import traceback

from monitor_window import start_monitor, wait_for_cleanup
from test_udp_burst_closure import owners

ROOT = Path(__file__).resolve().parents[2]
EVENT = re.compile(
    r'\[CONN v[46]\] id=\d+ pid=(?P<pid>\d+) (?:tid=\d+ )?(?P<direction>\w+) '
    r'proto=(?P<protocol>\d+)\([^)]*\) layer=(?P<layer>\d+)\([^)]*\)\r?\n'
    r'\s+\S+:(?P<local_port>\d+) -> \S+:(?P<remote_port>\d+)\s+payload=\d+ bytes\r?\n'
    r'(?:\s+compartment_id=\d+(?: condition_flags=0x[0-9a-fA-F]+)? interface_index=\d+ sub_interface_index=\d+\r?\n)?'
    r'\s+-> verdict (?P<verdict>\w+) sent'
)


def wait_for_verdict(records, monitor, protocol, local_port, remote_port, verdict, count=1):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        text = records.read_text(errors='replace') if records.exists() else ''
        events = [match.groupdict() for match in EVENT.finditer(text)]
        requests = [event for event in events
                    if int(event['pid']) == os.getpid() and event['direction'] == 'outbound'
                    and int(event['protocol']) == protocol and int(event['local_port']) == local_port
                    and int(event['remote_port']) == remote_port and event['verdict'] == verdict]
        if len(requests) >= count:
            return requests
        assert monitor.poll() is None, 'monitor exited before the verdict'
        time.sleep(0.01)
    raise AssertionError(f'missing {count} {verdict} verdict(s) for protocol {protocol}, port {local_port}')


def tcp_probe(family, address, listener, verdict):
    with socket.socket(family, socket.SOCK_STREAM) as client:
        client.settimeout(0.8)
        started = time.monotonic()
        error = None
        try:
            client.connect((address, listener.getsockname()[1]))
        except OSError as caught:
            error = caught
        elapsed = time.monotonic() - started
        if verdict == 'block':
            assert getattr(error, 'winerror', None) == 10013, f'ALE Block did not return WSAEACCES: {error!r}'
        elif verdict == 'drop':
            assert isinstance(error, TimeoutError), f'Drop was not silent: {error!r}'
        else:
            assert error is None, repr(error)
            with listener.accept()[0] as peer:
                peer.settimeout(2)
                client.sendall(b'outbound-tcp-control')
                data = peer.recv(128)
                assert data == b'outbound-tcp-control', data
                peer.sendall(data)
                assert client.recv(128) == data
        if verdict != 'accept':
            listener.settimeout(0.05)
            try:
                unexpected, _ = listener.accept()
            except socket.timeout:
                pass
            else:
                unexpected.close()
                raise AssertionError('blocked TCP reached the listener')
            finally:
                listener.settimeout(2)
        return dict(protocol='TCP', verdict=verdict, elapsed=elapsed,
                    winerror=getattr(error, 'winerror', None))


def udp_probe(family, address, server, verdict, connected, records, monitor, udp_at_ale):
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.bind((address, 0))
        client.settimeout(2)
        target = (address, server.getsockname()[1])
        if connected:
            client.connect(target)
        errors = []
        requests = []
        for index in range(3):
            payload = f'outbound-udp-{connected}-{index}'.encode()
            try:
                sent = client.send(payload) if connected else client.sendto(payload, target)
                assert sent == len(payload)
            except OSError as error:
                errors.append(getattr(error, 'winerror', None))
                assert verdict == 'block', repr(error)
                # Native hard blocks can fail sends with WSAEACCES. The optional
                # ALE experiment can also fail its initial send with WSAEINVAL.
                allowed_errors = (10013, 10022) if udp_at_ale else (10013,)
                assert errors[-1] in allowed_errors, repr(error)
            expected_requests = 1 if verdict == 'block' else index + 1
            requests = wait_for_verdict(records, monitor, 17, client.getsockname()[1],
                                        target[1], verdict.title(), count=expected_requests)
            if verdict == 'accept':
                server.settimeout(2)
                data, source = server.recvfrom(65535)
                assert data == payload
                server.sendto(data, source)
                assert client.recv(65535) == payload
            else:
                server.settimeout(0.05)
                try:
                    unexpected = server.recvfrom(65535)
                except socket.timeout:
                    pass
                else:
                    raise AssertionError(f'blocked UDP reached receiver: {unexpected!r}')
        if verdict == 'block':
            # Give the monitor two polling intervals to expose unwanted requests.
            time.sleep(0.2)
            requests = wait_for_verdict(records, monitor, 17, client.getsockname()[1],
                                        target[1], 'Block')
            assert len(requests) == 1, requests
            expected_layer = '4' if udp_at_ale else '3'
            assert all(event['layer'] == expected_layer for event in requests), requests
        return dict(protocol='UDP', verdict=verdict, connected=connected,
                    send_errors=errors, verdict_requests=len(requests))


def audit(records, console):
    text = records.read_text(errors='replace') + '\n' + console.read_text(errors='replace')
    errors = [line for line in text.splitlines()
              if re.search(r'\[LOG\s+(?:WARN|ERROR|CRIT)|\[WARN\]|verdict FAILED|ERROR:', line)]
    assert not errors, errors


def run_case(args, family, verdict, output):
    output.mkdir()
    address = '::1' if family == socket.AF_INET6 else '127.0.0.1'
    records, console = output / 'records.log', output / 'console.log'
    observations = []
    with socket.socket(family, socket.SOCK_STREAM) as listener, socket.socket(family, socket.SOCK_DGRAM) as server:
        listener.bind((address, 0))
        listener.listen(8)
        listener.settimeout(2)
        port = listener.getsockname()[1]
        server.bind((address, port))
        match = f'[{address}]:{port}' if family == socket.AF_INET6 else f'{address}:{port}'
        command = [str(args.monitor.resolve()), '--duration', '16', '--poll', '100',
                   '--no-bandwidth', '--timestamps', '--verdict', verdict, '--match', match,
                   '--out', str(records.resolve()), str(args.driver.resolve())]
        if args.udp_at_ale:
            command.insert(1, '--authorize-outbound-udp-at-ale')
        with console.open('w', encoding='utf-8') as handle:
            monitor = start_monitor(command, stdout=handle, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 8
                while 'Running for 16 second(s)' not in console.read_text(errors='replace'):
                    assert monitor.poll() is None and time.monotonic() < deadline, console.read_text(errors='replace')
                    time.sleep(0.02)
                for _ in range(args.repeats):
                    observations.append(tcp_probe(family, address, listener, verdict))
                    for connected in (False, True):
                        observations.append(udp_probe(family, address, server, verdict, connected,
                                                      records, monitor, args.udp_at_ale))
                # Separate unmatched ports must continue to work under every verdict.
                with socket.socket(family, socket.SOCK_STREAM) as control:
                    control.bind((address, 0))
                    control.listen(1)
                    control.settimeout(2)
                    observations.append(tcp_probe(family, address, control, 'accept'))
                with socket.socket(family, socket.SOCK_DGRAM) as control, socket.socket(family, socket.SOCK_DGRAM) as client:
                    control.bind((address, 0))
                    control.settimeout(2)
                    client.settimeout(2)
                    client.sendto(b'unmatched-udp-control', control.getsockname())
                    payload, source = control.recvfrom(128)
                    assert payload == b'unmatched-udp-control'
                    control.sendto(payload, source)
                    assert client.recv(128) == payload
                assert monitor.poll() is None, 'functional checks ran after monitor exit'
            finally:
                wait_for_cleanup(monitor, timeout=50)
        assert monitor.returncode == 0, console.read_text(errors='replace')
    audit(records, console)
    assert not owners(), 'monitor/service remained after cleanup'
    result = dict(ipv6=family == socket.AF_INET6, verdict=verdict,
                  udp_at_ale=args.udp_at_ale, observations=observations, command=command)
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(f'PASS: IPv{6 if family == socket.AF_INET6 else 4} {verdict}, UDP ALE={args.udp_at_ale}', flush=True)
    return result


def live_unload(args, family, output):
    output.mkdir()
    address = '::1' if family == socket.AF_INET6 else '127.0.0.1'
    records, console = output / 'records.log', output / 'console.log'
    command = [str(args.monitor.resolve()), '--duration', '6', '--poll', '100',
               '--no-bandwidth', '--out', str(records.resolve()), str(args.driver.resolve())]
    after_exit = total = 0
    with socket.socket(family, socket.SOCK_DGRAM) as client, socket.socket(family, socket.SOCK_DGRAM) as server:
        client.bind((address, 0))
        server.bind((address, 0))
        client.settimeout(4)
        server.settimeout(4)
        with console.open('w', encoding='utf-8') as handle:
            monitor = start_monitor(command, stdout=handle, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 20
                while after_exit < 12:
                    assert time.monotonic() < deadline, 'live-unload deadline exceeded'
                    payload = total.to_bytes(4, 'big') + b'U' * 271
                    client.sendto(payload, server.getsockname())
                    received, source = server.recvfrom(1024)
                    assert received == payload and source == client.getsockname()
                    server.sendto(received, source)
                    echoed, peer = client.recvfrom(1024)
                    assert echoed == payload and peer == server.getsockname()
                    total += 1
                    if monitor.poll() is not None:
                        after_exit += 1
                    time.sleep(0.1)
            finally:
                wait_for_cleanup(monitor, timeout=50)
        assert monitor.returncode == 0
    audit(records, console)
    assert not owners()
    result = dict(ipv6=family == socket.AF_INET6, exchanges=total, exchanges_after_exit=after_exit)
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(f'PASS: IPv{6 if family == socket.AF_INET6 else 4} UDP live-unload, {after_exit} post-exit exchanges', flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--monitor', type=Path, default=ROOT / 'kext_client/build/kext_monitor.exe')
    parser.add_argument('--driver', type=Path, default=ROOT / 'windows_kext/portmaster-kext.sys')
    parser.add_argument('--verdicts', nargs='+', choices=('block', 'drop', 'accept'), default=['block', 'drop', 'accept'])
    parser.add_argument('--repeats', type=int, default=2)
    parser.add_argument('--udp-at-ale', action='store_true')
    parser.add_argument('--live-unload', action='store_true')
    parser.add_argument('--output', type=Path, default=Path(__file__).parent / '_out' /
                        ('outbound_block_' + datetime.now().strftime('%Y%m%d_%H%M%S')))
    args = parser.parse_args()
    if os.name != 'nt' or not ctypes.windll.shell32.IsUserAnAdmin() or not 1 <= args.repeats <= 3:
        parser.error('requires Administrator on Windows and --repeats 1..3')
    for binary in (args.monitor, args.driver):
        if not binary.is_file():
            parser.error(f'missing binary: {binary}')
    assert not owners(), 'refusing to interfere with an existing driver owner'
    args.output.mkdir(parents=True, exist_ok=False)
    digest = hashlib.sha256(args.driver.read_bytes()).hexdigest()
    results = []
    failure = None
    try:
        for family in (socket.AF_INET, socket.AF_INET6):
            label = 'v6' if family == socket.AF_INET6 else 'v4'
            for verdict in args.verdicts:
                results.append(run_case(args, family, verdict, args.output / f'{label}_{verdict}'))
            if args.live_unload:
                results.append(live_unload(args, family, args.output / f'{label}_live_unload'))
        assert hashlib.sha256(args.driver.read_bytes()).hexdigest() == digest, 'driver changed during tests'
    except Exception:
        failure = traceback.format_exc()
        print(failure, flush=True)
    report = dict(driver_sha256=digest, results=results, failure=failure)
    (args.output / 'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return int(failure is not None)


if __name__ == '__main__':
    raise SystemExit(main())
