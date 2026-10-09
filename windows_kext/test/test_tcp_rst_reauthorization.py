"""Bounded TCP reset reauthorization regression (requires Administrator).

Establish sockets before loading the driver, then reset either side. A reset must
reach the peer without an ALE/packet-layer verdict request or failed injection.
The monitor owns driver cleanup and always runs with --duration.
"""
import argparse
from datetime import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import time
import traceback

from test_tcp_rst_closure import owners, receive_exact

ROOT = Path(__file__).resolve().parents[2]
CONN = re.compile(
    r"\[CONN v[46]\] id=(?P<id>\d+) pid=(?P<pid>\d+) (?:tid=\d+ )?(?P<direction>\w+) "
    r"proto=6\(TCP\) layer=(?P<layer>\d+)\([^)]*\)\r?\n"
    r"\s+(?P<local>\S+):(?P<lp>\d+) -> (?P<remote>\S+):(?P<rp>\d+)\s+payload=\d+ bytes\r?\n"
    r"\s+payload: (?P<payload>[0-9a-f]+|\(none\))\r?\n"
    r"\s+-> verdict (?P<verdict>\w+) (?P<status>sent|scheduled after \d+ ms)"
)


def tcp_flags(event):
    payload = event['payload']
    if payload == '(none)':
        return None
    data = bytes.fromhex(payload)
    offset = 0
    if int(event['layer']) == 3:
        if data[0] >> 4 == 4:
            offset = (data[0] & 15) * 4
        else:
            offset = 40
    assert len(data) >= offset + 20, event
    return data[offset + 13]


def driver_errors(text):
    return [line for line in text.splitlines()
            if re.search(r'\[LOG\s+(?:WARN|ERROR|CRIT)|\[WARN\]|verdict FAILED', line)
            and not re.search(r'\[LOG\s+WARN\s*\].*TCP endpoint timeout t=\d+ i=\d+ p: TCP l: ', line)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ipv6', action='store_true')
    parser.add_argument('--repeats', type=int, default=6)
    parser.add_argument('--reset-side', choices=('client', 'server'), default='client')
    parser.add_argument('--verdict-delay-ms', type=int, default=300)
    parser.add_argument('--verdict', choices=('accept', 'permanent-accept'), default='accept')
    parser.add_argument('--monitor', type=Path, default=ROOT / 'kext_client/build/kext_monitor.exe')
    parser.add_argument('--driver', type=Path, default=ROOT / 'windows_kext/portmaster-kext.sys')
    parser.add_argument('--output', type=Path,
                        default=Path(__file__).parent / '_out' /
                        ('tcp_rst_reauth_' + datetime.now().strftime('%Y%m%d_%H%M%S')))
    args = parser.parse_args()
    if os.name != 'nt' or not 1 <= args.repeats <= 12 or not 0 <= args.verdict_delay_ms <= 1000:
        parser.error('requires Windows, --repeats 1..12 and --verdict-delay-ms 0..1000')
    for binary in (args.monitor, args.driver):
        if not binary.is_file():
            parser.error(f'missing binary: {binary}')
    assert not owners(), 'refusing to interfere with an existing driver owner'
    args.output.mkdir(parents=True, exist_ok=False)
    records = args.output / 'records.log'
    console = args.output / 'console.log'
    family = socket.AF_INET6 if args.ipv6 else socket.AF_INET
    local = '::1' if args.ipv6 else '127.0.0.1'
    remote = '::1' if args.ipv6 else '127.0.0.2'
    listener = socket.socket(family, socket.SOCK_STREAM)
    pairs = []
    observations = []
    monitor = None
    failure = None
    command = None
    driver_hash = hashlib.sha256(args.driver.read_bytes()).hexdigest().upper()
    monitor_hash = hashlib.sha256(args.monitor.read_bytes()).hexdigest().upper()
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        listener.bind((remote, 0))
        listener.listen(args.repeats)
        listener.settimeout(4)
        port = listener.getsockname()[1]
        # No driver owns these sockets yet. Native echo verifies both directions
        # and the exact peer before the later reauthorization/reset is exercised.
        for index in range(args.repeats):
            client = socket.socket(family, socket.SOCK_STREAM)
            pairs.append((client, None))
            client.settimeout(3)
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client.bind((local, 0))
            client.connect((remote, port))
            server, address = listener.accept()
            pairs[-1] = (client, server)
            server.settimeout(3)
            server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            assert str(ipaddress.ip_address(address[0])) == local
            assert str(ipaddress.ip_address(client.getpeername()[0])) == remote
            assert client.getpeername()[1] == port
            payload = ('native-reset-control-%d' % index).encode()
            client.sendall(payload)
            assert receive_exact(server, len(payload)) == payload
            server.sendall(payload)
            assert receive_exact(client, len(payload)) == payload
            observations.append(dict(index=index, pid=os.getpid(), local=client.getsockname(),
                                     remote=client.getpeername(), native_echo=True))
        time.sleep(0.15)
        assert not owners(), 'driver owner appeared during native controls'
        match = f'[{remote}]:{port}' if args.ipv6 else f'{remote}:{port}'
        command = [str(args.monitor.resolve()), '--duration', '20', '--poll', '100',
                   '--timestamps', '--no-bandwidth', '--payload', '--verdict', args.verdict,
                   '--match', match, '--verdict-delay-ms', str(args.verdict_delay_ms),
                   '--out', str(records.resolve()), str(args.driver.resolve())]
        with console.open('w', encoding='utf-8') as handle:
            monitor = subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 8
            while 'Running for 20 second(s)' not in console.read_text(errors='replace'):
                assert monitor.poll() is None and time.monotonic() < deadline, console.read_text(errors='replace')
                time.sleep(0.05)
            for index, (client, server) in enumerate(pairs):
                text = records.read_text(errors='replace') if records.exists() else ''
                assert not driver_errors(text), driver_errors(text)
                sender, receiver = (client, server) if args.reset_side == 'client' else (server, client)
                sender.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('HH', 1, 0))
                started = time.monotonic()
                sender.close()
                try:
                    data = receiver.recv(1)
                    raise AssertionError(f'reset replaced by EOF/data: {data!r}')
                except ConnectionResetError as error:
                    observations[index].update(reset_received=True, winerror=error.winerror,
                                               elapsed=time.monotonic() - started)
                receiver.close()
                print(f'PASS: preexisting {args.reset_side} reset {index + 1}/{args.repeats}', flush=True)
    except Exception:
        failure = traceback.format_exc()
        print('STOP: first failure, no further resets.\n' + failure, flush=True)
    finally:
        for pair in pairs:
            for peer in pair:
                if peer is not None:
                    peer.close()
        listener.close()
        if monitor is not None:
            monitor.wait(timeout=80)
    text = records.read_text(errors='replace') if records.exists() else ''
    errors = driver_errors(text)
    remaining = owners()
    audit = None
    if failure is None:
        try:
            assert monitor is not None and monitor.returncode == 0
            assert not errors and not remaining, (errors, remaining)
            events = [event.groupdict() for event in CONN.finditer(text)
                      if int(event['pid']) == os.getpid()]
            owned_headers = re.findall(r'\[CONN v[46]\] id=\d+ pid=' + str(os.getpid()) + r' ', text)
            assert len(events) == len(owned_headers), 'unparsed owned CONN record'
            assert not any((tcp_flags(event) or 0) & 4 for event in events), 'RST sent for a userspace verdict'
            assert len(observations) == args.repeats and all(item.get('reset_received') for item in observations)
            assert hashlib.sha256(args.driver.read_bytes()).hexdigest().upper() == driver_hash
            assert hashlib.sha256(args.monitor.read_bytes()).hexdigest().upper() == monitor_hash
            audit = dict(owned_conn_headers=len(owned_headers), parsed_owned_conns=len(events),
                         rst_verdict_requests=0, complete_log_audited=True)
        except Exception:
            failure = traceback.format_exc()
    result = dict(command=command, monitor_exit=monitor.returncode if monitor else None,
                  pid=os.getpid(), ipv6=args.ipv6, reset_side=args.reset_side, observations=observations,
                  driver_errors=errors, owners_after=remaining, failure=failure, audit=audit,
                  driver_sha256=driver_hash, monitor_sha256=monitor_hash)
    (args.output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2), flush=True)
    return int(bool(failure or errors or remaining or monitor is None or monitor.returncode))


if __name__ == '__main__':
    raise SystemExit(main())
