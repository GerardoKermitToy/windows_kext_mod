"""Bounded process-inventory and presentation regressions (Administrator required)."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
CREATE = re.compile(r'\[PROCESS_CREATE\] pid=(\d+) parent_pid=(\d+)')
EXIT = re.compile(r'\[PROCESS_EXIT\] pid=(\d+)')


def wait_for(predicate, timeout=8, description='condition'):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.025)
    raise AssertionError('Timed out waiting for ' + description)


def text(path):
    return path.read_text(encoding='utf-8', errors='replace') if path.exists() else ''


def worker(args):
    child = None
    if args.worker == 'parent':
        child = subprocess.Popen([
            sys.executable, '-I', str(Path(__file__).resolve()), '--worker', 'child',
            '--worker-info', str(args.worker_info.with_suffix('.child.json')),
            '--worker-stop', str(args.worker_stop.with_suffix('.child.stop')),
        ])
    info = {'pid': os.getpid(), 'parent_pid': os.getppid()}
    if child:
        info['child'] = child.pid
    temporary = args.worker_info.with_suffix('.tmp')
    temporary.write_text(json.dumps(info), encoding='utf-8')
    temporary.replace(args.worker_info)
    deadline = time.monotonic() + 70
    while not args.worker_stop.exists() and time.monotonic() < deadline:
        time.sleep(.025)
    # Deliberately do not kill/wait for the child: parent exit must not remove it
    # from the driver's live inventory. Both workers have independent stop files.


def start_pair(directory, name):
    info = directory / (name + '.json')
    stop = directory / (name + '.stop')
    process = subprocess.Popen([
        sys.executable, '-I', str(Path(__file__).resolve()), '--worker', 'parent',
        '--worker-info', str(info), '--worker-stop', str(stop),
    ])
    metadata = wait_for(lambda: json.loads(text(info)) if text(info) else None,
                        description=name + ' metadata')
    wait_for(lambda: text(info.with_suffix('.child.json')), description=name + ' child')
    return process, metadata, stop


def process_is_live(pid):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        return code.value == 259
    finally:
        kernel.CloseHandle(handle)


def system_processes():
    result = subprocess.run([
        'powershell.exe', '-NoProfile', '-Command',
        'Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId | ConvertTo-Json -Compress',
    ], capture_output=True, text=True, check=True, timeout=20)
    return {int(row['ProcessId']): int(row['ParentProcessId']) for row in json.loads(result.stdout)}


def assert_cleanup(monitor):
    status = monitor.poll() if isinstance(monitor, subprocess.Popen) else monitor.returncode
    assert status == 0, ('Monitor exit', status)
    probe = subprocess.run(['sc.exe', 'query', 'PortmasterKext'], capture_output=True, timeout=10)
    assert probe.returncode == 1060, ('Driver service remains', probe.stdout.decode(errors='replace'))


def loopback_controls():
    results = []
    for family, address in [(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')]:
        payload = b'process-event-auto-verdict' + bytes(range(250))
        with socket.socket(family, socket.SOCK_STREAM) as server, socket.socket(family, socket.SOCK_STREAM) as client:
            server.settimeout(4)
            client.settimeout(4)
            server.bind((address, 0))
            server.listen(1)
            client.connect(server.getsockname())
            peer, _ = server.accept()
            with peer:
                peer.settimeout(4)
                client.sendall(payload)
                received = b''
                while len(received) < len(payload):
                    chunk = peer.recv(len(payload) - len(received))
                    assert chunk, 'TCP EOF'
                    received += chunk
                assert received == payload
                peer.sendall(received)
                received = b''
                while len(received) < len(payload):
                    chunk = client.recv(len(payload) - len(received))
                    assert chunk, 'TCP reply EOF'
                    received += chunk
                assert received == payload
        with socket.socket(family, socket.SOCK_DGRAM) as server, socket.socket(family, socket.SOCK_DGRAM) as client:
            server.settimeout(4)
            client.settimeout(4)
            server.bind((address, 0))
            client.sendto(payload, server.getsockname())
            received, peer = server.recvfrom(4096)
            assert received == payload
            server.sendto(received, peer)
            received, peer = client.recvfrom(4096)
            assert received == payload and peer == server.getsockname()
        results.append({'family': family, 'tcp': True, 'udp': True})
    return results


def run_process_case(args, directory):
    directory.mkdir()
    records = directory / 'records.log'
    pairs = []
    monitor = None
    results = {}
    with (directory / 'console.log').open('w', encoding='utf-8') as console:
        try:
            pair = start_pair(directory, 'existing')
            pairs.append(pair)
            before = system_processes()
            command = [str(args.monitor), '--duration', '20', '--poll', '5000',
                       '--process-events-only', '--timestamps', '--out', str(records), str(args.driver)]
            monitor = subprocess.Popen(command, stdout=console, stderr=subprocess.STDOUT)
            has_created = lambda pid, parent: (str(pid), str(parent)) in CREATE.findall(text(records))
            has_exit = lambda pid: str(pid) in EXIT.findall(text(records))
            for pid, parent in [(pair[1]['pid'], pair[1]['parent_pid']), (pair[1]['child'], pair[1]['pid']), (0, 0), (4, 0)]:
                wait_for(lambda pid=pid, parent=parent: has_created(pid, parent), description=f'baseline {pid}/{parent}')
            after = system_processes()
            stable = {pid: parent for pid, parent in before.items() if after.get(pid) == parent}
            for pid, parent in stable.items():
                assert has_created(pid, parent), ('Missing stable process', pid, parent)
            results['stable_processes_checked'] = len(stable)

            started = time.monotonic()
            pair = start_pair(directory, 'new')
            pairs.append(pair)
            for pid, parent in [(pair[1]['pid'], pair[1]['parent_pid']), (pair[1]['child'], pair[1]['pid'])]:
                wait_for(lambda pid=pid, parent=parent: has_created(pid, parent), timeout=2,
                         description=f'immediate creation {pid}/{parent}')
            results['creation_seconds_with_5s_poll'] = time.monotonic() - started
            assert results['creation_seconds_with_5s_poll'] < 2, 'Creation waited for the polling interval'
            transient = []
            for _ in range(12):
                child = subprocess.Popen([sys.executable, '-I', '-c', 'pass'])
                transient.append(child.pid)
                assert child.wait(timeout=5) == 0
            for pid in transient:
                wait_for(lambda pid=pid: has_created(pid, os.getpid()) and has_exit(pid),
                         description=f'short-lived process {pid}')
            results['short_lived_processes'] = len(transient)
            results['network_controls'] = loopback_controls()

            for process, info, stop in pairs:
                stop.touch()
                assert process.wait(timeout=5) == 0
                wait_for(lambda: has_exit(info['pid']), description='parent exit')
                assert process_is_live(info['child']), ('Child removed with parent', info)
                assert not has_exit(info['child']), ('Premature child exit', info)
                stop.with_suffix('.child.stop').touch()
                wait_for(lambda: has_exit(info['child']), description='child exit')
            assert monitor.wait(timeout=40) == 0
            assert_cleanup(monitor)
            output = text(records)
            assert output and all(CREATE.search(line) or EXIT.search(line) for line in output.splitlines()), output[-2000:]
            console_output = text(directory / 'console.log')
            # With --out, Emit writes records only to that file. Console may be
            # empty, but it must never contain unrelated banners/diagnostics.
            assert all(CREATE.search(line) or EXIT.search(line) for line in console_output.splitlines()), console_output[-2000:]
            live = {}
            for line in output.splitlines():
                creation = CREATE.search(line)
                if creation:
                    live[int(creation[1])] = int(creation[2])
                else:
                    live.pop(int(EXIT.search(line)[1]), None)
            for _, info, _ in pairs:
                assert info['pid'] not in live and info['child'] not in live, ('Stale terminated PID', info)
            results['final_inventory_count'] = len(live)
            results['success'] = True
        except BaseException as error:
            results.update(success=False, error=repr(error))
            raise
        finally:
            for process, info, stop in pairs:
                stop.touch()
                stop.with_suffix('.child.stop').touch()
                process.wait(timeout=8)
            if monitor is not None and monitor.poll() is None:
                monitor.wait(timeout=45)  # Only --duration stops the monitor.
            (directory / 'result.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return results


def run_default_case(args, directory):
    directory.mkdir()
    records = directory / 'records.log'
    with (directory / 'console.log').open('w', encoding='utf-8') as console:
        monitor = subprocess.Popen([str(args.monitor), '--duration', '6', '--poll', '100',
                                    '--out', str(records), str(args.driver)], stdout=console, stderr=subprocess.STDOUT)
        try:
            wait_for(lambda: 'Running for ' in text(directory / 'console.log'), description='default monitor')
            child = subprocess.Popen([sys.executable, '-I', '-c', 'pass'])
            assert child.wait(timeout=5) == 0
            controls = loopback_controls()
        finally:
            monitor.wait(timeout=35)
    assert_cleanup(monitor)
    output = text(records) + text(directory / 'console.log')
    assert '[PROCESS_CREATE]' not in output and '[PROCESS_EXIT]' not in output, 'Process events displayed by default'
    assert '[CONN ' in output, 'Default network output was suppressed'
    assert not re.search(r'\[LOG\s+(?:ERROR|CRIT)|\[WARN\]|verdict FAILED', output), output[-2000:]
    result = {'success': True, 'network_controls': controls, 'process_events_hidden': True}
    (directory / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result


def run_control_case(args, directory):
    directory.mkdir()
    probe = args.monitor.with_name('process_control_runtime.exe')
    completed = subprocess.run([str(probe), '--duration', '8', str(args.driver)],
                               capture_output=True, text=True, timeout=25)
    output = completed.stdout + completed.stderr
    (directory / 'console.log').write_text(output, encoding='utf-8')
    assert_cleanup(completed)
    assert completed.returncode == 0 and 'PASS:' in output, output
    result = {'success': True, 'no_events_before_request': True,
              'unread_snapshots_preserved_across_restarts': 3,
              'ioctl_and_write_rejected_after_shutdown': True}
    (directory / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result


def run_restart_case(args, directory, via_write):
    """Each explicit repeated command must publish another complete inventory."""
    directory.mkdir()
    records = directory / 'records.log'
    result = {'transport': 'WriteFile' if via_write else 'IOCTL'}
    monitor = None
    with (directory / 'console.log').open('w', encoding='utf-8') as console:
        try:
            command = [str(args.monitor), '--duration', '10', '--poll', '100',
                       '--process-events-only', '--process-events-restart-ms', '1000',
                       '--timestamps', '--out', str(records), str(args.driver)]
            if via_write:
                command.insert(1, '--process-events-write')
            monitor = subprocess.Popen(command, stdout=console, stderr=subprocess.STDOUT)

            def snapshots():
                return CREATE.findall(text(records)).count((str(os.getpid()), str(os.getppid())))

            wait_for(lambda: snapshots() >= 2, description=result['transport'] + ' repeated snapshot')
            child = subprocess.Popen([sys.executable, '-I', '-c', 'pass'])
            assert child.wait(timeout=5) == 0
            wait_for(lambda: (str(child.pid), str(os.getpid())) in CREATE.findall(text(records))
                     and str(child.pid) in EXIT.findall(text(records)),
                     description=result['transport'] + ' live events after restart')
            result['network_controls'] = loopback_controls()
            assert monitor.wait(timeout=25) == 0
            assert_cleanup(monitor)
            result['snapshots_for_stable_pid'] = snapshots()
            assert snapshots() >= 3, ('Missing full snapshots on repeated request', result)
            output = text(records)
            assert output and all(CREATE.search(line) or EXIT.search(line) for line in output.splitlines()), output[-2000:]
            assert not text(directory / 'console.log').strip(), text(directory / 'console.log')
            result['live_events_after_restart'] = True
            result['success'] = True
        except BaseException as error:
            result.update(success=False, error=repr(error))
            raise
        finally:
            if monitor is not None and monitor.poll() is None:
                monitor.wait(timeout=30)  # Only --duration stops the monitor.
            (directory / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result


def run_udp_unload_case(args, directory, ipv6):
    """Extra delivery control across unload, not a full standard runtime suite."""
    directory.mkdir()
    records = directory / 'records.log'
    family, address = (socket.AF_INET6, '::1') if ipv6 else (socket.AF_INET, '127.0.0.1')
    sent = post_exit = 0
    with (directory / 'console.log').open('w', encoding='utf-8') as console:
        monitor = subprocess.Popen([str(args.monitor), '--duration', '6', '--poll', '100',
                                    '--out', str(records), str(args.driver)], stdout=console, stderr=subprocess.STDOUT)
        try:
            wait_for(lambda: 'Running for ' in text(directory / 'console.log'), description='UDP monitor')
            with socket.socket(family, socket.SOCK_DGRAM) as server, socket.socket(family, socket.SOCK_DGRAM) as client:
                server.settimeout(4)
                client.settimeout(4)
                server.bind((address, 0))
                client.bind((address, 0))
                started = time.monotonic()
                while time.monotonic() - started < 10:
                    after_exit = monitor.poll() is not None
                    payload = sent.to_bytes(4, 'little') + bytes(range(256)) + bytes(15)
                    assert len(payload) == 275
                    client.sendto(payload, server.getsockname())
                    received, peer = server.recvfrom(4096)
                    assert received == payload and peer == client.getsockname(), 'UDP request mismatch'
                    server.sendto(received, peer)
                    received, peer = client.recvfrom(4096)
                    assert received == payload and peer == server.getsockname(), 'UDP reply mismatch'
                    sent += 1
                    post_exit += int(after_exit)
                    time.sleep(.1)
        finally:
            monitor.wait(timeout=35)
    assert_cleanup(monitor)
    assert post_exit >= 10, ('Insufficient post-exit exchanges', post_exit)
    output = text(records) + text(directory / 'console.log')
    assert not re.search(r'\[LOG\s+(?:WARN|ERROR|CRIT)|\[WARN\]|verdict FAILED', output), output[-2000:]
    result = {'success': True, 'ipv6': ipv6, 'exchanges': sent, 'post_exit_exchanges': post_exit,
              'payload_bytes': 275, 'interval_ms': 100,
              'legacy_IgnoreSpecialPorts': 'not available: redirect/special-port support removed; this is an extra control, not the legacy-flag regression'}
    (directory / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--monitor', type=Path, default=ROOT / 'kext_client/build/kext_monitor.exe')
    parser.add_argument('--driver', type=Path, default=ROOT / 'windows_kext/portmaster-kext.sys')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--worker', choices=['parent', 'child'])
    parser.add_argument('--worker-info', type=Path)
    parser.add_argument('--worker-stop', type=Path)
    args = parser.parse_args()
    if args.worker:
        worker(args)
        return
    if not args.output:
        parser.error('--output is required')
    assert ctypes.windll.shell32.IsUserAnAdmin(), 'Run as Administrator'
    assert subprocess.run(['sc.exe', 'query', 'PortmasterKext'], capture_output=True, timeout=10).returncode == 1060, 'Driver already installed/running'
    args.monitor = args.monitor.resolve()
    args.driver = args.driver.resolve()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    result = {'explicit_control': run_control_case(args, args.output / 'explicit_control'),
              'process_only': run_process_case(args, args.output / 'process_only'),
              'default': run_default_case(args, args.output / 'default'),
              'restart_ioctl': run_restart_case(args, args.output / 'restart_ioctl', False),
              'restart_write': run_restart_case(args, args.output / 'restart_write', True),
              'udp_unload_v4_control': run_udp_unload_case(args, args.output / 'udp_unload_v4', False),
              'udp_unload_v6_control': run_udp_unload_case(args, args.output / 'udp_unload_v6', True)}
    (args.output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
