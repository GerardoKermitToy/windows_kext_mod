"""Bounded IPv4 NAT/ICS transit-ICMP regression (Administrator).

The SSH host must route the target through this Windows machine's NAT. Check
that transit ping has no duplicates and never reaches userspace policy, even
with a narrow Drop verdict, while local ping still obeys that verdict. SSH is
opened only after the monitor is running, with a 30-second connection timeout.
The monitor always unloads through --duration, including on assertion failure.
"""
import argparse
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
import traceback
import xml.etree.ElementTree as ET

from monitor_window import start_monitor, check_monitor, wait_for_cleanup
from test_tcp_rst_closure import owners

ROOT = Path(__file__).resolve().parents[2]
TRANSIT_PATTERN = b'PM_TRANSIT_ICMP!'
PING_SUMMARY = re.compile(
    r'(\d+) packets transmitted,\s*(\d+) (?:packets )?received'
    r'(?:,\s*\+(\d+) duplicates)?'
)
LOCAL_EVENT = re.compile(
    r'\[CONN v4\] id=\d+ pid=(\d+) (?:tid=\d+ )?(inbound|outbound) proto=1\(ICMP\)'
)


def ping_statistics(text):
    match = PING_SUMMARY.search(text)
    if not match:
        raise AssertionError('missing remote ping summary: ' + text)
    sent, received, duplicates = match.groups()
    return dict(sent=int(sent), received=int(received),
                duplicates=int(duplicates or 0), duplicate_reply='(DUP!)' in text)


def check_transit_records(text):
    for packet in re.findall(r'^\s+payload: ([0-9a-fA-F]+)$', text, re.MULTILINE):
        if TRANSIT_PATTERN in bytes.fromhex(packet):
            raise AssertionError('NAT transit ICMP reached the userspace verdict path')


def check_wfp_sublayers(text):
    # netsh can append a separate firewallState document after the WFP root.
    end = text.find('</wfpstate>')
    if end < 0:
        raise AssertionError('missing WFP state document')
    document = ET.fromstring(text[:end + len('</wfpstate>')])
    sublayers = {
        item.findtext('subLayerKey'): dict(name=item.findtext('displayData/name'),
                                         weight=int(item.findtext('weight')))
        for item in document.findall('subLayers/item')
    }
    by_name = {item['name']: key for key, item in sublayers.items()}
    inbound_guid = by_name.get('PortmasterInboundPacketSublayer')
    default_guid = by_name.get('PortmasterSublayer')
    assert inbound_guid and default_guid, ('missing Portmaster sublayer', sublayers)
    assert 'FWPM_SUBLAYER_UNIVERSAL' in sublayers, ('missing UNIVERSAL sublayer', sublayers)
    inbound_weight = sublayers[inbound_guid]['weight']
    default_weight = sublayers[default_guid]['weight']
    universal_weight = sublayers['FWPM_SUBLAYER_UNIVERSAL']['weight']
    assert inbound_weight < universal_weight < default_weight, (
        'Portmaster sublayer priority crossed native NAT', sublayers)
    filters = {
        item.findtext('displayData/name'): item.findtext('subLayerKey')
        for item in document.findall('layers/item/filters/item')
        if item.findtext('displayData/name', '').startswith('Portmaster')
    }
    inbound_names = {'Portmaster Packet Inbound IPv4', 'Portmaster Packet Inbound IPv6'}
    assert inbound_names <= filters.keys(), ('missing inbound packet filter', filters)
    for name, guid in filters.items():
        expected = inbound_guid if name in inbound_names else default_guid
        assert guid == expected, ('incorrect Portmaster filter sublayer', name, guid, expected)
    return dict(inbound_weight=inbound_weight, universal_weight=universal_weight,
                default_weight=default_weight, filters=filters)


def capture_wfp_sublayers(path):
    state = subprocess.run(['netsh.exe', 'wfp', 'show', 'state', 'file=' + str(path.resolve())],
                           capture_output=True, timeout=25)
    assert state.returncode == 0, state.stdout + state.stderr
    return check_wfp_sublayers(path.read_text(encoding='utf-8-sig'))


def wait_ready(monitor, console):
    deadline = time.monotonic() + 10
    while 'Running for ' not in console.read_text(errors='replace'):
        if monitor.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError('monitor did not start: ' + console.read_text(errors='replace'))
        time.sleep(0.05)


def require_loaded(monitor):
    check_monitor(monitor)
    observation = monitor._driver_window['last_observation']
    if observation['phase'] != 'loaded':
        raise AssertionError('functional check ran outside the loaded driver window')


def run_case(args, verdict, output):
    existing = owners()
    if existing:
        raise RuntimeError('refusing to interfere with driver owner: ' + existing)
    output.mkdir()
    console = output / 'console.log'
    records = output / 'records.log'
    result = dict(verdict=verdict)
    error = None
    monitor = None
    with console.open('wb') as log:
        try:
            command = [str(args.monitor.resolve()), '--duration', '50', '--poll', '100',
                       '--timestamps', '--no-bandwidth', '--filter-protocol', '1',
                       '--filter-ip', str(args.target), '--payload', '--out', str(records.resolve()),
                       '--verdict', verdict, '--match', str(args.target), str(args.driver.resolve())]
            monitor = start_monitor(command, stdout=log, stderr=subprocess.STDOUT)
            wait_ready(monitor, console)
            require_loaded(monitor)
            result['wfp'] = capture_wfp_sublayers(output / 'wfp-loaded.xml')
            require_loaded(monitor)
            # Do not connect before driver startup, and do not alter remote routes.
            remote = subprocess.run(
                ['ssh.exe', '-o', 'ConnectTimeout=30', '-o', 'BatchMode=yes',
                 '-i', str(args.ssh_key.resolve()), args.ssh_host,
                 f'ping -n -c {args.count} -i 0.25 -W 2 -w 8 '
                 f'-p {TRANSIT_PATTERN.hex()} {args.target}'],
                capture_output=True, text=True, timeout=42,
            )
            (output / 'remote-ping.log').write_text(remote.stdout + remote.stderr, encoding='utf-8')
            require_loaded(monitor)
            result['transit'] = ping_statistics(remote.stdout)
            assert remote.returncode == 0, remote.stdout + remote.stderr
            assert result['transit']['sent'] == result['transit']['received'] == args.count, result
            assert not result['transit']['duplicates'] and not result['transit']['duplicate_reply'], result
            # Give the flushed record stream time to catch up before checking it.
            time.sleep(0.2)
            check_transit_records(records.read_text(encoding='utf-8', errors='replace'))

            local = subprocess.Popen(
                ['ping.exe', '-4', '-n', '2', '-w', '1000', str(args.target)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            local_output, _ = local.communicate(timeout=8)
            (output / 'local-ping.log').write_bytes(local_output)
            require_loaded(monitor)
            # TTL= is stable across Windows display languages; error replies do
            # not have it. A process exit code alone also accepts some ICMP errors.
            replies = len(re.findall(rb'TTL=\d+', local_output, re.IGNORECASE))
            result['local'] = dict(pid=local.pid, replies=replies, exit=local.returncode)
            accepting = verdict in ('accept', 'permanent-accept')
            assert replies == (2 if accepting else 0), result
            time.sleep(0.2)
            text = records.read_text(encoding='utf-8', errors='replace')
            local_events = [(int(pid), direction) for pid, direction in LOCAL_EVENT.findall(text)
                            if int(pid) == local.pid]
            assert any(direction == 'outbound' for _, direction in local_events), result
            if accepting:
                assert any(direction == 'inbound' for _, direction in local_events), (
                    'local reply lost its originating PID', result)
            result['local']['events'] = local_events
        except Exception:
            error = traceback.format_exc()
            result['error'] = error
        finally:
            if monitor is not None:
                result['monitor_exit'] = wait_for_cleanup(monitor, timeout=80)
    result['remaining_owners'] = owners()
    text = records.read_text(encoding='utf-8', errors='replace') if records.exists() else ''
    result['driver_logs'] = re.findall(r'^.*\[LOG [^\r\n]+', text, re.MULTILINE)
    if not error:
        try:
            assert result['monitor_exit'] == 0, result
            assert not result['remaining_owners'], result
            assert not result['driver_logs'], result
            check_transit_records(text)
        except Exception:
            error = traceback.format_exc()
            result['error'] = error
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    if error:
        raise AssertionError(error)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-host', default='root@192.168.219.15')
    parser.add_argument('--ssh-key', type=Path, default=Path.home() / '.ssh/id_ed25519_kext')
    parser.add_argument('--target', type=ipaddress.IPv4Address, default=ipaddress.IPv4Address('8.8.8.8'))
    parser.add_argument('--count', type=int, default=6)
    parser.add_argument('--repeats', type=int, default=1)
    parser.add_argument('--verdicts', nargs='+', default=['permanent-accept', 'drop'],
                        choices=('accept', 'permanent-accept', 'drop', 'permanent-drop'))
    parser.add_argument('--monitor', type=Path, default=ROOT / 'kext_client/build/kext_monitor.exe')
    parser.add_argument('--driver', type=Path, default=ROOT / 'windows_kext/portmaster-kext.sys')
    parser.add_argument('--output', type=Path, default=Path(__file__).parent / '_out' /
                        ('icmp_transit_' + datetime.now().strftime('%Y%m%d_%H%M%S')))
    args = parser.parse_args()
    if os.name != 'nt' or not 2 <= args.count <= 10 or not 1 <= args.repeats <= 5:
        parser.error('requires Windows, --count 2..10 and --repeats 1..5')
    for binary in (args.monitor, args.driver, args.ssh_key):
        if not binary.is_file():
            parser.error(f'missing file: {binary}')
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    for iteration in range(args.repeats):
        for verdict in args.verdicts:
            results.append(run_case(args, verdict, args.output / f'{iteration + 1}-{verdict}'))
    (args.output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(f'PASS: {len(results)} bounded transit ICMP cases; artifacts: {args.output}', flush=True)


if __name__ == '__main__':
    main()
