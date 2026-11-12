"""Exercise native IPv6 multicast membership through the WFP loopback path.

Run as Administrator with no existing driver owner. The bypass test temporarily
matches traffic involving ff02::16, regardless of protocol, for a blocking
verdict. The monitor always uses --duration and owns driver load/unload.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import struct
import tempfile
import time

from monitor_window import check_monitor, start_monitor, wait_for_cleanup
from test_udp_flow_idle import driver_owners

ROOT = Path(__file__).resolve().parents[2]
ROUTERS = "ff02::16"


def fingerprint(packet):
    value = 0xcbf29ce484222325
    for byte in packet[:128]:
        value = ((value ^ byte) * 0x100000001b3) & 0xffffffffffffffff
    return f"{value:016x}"


def control_ends(text, destinations=(ROUTERS,)):
    destinations = {ipaddress.IPv6Address(address).exploded for address in destinations}
    source = "0000:0000:0000:0000:0000:0000:0000:0001:0 -> "
    return [line for line in text.splitlines()
            if "[END  v6]" in line and " outbound proto=58" in line
            and any(f"{source}{destination}:0" in line for destination in destinations)]


def read_text(path):
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def wait_for(predicate, seconds, monitor, description):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if monitor.poll() is not None:
            raise RuntimeError(f"monitor exited while waiting for {description}")
        value = predicate()
        if value:
            return value
        time.sleep(.1)
    raise TimeoutError(f"missing {description}")


def entries(text, group):
    group_bytes = socket.inet_pton(socket.AF_INET6, group)
    result = []
    for block in text.split("[CONN v6]")[1:]:
        lines = block.splitlines()
        if len(lines) < 5 or "outbound proto=58(" not in lines[0]:
            continue
        if "interface_index=1 " not in lines[2]:
            continue
        match = re.search(r"payload: ([0-9a-fA-F]+)", lines[3])
        if not match:
            continue
        packet = bytes.fromhex(match.group(1))
        # A real generated MLDv2 report has a Hop-by-Hop header. Search for our
        # unique group in the ICMPv6 payload, not just in the IPv6 header.
        if len(packet) < 56 or packet[6] != 0 or packet[40] != 58 or packet[48] != 143:
            continue
        if (packet[8:24] != socket.inet_pton(socket.AF_INET6, "::1") or
                packet[24:40] != socket.inet_pton(socket.AF_INET6, ROUTERS)):
            continue
        if group_bytes not in packet[56:]:
            continue
        # The event must retain the original valid ICMPv6 checksum, including
        # the upper-layer length but excluding the Hop-by-Hop header.
        upper = packet[48:40 + int.from_bytes(packet[4:6], "big")]
        pseudo = packet[8:40] + len(upper).to_bytes(4, "big") + bytes(3) + bytes([58])
        checksum_data = pseudo + upper
        if len(checksum_data) & 1:
            checksum_data += b"\0"
        checksum = sum(int.from_bytes(checksum_data[i:i + 2], "big")
                       for i in range(0, len(checksum_data), 2))
        while checksum >> 16:
            checksum = (checksum & 0xffff) + (checksum >> 16)
        if checksum != 0xffff:
            raise AssertionError(f"invalid MLD event checksum: {packet.hex()}")
        event_id = re.match(r" id=(\d+) ", lines[0])
        if event_id:
            result.append({"id": int(event_id.group(1)), "payload": packet.hex(),
                           "fingerprint": fingerprint(packet), "verdict": lines[4].strip()})
    return result


def join(receiver, group):
    receiver.bind(("::", 0))
    receiver.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                        socket.inet_pton(socket.AF_INET6, group) + struct.pack("=I", 1))
    receiver.settimeout(2)


def exchange(receiver, sender, group, payload):
    start = time.monotonic()
    sender.sendto(payload, (group, receiver.getsockname()[1], 0, 1))
    data, peer = receiver.recvfrom(4096)
    elapsed = time.monotonic() - start
    if data != payload or peer[:2] != sender.getsockname()[:2] or elapsed >= 2:
        raise AssertionError((data, peer, sender.getsockname(), elapsed))
    receiver.settimeout(.3)
    try:
        extra, peer = receiver.recvfrom(4096)
        raise AssertionError(f"duplicate datagram: {extra!r} {peer}")
    except socket.timeout:
        pass
    finally:
        receiver.settimeout(2)
    return round(elapsed, 4)


def sockets(group):
    receiver = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sender = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        join(receiver, group)
        sender.bind(("::1", 0))
        sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, 1)
        sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
        return receiver, sender
    except Exception:
        receiver.close()
        sender.close()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--diagnose", action="store_true",
                        help="expect matching failures with the pre-bypass driver")
    parser.add_argument("--verdict-delay-ms", type=int, default=0)
    parser.add_argument("--assert-no-end", action="store_true",
                        help="check through idle cleanup that no ICMPv6 END is emitted")
    parser.add_argument("--monitor", type=Path, default=ROOT / "kext_client/build/kext_monitor.exe")
    parser.add_argument("--driver", type=Path, default=ROOT / "windows_kext/portmaster-kext.sys")
    args = parser.parse_args()
    if os.name != "nt" or not 0 <= args.verdict_delay_ms <= 10_000:
        parser.error("Windows and a verdict delay of 0..10000 ms are required")
    if args.diagnose and (args.verdict_delay_ms or args.assert_no_end):
        parser.error("--diagnose does not use delayed or idle verdict tests")
    if driver_owners():
        raise RuntimeError("refusing to interfere with an existing monitor or driver")
    for binary in (args.monitor, args.driver):
        if not binary.is_file():
            raise FileNotFoundError(binary)
    root = ROOT / "windows_kext/test/_out"
    root.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="mld_loopback_", dir=root))
    records, console = output / "records.log", output / "console.log"
    suffix = os.getpid() & 0xffff
    baseline_group = f"ff02::a1:{suffix:x}"
    group = f"ff02::a2:{suffix:x}"
    result = {"output": str(output), "group": group, "diagnose": args.diagnose}
    receiver, sender = sockets(baseline_group)
    with receiver, sender:
        result["baseline_delivery_seconds"] = exchange(receiver, sender, baseline_group, b"baseline")
    if driver_owners():
        raise RuntimeError("a driver owner appeared during baseline")
    duration = 125 if args.assert_no_end else max(20, 13 + (args.verdict_delay_ms + 999) // 1000)
    verdict = "permanent-accept" if args.diagnose else "permanent-block"
    command = [str(args.monitor), "--duration", str(duration), "--poll", "200", "--timestamps",
               "--no-bandwidth", "--payload", "--filter-protocol", "58", "--verdict", verdict,
               "--match", ROUTERS, "--verdict-delay-ms", str(args.verdict_delay_ms),
               "--out", str(records), str(args.driver)]
    with console.open("w", encoding="utf-8") as log:
        monitor = start_monitor(command, stdout=log, stderr=-2)
        try:
            wait_for(lambda: "Running for " in read_text(console), 10, monitor, "monitor startup")
            check_monitor(monitor)
            receiver, sender = sockets(group)
            with receiver, sender:
                result["before_verdict_delivery_seconds"] = exchange(receiver, sender, group, b"before")
                found = wait_for(lambda: entries(read_text(records), group), 8, monitor, "MLD report")
                first = found[0]
                if first["id"] == 0 or "<== MATCHED" not in first["verdict"]:
                    raise AssertionError(f"invalid notification: {first}")
                if args.verdict_delay_ms:
                    wait_for(lambda: re.search(rf"\[VERDICT\] id={first['id']} -> verdict PermanentBlock sent.*MATCHED",
                                               read_text(records)),
                             5 + args.verdict_delay_ms / 1000, monitor, "delayed MLD verdict")
                result["after_verdict_delivery_seconds"] = exchange(receiver, sender, group, b"after")
                if args.assert_no_end:
                    start = time.monotonic()
                    while time.monotonic() - start < 100:
                        if monitor.poll() is not None:
                            raise RuntimeError("monitor exited while checking for unexpected END")
                        if control_ends(read_text(records)):
                            raise AssertionError("unexpected ICMPv6 END during idle cleanup")
                        time.sleep(.5)
                    result["no_end_observed_seconds"] = round(time.monotonic() - start, 2)
                result["receiver_open_during_checks"] = receiver.fileno() != -1
                time.sleep(1)
            check_monitor(monitor)
        finally:
            code = wait_for_cleanup(monitor, timeout=duration + 30)
    if code or driver_owners():
        raise RuntimeError(f"monitor cleanup failed: exit={code}, owners={driver_owners()}")
    text = read_text(records)
    if not args.diagnose and control_ends(text):
        raise AssertionError(f"unexpected ICMPv6 END: {control_ends(text)}")
    found = entries(text, group)
    ids = [entry["id"] for entry in found]
    if not found or 0 in ids or len(ids) != len(set(ids)):
        raise AssertionError(f"missing/non-unique MLD event IDs: {found}")
    expected = "PermanentAccept" if args.diagnose else "PermanentBlock"
    for entry in found:
        if "<== MATCHED" not in entry["verdict"]:
            raise AssertionError(f"unmatched MLD event: {entry}")
        if args.verdict_delay_ms:
            sent = re.search(rf"\[VERDICT\] id={entry['id']} -> verdict PermanentBlock sent.*MATCHED", text)
            if not sent:
                raise AssertionError(f"missing delayed MLD verdict: {entry}")
        elif f"verdict {expected} sent" not in entry["verdict"]:
            raise AssertionError(f"missing MLD verdict: {entry}")
    failures = [line for line in text.splitlines() if "network-send injection failed" in line]
    matched = [line for line in failures if any(f"fingerprint={entry['fingerprint']}" in line for entry in found)]
    if args.diagnose and not matched:
        raise AssertionError(f"no failure matched any test report fingerprint: {failures}")
    if not args.diagnose and matched:
        raise AssertionError(f"loopback MLD network-send failures: {matched}")
    result.update(mld_events=found, matching_network_send_failures=matched,
                  all_network_send_failures=failures, **{"pass": True})
    (output / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
