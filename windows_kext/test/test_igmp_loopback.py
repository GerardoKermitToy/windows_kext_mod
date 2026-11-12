"""Bounded loopback IGMPv3 notification regression (Windows Administrator).

The monitor temporarily sends PermanentBlock for any connection involving
224.0.0.22, regardless of protocol. This can affect unrelated traffic while it
runs. Never run alongside another monitor or an existing PortmasterKext service.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import tempfile
import time

from monitor_window import check_monitor, start_monitor, wait_for_cleanup
from test_udp_flow_idle import driver_owners

ROOT = Path(__file__).resolve().parents[2]
ROUTERS = "224.0.0.22"


def join(receiver, group, interface):
    receiver.bind(("0.0.0.0", 0))
    receiver.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                        socket.inet_aton(group) + socket.inet_aton(interface))
    receiver.settimeout(2)


def send_and_receive(receiver, sender, group, payload):
    started = time.monotonic()
    sender.sendto(payload, (group, receiver.getsockname()[1]))
    received, peer = receiver.recvfrom(4096)
    elapsed = time.monotonic() - started
    if received != payload or peer[:2] != sender.getsockname()[:2] or elapsed >= 2:
        raise AssertionError((received, peer, sender.getsockname(), elapsed))
    receiver.settimeout(.3)
    try:
        extra, extra_peer = receiver.recvfrom(4096)
        raise AssertionError(f"duplicate datagram: {extra!r} {extra_peer}")
    except socket.timeout:
        pass
    finally:
        receiver.settimeout(2)
    return round(elapsed, 4)


def connection_entries(text, group):
    group_bytes = socket.inet_aton(group).hex()
    result = []
    for block in text.split("[CONN v4]")[1:]:
        lines = block.splitlines()
        if len(lines) < 5 or "outbound proto=2(" not in lines[0]:
            continue
        if "-> 224.0.0.22:0" not in lines[1] or "interface_index=1 " not in lines[2]:
            continue
        payload_match = re.search(r"payload: ([0-9a-fA-F]+)", lines[3])
        if not payload_match or group_bytes not in payload_match.group(1).lower():
            continue
        payload = bytes.fromhex(payload_match.group(1))
        if len(payload) < 32 or payload[24] != 0x22:
            continue
        header = payload[:(payload[0] & 0x0f) * 4]
        checksum = sum(int.from_bytes(header[i:i + 2], "big") for i in range(0, len(header), 2))
        while checksum >> 16:
            checksum = (checksum & 0xffff) + (checksum >> 16)
        if checksum != 0xffff:
            raise AssertionError(f"notification IPv4 checksum is invalid: {header.hex()}")
        id_match = re.match(r" id=(\d+) ", lines[0])
        if id_match:
            result.append({"id": int(id_match.group(1)), "payload": payload_match.group(1),
                           "verdict": lines[4].strip()})
    return result


def control_ends(text):
    return [line for line in text.splitlines()
            if "[END  v4]" in line and " outbound proto=2" in line
            and " 127." in line and " -> 224.0.0.22:0" in line]


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipv4-loopback", default="127.0.0.1")
    parser.add_argument("--verdict-delay-ms", type=int, default=0)
    parser.add_argument("--assert-no-end", action="store_true",
                        help="check through idle cleanup that no IGMP END is emitted")
    parser.add_argument("--monitor", type=Path, default=ROOT / "kext_client/build/kext_monitor.exe")
    parser.add_argument("--driver", type=Path, default=ROOT / "windows_kext/portmaster-kext.sys")
    args = parser.parse_args()
    if os.name != "nt" or not ipaddress.ip_address(args.ipv4_loopback).is_loopback:
        parser.error("Windows and an IPv4 loopback address are required")
    if ipaddress.ip_address(args.ipv4_loopback).version != 4:
        parser.error("--ipv4-loopback must be IPv4")
    if not 0 <= args.verdict_delay_ms <= 10_000:
        parser.error("--verdict-delay-ms must be 0..10000")
    if driver_owners():
        raise RuntimeError("refusing to interfere with an existing monitor or driver")
    for binary in (args.monitor, args.driver):
        if not binary.is_file():
            raise RuntimeError(f"binary not found: {binary}")

    output_root = ROOT / "windows_kext/test/_out"
    output_root.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="igmp_loopback_", dir=output_root))
    records, console = output / "records.log", output / "console.log"
    third = 100 + (os.getpid() % 80)
    baseline_group, group = f"239.255.{third}.230", f"239.255.{third}.231"
    result = {"output": str(output), "interface": args.ipv4_loopback,
              "baseline_group": baseline_group, "driver_group": group}

    # First confirm the same membership and UDP exchange without the driver.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        join(receiver, baseline_group, args.ipv4_loopback)
        sender.bind((args.ipv4_loopback, 0))
        sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(args.ipv4_loopback))
        result["baseline_delivery_seconds"] = send_and_receive(receiver, sender, baseline_group, b"baseline")
    if driver_owners():
        raise RuntimeError("a monitor or driver appeared during the baseline")

    duration = 125 if args.assert_no_end else max(18, 12 + (args.verdict_delay_ms + 999) // 1000)
    command = [str(args.monitor), "--duration", str(duration), "--poll", "200", "--timestamps",
               "--no-bandwidth", "--payload", "--filter-protocol", "2", "--verdict", "permanent-block",
               "--match", ROUTERS, "--verdict-delay-ms", str(args.verdict_delay_ms), "--out", str(records),
               str(args.driver)]
    monitor = None
    with console.open("w", encoding="utf-8") as log:
        monitor = start_monitor(command, stdout=log, stderr=-2)
        try:
            wait_for(lambda: "Running for " in read_text(console), 10, monitor, "monitor startup")
            check_monitor(monitor)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                join(receiver, group, args.ipv4_loopback)
                sender.bind((args.ipv4_loopback, 0))
                sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                                  socket.inet_aton(args.ipv4_loopback))
                result["before_verdict_delivery_seconds"] = send_and_receive(receiver, sender, group, b"before")
                entries = wait_for(lambda: connection_entries(read_text(records), group), 8, monitor,
                                   "loopback IGMP notification")
                first = entries[0]
                if first["id"] == 0 or "<== MATCHED" not in first["verdict"]:
                    raise AssertionError(f"invalid notification: {first}")
                if args.verdict_delay_ms:
                    wait_for(lambda: re.search(rf"\[VERDICT\] id={first['id']} -> verdict PermanentBlock sent.*MATCHED",
                                               read_text(records)),
                             5 + args.verdict_delay_ms / 1000, monitor, "delayed IGMP verdict")
                elif "PermanentBlock sent" not in first["verdict"]:
                    raise AssertionError(f"missing IGMP block verdict: {first}")
                result["after_verdict_delivery_seconds"] = send_and_receive(receiver, sender, group, b"after")
                if args.assert_no_end:
                    start = time.monotonic()
                    while time.monotonic() - start < 100:
                        if monitor.poll() is not None:
                            raise RuntimeError("monitor exited while checking for unexpected END")
                        if control_ends(read_text(records)):
                            raise AssertionError("unexpected IGMP END during idle cleanup")
                        time.sleep(.5)
                    result["no_end_observed_seconds"] = round(time.monotonic() - start, 2)
                # Keep the socket alive until the checks above have finished.
                result["receiver_open_during_checks"] = receiver.fileno() != -1
                time.sleep(1)
            check_monitor(monitor)
        finally:
            code = wait_for_cleanup(monitor, timeout=duration + 30)
    if code or driver_owners():
        raise RuntimeError(f"monitor cleanup failed: exit={code}, owners={driver_owners()}")

    text = read_text(records)
    if control_ends(text):
        raise AssertionError(f"unexpected IGMP END: {control_ends(text)}")
    entries = connection_entries(text, group)
    ids = [entry["id"] for entry in entries]
    if not entries or 0 in ids or len(ids) != len(set(ids)):
        raise AssertionError(f"missing/non-unique IGMP notification IDs: {entries}")
    for entry in entries:
        if "<== MATCHED" not in entry["verdict"]:
            raise AssertionError(f"IGMP notification was not matched: {entry}")
        if args.verdict_delay_ms:
            expected = f"verdict PermanentBlock scheduled after {args.verdict_delay_ms} ms"
            sent = re.search(rf"\[VERDICT\] id={entry['id']} -> verdict PermanentBlock sent.*MATCHED", text)
            if expected not in entry["verdict"] or not sent:
                raise AssertionError(f"missing delayed IGMP verdict: {entry}")
        elif "verdict PermanentBlock sent" not in entry["verdict"]:
            raise AssertionError(f"missing IGMP verdict: {entry}")
    failures = [line for line in text.splitlines() if "network-send injection failed" in line]
    matching_failures = [line for line in failures if "proto=2 127." in line and "-> 224.0.0.22" in line]
    if matching_failures:
        raise AssertionError(f"loopback IGMP network-send failures: {matching_failures}")
    result.update(igmp_events=entries, other_network_send_failures=failures, pass_=True)
    (output / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
