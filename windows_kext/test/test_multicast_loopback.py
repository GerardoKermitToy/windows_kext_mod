"""Compare IPv4/IPv6 multicast loopback delivery without and with the WFP driver.

Requires Windows Administrator privileges. Uses only loopback multicast, owns all
sockets it creates, and lets the duration-bounded monitor unload its own driver.
"""

import argparse
import ctypes
import ipaddress
import json
import re
from collections import Counter
import multiprocessing
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import tempfile
import time

from monitor_window import check_monitor, start_monitor, wait_for_cleanup
from test_udp_flow_idle import driver_owners


ROOT = Path(__file__).resolve().parents[2]
GROUP = "239.255.23.91"
GROUP_V6 = "ff02::114"
INTERFACE = "127.0.0.1"
PAYLOADS = [b"loopback-mcast-0", b"loopback-mcast-1", b"loopback-mcast-2"]


def join_group(receiver, group, interface, interface_index):
    if receiver.family == socket.AF_INET6:
        membership = socket.inet_pton(socket.AF_INET6, group) + struct.pack("=I", interface_index)
        receiver.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, membership)
    else:
        membership = socket.inet_aton(group) + socket.inet_aton(interface)
        receiver.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)


def child_receiver(port, interface, group, interface_index, channel):
    """Receive on a separately owned socket until the parent finishes sending."""
    family = socket.AF_INET6 if ":" in group else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as receiver:
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            receiver.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", port))
            join_group(receiver, group, interface, interface_index)
            channel.send({"ready": os.getpid()})
            deliveries = []
            deadline = time.monotonic() + 20
            stopping = False
            while time.monotonic() < deadline:
                ready, _, _ = select.select([receiver], [], [], 0.05)
                if ready:
                    data, peer = receiver.recvfrom(65535)
                    deliveries.append([data.decode("ascii"), *peer[:2]])
                if channel.poll():
                    stopping = channel.recv() == "stop"
                if stopping and not ready:
                    break
            else:
                raise TimeoutError("child receiver timed out")
            channel.send({"deliveries": deliveries})
    except Exception as error:
        channel.send({"error": repr(error)})
    finally:
        channel.close()


def exchange(source, member_count, cross_process=False, interface=INTERFACE, expect_block=False,
             group=GROUP, interface_index=1, source_port=0):
    family = socket.AF_INET6 if ":" in group else socket.AF_INET
    wildcard = "::" if family == socket.AF_INET6 else "0.0.0.0"
    members = []
    nonmember = None
    sender = None
    child = None
    parent_channel = None
    child_pid = None
    try:
        local_members = member_count - int(cross_process)
        for _ in range(local_members):
            receiver = socket.socket(family, socket.SOCK_DGRAM)
            members.append(receiver)
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            receiver.bind((wildcard, members[0].getsockname()[1] if len(members) > 1 else 0))
            join_group(receiver, group, interface, interface_index)
        destination_port = members[0].getsockname()[1]
        if cross_process:
            context = multiprocessing.get_context("spawn")
            parent_channel, child_channel = context.Pipe()
            child = context.Process(target=child_receiver,
                                    args=(destination_port, interface, group, interface_index, child_channel))
            child.start()
            child_channel.close()
            if not parent_channel.poll(8):
                raise TimeoutError("child receiver did not become ready")
            message = parent_channel.recv()
            if "ready" not in message:
                raise RuntimeError(f"child receiver failed: {message}")
            child_pid = message["ready"]
        # A socket bound to the same port but not joined to the group must not
        # receive the packet, even if an authorized member does.
        nonmember = socket.socket(family, socket.SOCK_DGRAM)
        nonmember.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        nonmember.bind((wildcard, destination_port))
        sender = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, interface_index)
            sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)
            sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
            destination = (group, destination_port, 0, interface_index)
        else:
            sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface))
            sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
            # Exercise the physical-interface local loop without transmitting
            # the test multicast beyond this machine.
            sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL,
                              1 if ipaddress.ip_address(interface).is_loopback else 0)
            destination = (group, destination_port)
        sender.bind((source, source_port))
        sender_port = sender.getsockname()[1]
        deliveries = [[] for _ in members]
        send_errors = []
        for payload in PAYLOADS:
            try:
                sender.sendto(payload, destination)
            except OSError as error:
                send_errors.append({"payload": payload.decode("ascii"), "error": repr(error)})
                break
            # Keep each send distinct so first-packet replay is distinguishable
            # from subsequent packets that reuse the cached verdict.
            deadline = time.monotonic() + 0.5
            while time.monotonic() < deadline:
                ready, _, _ = select.select(members, [], [], max(0, deadline - time.monotonic()))
                if not ready:
                    break
                for receiver in ready:
                    data, peer = receiver.recvfrom(65535)
                    deliveries[members.index(receiver)].append([data.decode("ascii"), *peer[:2]])
                if all(len(received) >= PAYLOADS.index(payload) + 1 for received in deliveries):
                    break
        # Catch a late duplicate after all expected packets were delivered.
        deadline = time.monotonic() + 0.3
        while time.monotonic() < deadline:
            ready, _, _ = select.select(members, [], [], max(0, deadline - time.monotonic()))
            if not ready:
                break
            for receiver in ready:
                data, peer = receiver.recvfrom(65535)
                deliveries[members.index(receiver)].append([data.decode("ascii"), *peer[:2]])
        if child:
            parent_channel.send("stop")
            if not parent_channel.poll(8):
                raise TimeoutError("child receiver did not return its deliveries")
            message = parent_channel.recv()
            if "deliveries" not in message:
                raise RuntimeError(f"child receiver failed: {message}")
            deliveries.append(message["deliveries"])
        # Windows selects 127.0.0.1 as the source for a wildcard-bound IPv4
        # sender even when the selected loopback interface was 127.0.0.2.
        expected_source = (INTERFACE if family == socket.AF_INET and source == wildcard
                           and ipaddress.ip_address(interface).is_loopback else interface)
        expected = [] if expect_block else [
            [payload.decode("ascii"), expected_source, sender_port] for payload in PAYLOADS
        ]
        expected_by_member = [expected] * member_count
        nonmember_ready, _, _ = select.select([nonmember], [], [], 0)
        nonmember_received = bool(nonmember_ready)
        return {"interface": interface, "source_bind": source, "source_ip": expected_source,
                "members": member_count, "parent_pid": os.getpid(), "child_pid": child_pid,
                "sender_port": sender_port, "destination_port": destination_port,
                "deliveries": deliveries, "nonmember_received": nonmember_received,
                "send_errors": send_errors,
                "pass": not send_errors and not nonmember_received and deliveries == expected_by_member}
    finally:
        if child:
            # Child has a bounded deadline even if the parent failed earlier.
            if child.is_alive() and parent_channel:
                try:
                    parent_channel.send("stop")
                except (BrokenPipeError, EOFError, OSError):
                    pass
            child.join(timeout=21)
            if child.is_alive():
                child.terminate()
                child.join(timeout=3)
        if parent_channel:
            parent_channel.close()
        if sender:
            sender.close()
        if nonmember:
            nonmember.close()
        for receiver in members:
            receiver.close()


def run_matrix(label, interface=INTERFACE, expect_block=False, group=GROUP, interface_index=1,
               source_port=0):
    rows = []
    wildcard = "::" if ":" in group else "0.0.0.0"
    for source in (wildcard, interface):
        for count, cross_process in ((1, False), (2, False), (2, True)):
            row = exchange(source, count, cross_process, interface, expect_block, group,
                           interface_index, source_port)
            rows.append(row)
            print(json.dumps({"phase": label, **row}), flush=True)
    return rows


def event_tuple(row, group):
    """The monitor prints full IPv6 addresses followed by the UDP port."""
    local = ipaddress.ip_address(group).exploded.lower()
    remote = ipaddress.ip_address(row.get("source_ip", row["interface"])).exploded.lower()
    return f"{local}:{row['destination_port']} -> {remote}:{row['sender_port']}"


def verify_events(records, rows, group, verdict, match_interface, match_group_sends=False,
                  verdict_delay_ms=0):
    text = records.read_text(encoding="utf-8", errors="replace")
    entries = [entry.splitlines()[:4] for entry in text.split("[CONN ")[1:]]
    verdict_name = {"permanent-accept": "PermanentAccept", "accept": "Accept",
                    "permanent-block": "PermanentBlock"}[verdict]

    def requested_verdict_was_sent(event):
        event_id, _, line = event
        if "<== MATCHED" not in line:
            return False
        if not verdict_delay_ms:
            return f"verdict {verdict_name} sent" in line
        scheduled = f"verdict {verdict_name} scheduled after {verdict_delay_ms} ms" in line
        sent = (f"[VERDICT] id={event_id} -> verdict {verdict_name} sent  <== MATCHED" in text)
        return scheduled and sent

    for row in rows:
        tuple_text = event_tuple(row, group)
        source = ipaddress.ip_address(row["source_ip"]).exploded.lower()
        destination = ipaddress.ip_address(group).exploded.lower()
        outbound_tuple = (f"{source}:{row['sender_port']} -> "
                          f"{destination}:{row['destination_port']}")
        outbound = []
        for lines in entries:
            if len(lines) < 4 or outbound_tuple not in lines[1].lower():
                continue
            header = re.match(r"v[46]\] id=(\d+) pid=(\d+) .* outbound proto=17", lines[0])
            if header:
                outbound.append((int(header.group(1)), int(header.group(2)), lines[3]))
        if row["interface"] == match_interface and not outbound:
            raise AssertionError(f"missing sender CONN for {outbound_tuple}")
        if any(event_id == 0 for event_id, _, _ in outbound):
            raise AssertionError(f"zero sender notification ID: {outbound}")
        if match_group_sends and any(not requested_verdict_was_sent(event) for event in outbound):
            raise AssertionError(f"missing requested sender verdict: {outbound}")
        found = []
        for lines in entries:
            if len(lines) < 4 or tuple_text not in lines[1].lower():
                continue
            header = re.match(r"v[46]\] id=(\d+) pid=(\d+) .* inbound proto=17", lines[0])
            if header:
                found.append((int(header.group(1)), int(header.group(2)), lines[3]))
        expected_pids = [row["parent_pid"]] * (row["members"] - bool(row["child_pid"]))
        if row["child_pid"]:
            expected_pids.append(row["child_pid"])
        actual = Counter(pid for _, pid, _ in found)
        if any(actual[pid] < count for pid, count in Counter(expected_pids).items()):
            raise AssertionError(f"missing per-receiver CONN events: {row}, found={found}")
        if any(event_id == 0 for event_id, _, _ in found):
            raise AssertionError(f"zero notification ID: {found}")
        if not match_group_sends and row["source_ip"] == match_interface:
            if any(not requested_verdict_was_sent(event) for event in found):
                raise AssertionError(f"missing requested inbound verdict: {found}")
        ends = [line for line in text.splitlines()
                if "[END " in line and " inbound proto=17" in line and tuple_text in line.lower()]
        ended_pids = Counter(int(re.search(r"pid=(\d+)", line).group(1)) for line in ends)
        if any(ended_pids[pid] < count for pid, count in Counter(expected_pids).items()):
            raise AssertionError(f"missing per-receiver END events: {row}, found={ends}")


def idle_end_probe(monitor, records, group, interface, interface_index, source_port):
    """Wait for END while the joined receiving socket is still open."""
    family = socket.AF_INET6 if ":" in group else socket.AF_INET
    wildcard = "::" if family == socket.AF_INET6 else "0.0.0.0"
    with socket.socket(family, socket.SOCK_DGRAM) as receiver, \
            socket.socket(family, socket.SOCK_DGRAM) as sender:
        receiver.bind((wildcard, 0))
        join_group(receiver, group, interface, interface_index)
        if family == socket.AF_INET6:
            sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, interface_index)
            sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
            destination = (group, receiver.getsockname()[1], 0, interface_index)
        else:
            sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface))
            sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            destination = (group, receiver.getsockname()[1])
        sender.bind((interface, source_port))
        sender.sendto(b"multicast-idle-end", destination)
        receiver.settimeout(3)
        received, _ = receiver.recvfrom(65535)
        if received != b"multicast-idle-end":
            raise AssertionError(f"unexpected idle-probe payload: {received!r}")
        row = {"interface": interface, "destination_port": destination[1],
               "sender_port": sender.getsockname()[1]}
        tuple_text = event_tuple(row, group)
        started = time.monotonic()
        while time.monotonic() - started < 145:
            if monitor.poll() is not None:
                raise RuntimeError("monitor exited before multicast idle END")
            text = records.read_text(encoding="utf-8", errors="replace")
            if any("[END " in line and " inbound proto=17" in line and tuple_text in line.lower()
                   for line in text.splitlines()):
                elapsed = time.monotonic() - started
                if elapsed < 50:
                    raise AssertionError(f"multicast END occurred too early: {elapsed:.1f}s")
                print(f"PASS: multicast idle END after {elapsed:.1f}s with socket open", flush=True)
                return {"elapsed_seconds": elapsed, **row}
            time.sleep(0.5)
        raise AssertionError(f"no multicast idle END while socket remained open: {row}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extra-interface", help="also test a local IPv4 interface with TTL 0")
    parser.add_argument("--ipv6", action="store_true", help="test IPv6 loopback multicast")
    parser.add_argument("--ipv4-loopback", default=INTERFACE,
                        help="IPv4 loopback source and interface (default: 127.0.0.1)")
    parser.add_argument("--ipv6-interface-index", type=int, default=1,
                        help="loopback interface index for IPv6 (default: 1)")
    parser.add_argument("--verdict", choices=("permanent-accept", "accept", "permanent-block"),
                        default="permanent-accept", help="verdict for inbound packets from --match-interface")
    parser.add_argument("--match-interface", help="source address to match (default: loopback)")
    parser.add_argument("--match-group-sends", action="store_true",
                        help="apply the selected verdict to sends to the test group instead")
    parser.add_argument("--verdict-delay-ms", type=int, default=0,
                        help="delay matched verdicts by up to 10000 ms")
    parser.add_argument("--idle-end", action="store_true",
                        help="also wait for idle END while a joined socket remains open")
    parser.add_argument("--monitor", type=Path, default=ROOT / "kext_client/build/kext_monitor.exe")
    parser.add_argument("--driver", type=Path, default=ROOT / "windows_kext/portmaster-kext.sys")
    args = parser.parse_args()
    if os.name != "nt":
        raise RuntimeError("this test requires Windows")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError("this test requires Administrator privileges")
    owners = driver_owners()
    if owners:
        raise RuntimeError(f"refusing to interfere with an existing driver owner: {owners}")
    monitor_path = args.monitor.resolve()
    driver_path = args.driver.resolve()
    for path in (monitor_path, driver_path):
        if not path.is_file():
            raise FileNotFoundError(path)
    out_root = ROOT / "windows_kext/test/_out"
    out_root.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="multicast_loopback_", dir=out_root))
    records, console = output / "records.log", output / "console.log"
    print(f"output: {output}", flush=True)

    if args.ipv6 and args.extra_interface:
        parser.error("--extra-interface is available only for IPv4")
    if args.match_group_sends and (args.extra_interface or args.match_interface):
        parser.error("--match-group-sends cannot be combined with interface matching")
    if not 0 <= args.verdict_delay_ms <= 10_000:
        parser.error("--verdict-delay-ms must be between 0 and 10000")
    if not ipaddress.IPv4Address(args.ipv4_loopback).is_loopback:
        parser.error("--ipv4-loopback must be in 127.0.0.0/8")
    group = GROUP_V6 if args.ipv6 else GROUP
    interfaces = ["::1" if args.ipv6 else args.ipv4_loopback]
    if args.extra_interface and args.extra_interface != interfaces[0]:
        socket.inet_aton(args.extra_interface)
        interfaces.append(args.extra_interface)
    match_interface = args.match_interface or interfaces[0]
    if match_interface not in interfaces:
        parser.error("--match-interface must be one of the tested interfaces")
    family = socket.AF_INET6 if args.ipv6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as probe:
        probe.bind(("::" if args.ipv6 else "0.0.0.0", 0))
        source_port = probe.getsockname()[1]
    match_endpoint = (group if args.match_group_sends else
                      f"[{match_interface}]:{source_port}" if args.ipv6 else
                      f"{match_interface}:{source_port}")
    baseline = [row for interface in interfaces
                for row in run_matrix("without_driver", interface, group=group,
                                      interface_index=args.ipv6_interface_index,
                                      source_port=source_port)]
    if not all(row["pass"] for row in baseline):
        raise AssertionError("multicast loopback does not work without the driver")
    duration = 175 if args.idle_end else (40 if len(interfaces) > 1 else 25)
    command = [str(monitor_path), "--duration", str(duration), "--poll", "300",
               "--timestamps", "--no-bandwidth", "--verdict", args.verdict, "--match", match_endpoint,
               "--verdict-delay-ms", str(args.verdict_delay_ms), "--out", str(records), str(driver_path)]
    monitored = []
    idle_result = None
    with console.open("w", encoding="utf-8") as log:
        monitor = start_monitor(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if monitor.poll() is not None:
                    raise RuntimeError(f"monitor exited early: {console.read_text(errors='replace')}")
                if "Running for " in console.read_text(errors="replace"):
                    break
                time.sleep(0.1)
            else:
                raise TimeoutError("monitor did not become ready")
            check_monitor(monitor, minimum_seconds=22 if len(interfaces) > 1 else 12)
            if monitor._driver_window["last_observation"]["phase"] != "loaded":
                raise RuntimeError("monitor is not loaded before the test")
            monitored = [row for interface in interfaces
                         for row in run_matrix(
                             "with_driver", interface,
                             args.verdict == "permanent-block" and interface == match_interface
                             and interface != interfaces[0],
                             group, args.ipv6_interface_index, source_port)]
            if args.idle_end:
                idle_result = idle_end_probe(monitor, records, group, interfaces[0],
                                            args.ipv6_interface_index, source_port)
            check_monitor(monitor)
            if monitor._driver_window["last_observation"]["phase"] != "loaded":
                raise RuntimeError("monitor stopped before the test completed")
        finally:
            code = wait_for_cleanup(monitor, timeout=duration + 60)
            if code:
                raise RuntimeError(f"monitor failed ({code}): {console.read_text(errors='replace')}")
    owners = driver_owners()
    if owners:
        raise RuntimeError(f"monitor/driver was not cleaned up: {owners}")
    print("PASS: monitor and driver service cleaned up", flush=True)
    wfp_errors = [line for line in records.read_text(encoding="utf-8", errors="replace").splitlines()
                  if "asynchronous WFP" in line and "injection failed" in line]
    if wfp_errors:
        print(f"NOTE: {len(wfp_errors)} asynchronous WFP injection failures recorded; "
              f"not all failures are correlated with the test datagrams: {records}", flush=True)
    (output / "result.json").write_text(json.dumps({
        "group": group,
        "verdict": args.verdict,
        "match_interface": match_interface,
        "match_group_sends": args.match_group_sends,
        "verdict_delay_ms": args.verdict_delay_ms,
        "without_driver": baseline,
        "with_driver": monitored,
        "idle_end": idle_result,
        "monitor_exit": code,
        "driver_owners_after": owners,
        "wfp_injection_errors": wfp_errors,
    }, indent=2), encoding="utf-8")
    verify_events(records, monitored, group, args.verdict, match_interface,
                  args.match_group_sends, args.verdict_delay_ms)
    if not all(row["pass"] for row in monitored):
        raise AssertionError(f"multicast delivery differs with the driver; logs: {output}")
    print(f"PASS: multicast loopback matches expected {args.verdict} behavior", flush=True)


if __name__ == "__main__":
    main()
