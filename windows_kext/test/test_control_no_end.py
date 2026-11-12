"""Verify IGMP and ICMPv6 packet notifications never produce an idle END.

Run as Administrator with no existing driver owner. A duration-bounded monitor
uses PermanentAccept and owns driver loading/unloading. The same monitor observes
both protocols through multiple cleanup sweeps while both sockets stay open.
"""
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
from test_igmp_loopback import control_ends as igmp_ends, join as join_igmp, send_and_receive
from test_mld_loopback import control_ends as mld_ends, exchange, sockets

ROOT = Path(__file__).resolve().parents[2]


def read(path):
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def control_ids(text, ipv6, destination="ff02::16"):
    version = 6 if ipv6 else 4
    protocol = 58 if ipv6 else 2
    tuple_text = ("0000:0000:0000:0000:0000:0000:0000:0001:0 -> "
                  f"{ipaddress.IPv6Address(destination).exploded}:0" if ipv6 else
                  "127.0.0.1:0 -> 224.0.0.22:0")
    ids = []
    for block in text.split(f"[CONN v{version}]")[1:]:
        lines = block.splitlines()
        if (len(lines) < 3 or f"outbound proto={protocol}(" not in lines[0] or
                tuple_text not in lines[1] or "interface_index=1 " not in lines[2]):
            continue
        event = re.match(r" id=(\d+) ", lines[0])
        if event:
            ids.append(int(event.group(1)))
    return ids


def send_all_nodes_query():
    with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6) as sender:
        sender.bind(("::1", 0))
        sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, 1)
        try:
            return {"sent": sender.sendto(struct.pack("!BBHI", 130, 0, 0, 0) + bytes(16),
                                          ("ff02::1", 0, 0, 1))}
        except OSError as error:
            return {"winerror": error.winerror}


def main():
    if os.name != "nt" or driver_owners():
        raise RuntimeError("Windows and no existing monitor or driver owner are required")
    root = ROOT / "windows_kext/test/_out"
    root.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="control_no_end_", dir=root))
    records, console = out / "records.log", out / "console.log"
    ipv4_group = f"239.255.{100 + os.getpid() % 80}.234"
    ipv6_group = f"ff02::a4:{os.getpid() & 0xffff:x}"
    command = [str(ROOT / "kext_client/build/kext_monitor.exe"), "--duration", "125",
               "--poll", "200", "--timestamps", "--no-bandwidth",
               "--out", str(records), str(ROOT / "windows_kext/portmaster-kext.sys")]
    result = {"output": str(out), "ipv4_group": ipv4_group, "ipv6_group": ipv6_group}
    with console.open("w", encoding="utf-8") as log:
        monitor = start_monitor(command, stdout=log, stderr=-2)
        try:
            deadline = time.monotonic() + 10
            while "Running for " not in read(console):
                if monitor.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("monitor did not start")
                time.sleep(.1)
            check_monitor(monitor, minimum_seconds=110)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as v4_receiver, \
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as v4_sender:
                join_igmp(v4_receiver, ipv4_group, "127.0.0.1")
                v4_sender.bind(("127.0.0.1", 0))
                v4_sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                                     socket.inet_aton("127.0.0.1"))
                v6_receiver, v6_sender = sockets(ipv6_group)
                with v6_receiver, v6_sender:
                    send_and_receive(v4_receiver, v4_sender, ipv4_group, b"ipv4")
                    exchange(v6_receiver, v6_sender, ipv6_group, b"ipv6")
                    result["raw_all_nodes_send"] = send_all_nodes_query()
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        text = read(records)
                        v4 = control_ids(text, False)
                        v6 = control_ids(text, True)
                        all_nodes = control_ids(text, True, "ff02::1")
                        if v4 and v6 and all_nodes:
                            break
                        if monitor.poll() is not None:
                            raise RuntimeError("monitor exited before control notifications")
                        time.sleep(.1)
                    else:
                        raise AssertionError(f"missing notifications: IGMP={v4}, ICMPv6={v6}, all-nodes={all_nodes}")
                    ids = v4 + v6 + all_nodes
                    if 0 in ids or len(ids) != len(set(ids)):
                        raise AssertionError(f"duplicate or zero IDs: {ids}")
                    start = time.monotonic()
                    while time.monotonic() - start < 100:
                        if monitor.poll() is not None:
                            raise RuntimeError("monitor exited before the idle check finished")
                        text = read(records)
                        if igmp_ends(text) or mld_ends(text, ("ff02::16", "ff02::1")):
                            raise AssertionError(f"unexpected control END: {igmp_ends(text) + mld_ends(text, ('ff02::16', 'ff02::1'))}")
                        time.sleep(.5)
                    result.update(no_end_seconds=round(time.monotonic() - start, 2),
                                  igmp_notifications=len(v4), icmpv6_notifications=len(v6),
                                  all_nodes_notifications=len(all_nodes),
                                  sockets_open=v4_receiver.fileno() != -1 and v6_receiver.fileno() != -1)
            check_monitor(monitor)
        finally:
            code = wait_for_cleanup(monitor, timeout=155)
    if code or driver_owners():
        raise RuntimeError(f"monitor cleanup failed: {code}, {driver_owners()}")
    text = read(records)
    if igmp_ends(text) or mld_ends(text, ("ff02::16", "ff02::1")):
        raise AssertionError(f"unexpected END after socket closure: {igmp_ends(text) + mld_ends(text, ('ff02::16', 'ff02::1'))}")
    result["pass"] = True
    (out / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
