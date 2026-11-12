"""Compare physical-interface MLDv2 reports with native, accept and block policy.

Requires Windows Administrator, Npcap and Scapy. The blocking phase temporarily
matches all traffic involving ff02::16, regardless of protocol and interface.
The duration-bounded monitor owns driver load/unload and no capture settings are
changed. Use an interface on which sending a few group reports is acceptable.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
from threading import Event
import time

from monitor_window import check_monitor, start_monitor, wait_for_cleanup
from test_udp_flow_idle import driver_owners

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface-index", type=int, required=True)
    parser.add_argument("--capture-interface", required=True)
    parser.add_argument("--monitor", type=Path, default=ROOT / "kext_client/build/kext_monitor.exe")
    parser.add_argument("--driver", type=Path, default=ROOT / "windows_kext/portmaster-kext.sys")
    args = parser.parse_args()
    if os.name != "nt" or args.interface_index <= 1:
        parser.error("Windows and a non-loopback interface index are required")
    if driver_owners():
        raise RuntimeError("refusing to interfere with an existing monitor or driver")
    from scapy.config import conf
    conf.use_pcap = True
    from scapy.all import AsyncSniffer, IPv6

    root = ROOT / "windows_kext/test/_out"
    root.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="mld_wire_", dir=root))
    suffix = os.getpid() & 0xffff

    def join_and_capture(group, monitor=None):
        ready = Event()
        sniffer = AsyncSniffer(iface=args.capture_interface,
                               filter="ip6 and dst host ff02::16",
                               store=True, started_callback=ready.set)
        sniffer.start()
        if not ready.wait(8):
            raise TimeoutError("Npcap capture did not start")
        try:
            if monitor:
                check_monitor(monitor, minimum_seconds=5)
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as receiver:
                receiver.bind(("::", 0))
                receiver.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                                    socket.inet_pton(socket.AF_INET6, group) +
                                    struct.pack("=I", args.interface_index))
                time.sleep(2.5)
            time.sleep(2)
        finally:
            packets = sniffer.stop()
        needle = socket.inet_pton(socket.AF_INET6, group)
        return sum(1 for packet in packets if IPv6 in packet and needle in bytes(packet[IPv6].payload))

    results = {"output": str(out), "interface_index": args.interface_index,
               "capture_interface": args.capture_interface, "phases": []}
    for number, (phase, verdict) in enumerate((("baseline", None), ("accept", "permanent-accept"),
                                                ("block", "permanent-block")), 1):
        group = f"ff02::b{number:x}:{suffix:x}"
        if driver_owners():
            raise RuntimeError("a monitor or driver is already present")
        if verdict is None:
            count = join_and_capture(group)
            results["phases"].append({"phase": phase, "group": group, "wire_reports": count})
            continue
        phase_dir = out / phase
        phase_dir.mkdir()
        records, console = phase_dir / "records.log", phase_dir / "console.log"
        command = [str(args.monitor), "--duration", "15", "--poll", "200", "--timestamps",
                   "--no-bandwidth", "--payload", "--filter-protocol", "58", "--verdict", verdict,
                   "--match", "ff02::16", "--out", str(records), str(args.driver)]
        with console.open("w", encoding="utf-8") as log:
            monitor = start_monitor(command, stdout=log, stderr=-2)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if monitor.poll() is not None:
                        raise RuntimeError("monitor exited before capture")
                    if "Running for " in console.read_text(errors="replace"):
                        break
                    time.sleep(.1)
                else:
                    raise TimeoutError("monitor did not start")
                count = join_and_capture(group, monitor)
            finally:
                code = wait_for_cleanup(monitor, timeout=30)
        if code or driver_owners():
            raise RuntimeError(f"monitor cleanup failed: exit={code}, owners={driver_owners()}")
        text = records.read_text(errors="replace")
        group_hex = socket.inet_pton(socket.AF_INET6, group).hex()
        entries = [block for block in text.split("[CONN v6]")[1:]
                   if "outbound proto=58(" in block[:150]
                   and f"interface_index={args.interface_index} " in block[:500]
                   and group_hex in block[:1000].lower()]
        expected = "PermanentAccept" if verdict == "permanent-accept" else "PermanentBlock"
        if not entries or not all(f"verdict {expected} sent" in entry[:1000] for entry in entries):
            raise AssertionError(f"missing matched {expected} physical MLD events for {group}")
        failures = [line for line in text.splitlines() if "network-send injection failed" in line]
        results["phases"].append({"phase": phase, "group": group, "wire_reports": count,
                                  "mld_events": len(entries), "network_send_failures": failures})
    (out / "result.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2), flush=True)
    baseline, accept, block = [phase["wire_reports"] for phase in results["phases"]]
    if baseline == 0 or accept == 0 or block != 0:
        raise AssertionError(f"unexpected physical MLD report counts: {baseline}, {accept}, {block}")


if __name__ == "__main__":
    main()
