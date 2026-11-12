"""Compare IGMPv3 reports on one chosen NIC without and with the driver.

Requires Windows Administrator, Npcap and Scapy. The blocking phase briefly
blocks any traffic involving 224.0.0.22, regardless of protocol, including
unrelated traffic. It sends no multicast data and alters no capture settings.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import tempfile
from threading import Event
import time

from monitor_window import check_monitor, start_monitor, wait_for_cleanup
from test_udp_flow_idle import driver_owners

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True, help="local non-loopback IPv4 address")
    parser.add_argument("--capture-interface", required=True, help="Npcap/Scapy interface name")
    parser.add_argument("--monitor", type=Path, default=ROOT / "kext_client/build/kext_monitor.exe")
    parser.add_argument("--driver", type=Path, default=ROOT / "windows_kext/portmaster-kext.sys")
    args = parser.parse_args()
    import ipaddress
    address = ipaddress.ip_address(args.interface)
    if os.name != "nt" or address.version != 4 or address.is_loopback:
        parser.error("Windows and a non-loopback IPv4 interface address are required")
    if driver_owners():
        raise RuntimeError("refusing to interfere with an existing monitor or driver")
    from scapy.config import conf
    conf.use_pcap = True
    from scapy.all import AsyncSniffer, IP

    root = ROOT / "windows_kext/test/_out"
    root.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="igmp_wire_", dir=root))
    third = 100 + os.getpid() % 80

    def join_and_capture(group, monitor=None):
        ready = Event()
        sniffer = AsyncSniffer(iface=args.capture_interface,
                               filter=f"igmp and src host {args.interface} and dst host 224.0.0.22",
                               store=True, started_callback=ready.set)
        sniffer.start()
        if not ready.wait(8):
            raise TimeoutError("Npcap capture did not start")
        try:
            if monitor:
                check_monitor(monitor, minimum_seconds=5)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
                receiver.bind(("0.0.0.0", 0))
                receiver.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                    socket.inet_aton(group) + socket.inet_aton(args.interface))
                time.sleep(2.5)
            time.sleep(2)
        finally:
            packets = sniffer.stop()
        selected = [packet for packet in packets if IP in packet
                    and socket.inet_aton(group) in bytes(packet[IP].payload)]
        return len(selected)

    results = {"output": str(out), "interface": args.interface,
               "capture_interface": args.capture_interface, "phases": []}
    for number, (phase, verdict) in enumerate((("baseline", None), ("accept", "permanent-accept"),
                                                ("block", "permanent-block")), 1):
        group = f"239.255.{third}.{220 + number}"
        if driver_owners():
            raise RuntimeError("a monitor or driver is already present")
        if verdict is None:
            count = join_and_capture(group)
            results["phases"].append({"phase": phase, "group": group, "wire_reports": count})
            continue
        phase_dir = out / phase
        phase_dir.mkdir()
        records, console = phase_dir / "records.log", phase_dir / "console.log"
        command = [str(args.monitor), "--duration", "14", "--poll", "200", "--timestamps",
                   "--no-bandwidth", "--payload", "--filter-protocol", "2", "--verdict", verdict,
                   "--match", "224.0.0.22", "--out", str(records), str(args.driver)]
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
        group_hex = socket.inet_aton(group).hex()
        entries = [block for block in text.split("[CONN v4]")[1:]
                   if f"{args.interface}:0 -> 224.0.0.22:0" in block[:500]
                   and group_hex in block[:500].lower()]
        expected = "PermanentAccept" if verdict == "permanent-accept" else "PermanentBlock"
        if not entries or not all(f"verdict {expected} sent" in entry[:500] for entry in entries):
            raise AssertionError(f"missing matched {expected} IGMP events for {group}")
        failures = [line for line in text.splitlines() if "network-send injection failed" in line]
        results["phases"].append({"phase": phase, "group": group, "wire_reports": count,
                                  "igmp_events": len(entries), "network_send_failures": failures})
    (out / "result.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2), flush=True)
    baseline, accept, block = [phase["wire_reports"] for phase in results["phases"]]
    if baseline == 0 or accept == 0 or block != 0:
        raise AssertionError(f"unexpected physical IGMP report counts: {baseline}, {accept}, {block}")


if __name__ == "__main__":
    main()
