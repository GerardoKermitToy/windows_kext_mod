"""Check several raw IGMP types and destinations on loopback only.

Requires Windows Administrator and an idle PortmasterKext service/monitor.
The second bounded phase matches 224.0.0.22 regardless of protocol and may
briefly block unrelated traffic involving that address.
"""
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
CASES = [(0x11, "224.0.0.1"), (0x16, "224.0.0.2"), (0x17, "224.0.0.22"),
         (0x22, "224.0.0.22"), (0xfe, "224.0.0.22")]


def checksum(data):
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def packet(ip_id, message_type, destination):
    # Deliberately no Router Alert; the last case is an unknown IGMP type.
    body = struct.pack("!BBHI", message_type, 0, 0, 0)
    body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), ip_id,
                         0, 1, 2, 0, socket.inet_aton("127.0.0.1"),
                         socket.inet_aton(destination))
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + body


def entries(text):
    result = {}
    for block in text.split("[CONN v4]")[1:]:
        lines = block.splitlines()
        if len(lines) < 5 or "outbound proto=2(" not in lines[0]:
            continue
        if "127.0.0.1:0 -> 224.0.0." not in lines[1] or "interface_index=1 " not in lines[2]:
            continue
        match = re.search(r"payload: ([0-9a-fA-F]+)", lines[3])
        event = re.match(r" id=(\d+) ", lines[0])
        if not match or not event:
            continue
        payload = bytes.fromhex(match.group(1))
        if len(payload) < 21:
            continue
        ip_id = int.from_bytes(payload[4:6], "big")
        result.setdefault(ip_id, []).append({
            "event_id": int(event.group(1)), "type": payload[20],
            "destination": socket.inet_ntoa(payload[16:20]), "verdict": lines[4].strip(),
        })
    return result


def send_cases():
    outcomes = []
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP) as sender:
        sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                          socket.inet_aton("127.0.0.1"))
        sender.bind(("127.0.0.1", 0))
        for index, (message_type, destination) in enumerate(CASES):
            payload = packet(0x7100 + index, message_type, destination)
            try:
                outcomes.append({"sent": sender.sendto(payload, (destination, 0))})
            except OSError as error:
                outcomes.append({"winerror": error.winerror})
            time.sleep(.25)
    return outcomes


def main():
    if os.name != "nt":
        raise RuntimeError("this control requires Windows")
    if driver_owners():
        raise RuntimeError("refusing to interfere with an existing monitor or driver")
    root = ROOT / "windows_kext/test/_out"
    root.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="igmp_raw_", dir=root))
    baseline = send_cases()
    if driver_owners():
        raise RuntimeError("a monitor or driver appeared during the baseline")
    phases = []
    for phase in ("accept", "delay-block"):
        if driver_owners():
            raise RuntimeError("a monitor or driver is already present")
        directory = out / phase
        directory.mkdir()
        records, console = directory / "records.log", directory / "console.log"
        command = [str(ROOT / "kext_client/build/kext_monitor.exe"), "--duration", "14",
                   "--poll", "100", "--timestamps", "--no-bandwidth", "--payload",
                   "--filter-protocol", "2", "--out", str(records)]
        if phase == "delay-block":
            command += ["--verdict", "permanent-block", "--match", "224.0.0.22",
                        "--verdict-delay-ms", "3000"]
        command.append(str(ROOT / "windows_kext/portmaster-kext.sys"))
        with console.open("w", encoding="utf-8") as log:
            monitor = start_monitor(command, stdout=log, stderr=-2)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if monitor.poll() is not None:
                        raise RuntimeError("monitor exited before raw IGMP test")
                    if "Running for " in console.read_text(errors="replace"):
                        break
                    time.sleep(.1)
                else:
                    raise TimeoutError("monitor did not start")
                check_monitor(monitor, minimum_seconds=7)
                outcomes = send_cases()
                if outcomes != baseline:
                    raise AssertionError(f"raw send results changed: native={baseline}, driver={outcomes}")
                time.sleep(5)
                if monitor.poll() is not None:
                    raise RuntimeError("monitor stopped before test completed")
                check_monitor(monitor)
            finally:
                code = wait_for_cleanup(monitor, timeout=30)
        if code or driver_owners():
            raise RuntimeError(f"monitor cleanup failed: exit={code}, owners={driver_owners()}")
        text = records.read_text(encoding="utf-8", errors="replace")
        found = entries(text)
        selected = []
        for index, (message_type, destination) in enumerate(CASES):
            ip_id = 0x7100 + index
            indications = found.get(ip_id, [])
            if not indications:
                raise AssertionError(f"missing raw IGMP event {ip_id}")
            for event in indications:
                if event["event_id"] == 0 or event["type"] != message_type or event["destination"] != destination:
                    raise AssertionError(f"incorrect raw IGMP event {ip_id}: {event}")
                if phase == "delay-block" and destination == "224.0.0.22":
                    if "PermanentBlock scheduled after 3000 ms" not in event["verdict"]:
                        raise AssertionError(f"missing delayed verdict: {event}")
                    if not re.search(rf"\[VERDICT\] id={event['event_id']} -> verdict PermanentBlock sent.*MATCHED", text):
                        raise AssertionError(f"delayed verdict not sent: {event}")
                selected.append({"ipv4_id": ip_id, **event})
        if len({entry["event_id"] for entry in selected}) != len(selected):
            raise AssertionError("non-unique IGMP event IDs")
        failures = [line for line in text.splitlines() if "network-send injection failed" in line]
        for entry in selected:
            if any(f"IPv4 id={entry['ipv4_id']} proto=2 127.0.0.1" in line for line in failures):
                raise AssertionError(f"raw IGMP was reinjected and failed: {entry}")
        phases.append({"phase": phase, "send_results": outcomes, "events": selected,
                       "network_send_failures": failures})
    result = {"output": str(out), "native_send_results": baseline, "phases": phases, "pass": True}
    (out / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
