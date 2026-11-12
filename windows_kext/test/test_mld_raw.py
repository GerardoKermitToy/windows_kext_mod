"""Bounded raw ICMPv6 loopback probes; Administrator only.

The blocking phase temporarily matches the test-only ff02::a3:fd01 address,
regardless of protocol or interface. All raw sends select loopback interface 1.
"""
import argparse
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
from test_mld_loopback import control_ends, fingerprint

ROOT = Path(__file__).resolve().parents[2]
BLOCK_TARGET = "ff02::a3:fd01"
CASES = [(130, destination) for destination in
         ("ff02::1", "ff01::1", BLOCK_TARGET, "ff05::1234")] + [
             (message_type, "ff02::16") for message_type in
             (1, 2, 3, 4, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 143, 144, 200, 254)]
MARKER = b"mld-probe-2026"


def send_case(sender, index):
    message_type, destination = CASES[index % len(CASES)]
    data = struct.pack("!BBHI", message_type, 0, 0, index) + MARKER + bytes(16)
    try:
        return {"sent": sender.sendto(data, (destination, 0, 0, 1))}
    except OSError as error:
        return {"winerror": error.winerror}


def send_cases(indices=None):
    outcomes = []
    with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6) as sender:
        sender.bind(("::1", 0))
        sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, 1)
        sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
        for index in range(len(CASES)) if indices is None else indices:
            outcomes.append(send_case(sender, index))
            time.sleep(.2)
    return outcomes


def events(text):
    result = []
    for block in text.split("[CONN v6]")[1:]:
        lines = block.splitlines()
        if len(lines) < 5 or "outbound proto=58(" not in lines[0]:
            continue
        match = re.search(r"payload: ([0-9a-fA-F]+)", lines[3])
        event = re.match(r" id=(\d+) pid=(\d+) tid=(\d+) ", lines[0])
        if not match or not event or "interface_index=1 " not in lines[2]:
            continue
        packet = bytes.fromhex(match.group(1))
        position = packet.find(MARKER)
        if position < 8:
            continue
        result.append({"id": int(event.group(1)), "pid": int(event.group(2)),
                       "tid": int(event.group(3)), "type": packet[position-8],
                       "case": int.from_bytes(packet[position-4:position], "big"),
                       "source": socket.inet_ntop(socket.AF_INET6, packet[8:24]),
                       "destination": socket.inet_ntop(socket.AF_INET6, packet[24:40]),
                       "fingerprint": fingerprint(packet), "verdict": lines[4].strip()})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--diagnose", action="store_true")
    args = parser.parse_args()
    if os.name != "nt" or driver_owners():
        raise RuntimeError("Windows and no existing driver owner are required")
    root = ROOT / "windows_kext/test/_out"
    root.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="mld_raw_", dir=root))
    baseline = send_cases()
    if driver_owners():
        raise RuntimeError("a driver owner appeared during baseline")
    phases = []
    for phase in (["diagnose"] if args.diagnose else ["accept", "delay-block"]):
        if driver_owners():
            raise RuntimeError("a driver owner appeared before the test")
        directory = out / phase
        directory.mkdir()
        records, console = directory / "records.log", directory / "console.log"
        command = [str(ROOT / "kext_client/build/kext_monitor.exe"), "--duration", "17", "--poll", "100",
                   "--timestamps", "--no-bandwidth", "--payload", "--filter-protocol", "58",
                   "--out", str(records)]
        if phase == "delay-block":
            command += ["--verdict", "permanent-block", "--match", BLOCK_TARGET,
                        "--verdict-delay-ms", "3000"]
        command.append(str(ROOT / "windows_kext/portmaster-kext.sys"))
        with console.open("w", encoding="utf-8") as log:
            monitor = start_monitor(command, stdout=log, stderr=-2)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if monitor.poll() is not None:
                        raise RuntimeError("monitor exited before raw test")
                    if "Running for " in console.read_text(errors="replace"):
                        break
                    time.sleep(.1)
                else:
                    raise TimeoutError("monitor did not start")
                check_monitor(monitor, minimum_seconds=10)
                outcomes = send_cases()
                time.sleep(4)
                repeated = None
                if phase == "delay-block":
                    block_index = next(index for index, (_, destination) in enumerate(CASES)
                                       if destination == BLOCK_TARGET)
                    before_repeat = records.read_text(errors="replace")
                    first_blocks = [entry for entry in events(before_repeat) if entry["case"] == block_index]
                    if not first_blocks or not all(
                        re.search(rf"\[VERDICT\] id={entry['id']} -> verdict PermanentBlock sent.*MATCHED",
                                  before_repeat) for entry in first_blocks
                    ):
                        raise AssertionError("initial delayed block was not sent before the repeat")
                    repeated = send_cases([len(CASES) + block_index])[0]
                    if repeated != baseline[block_index]:
                        raise AssertionError(f"late block changed repeated send: {repeated}")
                check_monitor(monitor)
            finally:
                code = wait_for_cleanup(monitor, timeout=30)
        if code or driver_owners():
            raise RuntimeError(f"monitor cleanup failed: {code}, {driver_owners()}")
        text = records.read_text(errors="replace")
        if phase != "diagnose" and control_ends(text, {destination for _, destination in CASES}):
            raise AssertionError(f"unexpected ICMPv6 END: {control_ends(text, {destination for _, destination in CASES})}")
        found = events(text)
        failures = [line for line in text.splitlines() if "network-send injection failed" in line]
        phases.append({"phase": phase, "driver": outcomes, "repeated_after_block": repeated,
                       "events": found, "network_send_failures": failures})
        if phase == "delay-block" and not any(entry["case"] == len(CASES) + block_index for entry in found):
            raise AssertionError("repeated raw send did not produce a fresh notification")
        expected_cases = set(range(len(CASES)))
        if phase == "delay-block":
            expected_cases.add(len(CASES) + block_index)
        if set(entry["case"] for entry in found) != expected_cases:
            raise AssertionError(f"not every raw case produced an indication: {found}")
        ids = [entry["id"] for entry in found]
        if 0 in ids or len(ids) != len(set(ids)):
            raise AssertionError(f"missing or duplicate event IDs: {ids}")
        for entry in found:
            index = entry["case"] % len(CASES)
            if (entry["type"] != CASES[index][0] or entry["source"] != "::1" or
                    entry["destination"] != CASES[index][1]):
                raise AssertionError(f"wrong raw event identity: {entry}")
            if entry["type"] == 128 and (entry["pid"] != os.getpid() or entry["tid"] == 0):
                raise AssertionError(f"ICMPv6 echo request lost sender attribution: {entry}")
            matching_failure = any(f"fingerprint={entry['fingerprint']}" in line for line in failures)
            if phase == "diagnose":
                if not matching_failure:
                    raise AssertionError(f"raw probe completion did not correlate: {entry}")
            else:
                if outcomes[index] != baseline[index]:
                    raise AssertionError(f"raw result changed: {baseline[index]} -> {outcomes[index]}")
                if matching_failure:
                    raise AssertionError(f"qualifying ICMPv6 packet was reinjected: {entry}")
                if phase == "delay-block" and entry["destination"] == BLOCK_TARGET:
                    if "PermanentBlock scheduled after 3000 ms" not in entry["verdict"]:
                        raise AssertionError(f"missing delayed verdict: {entry}")
                    if not re.search(rf"\[VERDICT\] id={entry['id']} -> verdict PermanentBlock sent.*MATCHED", text):
                        raise AssertionError(f"delayed verdict not sent: {entry}")
    result = {"output": str(out), "native": baseline, "phases": phases, "pass": True}
    (out / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
