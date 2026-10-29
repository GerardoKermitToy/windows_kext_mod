"""Summarize validated connection-cache JSONL samples without third-party packages."""
import argparse
import collections
import json
import math
from pathlib import Path
import statistics


def summarize(directory: Path) -> str:
    groups = collections.defaultdict(list)
    for line in (directory / "samples.jsonl").read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        assert (row["entries"], row["queries"], row["hits"]) == (50_000, 1_000_000, 700_000)
        groups[row["scenario"], row["variant"]].append(row)
    assert groups, "no benchmark samples"
    scenarios = sorted({key[0] for key in groups})
    variants = ["btree-btree", "fx-btree", "btree-fx", "fx-fx", "directory-btree", "directory-fx", "sip-sip", "directory-sip"]
    for scenario in scenarios:
        counts = {len(groups[scenario, variant]) for variant in variants}
        assert len(counts) == 1 and next(iter(counts)) >= 3, "incomplete scenario"
        for variant in variants:
            rows = groups[scenario, variant]
            assert len({row["round"] for row in rows}) == len(rows), "duplicate round"
            assert len({row["checksum"] for row in rows}) == 1
            assert sum(row["memory_measured"] for row in rows) == 1
        assert len({row["checksum"] for variant in variants for row in groups[scenario, variant]}) == 1

    def median(scenario, variant, field):
        return statistics.median(row[field] for row in groups[scenario, variant])

    lines = ["# Connection-cache benchmark samples", "", "## Lookup: median milliseconds per 1,000,000 requests", "",
             "The numerical value is also ns/request. Each pass contains exactly 700,000 hits and 300,000 misses.", "",
             "| Scenario | " + " | ".join(variants) + " |",
             "|---|" + "---:|" * len(variants)]
    for scenario in scenarios:
        lines.append("| " + scenario + " | " + " | ".join(f"{median(scenario, variant, 'lookup_ns') / 1e6:.2f}" for variant in variants) + " |")

    lines += ["", "## Equal-weight geometric mean speedup vs B-tree reference", "",
              "| Variant | Geometric mean | Slowest-case speedup |", "|---|---:|---:|"]
    for variant in variants:
        ratios = [median(scenario, "btree-btree", "lookup_ns") / median(scenario, variant, "lookup_ns") for scenario in scenarios]
        lines.append(f"| {variant} | {math.exp(statistics.mean(map(math.log, ratios))):.3f}x | {min(ratios):.3f}x |")

    lines += ["", "## Lookup spread (complete-pass min / median / max, ms)", "",
              "This is variation across complete passes, not per-request percentile latency.", "",
              "| Scenario | Variant | Min | Median | Max |", "|---|---|---:|---:|---:|"]
    for scenario in scenarios:
        for variant in variants:
            values = [row["lookup_ns"] / 1e6 for row in groups[scenario, variant]]
            lines.append(f"| {scenario} | {variant} | {min(values):.2f} | {statistics.median(values):.2f} | {max(values):.2f} |")

    lines += ["", "## Cache heap (requested bytes, not allocator headers/kernel pool accounting)", "",
              "Input records, request arrays and expected results are excluded. Lookup allocation count is asserted to be zero.", "",
              "| Scenario | Variant | Live KiB | Peak KiB | Build allocation/reallocation calls | Empty KiB after cleanup |",
              "|---|---|---:|---:|---:|---:|"]
    for scenario in scenarios:
        for variant in variants:
            row = next(row for row in groups[scenario, variant] if row["memory_measured"])
            lines.append(f"| {scenario} | {variant} | {row['live_bytes'] / 1024:.1f} | {row['peak_bytes'] / 1024:.1f} | {row['alloc_calls']} | {row['empty_bytes'] / 1024:.1f} |")

    lines += ["", "## Other driver operations (median total ms)", "",
              "Insert: 50,000 preconstructed records, cloning and insert-if-absent included. Instance check: 50,000 successful checks.",
              "End: visit all occupied local-port groups and end all 50,000 connections, including result clones/allocations.",
              "Cleanup: remove 50,000 separately pre-aged records using the actual grace-period cleanup.", "",
              "| Scenario | Variant | Insert | Instance check | End by endpoint | Cleanup |", "|---|---|---:|---:|---:|---:|"]
    for scenario in scenarios:
        for variant in variants:
            values = " | ".join(f"{median(scenario, variant, field) / 1e6:.2f}" for field in ["insert_ns", "instance_ns", "end_ns", "cleanup_ns"])
            lines.append(f"| {scenario} | {variant} | {values} |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    text = summarize(args.directory)
    output = args.directory / "summary.md"
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    print(output)
    print(text.split("## Lookup spread")[0])


if __name__ == "__main__":
    main()
