#!/usr/bin/env python3
"""The median table of hack/bench/ab.sh's logs, as Markdown.

    python3 hack/bench/ab-table.py <out-dir>

Every value is in ms. Each run's value is printed, then the median per
side and the new median minus the old. Warm-up logs are left out.
"""
import glob
import os
import re
import statistics
import sys

UNIT = {"µs": 1e-3, "us": 1e-3, "ms": 1.0, "s": 1000.0}
DUR = r"([0-9.]+)(µs|us|ms|s)"


def ms(value, unit):
    return float(value) * UNIT[unit]


def p50(line):
    m = re.search(r"p50=" + DUR, line)
    return ms(*m.groups()) if m else None


def parse(harness, path):
    out, case = {}, ""
    for line in open(path, encoding="utf-8"):
        m = re.match(r"=== RUN\s+Test\w+/(\S+)", line)
        if m:
            case = m.group(1).replace("_", " ")
        if harness == "clone":
            if "client round trip" in line:
                out[case + ", round trip p50"] = p50(line)
            m = re.match(r"\s+zygote: ", line)
            if m:
                out[case + ", zygote p50"] = p50(line)
        elif harness == "storm":
            for key, pat in (("single clone p50", "single clone"), ("storm p50", "-way storm"),
                             ("park p50", "park ("), ("resume p50", "resume from")):
                if pat in line and p50(line) is not None:
                    out[f"{case}, {key}"] = p50(line)
        elif harness == "park":
            m = re.search(r"RESULT park=" + DUR + " resume=" + DUR, line)
            if m:
                out["park"] = ms(m.group(1), m.group(2))
                out["resume"] = ms(m.group(3), m.group(4))
        if re.match(r"\s*--- FAIL", line):
            out["FAIL " + re.sub(r" \([0-9.]+s\)$", "", line.strip())] = 1.0
    return out


def load(path):
    """The host's 1-minute load from a log's first line, in the Linux or the macOS form."""
    m = re.search(r"hostload=\{?\s*([0-9.]+)", open(path, encoding="utf-8").readline())
    return m.group(1) if m else "?"


def main(d):
    for harness in ("clone", "storm", "park"):
        runs = {}
        for path in sorted(glob.glob(os.path.join(d, f"{harness}-*-*.log"))):
            side, label = os.path.basename(path)[:-4].split("-")[1:3]
            if label != "warmup":
                runs.setdefault(side, []).append((path, parse(harness, path)))
        if not runs:
            continue
        loads = {s: [load(p) for p, _ in r] for s, r in runs.items()}
        print(f"\n### {harness}\n\nhost load per run: old {loads.get('old')}, new {loads.get('new')}\n")
        print("| metric | old runs | old median | new runs | new median | new − old |")
        print("|---|---|---:|---|---:|---:|")
        keys = list(dict.fromkeys(k for side in runs.values() for _, v in side for k in v))
        for k in keys:
            row, med = [], {}
            for side in ("old", "new"):
                vals = [v[k] for _, v in runs.get(side, []) if v.get(k) is not None]
                med[side] = statistics.median(vals) if vals else None
                row += [" ".join(f"{x:.3g}" for x in vals), f"{med[side]:.3g}" if vals else ""]
            delta = f"{med['new'] - med['old']:+.3g}" if None not in med.values() else ""
            print(f"| {k} | " + " | ".join(row) + f" | {delta} |")


if __name__ == "__main__":
    main(sys.argv[1])
