#!/usr/bin/env python3
"""The summary of hack/bench/ab.sh's logs, as Markdown.

    python3 hack/bench/ab-table.py [--annotate] <out-dir>

Every value is a p50 in ms, lower is better. Each row compares the
median of each side's runs. A row is slower or faster only when the two
sides' runs do not overlap at all, otherwise it is noise. With 3 runs a
side that is a reason to look again, not proof. Warm-up logs are left
out.

AB_OLD and AB_NEW name the sides in the header, for example
"main a272cf0". A runner.txt in <out-dir> is shown folded at the end.

--annotate prints a GitHub warning annotation per slower row and per
failed test instead of the Markdown, so they show on the checks page.
"""
import glob
import os
import re
import statistics
import sys

UNIT = {"µs": 1e-3, "us": 1e-3, "ms": 1.0, "s": 1000.0}
DUR = r"([0-9.]+)(µs|us|ms|s)"
MARK = {"slower": "🔴 slower", "faster": "🟢 faster", "noise": "⚪ noise", "fail": "❌ failed", "one side": "➖ one side"}


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
            out["FAIL " + re.sub(r"^--- FAIL: | \([0-9.]+s\)$", "", line.strip())] = 1.0
    return out


def start(path):
    """The host's 1-minute load a run started at and the seconds it waited
    for it, from the log's first line. The load is in the Linux or the
    macOS form."""
    first = open(path, encoding="utf-8").readline()
    m = re.search(r"hostload=\{?\s*([0-9.]+)", first)
    w = re.search(r"waited=([0-9]+)s", first)
    return (m.group(1) if m else "?"), (w.group(1) if w else "?")


def num(x):
    return f"{x:.3g}"


def verdict(old, new):
    """slower, faster or noise, from whether the two sides' runs overlap."""
    if not old or not new:
        return "one side"
    if min(new) > max(old):
        return "slower"
    if max(new) < min(old):
        return "faster"
    return "noise"


def collect(d):
    """Per harness, its runs per side and one row per metric."""
    out = []
    for harness in ("clone", "storm", "park"):
        runs = {}
        for path in sorted(glob.glob(os.path.join(d, f"{harness}-*-*.log"))):
            side, label = os.path.basename(path)[:-4].split("-")[1:3]
            if label != "warmup":
                runs.setdefault(side, []).append((path, parse(harness, path)))
        if not runs:
            continue
        rows = []
        for k in dict.fromkeys(k for side in runs.values() for _, v in side for k in v):
            vals = {s: [v[k] for _, v in runs.get(s, []) if v.get(k) is not None] for s in ("old", "new")}
            if k.startswith("FAIL "):
                where = ", ".join(f"{len(vals[s])} of {len(runs.get(s, []))} {s} runs" for s in ("old", "new") if vals[s])
                rows.append({"metric": f"{k[5:]} ({where})", "verdict": "fail", **vals})
                continue
            med = {s: statistics.median(v) if v else None for s, v in vals.items()}
            rows.append({"metric": k.removesuffix(" p50"), "verdict": verdict(vals["old"], vals["new"]), "med": med, **vals})
        out.append((harness, runs, rows))
    return out


def change(r):
    old, new = r["med"]["old"], r["med"]["new"]
    if old is None or new is None:
        return ""
    pct = f" ({(new - old) / old * 100:+.0f}%)" if old else ""
    return f"{new - old:+.3g}{pct}"


def markdown(d, out):
    old, new = os.environ.get("AB_OLD", "old"), os.environ.get("AB_NEW", "new")
    rows = [r for _, _, rs in out for r in rs]
    count = {v: sum(r["verdict"] == v for r in rows) for v in MARK}
    print(f"## bench-ab: {old} → {new}\n")
    if not rows:
        print("No results. The raw logs are in the artifact.")
        return
    parts = [f"**{count[v]} {v}**" if v in ("slower", "fail") and count[v] else f"{count[v]} {v}"
             for v in ("fail", "slower", "faster", "noise", "one side") if count[v] or v in ("slower", "noise")]
    print(" · ".join(parts) + f" of {len(rows)} rows\n")
    print("p50 in ms, lower is better. A row is slower or faster only when the two sides' "
          "runs do not overlap. With 3 runs a side, rerun before trusting one.\n")
    for harness, runs, rs in out:
        print(f"### {harness}\n")
        print(f"| | metric | {old} | {new} | change |")
        print("|---|---|---:|---:|---:|")
        for r in rs:
            if r["verdict"] == "fail":
                print(f"| {MARK['fail']} | {r['metric']} | | | |")
                continue
            med = r["med"]
            cells = [num(med[s]) if med[s] is not None else "" for s in ("old", "new")]
            print(f"| {MARK[r['verdict']]} | {r['metric']} | {cells[0]} | {cells[1]} | {change(r)} |")
        starts = {s: [start(p) for p, _ in v] for s, v in runs.items()}
        print("\n<details><summary>each run, and the load it started at</summary>\n")
        print(f"| metric | {old} runs | {new} runs |")
        print("|---|---|---|")
        for r in rs:
            if r["verdict"] != "fail":
                print(f"| {r['metric']} | " + " | ".join(" ".join(num(x) for x in r[s]) for s in ("old", "new")) + " |")
        for s, name in (("old", old), ("new", new)):
            if s in starts:
                print(f"\n{name}: load {' '.join(x[0] for x in starts[s])}, "
                      f"waited {' '.join(x[1] for x in starts[s])} s")
        print("\n</details>\n")
    facts = os.path.join(d, "runner.txt")
    if os.path.exists(facts):
        print("<details><summary>runner</summary>\n\n```")
        print(open(facts, encoding="utf-8").read().rstrip())
        print("```\n\n</details>")


def annotate(out):
    for harness, _, rs in out:
        for r in rs:
            if r["verdict"] == "fail":
                print(f"::error title=bench-ab {harness}::{r['metric']} failed")
            elif r["verdict"] == "slower":
                print(f"::warning title=bench-ab {harness} slower::{r['metric']} "
                      f"{num(r['med']['old'])} → {num(r['med']['new'])} ms, {change(r)}, the runs do not overlap")


def main(args):
    flag = "--annotate" in args
    d = [a for a in args if a != "--annotate"][0]
    out = collect(d)
    annotate(out) if flag else markdown(d, out)


if __name__ == "__main__":
    main(sys.argv[1:])
