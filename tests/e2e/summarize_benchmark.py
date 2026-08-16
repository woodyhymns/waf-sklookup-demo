#!/usr/bin/env python3
"""Summarize bench-sklookup.sh raw artifacts without rounding away evidence."""
from __future__ import annotations

import csv
import statistics
import sys
from pathlib import Path


def latency_us(raw: str) -> float:
    raw = raw.strip().lower()
    if raw.endswith("us"):
        return float(raw[:-2])
    if raw.endswith("ms"):
        return float(raw[:-2]) * 1000.0
    if raw.endswith("s"):
        return float(raw[:-1]) * 1_000_000.0
    raise ValueError(f"unsupported wrk latency unit: {raw!r}")


def med(values: list[float]) -> float:
    return statistics.median(values)


def main(path: str) -> int:
    root = Path(path)
    rows: list[dict[str, str]] = []
    with (root / "samples.tsv").open(newline="") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))

    keep = [r for r in rows if not r["case"].startswith("close-")]
    by_kind: dict[str, list[dict[str, str]]] = {"internal": [], "steered": []}
    for row in keep:
        by_kind["internal" if "internal" in row["case"] else "steered"].append(row)

    summary: list[str] = ["# sk_lookup performance summary", ""]
    metrics: dict[str, tuple[float, float, int]] = {}
    for kind, sample in by_kind.items():
        rps = [float(r["rps"]) for r in sample]
        p99 = [latency_us(r["p99"]) for r in sample]
        metrics[kind] = (med(rps), med(p99), len(sample))
        summary.append(
            f"{kind}: n={len(sample)} median_rps={med(rps):.2f} "
            f"median_p99_us={med(p99):.2f}"
        )

    irps, ip99, _ = metrics["internal"]
    srps, sp99, _ = metrics["steered"]
    summary.extend(
        [
            "",
            f"keepalive_rps_ratio_steered_over_internal={srps / irps:.4f}",
            f"keepalive_p99_abs_delta_us={sp99 - ip99:.2f}",
            f"keepalive_p99_ratio_steered_over_internal={sp99 / ip99:.4f}",
        ]
    )

    close = {"internal": None, "steered": None}
    for row in rows:
        if row["case"] == "close-internal":
            close["internal"] = row
        elif row["case"] == "close-steered":
            close["steered"] = row
    if close["internal"] and close["steered"]:
        ci, cs = close["internal"], close["steered"]
        ci_rps, cs_rps = float(ci["rps"]), float(cs["rps"])
        ci_p99, cs_p99 = latency_us(ci["p99"]), latency_us(cs["p99"])
        summary.extend(
            [
                "",
                f"new_connection_internal_rps={ci_rps:.2f}",
                f"new_connection_steered_rps={cs_rps:.2f}",
                f"new_connection_rps_ratio_steered_over_internal={cs_rps / ci_rps:.4f}",
                f"new_connection_p99_abs_delta_us={cs_p99 - ci_p99:.2f}",
                f"new_connection_p99_ratio_steered_over_internal={cs_p99 / ci_p99:.4f}",
            ]
        )

    runtime: list[dict[str, str]] = []
    with (root / "bpf-runtime.tsv").open(newline="") as f:
        runtime = list(csv.DictReader(f, delimiter="\t"))
    keep_ns = [float(r["ns_per_syn"]) for r in runtime if r["pair"] != "close"]
    close_ns = [float(r["ns_per_syn"]) for r in runtime if r["pair"] == "close"]
    summary.extend(
        [
            "",
            f"bpf_keepalive_connection_dispatch_median_ns_per_syn={med(keep_ns):.2f}",
            f"bpf_close_connection_dispatch_ns_per_syn={close_ns[0]:.2f}",
            "hardware_cycles=UNAVAILABLE_IN_THIS_VM (perf reports <not supported>; no substitute value asserted)",
        ]
    )

    text = "\n".join(summary) + "\n"
    (root / "summary.md").write_text(text)
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) == 2 else "."))
