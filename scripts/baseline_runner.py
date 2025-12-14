#!/usr/bin/env python3
"""
Baseline AFL++ runner with periodic stats polling and quick plots.
Usage example:
  python scripts/baseline_runner.py \
      --binary ./binaries/cgc_cadet_00001_instrumented \
      --input data/inputs_cgc_cadet_00001 \
      --output data/outputs_baseline_5min \
      --duration 300
"""

import argparse
import json
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Dict, List

import matplotlib.pyplot as plt


def parse_fuzzer_stats(path: Path) -> Dict[str, float]:
    stats: Dict[str, float] = {}
    if not path.exists():
        return stats
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                if ":" not in line:
                    continue
                key, val = line.split(":", 1)
                stats[key.strip()] = val.strip()
    except Exception:
        return {}
    try:
        stats["execs_done"] = float(stats.get("execs_done", 0))
        stats["execs_per_sec"] = float(stats.get("execs_per_sec", 0.0))
        stats["corpus_count"] = float(stats.get("corpus_count", 0))
        stats["saved_crashes"] = float(stats.get("saved_crashes", 0))
        stats["bitmap_cvg"] = float(str(stats.get("bitmap_cvg", "0")).rstrip("%"))
        stats["last_update"] = float(stats.get("last_update", 0))
    except Exception:
        pass
    return stats


def poll_stats(stats_file: Path, start_ts: float, log_file: Path) -> List[Dict[str, float]]:
    history: List[Dict[str, float]] = []
    if not stats_file.exists():
        return history
    stats = parse_fuzzer_stats(stats_file)
    if not stats:
        return history
    snapshot = {
        "timestamp": time.time(),
        "session_runtime": time.monotonic() - start_ts,
        "execs_done": stats.get("execs_done", 0),
        "execs_per_sec": stats.get("execs_per_sec", 0),
        "paths_total": stats.get("corpus_count", 0),
        "crashes_total": stats.get("saved_crashes", 0),
        "coverage_estimate": stats.get("bitmap_cvg", 0),
    }
    history.append(snapshot)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(snapshot) + "\n")
    return history


def plot_series(times: List[float], values: List[float], title: str, ylabel: str, path: Path, color: str) -> None:
    if not times or not values or len(times) != len(values):
        return
    plt.figure(figsize=(10, 5))
    plt.plot(times, values, color=color, linewidth=2.0, marker="o", markersize=3, alpha=0.85)
    plt.fill_between(times, values, alpha=0.18, color=color)
    plt.xlabel("Time (minutes)")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.grid(True, alpha=0.3, linestyle="--")
    plt.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()


def generate_plots(log_file: Path, plot_dir: Path) -> None:
    if not log_file.exists():
        return
    times: List[float] = []
    paths: List[float] = []
    crashes: List[float] = []
    execs: List[float] = []
    coverage: List[float] = []
    with log_file.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            times.append(entry.get("session_runtime", 0) / 60.0)
            paths.append(entry.get("paths_total", 0))
            crashes.append(entry.get("crashes_total", 0))
            execs.append(entry.get("execs_per_sec", 0))
            coverage.append(entry.get("coverage_estimate", 0))
    plot_series(times, paths, "Baseline Paths Over Time", "Total Paths", plot_dir / "paths_over_time.png", "#3498db")
    plot_series(times, crashes, "Baseline Crashes Over Time", "Crashes", plot_dir / "crashes_over_time.png", "#e74c3c")
    plot_series(times, execs, "Baseline Exec Speed", "Execs/sec", plot_dir / "exec_speed_over_time.png", "#2ecc71")
    plot_series(times, coverage, "Baseline Coverage", "Coverage (%)", plot_dir / "coverage_over_time.png", "#9b59b6")


def run_baseline(args: argparse.Namespace) -> None:
    output_dir = Path(args.output).resolve()
    stats_file = output_dir / "default" / "fuzzer_stats"
    log_file = output_dir / "baseline_metrics.jsonl"
    plot_dir = output_dir / "baseline_plots"

    cmd = [
        "afl-fuzz",
        "-i",
        args.input,
        "-o",
        args.output,
        "-m",
        args.mem_limit,
        "-t",
        str(args.timeout_ms),
        "--",
        args.binary,
    ]
    env = os.environ.copy()
    env.setdefault("AFL_SKIP_CPUFREQ", "1")

    start_ts = time.monotonic()
    proc = subprocess.Popen(cmd, env=env)
    try:
        while True:
            now = time.monotonic()
            if args.duration and now - start_ts >= args.duration:
                break
            poll_stats(stats_file, start_ts, log_file)
            time.sleep(args.poll_interval)
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    # Final poll after stop
    poll_stats(stats_file, start_ts, log_file)
    generate_plots(log_file, plot_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run baseline AFL++ with periodic stats polling and plots")
    parser.add_argument("--binary", required=True, help="Path to target binary")
    parser.add_argument("--input", required=True, help="Seed directory")
    parser.add_argument("--output", required=True, help="AFL++ output directory")
    parser.add_argument("--duration", type=int, default=300, help="Duration in seconds (default: 300)")
    parser.add_argument("--poll-interval", type=int, default=5, help="Stats poll interval seconds (default: 5)")
    parser.add_argument("--timeout-ms", type=int, default=1000, help="AFL exec timeout ms (default: 1000)")
    parser.add_argument("--mem-limit", default="none", help="AFL memory limit (default: none)")
    args = parser.parse_args()
    run_baseline(args)
