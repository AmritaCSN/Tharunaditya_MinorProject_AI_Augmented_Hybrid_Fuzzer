"""
Sequential multi-binary runner for NeuroFuzz.

Usage:
    python multi_binary_runner.py --config configs/run_30min.yml --binaries binaries/a binaries/b

This reuses the same config file, swapping binary.target_path and campaign_name per binary.
"""

import argparse
import copy
import subprocess
import sys
from pathlib import Path
import yaml


def run_for_binary(base_config_path: Path, binary_path: Path, suffix: str) -> int:
    with open(base_config_path, 'r') as f:
        cfg = yaml.safe_load(f)

    cfg['binary']['target_path'] = str(binary_path)
    cfg['general']['campaign_name'] = f"{cfg['general'].get('campaign_name', 'campaign')}_{suffix}"

    temp_cfg_path = base_config_path.parent / f".{binary_path.name}_tmp.yml"
    with open(temp_cfg_path, 'w') as f:
        yaml.safe_dump(cfg, f)

    cmd = [sys.executable, 'neurofuzz.py', '--config', str(temp_cfg_path)]
    result = subprocess.run(cmd)

    try:
        temp_cfg_path.unlink()
    except Exception:
        pass

    return result.returncode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True, help='Base YAML config path')
    parser.add_argument('--binaries', nargs='+', required=True, help='List of binary paths to run sequentially')
    args = parser.parse_args()

    base_config = Path(args.config)
    binaries = [Path(b) for b in args.binaries]

    failures = []
    for idx, bin_path in enumerate(binaries):
        code = run_for_binary(base_config, bin_path, suffix=f"b{idx}")
        if code != 0:
            failures.append((bin_path, code))

    if failures:
        print("Failures:")
        for b, c in failures:
            print(f"  {b} -> exit {c}")
        sys.exit(1)


if __name__ == '__main__':
    main()
