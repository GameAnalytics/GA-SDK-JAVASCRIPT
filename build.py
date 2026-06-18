#!/usr/bin/env python3
"""
Build the GA JavaScript SDK.

Usage:
    python build.py            # full build (all targets)
    python build.py debug      # debug build only  -> dist/GameAnalytics.debug.js
    python build.py mini       # minified build    -> dist/GameAnalytics.min.js
    python build.py normal     # normal build      -> dist/GameAnalytics.js
"""

import subprocess
import sys
import shutil
import os

ROOT = os.path.dirname(os.path.abspath(__file__))

VALID_TASKS = {"debug", "mini", "normal", "unity", "ga_node", "construct", "esm", "default"}


def main():
    task = sys.argv[1] if len(sys.argv) > 1 else "default"

    if task not in VALID_TASKS:
        print(f"Unknown task '{task}'. Valid tasks: {', '.join(sorted(VALID_TASKS))}")
        sys.exit(1)

    npx = shutil.which("npx")
    if not npx:
        print("Error: npx not found. Install Node.js and npm first.")
        sys.exit(1)

    cmd = [npx, "gulp", task]
    print(f"Running: {' '.join(cmd)}")

    result = subprocess.run(cmd, cwd=ROOT)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
