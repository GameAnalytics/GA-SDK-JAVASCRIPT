#!/usr/bin/env python3
"""
Build the GA JavaScript SDK.

Usage:
    python build.py            # full build (all targets)
    python build.py debug      # debug build only  -> dist/GameAnalytics.debug.js
    python build.py mini       # minified build    -> dist/GameAnalytics.min.js
    python build.py normal     # normal build      -> dist/GameAnalytics.js
    python build.py --clean    # clean then full build
    python build.py debug --clean  # clean then debug build
"""

import subprocess
import sys
import shutil
import os

ROOT = os.path.dirname(os.path.abspath(__file__))

VALID_TASKS = {"debug", "mini", "normal", "unity", "ga_node", "construct", "esm", "default"}


def clean():
    npm = shutil.which("npm")
    if not npm:
        print("Error: npm not found. Install Node.js and npm first.")
        sys.exit(1)

    print("Cleaning npm cache...")
    subprocess.run([npm, "cache", "clean", "--force"], cwd=ROOT, check=True)

    node_modules = os.path.join(ROOT, "node_modules")
    if os.path.isdir(node_modules):
        print("Removing node_modules...")
        shutil.rmtree(node_modules)

    lock_file = os.path.join(ROOT, "package-lock.json")
    if os.path.isfile(lock_file):
        print("Removing package-lock.json...")
        os.remove(lock_file)

    print("Reinstalling dependencies...")
    result = subprocess.run([npm, "install"], cwd=ROOT)
    if result.returncode != 0:
        sys.exit(result.returncode)


def main():
    args = sys.argv[1:]
    do_clean = "--clean" in args
    args = [a for a in args if a != "--clean"]

    task = args[0] if args else "default"

    if task not in VALID_TASKS:
        print(f"Unknown task '{task}'. Valid tasks: {', '.join(sorted(VALID_TASKS))}")
        sys.exit(1)

    if do_clean:
        clean()

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
