#!/usr/bin/env python3
"""
Control script for the GA SDK dev server (server.py).

Usage (from the repo root):
    python3 app/control.py --restart    # restart the server in-place
    python3 app/control.py --exit       # shut the server down cleanly
"""

from __future__ import annotations   # allows X | Y union hints on Python < 3.10

import argparse
import os
import signal
import sys

# Must match the path written by server.py
PID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".server.pid")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def read_pid() -> int | None:
    """Return the PID from the file, or None if absent / unreadable."""
    try:
        with open(PID_FILE) as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None


def is_alive(pid: int) -> bool:
    """Return True if a process with this PID exists."""
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def require_server() -> int:
    """Return the server PID, or exit with an error if it isn't running."""
    pid = read_pid()
    if pid is None:
        sys.exit(
            "No PID file found — is server.py running?\n"
            f"  (looked for {PID_FILE})"
        )
    if not is_alive(pid):
        sys.exit(
            f"PID {pid} is no longer alive — the server may have crashed.\n"
            f"  Remove {PID_FILE} manually if it is stale."
        )
    return pid


# ─── Actions ──────────────────────────────────────────────────────────────────

def do_exit(pid: int) -> None:
    if sys.platform == "win32":
        # Windows has no SIGTERM; TerminateProcess via taskkill is the equivalent
        import subprocess
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=True)
    else:
        os.kill(pid, signal.SIGTERM)
    print(f"  ✓ Sent SIGTERM to server (PID {pid}) — it will exit cleanly.")


def do_restart(pid: int) -> None:
    if sys.platform == "win32":
        sys.exit(
            "In-place restart via SIGUSR1 is not supported on Windows.\n"
            "  Use --exit, then start server.py manually."
        )
    if not hasattr(signal, "SIGUSR1"):
        sys.exit("SIGUSR1 is not available on this platform.")
    os.kill(pid, signal.SIGUSR1)
    print(f"  ✓ Sent SIGUSR1 to server (PID {pid}) — it will restart in-place.")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Control the GA SDK dev server (server.py).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 app/control.py --restart\n"
            "  python3 app/control.py --exit\n"
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--restart",
        action="store_true",
        help="Restart the server in-place (sends SIGUSR1)",
    )
    group.add_argument(
        "--exit",
        action="store_true",
        help="Stop the server cleanly (sends SIGTERM)",
    )
    args = parser.parse_args()

    pid = require_server()

    if args.exit:
        do_exit(pid)
    elif args.restart:
        do_restart(pid)


if __name__ == "__main__":
    main()
