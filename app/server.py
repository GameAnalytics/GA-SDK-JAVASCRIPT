#!/usr/bin/env python3
"""
GA SDK test-app dev server.

Serves the repo root so ../dist/ paths resolve from app/.
Proxies /ga-proxy/* → https://api.gameanalytics.com/* so the browser
never makes a cross-origin request and CORS is not an issue.
Opens the browser automatically.

Usage:
    python3 app/server.py           # port 3000 (default)
    python3 app/server.py 8080      # custom port
"""

import http.server
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser

PORT      = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
GA_API    = "https://api.gameanalytics.com"
PROXY_PFX = "/ga-proxy"

# Serve files from the repo root so app/ can reference ../dist/
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Build state (shared across threads) ──────────────────────────────────────
_build_lock        = threading.Lock()
_building          = False
_build_queued      = False
_last_build_result = None   # {"status": "done"|"failed", "message": str}
_build_log         = []     # list of output lines


def _run_build():
    global _building, _build_queued, _last_build_result, _build_log

    with _build_lock:
        if _building:
            _build_queued = True
            return
        _building = True
        _build_queued = False

    _build_log = ["[build] compiling src → dist/GameAnalytics.debug.js …"]
    _last_build_result = None

    npx = shutil.which("npx") or "npx"
    try:
        proc = subprocess.Popen(
            [npx, "gulp", "debug"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            clean = re.sub(r'\x1b\[[0-9;]*m', '', line).rstrip()
            if clean:
                _build_log.append(clean)
        proc.wait()
        code = proc.returncode
    except Exception as exc:
        code = 1
        _build_log.append(f"[build] error: {exc}")

    with _build_lock:
        _building = False
        if code == 0:
            _build_log.append("[build] ✓ done")
            _last_build_result = {"status": "done"}
        else:
            _build_log.append(f"[build] ✗ failed (exit {code})")
            _last_build_result = {"status": "failed", "message": "\n".join(_build_log)}
        queued = _build_queued

    if queued:
        threading.Thread(target=_run_build, daemon=True).start()

EXTRA_MIME = {
    ".js":   "application/javascript; charset=utf-8",
    ".mjs":  "application/javascript; charset=utf-8",
    ".ts":   "application/typescript",
    ".wasm": "application/wasm",
    ".map":  "application/json",
}

# Forward exactly these request headers to the GA API
FORWARD_HEADERS = {"content-type", "authorization"}


class Handler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=REPO_ROOT, **kwargs)

    # ── CORS preflight ────────────────────────────────────────────────────
    def do_OPTIONS(self):
        self._send_cors_preflight()

    # ── GET: static files, build status, or proxy ────────────────────────
    def do_GET(self):
        if self.path.startswith(PROXY_PFX):
            self._proxy()
            return
        if self.path.split("?")[0] == "/build-status":
            self._build_status()
            return
        if self.path in ("/", ""):
            self.send_response(302)
            self.send_header("Location", "/app/")
            self.end_headers()
            return
        super().do_GET()

    # ── POST: proxy or rebuild trigger ────────────────────────────────────
    def do_POST(self):
        if self.path.startswith(PROXY_PFX):
            self._proxy()
        elif self.path.split("?")[0] == "/rebuild":
            self._trigger_rebuild()
        else:
            self.send_error(404)

    # ── Build endpoints ───────────────────────────────────────────────────
    def _trigger_rebuild(self):
        global _last_build_result
        _last_build_result = None
        threading.Thread(target=_run_build, daemon=True).start()
        body = json.dumps({"status": "started"}).encode()
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _build_status(self):
        with _build_lock:
            payload = {
                "building": _building,
                "result":   _last_build_result,
                "log":      list(_build_log),
            }
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── Proxy implementation ──────────────────────────────────────────────
    def _proxy(self):
        # Strip /ga-proxy prefix, forward the rest to the GA API
        upstream_path = self.path[len(PROXY_PFX):]   # e.g. /v2/{key}/events
        target = GA_API + upstream_path

        # Read request body (POST only)
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length) if length > 0 else None

        # Build upstream request, forwarding relevant headers
        fwd_headers = {
            k: v for k, v in self.headers.items()
            if k.lower() in FORWARD_HEADERS
        }
        req = urllib.request.Request(
            target, data=body, headers=fwd_headers, method=self.command
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_body = resp.read()
                self._send_proxy_response(resp.status, resp_body,
                                          resp.headers.get("Content-Type", "application/json"))
        except urllib.error.HTTPError as exc:
            # GA API returned a 4xx/5xx — relay it faithfully
            resp_body = exc.read()
            self._send_proxy_response(exc.code, resp_body, "application/json")
        except Exception as exc:
            msg = f'{{"proxy_error": "{exc}"}}'.encode()
            self._send_proxy_response(502, msg, "application/json")
            print(f"  [proxy error] {exc}")

    def _send_proxy_response(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type",   content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control",  "no-store")
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def _send_cors_preflight(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Max-Age",       "86400")
        self.end_headers()

    # ── Static file overrides ─────────────────────────────────────────────
    def guess_type(self, path):
        ext = os.path.splitext(path)[1].lower()
        return EXTRA_MIME.get(ext, super().guess_type(path))

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

    def log_message(self, fmt, *args):
        # Only print proxy requests; suppress noisy static-file lines
        pass


# ── Startup ───────────────────────────────────────────────────────────────

def is_port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


PID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".server.pid")


def _stop_existing():
    """Kill a previously-started instance recorded in the PID file."""
    if not os.path.exists(PID_FILE):
        return
    try:
        with open(PID_FILE) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        # Wait up to 3 s for the process to exit and release the port
        for _ in range(30):
            try:
                os.kill(pid, 0)   # 0 = just check existence
            except ProcessLookupError:
                break
            time.sleep(0.1)
    except (ValueError, ProcessLookupError, PermissionError):
        pass
    try:
        os.unlink(PID_FILE)
    except FileNotFoundError:
        pass


def main():
    _stop_existing()

    if not is_port_free(PORT):
        print(f"\n  Port {PORT} is already in use. Try:  python3 app/server.py <other-port>\n")
        sys.exit(1)

    url       = f"http://127.0.0.1:{PORT}/app/"
    proxy_url = f"http://127.0.0.1:{PORT}{PROXY_PFX}"

    print()
    print("  GA SDK Test App")
    print("  " + "─" * 45)
    print(f"  App:     {url}")
    print(f"  Proxy:   {proxy_url}  →  {GA_API}")
    print()
    print("  In the test app, click 'Use Local Proxy' before")
    print("  initializing to route SDK traffic through the proxy")
    print("  and avoid browser CORS restrictions.")
    print()
    print("  Ctrl+C to stop")
    print()

    _restart  = threading.Event()
    httpd_ref = [None]   # mutable cell so signal handlers can reach the server

    def _shutdown(signum, frame):
        """SIGTERM — clean exit."""
        if httpd_ref[0]:
            threading.Thread(target=httpd_ref[0].shutdown, daemon=True).start()

    def _restart_handler(signum, frame):
        """SIGUSR1 — restart in-place."""
        _restart.set()
        if httpd_ref[0]:
            threading.Thread(target=httpd_ref[0].shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    if hasattr(signal, "SIGUSR1"):          # not available on Windows
        signal.signal(signal.SIGUSR1, _restart_handler)

    # Write PID so control.py can find this process
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    try:
        with http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler) as httpd:
            httpd_ref[0] = httpd
            threading.Timer(0.4, webbrowser.open, args=[url]).start()
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\n  Server stopped.")
    finally:
        try:
            os.unlink(PID_FILE)
        except FileNotFoundError:
            pass

    if _restart.is_set():
        print("  Restarting …")
        os.execv(sys.executable, [sys.executable] + sys.argv)


if __name__ == "__main__":
    main()
