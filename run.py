#!/usr/bin/env python3
"""HQG Security Platform — single-command launcher.

Usage:
    python3 run.py                  # backend + pipeline + frontend
    python3 run.py --no-ui          # skip the Vite frontend
    python3 run.py --no-pipeline    # skip the XDR pipeline (just API + UI)
    python3 run.py --check          # validate prereqs, print diagnostics, exit

Behavior:
    • Validates prereqs (venv, .env, postgres, Zeek) and prints a checklist
    • Spawns each service as a child process
    • Multiplexes their stdout/stderr into one console with coloured prefixes
    • Ctrl-C → graceful shutdown of every child (SIGTERM, then SIGKILL after 5s)
    • If a child crashes, logs a banner and exits the launcher (you'll know fast)

This launcher does NOT touch Zeek (which runs as root via zeekctl).  It will
warn if Zeek isn't healthy and tell you exactly what command to run.
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
VENV_PY      = PROJECT_ROOT / ".venv" / "bin" / "python"
ENV_FILE     = PROJECT_ROOT / ".env"
ZEEK_BIN     = Path("/usr/local/zeek/bin/zeekctl")
ZEEK_LOG_DIR = Path("/usr/local/zeek/logs/current")

# ── ANSI colours ────────────────────────────────────────────────────────────
USE_COLOR = sys.stdout.isatty()
def C(code: str) -> str: return code if USE_COLOR else ""
RESET    = C("\033[0m")
DIM      = C("\033[2m")
BOLD     = C("\033[1m")
RED      = C("\033[31m")
GREEN    = C("\033[32m")
YELLOW   = C("\033[33m")
BLUE     = C("\033[34m")
MAGENTA  = C("\033[35m")
CYAN     = C("\033[36m")

def log(prefix: str, color: str, text: str) -> None:
    print(f"{color}[{prefix:<8}]{RESET} {text}", flush=True)

def banner(text: str) -> None:
    line = "═" * max(len(text), 60)
    print(f"\n{BOLD}{CYAN}{line}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{line}{RESET}\n")

# ── Prereq checks ───────────────────────────────────────────────────────────

def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

def check_prereqs(verbose: bool = True) -> dict:
    """Returns a dict of check → (ok, detail).  Prints a tidy table."""
    checks: dict[str, tuple[bool, str]] = {}

    checks["venv (.venv/bin/python)"] = (
        VENV_PY.exists(), str(VENV_PY)
    )
    checks[".env file"] = (
        ENV_FILE.exists(), str(ENV_FILE)
    )
    checks["node_modules"] = (
        (PROJECT_ROOT / "node_modules").exists(),
        "run `npm install` if missing",
    )
    pg = port_open("127.0.0.1", 5432)
    checks["PostgreSQL :5432"] = (
        pg, "ok" if pg else "start with: sudo systemctl start postgresql",
    )
    api_already = port_open("127.0.0.1", 3001)
    checks["API :3001 free"] = (
        not api_already,
        "in use — old uvicorn?  pkill -f 'uvicorn passive_asset_intel'" if api_already else "available",
    )
    ui_already = port_open("127.0.0.1", 8080)
    checks["UI :8080 free"] = (
        not ui_already,
        "in use — old vite?  pkill -f vite" if ui_already else "available",
    )
    # Zeek health check WITHOUT sudo: any conn.log/dns.log written in the
    # last 5 minutes ⇒ sensor is alive.  Avoids the password prompt that
    # `zeekctl status` would otherwise require.
    zeek_ok = False
    zeek_detail = "log dir empty / no recent activity"
    if ZEEK_LOG_DIR.exists():
        recent = 0
        for log_name in ("conn.log", "dns.log", "ssl.log", "http.log"):
            p = ZEEK_LOG_DIR / log_name
            if p.exists():
                age = time.time() - p.stat().st_mtime
                if age < 300:    # 5 minutes
                    recent += 1
        if recent > 0:
            zeek_ok = True
            zeek_detail = f"{recent} log(s) updated in last 5 min"
        elif any(ZEEK_LOG_DIR.glob("*.log")):
            zeek_ok = True   # logs exist, just no recent traffic — still ok
            zeek_detail = "logs present (idle network)"
        else:
            zeek_detail = "start with: sudo /usr/local/zeek/bin/zeekctl deploy"
    checks["Zeek sensor"] = (zeek_ok, zeek_detail)
    checks["Zeek log dir readable"] = (
        ZEEK_LOG_DIR.exists() and os.access(ZEEK_LOG_DIR, os.R_OK),
        str(ZEEK_LOG_DIR),
    )

    if verbose:
        for name, (ok, detail) in checks.items():
            mark = f"{GREEN}✓{RESET}" if ok else f"{YELLOW}⚠{RESET}"
            print(f"  {mark} {name:<30}  {DIM}{detail}{RESET}")
    return checks

# ── Process orchestration ───────────────────────────────────────────────────

class Service:
    def __init__(self, name: str, color: str, cmd: list[str], cwd: Path = PROJECT_ROOT,
                 env_extra: dict | None = None):
        self.name  = name
        self.color = color
        self.cmd   = cmd
        self.cwd   = cwd
        self.env_extra = env_extra or {}
        self.proc: subprocess.Popen | None = None
        self.reader_thread: threading.Thread | None = None

    def start(self) -> None:
        env = os.environ.copy()
        env.update(self.env_extra)
        log(self.name, self.color, f"{BOLD}starting{RESET} → {' '.join(self.cmd)}")
        self.proc = subprocess.Popen(
            self.cmd,
            cwd=str(self.cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            text=True,
            env=env,
            preexec_fn=os.setsid,   # new process group for clean kill
        )
        self.reader_thread = threading.Thread(
            target=self._pump, daemon=True, name=f"reader-{self.name}",
        )
        self.reader_thread.start()

    def _pump(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            print(f"{self.color}[{self.name:<8}]{RESET} {line.rstrip()}", flush=True)

    def stop(self, timeout: float = 5.0) -> None:
        if not self.proc or self.proc.poll() is not None:
            return
        log(self.name, self.color, "stopping (SIGTERM)…")
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            log(self.name, self.color, f"{YELLOW}didn't stop in {timeout}s — SIGKILL{RESET}")
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None


def build_services(args) -> list[Service]:
    services: list[Service] = []

    # Backend
    services.append(Service(
        name="API",
        color=GREEN,
        cmd=[str(VENV_PY), "-m", "uvicorn",
             "passive_asset_intel.api.main:app",
             "--host", "0.0.0.0", "--port", "3001"],
    ))

    # Pipeline (XDR live ingest)
    if not args.no_pipeline:
        services.append(Service(
            name="PIPE",
            color=MAGENTA,
            cmd=[str(VENV_PY), "-m", "passive_asset_intel.services.zeek_pipeline"],
        ))

    # Frontend
    if not args.no_ui:
        npm = shutil.which("npm")
        if not npm:
            log("LAUNCH", RED, "npm not found in PATH — skipping UI")
        else:
            services.append(Service(
                name="UI",
                color=BLUE,
                cmd=[npm, "run", "dev:ui"],
            ))

    return services


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--no-ui",        action="store_true", help="skip Vite frontend")
    p.add_argument("--no-pipeline",  action="store_true", help="skip XDR pipeline (only API + UI)")
    p.add_argument("--check",        action="store_true", help="run prereq checks then exit")
    p.add_argument("--quiet-checks", action="store_true", help="suppress prereq diagnostics")
    args = p.parse_args()

    banner("HQG Security Platform — launcher")

    print(f"{BOLD}Prerequisites:{RESET}")
    checks = check_prereqs(verbose=not args.quiet_checks)

    blocking = [name for name, (ok, _) in checks.items()
                if not ok and name in ("venv (.venv/bin/python)", ".env file",
                                        "PostgreSQL :5432",
                                        "API :3001 free", "UI :8080 free")]
    if blocking:
        print(f"\n{RED}{BOLD}Blocking issues — fix and retry:{RESET}")
        for name in blocking:
            print(f"  {RED}✗{RESET} {name}: {checks[name][1]}")
        return 2

    if args.check:
        return 0

    services = build_services(args)

    # Start every service
    for s in services:
        s.start()
        time.sleep(0.5)

    # Print where to point the browser
    print()
    print(f"{BOLD}{GREEN}╭─────────────────────────────────────────────────────────╮{RESET}")
    print(f"{BOLD}{GREEN}│  Dashboard : http://localhost:8080                      │{RESET}")
    print(f"{BOLD}{GREEN}│  API       : http://localhost:3001/health               │{RESET}")
    print(f"{BOLD}{GREEN}│  Login     : admin / admin123                           │{RESET}")
    print(f"{BOLD}{GREEN}│  Stop      : Ctrl-C                                     │{RESET}")
    print(f"{BOLD}{GREEN}╰─────────────────────────────────────────────────────────╯{RESET}")
    print()

    # Graceful shutdown handler
    stopping = threading.Event()
    def on_signal(_sig, _frm):
        if stopping.is_set():
            return
        stopping.set()
        print()
        banner("Shutting down all services…")
        for s in reversed(services):
            s.stop()
        print(f"{GREEN}{BOLD}Bye.{RESET}")

    signal.signal(signal.SIGINT,  on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    # Supervise — exit if any service dies unexpectedly
    try:
        while not stopping.is_set():
            for s in services:
                if not s.alive:
                    log("LAUNCH", RED,
                        f"{BOLD}{s.name} exited (code {s.proc.returncode if s.proc else '?'}) — tearing down{RESET}")
                    on_signal(0, None)
                    return s.proc.returncode if s.proc else 1
            time.sleep(1)
    except KeyboardInterrupt:
        on_signal(0, None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
