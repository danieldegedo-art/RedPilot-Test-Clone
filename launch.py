#!/usr/bin/env python3
"""RedPilot Desktop Launcher — paste a domain, press Run, see results.

Usage:
    python3 launch.py

Starts the backend server automatically, opens a GUI window.
No configuration needed. Just a domain and go.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BACKEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend")
API_BASE = "http://127.0.0.1:8420"
SERVER_PROC: subprocess.Popen | None = None


# ---------------------------------------------------------------------------
# Server management
# ---------------------------------------------------------------------------
def start_server(status_var: tk.StringVar, root: tk.Tk) -> None:
    global SERVER_PROC
    env = os.environ.copy()
    env["PYTHONPATH"] = BACKEND_DIR
    try:
        SERVER_PROC = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app",
             "--host", "127.0.0.1", "--port", "8420"],
            cwd=BACKEND_DIR, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        # Wait for health
        import urllib.request
        for attempt in range(30):
            time.sleep(1)
            try:
                r = urllib.request.urlopen(f"{API_BASE}/health", timeout=2)
                if r.status == 200:
                    root.after(0, lambda: status_var.set("Server ready"))
                    return
            except Exception:
                pass
        root.after(0, lambda: status_var.set("Server failed to start"))
    except Exception as e:
        root.after(0, lambda: status_var.set(f"Error: {e}"))


def stop_server() -> None:
    global SERVER_PROC
    if SERVER_PROC:
        SERVER_PROC.terminate()
        try:
            SERVER_PROC.wait(timeout=5)
        except subprocess.TimeoutExpired:
            SERVER_PROC.kill()
        SERVER_PROC = None


# ---------------------------------------------------------------------------
# Scan logic
# ---------------------------------------------------------------------------
def run_scan(url: str, twin_url: str | None, output: scrolledtext.ScrolledText,
             status_var: tk.StringVar, run_btn: ttk.Button, root: tk.Tk) -> None:
    import urllib.request

    def log(msg: str) -> None:
        root.after(0, lambda: (output.insert(tk.END, msg + "\n"), output.see(tk.END)))

    def set_status(msg: str) -> None:
        root.after(0, lambda: status_var.set(msg))

    def done() -> None:
        root.after(0, lambda: run_btn.configure(state="normal"))

    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"https://{url}"

        body: dict = {"url": url}
        if twin_url and twin_url.strip():
            body["twin_url"] = twin_url.strip()

        log(f"{'=' * 60}")
        log(f"  RedPilot Scan")
        log(f"  Target: {url}")
        if twin_url and twin_url.strip():
            log(f"  Twin:   {twin_url.strip()}")
        log(f"  Mode:   {'DUAL-TARGET' if twin_url and twin_url.strip() else 'FULL REGRESSION'}")
        log(f"{'=' * 60}\n")

        set_status("Starting scan...")
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            f"{API_BASE}/api/v1/runs/scan",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=30)
        result = json.loads(resp.read())
        run_id = result["run_id"]
        log(f"Run started: {run_id}")
        log(f"Status: {result['status']}\n")

        # Poll for completion
        while True:
            time.sleep(2)
            resp = urllib.request.urlopen(f"{API_BASE}/api/v1/runs/{run_id}", timeout=10)
            run = json.loads(resp.read())
            status = run["status"]

            if status in ("completed", "failed", "cancelled"):
                results = run.get("results", [])
                fails = [r for r in results if r.get("status") == "FAIL"]
                warnings = [r for r in results if r.get("status") == "WARNING"]
                passes = [r for r in results if r.get("status") == "PASS"]

                log(f"\nStatus: {status.upper()}")
                log(f"Results: {len(results)} total | {len(fails)} FAIL | {len(warnings)} WARNING | {len(passes)} PASS\n")

                if fails:
                    log("=== CRITICAL FINDINGS ===\n")
                    for f in fails:
                        log(f"  [{f.get('category', '?')}] {f.get('name', '?')}")
                        log(f"    {str(f.get('actual', ''))[:200]}")
                        if f.get("recommendation"):
                            log(f"    -> {f['recommendation'][:200]}")
                        log("")

                if warnings:
                    log("=== WARNINGS ===\n")
                    for w in warnings:
                        log(f"  [{w.get('category', '?')}] {w.get('name', '?')}")
                        log(f"    {str(w.get('actual', ''))[:200]}")
                        log("")

                if not fails and not warnings:
                    log("No critical findings or warnings. Target appears hardened.\n")

                if run.get("error_message"):
                    log(f"Error: {run['error_message']}")

                set_status(f"Done — {len(fails)} FAIL, {len(warnings)} WARNING, {len(passes)} PASS")
                done()
                return

            set_status(f"Running... ({status})")

    except Exception as e:
        log(f"\nError: {e}")
        set_status(f"Error: {e}")
        done()


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
def build_gui() -> None:
    root = tk.Tk()
    root.title("RedPilot")
    root.geometry("780x620")
    root.configure(bg="#1a1a2e")
    root.resizable(True, True)

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Title.TLabel", background="#1a1a2e", foreground="#e94560",
                     font=("Helvetica", 22, "bold"))
    style.configure("Sub.TLabel", background="#1a1a2e", foreground="#888888",
                     font=("Helvetica", 11))
    style.configure("Field.TLabel", background="#1a1a2e", foreground="#cccccc",
                     font=("Helvetica", 12))
    style.configure("Status.TLabel", background="#1a1a2e", foreground="#0f3460",
                     font=("Helvetica", 10))
    style.configure("Run.TButton", font=("Helvetica", 14, "bold"), padding=(20, 10))
    style.map("Run.TButton",
              background=[("active", "#e94560"), ("!active", "#e94560")],
              foreground=[("active", "white"), ("!active", "white")])

    # Title
    ttk.Label(root, text="RedPilot", style="Title.TLabel").pack(pady=(20, 0))
    ttk.Label(root, text="Paste a domain. Press Run. Everything fires.",
              style="Sub.TLabel").pack(pady=(2, 15))

    # URL input
    input_frame = tk.Frame(root, bg="#1a1a2e")
    input_frame.pack(fill="x", padx=30)

    ttk.Label(input_frame, text="Cold Domain", style="Field.TLabel").pack(anchor="w")
    url_entry = tk.Entry(input_frame, font=("Menlo", 14), bg="#16213e", fg="white",
                         insertbackground="white", relief="flat", bd=8)
    url_entry.pack(fill="x", pady=(2, 10))
    url_entry.insert(0, "https://")
    url_entry.focus_set()

    ttk.Label(input_frame, text="Digital Twin (optional)", style="Field.TLabel").pack(anchor="w")
    twin_entry = tk.Entry(input_frame, font=("Menlo", 14), bg="#16213e", fg="#888888",
                          insertbackground="white", relief="flat", bd=8)
    twin_entry.pack(fill="x", pady=(2, 15))

    # Status
    status_var = tk.StringVar(value="Starting server...")
    ttk.Label(root, textvariable=status_var, style="Status.TLabel").pack()

    # Run button
    def on_run() -> None:
        url = url_entry.get().strip()
        if not url or url == "https://":
            messagebox.showwarning("RedPilot", "Enter a target domain.")
            return
        twin = twin_entry.get().strip() or None
        run_btn.configure(state="disabled")
        output.delete("1.0", tk.END)
        threading.Thread(target=run_scan, args=(url, twin, output, status_var, run_btn, root),
                         daemon=True).start()

    run_btn = ttk.Button(root, text="Run", style="Run.TButton", command=on_run)
    run_btn.pack(pady=10)

    # Output
    output = scrolledtext.ScrolledText(root, font=("Menlo", 11), bg="#0f0f23", fg="#00ff41",
                                       insertbackground="#00ff41", relief="flat", bd=8,
                                       height=14, state="normal")
    output.pack(fill="both", expand=True, padx=30, pady=(5, 20))

    # Start server in background
    threading.Thread(target=start_server, args=(status_var, root), daemon=True).start()

    # Cleanup on close
    def on_close() -> None:
        stop_server()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)

    # Enter key triggers Run
    root.bind("<Return>", lambda e: on_run())

    root.mainloop()


if __name__ == "__main__":
    build_gui()
