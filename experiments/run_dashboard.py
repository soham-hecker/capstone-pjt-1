#!/usr/bin/env python3
"""
Dashboard Launcher for Phase 8C: Human-in-the-Loop SOC Dashboard.
Project: Self-Adaptive Zero Trust Cybersecurity Architecture for Industry 5.0

Usage:
    python experiments/run_dashboard.py
"""

from pathlib import Path
import subprocess
import sys

BASE_DIR = Path(__file__).resolve().parent.parent
APP_PATH = BASE_DIR / "dashboard/app.py"


def main():
    print("=" * 80)
    print("INDUSTRY 5.0 ZERO TRUST CYBERSECURITY: SOC DASHBOARD LAUNCHER")
    print("=" * 80)
    print(f"Target App       : {APP_PATH}")
    print(f"Python Runtime   : {sys.executable}")

    # Check streamlit module
    try:
        import streamlit
        print(f"Streamlit Engine : Version {streamlit.__version__} (READY)")
    except ImportError:
        print("[!] Streamlit is not installed. Run: pip install streamlit")
        sys.exit(1)

    print("\n[+] Launching Streamlit web application on http://localhost:8501 ...")
    print("[+] Press Ctrl+C in terminal to stop dashboard server.\n")

    cmd = [sys.executable, "-m", "streamlit", "run", str(APP_PATH), "--server.headless", "false"]
    try:
        subprocess.run(cmd, cwd=str(BASE_DIR))
    except KeyboardInterrupt:
        print("\n[*] SOC Dashboard terminated by user.")


if __name__ == "__main__":
    main()
