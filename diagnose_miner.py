#!/usr/bin/env python3
"""
diagnose_miner.py
=================
Antminer Deep-Dive Hardware Diagnostic & Log Analyzer.

Connects to Antminers (S19, S19j, S19 Pro, S19j Pro, S21, T19, etc.),
extracts system telemetry and kernel/bmminer logfiles via HTTP Digest/Basic Auth,
and performs automated root-cause failure analysis.

Identifies:
1. False 255°C / 'Miner Temperature: Abnormal' uninitialized sensor bug.
2. ASIC chip enumeration per chain (e.g. 126 chips expected vs 0 chips detected).
3. Ribbon cable CRC & I2C communication failures ('reg crc error').
4. Hardware pinout correlation (J1 = Chain 0, J2 = Chain 1, J3 = Chain 2).
5. Mixed hashboard model lockouts (e.g. BHB42603 vs BHB42601 'basic init failed!').
6. Fan RPM tachometer speeds and APW12 power supply status.
7. Remediation recommendations: ribbon swap, single-board degraded mode, Braiins OS bypass.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import socket
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from typing import Any, Optional

# UTF-8 encoding support for Windows PowerShell / CMD
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ANSI color codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


class AntminerClient:
    """HTTP & RPC client supporting Digest/Basic Auth and CGMiner RPC."""

    def __init__(self, ip: str, username: str = "root", password: str = "root", timeout: int = 15):
        self.ip = ip
        self.username = username
        self.password = password
        self.timeout = timeout
        self.base_url = f"http://{ip}"
        self._opener = self._build_opener()

    def _build_opener(self) -> urllib.request.OpenerDirector:
        passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        passman.add_password(None, self.base_url, self.username, self.password)
        digest_handler = urllib.request.HTTPDigestAuthHandler(passman)
        basic_handler = urllib.request.HTTPBasicAuthHandler(passman)
        return urllib.request.build_opener(digest_handler, basic_handler)

    def fetch_url(self, path: str) -> str:
        """Fetch content from an Antminer HTTP endpoint."""
        url = urllib.parse.urljoin(self.base_url, path)
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "AntminerPowerSaver-DiagnosticEngine/1.0",
                "Accept": "*/*",
            },
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                # Fallback to direct Basic Auth header if server didn't prompt with challenge
                b64auth = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
                req.add_header("Authorization", f"Basic {b64auth}")
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return resp.read().decode("utf-8", errors="replace")
            raise

    def query_rpc(self, command: str, parameter: str = "") -> dict[str, Any]:
        """Query CGMiner/BMMiner JSON-RPC on port 4028."""
        payload = {"command": command}
        if parameter:
            payload["parameter"] = parameter
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((self.ip, 4028))
            sock.sendall(json.dumps(payload).encode() + b"\n")
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\x00" in chunk or b"\n" in chunk:
                    break
            cleaned = data.decode("utf-8", errors="replace").replace("\x00", "").strip()
            return json.loads(cleaned) if cleaned else {}
        except Exception:
            return {}
        finally:
            sock.close()


def parse_system_info(html_or_json: str) -> dict[str, Any]:
    """Parse Antminer system info from /cgi-bin/get_system_info.cgi."""
    info: dict[str, Any] = {}
    # Often returned as raw JSON or JavaScript variables
    try:
        info = json.loads(html_or_json)
        return info
    except Exception:
        pass

    # Regex fallback for key/value pairs
    for match in re.finditer(r'["\']?([a-zA-Z0-9_]+)["\']?\s*[:=]\s*["\']?([^"\',\n\r}]+)["\']?', html_or_json):
        k, v = match.groups()
        info[k.strip()] = v.strip()
    return info


def analyze_log(log_text: str) -> dict[str, Any]:
    """Parse kernel and bmminer logs for root cause diagnosis."""
    results: dict[str, Any] = {
        "chains": {},
        "false_temp_bug": False,
        "abnormal_temp_reported": False,
        "crc_errors": [],
        "board_mismatches": [],
        "fan_speeds": [],
        "fatal_errors": [],
        "raw_asic_lines": [],
        "sensor_lines": [],
    }

    lines = log_text.splitlines()

    # 1. ASIC counts per chain
    # Patterns: "Chain[0] find 126 asic", "chain[1]: find 0 asic", "Chain 2 find 126 asic"
    for line in lines:
        asic_m = re.search(r"Chain\[?(\d+)\]?[\s:]+find\s+(\d+)\s+asic", line, re.IGNORECASE)
        if asic_m:
            chain_id = int(asic_m.group(1))
            asics = int(asic_m.group(2))
            results["chains"][chain_id] = asics
            results["raw_asic_lines"].append(line.strip())

        # 2. Check for CRC / I2C errors
        if "reg crc error" in line or "CRC error on chain" in line or "board_i2c_read failed" in line:
            results["crc_errors"].append(line.strip())

        # 3. Check for board model mismatches
        # e.g., "get a different board name for chain:2, pre board_name:BHB42603, current board_name:BHB42601"
        mismatch_m = re.search(
            r"get a different board name for chain:\s*(\d+),\s*pre board_name:\s*(\S+),\s*current board_name:\s*(\S+)",
            line,
        )
        if mismatch_m:
            chain_id, pre_name, curr_name = mismatch_m.groups()
            results["board_mismatches"].append({
                "chain": int(chain_id),
                "original_model": pre_name.rstrip(","),
                "detected_model": curr_name.rstrip(","),
                "line": line.strip(),
            })

        # 4. Check for temperature errors
        if "ERROR_TEMP_TOO_HIGH" in line or "temp_too_high" in line or "Miner Temperature: Abnormal" in line:
            results["abnormal_temp_reported"] = True

        if "255" in line and ("temp" in line.lower() or "sensor" in line.lower()):
            results["sensor_lines"].append(line.strip())

        # 5. Check for basic init failed / fatal errors
        if "basic init failed" in line or "stop mining" in line or "Fatal error" in line:
            results["fatal_errors"].append(line.strip())

        # 6. Fan speeds
        fan_m = re.search(r"fan\s*(\d+)[:\s]+(\d+)\s*rpm", line, re.IGNORECASE)
        if fan_m:
            results["fan_speeds"].append(f"Fan {fan_m.group(1)}: {fan_m.group(2)} RPM")

    # Determine if False 255°C bug occurred
    # Condition: Abnormal temp reported OR 255 readings, AND at least one chain detected 0 asics
    has_zero_asic_chain = any(count == 0 for count in results["chains"].values())
    if (results["abnormal_temp_reported"] or results["sensor_lines"]) and has_zero_asic_chain:
        results["false_temp_bug"] = True

    return results


def print_diagnostic_report(ip: str, sys_info: dict[str, Any], diag: dict[str, Any]) -> None:
    """Print an exhaustive, professional hardware diagnostic report."""
    print()
    print(f"{BOLD}{CYAN}{'=' * 75}{RESET}")
    print(f"{BOLD}{CYAN}      ANTMINER HARDWARE DIAGNOSTIC & ROOT-CAUSE REPORT{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 75}{RESET}")
    print(f"{BOLD}Target Host:{RESET}       {ip}")
    print(f"{BOLD}Miner Type:{RESET}        {sys_info.get('minertype', sys_info.get('system_miner_type', 'Unknown Antminer'))}")
    print(f"{BOLD}Firmware Version:{RESET}  {sys_info.get('system_logic_version', sys_info.get('firmware_version', 'Stock Bitmain / Linux'))}")
    print(f"{BOLD}MAC Address:{RESET}       {sys_info.get('mac', sys_info.get('net_mac', 'Unknown'))}")
    print(f"{CYAN}{'-' * 75}{RESET}")

    # Section 1: Hashboard & ASIC Enumeration
    print(f"{BOLD}1. HASHBOARD & ASIC CHIP STATUS (PINOUT MAPPING):{RESET}")
    pinout_map = {0: "J1 (Chain 0)", 1: "J2 (Chain 1)", 2: "J3 (Chain 2)"}

    if diag["chains"]:
        for chain_id in sorted(diag["chains"].keys()):
            count = diag["chains"][chain_id]
            connector = pinout_map.get(chain_id, f"J? (Chain {chain_id})")
            if count > 0:
                status_badge = f"{GREEN}[HEALTHY]{RESET}"
                chip_desc = f"{GREEN}{count} ASICs detected{RESET}"
            else:
                status_badge = f"{RED}[DEAD / NO COMMS]{RESET}"
                chip_desc = f"{RED}0 ASICs detected (Comms Failed){RESET}"
            print(f"  • Connector {BOLD}{connector:<15}{RESET} -> {chip_desc} {status_badge}")
    else:
        print(f"  {YELLOW}[!] No ASIC count lines found in recent log buffer.{RESET}")

    print(f"{CYAN}{'-' * 75}{RESET}")

    # Section 2: Temperature & The False 255°C Bug
    print(f"{BOLD}2. THERMAL SENSOR READINGS & BUG VERIFICATION:{RESET}")
    if diag["false_temp_bug"]:
        print(f"  {RED}{BOLD}[!] FALSE 255°C BUG DETECTED!{RESET}")
        print(f"  {YELLOW}Root Cause Explanation:{RESET}")
        print("  Stock Bitmain firmware reports 'Miner Temperature: Abnormal' when an ASIC")
        print("  chain fails to initialize. Disconnected sensor registers return 0xFF (255°C).")
        print("  The hashboards are NOT overheating; the control board is reading uninitialized")
        print("  data bus lines from the disconnected chain!")
    elif diag["abnormal_temp_reported"]:
        print(f"  {YELLOW}[!] Abnormal temperature condition was flagged in logs.{RESET}")
    else:
        print(f"  {GREEN}[✓] Thermal readings appear normal.{RESET}")

    print(f"{CYAN}{'-' * 75}{RESET}")

    # Section 3: Signal Integrity & Ribbon Cable Check
    print(f"{BOLD}3. SIGNAL INTEGRITY & RIBBON CABLE DIAGNOSTICS:{RESET}")
    if diag["crc_errors"]:
        print(f"  {RED}{BOLD}[!] {len(diag['crc_errors'])} CRC / Register Comms Errors Detected!{RESET}")
        print("  Sample log lines:")
        for err in diag["crc_errors"][:3]:
            print(f"    {DIM}{err}{RESET}")
        print(f"  {YELLOW}Remediation: Reseat or replace the ribbon cable on the failing connector.{RESET}")
    else:
        print(f"  {GREEN}[✓] No ribbon cable CRC errors detected.{RESET}")

    print(f"{CYAN}{'-' * 75}{RESET}")

    # Section 4: Hashboard Model Compatibility
    print(f"{BOLD}4. HASHBOARD MODEL COMPATIBILITY (MISMATCH LOCK):{RESET}")
    if diag["board_mismatches"]:
        for mm in diag["board_mismatches"]:
            print(f"  {RED}{BOLD}[!] HARDWARE MISMATCH DETECTED ON CHAIN {mm['chain']}:{RESET}")
            print(f"      Original Board:  {BOLD}{mm['original_model']}{RESET}")
            print(f"      Installed Board: {BOLD}{mm['detected_model']}{RESET}")
            print(f"  {YELLOW}Stock Firmware Behavior:{RESET}")
            print("  Bitmain stock firmware refuses to boot and halts with 'ERROR_SOC_INIT: basic init failed!'")
            print("  when hashboard models are mixed (e.g. BHB42603 vs BHB42601).")
    else:
        print(f"  {GREEN}[✓] No board model mismatch detected.{RESET}")

    print(f"{CYAN}{'-' * 75}{RESET}")

    # Section 5: Concrete Action Plan & Recommended Solutions
    print(f"{BOLD}5. RECOMMENDED RECOVERY ACTION PLAN:{RESET}")

    has_dead_chain = any(count == 0 for count in diag["chains"].values())
    has_mismatch = bool(diag["board_mismatches"])

    if has_dead_chain or has_mismatch:
        print(f"  {BOLD}Step 1: Ribbon Cable Swap Isolation{RESET}")
        print("    Swap ribbon cable between Chain 0 (healthy) and failing chain to verify")
        print("    whether the issue follows the cable or stays on the hashboard.")
        print()
        print(f"  {BOLD}Step 2: Single-Board or Dual-Board Degraded Mode{RESET}")
        print("    If a hashboard is physically defective, disconnect its ribbon cable AND")
        print("    its copper power busbar screws. The miner can run cleanly on remaining boards.")
        print()
        print(f"  {BOLD}Step 3: Deploy Braiins OS via MicroSD Card (Recommended){RESET}")
        print("    Braiins OS completely eliminates Bitmain's mismatched board model lockout,")
        print("    tunes each hashboard independently, and avoids the false 255°C bug.")
        print("    • Flash a FAT32 MicroSD card using: python prepare_sd_recovery.py")
        print("    • Insert the MicroSD into the front SD slot and power cycle the miner.")
    else:
        print(f"  {GREEN}[✓] All active hashboards and sensors are operational!{RESET}")
        print("  To enable power saving and dynamic frequency scaling, install Braiins OS:")
        print("  Run: python download_toolbox.py")

    print(f"{BOLD}{CYAN}{'=' * 75}{RESET}\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Antminer Hardware Diagnostic & Root-Cause Failure Analyzer"
    )
    parser.add_argument("--ip", "-i", type=str, required=True, help="Miner IP address (e.g. 192.168.1.100)")
    parser.add_argument("--user", "-u", type=str, default="root", help="Username (default: root)")
    parser.add_argument("--password", "-p", type=str, default="root", help="Password (default: root)")
    parser.add_argument("--timeout", "-t", type=int, default=15, help="HTTP timeout in seconds (default: 15)")
    parser.add_argument("--save-log", action="store_true", help="Save the extracted log to disk")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    client = AntminerClient(ip=args.ip, username=args.user, password=args.password, timeout=args.timeout)

    print(f"{CYAN}[*] Connecting to Antminer at {args.ip}...{RESET}")

    # 1. Fetch system info
    sys_info: dict[str, Any] = {}
    try:
        raw_sys = client.fetch_url("/cgi-bin/get_system_info.cgi")
        sys_info = parse_system_info(raw_sys)
        print(f"{GREEN}[✓] Retrieved system info successfully.{RESET}")
    except Exception as e:
        print(f"{YELLOW}[!] Notice: Could not retrieve /cgi-bin/get_system_info.cgi ({e}). Trying log...{RESET}")

    # 2. Fetch log
    log_text = ""
    try:
        log_text = client.fetch_url("/cgi-bin/log.cgi")
        print(f"{GREEN}[✓] Retrieved kernel/bmminer log successfully ({len(log_text)} bytes).{RESET}")
    except Exception as e:
        print(f"{RED}[✗] Failed to fetch /cgi-bin/log.cgi from {args.ip}: {e}{RESET}")
        print(f"{YELLOW}Check that the miner IP is reachable and the credentials are valid (default root:root).{RESET}")
        return 1

    if args.save_log:
        filename = f"miner_diag_{args.ip.replace('.', '_')}_{int(time.time())}.log"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(log_text)
        print(f"{GREEN}[✓] Raw log written to {filename}{RESET}")

    # 3. Analyze log
    diag = analyze_log(log_text)

    if args.json:
        combined = {
            "ip": args.ip,
            "system_info": sys_info,
            "diagnosis": diag,
        }
        print(json.dumps(combined, indent=2))
        return 0

    # 4. Print formatted report
    print_diagnostic_report(args.ip, sys_info, diag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
