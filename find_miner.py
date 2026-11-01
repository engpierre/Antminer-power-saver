#!/usr/bin/env python3
"""
find_miner.py
=============
Ultra-Fast Async Bitcoin Miner (ASIC / Bitaxe / AxeOS / CGMiner) Discovery Engine.
Zero external dependencies. Strictly typed dataclasses.

Supported Discovery & Telemetry:
- Bitaxe (Max, Ultra, Supra, Gamma, Hex) running AxeOS / ESP-Miner (BM1366, BM1397, etc.)
- Bitmain Antminer (S9, S17, S19, S19 Pro, S21, T19, T21, L7, etc.) running BMMiner, VNish, Braiins OS
- MicroBT WhatsMiner (M20, M30, M50, M60 series)
- Canaan Avalon (A11, A12, A13, A14 series)
- Braiins OS / BOSminer nodes
- Generic CGMiner / BMMiner / BFGMiner JSON-RPC daemons (Port 4028)
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
from dataclasses import dataclass, field
import ipaddress
import json
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
from typing import Any, Optional

# Ensure clean UTF-8 console output across Windows cmd / PowerShell
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# =============================================================================
# 1. STRICTLY TYPED DATA MODELS
# =============================================================================

@dataclass(slots=True, frozen=True)
class HostScanResult:
    ip: str
    open_ports: tuple[int, ...]
    mac: str = ""
    vendor: str = ""


@dataclass(slots=True, frozen=True)
class ChainStats:
    chain_id: int
    asics: int
    hashrate_ghs: float
    frequency_mhz: int
    pcb_temp: str
    chip_temp: str
    hw_errors: int


@dataclass(slots=True, frozen=True)
class MinerMetrics:
    model: str = "Unknown"
    hardware: str = ""
    firmware_version: str = ""
    hashrate_str: str = "0.00 H/s"
    hashrate_ghs: float = 0.0
    ideal_hashrate_ghs: float = 0.0
    temperature_str: str = ""
    fan_speeds: tuple[int, ...] = ()
    power_watts: float = 0.0
    voltage: float = 0.0
    current_amps: float = 0.0
    efficiency_j_th: float = 0.0
    frequency_mhz: int = 0
    pool_stratum: str = ""
    pool_user: str = ""
    pool_status: str = ""
    best_diff: str = ""
    difficulty: str = ""
    shares_accepted: int = 0
    shares_rejected: int = 0
    uptime_seconds: int = 0
    chains: tuple[ChainStats, ...] = ()
    raw_payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class MinerDevice:
    ip: str
    mac: str
    vendor: str
    open_ports: tuple[int, ...]
    is_miner: bool
    miner_type: str  # e.g., "Antminer S19 Pro", "Bitaxe Ultra (AxeOS)", "WhatsMiner"
    model: str
    firmware: str
    metrics: MinerMetrics
    web_url: str
    detection_method: str  # "CGMiner RPC (Port 4028)", "AxeOS REST API", "HTTP Auth Digest"


# =============================================================================
# 2. KNOWN OUI & ASIC VENDOR SIGNATURES
# =============================================================================

KNOWN_OUIS: dict[str, str] = {
    # Espressif (Bitaxe / AxeOS / Nerdminer / ESP32 ASICs)
    "1C:1A:DF": "Espressif Inc. (Bitaxe / ESP32)",
    "24:4C:AB": "Espressif Inc. (Bitaxe / ESP32)",
    "30:AE:A4": "Espressif Inc. (Bitaxe / ESP32)",
    "40:22:D8": "Espressif Inc. (Bitaxe / ESP32)",
    "48:27:E2": "Espressif Inc. (Bitaxe / ESP32)",
    "54:32:04": "Espressif Inc. (Bitaxe / ESP32)",
    "68:B6:B3": "Espressif Inc. (Bitaxe / ESP32)",
    "7C:DF:A1": "Espressif Inc. (Bitaxe / ESP32)",
    "84:F7:03": "Espressif Inc. (Bitaxe / ESP32)",
    "8C:AA:B5": "Espressif Inc. (Bitaxe / ESP32)",
    "94:B5:55": "Espressif Inc. (Bitaxe / ESP32)",
    "A0:B7:65": "Espressif Inc. (Bitaxe / ESP32)",
    "AC:67:B2": "Espressif Inc. (Bitaxe / ESP32)",
    "B4:E6:2D": "Espressif Inc. (Bitaxe / ESP32)",
    "BC:DD:C2": "Espressif Inc. (Bitaxe / ESP32)",
    "C4:DE:E2": "Espressif Inc. (Bitaxe / ESP32)",
    "DC:54:75": "Espressif Inc. (Bitaxe / ESP32)",
    "EC:62:60": "Espressif Inc. (Bitaxe / ESP32)",
    "F4:12:FA": "Espressif Inc. (Bitaxe / ESP32)",

    # Bitmain (Antminer)
    "00:0A:35": "Bitmain Technologies (Antminer)",
    "D4:6E:0E": "Bitmain Technologies (Antminer)",
    "30:F7:72": "Bitmain Technologies (Antminer)",
    "44:33:4C": "Bitmain Technologies (Antminer)",
    "A4:C3:F0": "Bitmain Technologies (Antminer)",

    # MicroBT (WhatsMiner)
    "C8:F2:30": "MicroBT (WhatsMiner)",
    "58:2D:34": "MicroBT (WhatsMiner)",
    "00:23:CD": "MicroBT (WhatsMiner)",

    # Canaan (Avalon)
    "00:04:A3": "Canaan Creative (Avalon)",
    "B0:91:22": "Canaan Creative (Avalon)",

    # Raspberry Pi (Controllers / Braiins Nodes)
    "2C:F0:5D": "Raspberry Pi Foundation",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",

    # Common Network Infrastructure
    "C0:3C:04": "Sagemcom Broadband (Gateway)",
    "BC:FC:E7": "Host Physical Interface",
}


def resolve_mac_address(ip_str: str) -> str:
    """Resolve IPv4 MAC address on Windows via kernel SendARP API."""
    try:
        dest_ip = struct.unpack("<I", socket.inet_aton(ip_str))[0]
        mac_addr = (ctypes.c_ubyte * 6)()
        mac_len = ctypes.c_ulong(6)
        res = ctypes.windll.iphlpapi.SendARP(
            ctypes.c_ulong(dest_ip),
            ctypes.c_ulong(0),
            ctypes.byref(mac_addr),
            ctypes.byref(mac_len),
        )
        if res == 0:
            return ":".join(f"{b:02X}" for b in mac_addr)
    except Exception:
        pass
    return ""


def lookup_vendor(mac_str: str) -> str:
    """Lookup vendor from MAC address OUI prefix."""
    if not mac_str:
        return "Unknown"
    prefix = mac_str.upper()[:8]
    if mac_str.upper().startswith("02:"):
        return "Embedded Linux / Control Board (LAA)"
    return KNOWN_OUIS.get(prefix, "Standard Network Interface")


# =============================================================================
# 3. SUBNET ENUMERATION ENGINE
# =============================================================================

def get_active_ipv4_subnets() -> list[ipaddress.IPv4Network]:
    """Detect all physical, non-virtual active IPv4 /24 subnets on host."""
    subnets: list[ipaddress.IPv4Network] = []
    seen: set[str] = set()

    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            (
                "Get-NetIPAddress -AddressFamily IPv4 | "
                "Where-Object { "
                "  $_.IPAddress -notlike '127.*' -and "
                "  $_.IPAddress -notlike '169.254.*' -and "
                "  $_.InterfaceAlias -notlike '*Loopback*' -and "
                "  $_.InterfaceAlias -notlike '*vEthernet*' -and "
                "  $_.InterfaceAlias -notlike '*WSL*' -and "
                "  $_.InterfaceAlias -notlike '*Hyper-V*' "
                "} | "
                "Select-Object -ExpandProperty IPAddress"
            ),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        for line in res.stdout.splitlines():
            ip_str = line.strip()
            if ip_str and not ip_str.startswith("127.") and not ip_str.startswith("169.254."):
                try:
                    net = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
                    if str(net) not in seen:
                        seen.add(str(net))
                        subnets.append(net)
                except ValueError:
                    continue
    except Exception:
        pass

    if not subnets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            subnets.append(net)
        except Exception:
            subnets.append(ipaddress.IPv4Network("192.168.1.0/24"))

    return subnets


# =============================================================================
# 4. HIGH-CONCURRENCY ASYNC TCP PORT PROBER
# =============================================================================

TARGET_PORTS = (4028, 80, 443, 8080, 22)


async def check_port(
    ip: str,
    port: int,
    semaphore: asyncio.Semaphore,
    timeout: float = 0.45,
) -> bool:
    """Async TCP handshake probe with sub-second timeout."""
    async with semaphore:
        try:
            connect_coro = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, OSError):
            return False


async def scan_single_host(
    ip: str,
    ports: tuple[int, ...],
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> Optional[HostScanResult]:
    """Scan all target ports for a specific host IP."""
    tasks = [check_port(ip, port, semaphore, timeout) for port in ports]
    results = await asyncio.gather(*tasks)

    open_ports = tuple(port for port, is_open in zip(ports, results) if is_open)
    if open_ports:
        mac = resolve_mac_address(ip)
        vendor = lookup_vendor(mac)
        return HostScanResult(
            ip=ip,
            open_ports=open_ports,
            mac=mac,
            vendor=vendor,
        )
    return None


async def scan_subnet(
    subnet: ipaddress.IPv4Network,
    ports: tuple[int, ...] = TARGET_PORTS,
    concurrency: int = 100,
    timeout: float = 0.45,
) -> list[HostScanResult]:
    """Probe all 254 host IPs across the subnet concurrently."""
    semaphore = asyncio.Semaphore(concurrency)
    hosts = [str(ip) for ip in subnet.hosts()]

    tasks = [
        scan_single_host(ip, ports, semaphore, timeout)
        for ip in hosts
    ]
    raw_results = await asyncio.gather(*tasks)
    return [res for res in raw_results if res is not None]


# =============================================================================
# 5. ASIC & BITCOIN MINER PROTOCOL FINGERPRINTING
# =============================================================================

async def send_cgminer_rpc(ip: str, port: int, command: str, timeout: float = 1.5) -> dict[str, Any]:
    """Send single JSON-RPC command to CGMiner / BMMiner / BOSminer socket."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        payload = json.dumps({"command": command}).encode("utf-8") + b"\n"
        writer.write(payload)
        await writer.drain()

        raw_data = b""
        while True:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            raw_data += chunk
            if b"\x00" in chunk:
                break

        writer.close()
        await writer.wait_closed()

        clean_text = raw_data.replace(b"\x00", b"").decode("utf-8", errors="ignore").strip()
        if clean_text:
            return json.loads(clean_text)
    except Exception:
        pass
    return {}


async def probe_cgminer_full(ip: str, port: int = 4028) -> Optional[MinerMetrics]:
    """Deep interrogation of CGMiner/BMMiner node via version, summary, stats, and pools."""
    ver_data = await send_cgminer_rpc(ip, port, "version")
    if not ver_data:
        return None

    # Version parsing
    version_obj = (
        ver_data.get("VERSION", [{}])[0]
        if isinstance(ver_data.get("VERSION"), list)
        else ver_data.get("VERSION", {})
    )

    model = (
        version_obj.get("Type")
        or version_obj.get("Miner")
        or version_obj.get("Description")
        or "CGMiner / BMMiner ASIC"
    )
    if "BOSer" in version_obj or "BOSminer" in version_obj:
        bos_ver = version_obj.get("BOSer") or version_obj.get("BOSminer") or "Braiins OS"
        firmware = f"Braiins OS ({bos_ver})"
        model = "Antminer S19 Pro (Braiins OS)"
    else:
        firmware = (
            version_obj.get("BMMiner")
            or version_obj.get("CGMiner")
            or version_obj.get("BOSminer")
            or version_obj.get("CompileTime")
            or "Stock Firmware"
        )
        if "CompileTime" in version_obj:
            firmware = f"{firmware} ({version_obj['CompileTime'].strip()})"

    # Summary query
    sum_data = await send_cgminer_rpc(ip, port, "summary")
    summary_obj = (
        sum_data.get("SUMMARY", [{}])[0]
        if isinstance(sum_data.get("SUMMARY"), list)
        else sum_data.get("SUMMARY", {})
    )

    uptime = int(summary_obj.get("Elapsed", 0))
    shares_acc = int(summary_obj.get("Accepted", 0))
    shares_rej = int(summary_obj.get("Rejected", 0))

    # Stats query (detailed ASIC chip temps, fan speeds, hashrate)
    stats_data = await send_cgminer_rpc(ip, port, "stats")
    stats_list = stats_data.get("STATS", [])
    s1 = stats_list[1] if len(stats_list) > 1 and isinstance(stats_list[1], dict) else {}

    # Extract Hashrate from stats (rate_30m, total rate, or summary)
    ghs_real = float(s1.get("rate_30m", s1.get("total rate", 0.0)))
    if ghs_real <= 0:
        ghs_real = float(summary_obj.get("GHS 5s", summary_obj.get("GHS av", 0.0)))
    if ghs_real <= 0 and "MHS av" in summary_obj:
        ghs_real = float(summary_obj.get("MHS av", 0.0)) / 1000.0

    ideal_ghs = float(s1.get("total_rateideal", 0.0))

    if ghs_real >= 1000.0:
        hashrate_str = f"{ghs_real / 1000.0:.2f} TH/s"
    elif ghs_real > 0:
        hashrate_str = f"{ghs_real:.2f} GH/s"
    else:
        hashrate_str = "0.00 H/s"

    # Fan speeds
    fans = []
    for fn in ("fan1", "fan2", "fan3", "fan4"):
        if fn in s1 and int(s1[fn]) > 0:
            fans.append(int(s1[fn]))
    if not fans:
        fans_data = await send_cgminer_rpc(ip, port, "fans")
        for f_entry in fans_data.get("FANS", []):
            if isinstance(f_entry, dict) and "RPM" in f_entry and f_entry["RPM"] > 0:
                fans.append(int(f_entry["RPM"]))

    # Temperatures
    temp_chip_max = 0
    temp_pcb_max = 0
    for tn in ("temp_chip1", "temp_chip2", "temp_chip3"):
        if tn in s1 and isinstance(s1[tn], str):
            for val in s1[tn].split("-"):
                try:
                    num = int(val)
                    if num > temp_chip_max:
                        temp_chip_max = num
                except ValueError:
                    pass

    for tn in ("temp_pcb1", "temp_pcb2", "temp_pcb3"):
        if tn in s1 and isinstance(s1[tn], str):
            for val in s1[tn].split("-"):
                try:
                    num = int(val)
                    if num > temp_pcb_max:
                        temp_pcb_max = num
                except ValueError:
                    pass

    temp_str = ""
    if temp_chip_max > 0 or temp_pcb_max > 0:
        temp_str = f"Chip: {temp_chip_max}°C | PCB: {temp_pcb_max}°C"
    elif "Temperature" in summary_obj and float(summary_obj.get("Temperature", 0.0)) > 0:
        temp_str = f"{float(summary_obj['Temperature']):.1f} °C"
    else:
        temps_data = await send_cgminer_rpc(ip, port, "temps")
        t_chips = [float(t["Chip"]) for t in temps_data.get("TEMPS", []) if isinstance(t, dict) and "Chip" in t]
        t_boards = [float(t["Board"]) for t in temps_data.get("TEMPS", []) if isinstance(t, dict) and "Board" in t]
        if t_chips:
            temp_str = f"Chip: {max(t_chips):.1f}°C | PCB: {max(t_boards):.1f}°C"

    # Chain Details
    chains: list[ChainStats] = []
    for c_idx in range(1, 5):
        rate_key = f"chain_rate{c_idx}"
        acn_key = f"chain_acn{c_idx}"
        hw_key = f"chain_hw{c_idx}"
        freq_key = f"freq{c_idx}"
        chip_t_key = f"temp_chip{c_idx}"
        pcb_t_key = f"temp_pcb{c_idx}"

        if acn_key in s1 and int(s1[acn_key]) > 0:
            chains.append(
                ChainStats(
                    chain_id=c_idx,
                    asics=int(s1[acn_key]),
                    hashrate_ghs=float(s1.get(rate_key, 0.0)),
                    frequency_mhz=int(s1.get(freq_key, 525)),
                    pcb_temp=str(s1.get(pcb_t_key, "")),
                    chip_temp=str(s1.get(chip_t_key, "")),
                    hw_errors=int(s1.get(hw_key, 0)),
                )
            )

    # Pools query
    pools_data = await send_cgminer_rpc(ip, port, "pools")
    pools_list = pools_data.get("POOLS", [])
    active_pool = pools_list[0] if pools_list and isinstance(pools_list[0], dict) else {}

    pool_url = active_pool.get("URL", "")
    pool_user = active_pool.get("User", "")
    pool_status = active_pool.get("Status", "Standby" if not pool_url else "Active")
    best_diff = str(active_pool.get("Best Share", ""))
    diff = str(active_pool.get("Diff", ""))

    freq = int(s1.get("frequency", s1.get("total_freqavg", 0)))

    return MinerMetrics(
        model=model,
        hardware=version_obj.get("Type", "ASIC Miner"),
        firmware_version=firmware,
        hashrate_str=hashrate_str,
        hashrate_ghs=ghs_real,
        ideal_hashrate_ghs=ideal_ghs,
        temperature_str=temp_str,
        fan_speeds=tuple(fans),
        frequency_mhz=freq,
        pool_stratum=pool_url,
        pool_user=pool_user,
        pool_status=pool_status,
        best_diff=best_diff,
        difficulty=diff,
        shares_accepted=shares_acc,
        shares_rejected=shares_rej,
        uptime_seconds=uptime,
        chains=tuple(chains),
        raw_payload={"version": ver_data, "summary": sum_data, "stats": stats_data, "pools": pools_data},
    )


async def probe_axeos_http_api(ip: str, port: int = 80, timeout: float = 1.2) -> Optional[MinerMetrics]:
    """Query AxeOS / Bitaxe REST API endpoints (/api/system/info)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )

        req = (
            f"GET /api/system/info HTTP/1.1\r\n"
            f"Host: {ip}:{port}\r\n"
            f"User-Agent: AntminerDiscoveryEngine/1.0\r\n"
            f"Accept: application/json\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(req.encode("ascii"))
        await writer.drain()

        raw_response = b""
        while True:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            raw_response += chunk

        writer.close()
        await writer.wait_closed()

        parts = raw_response.split(b"\r\n\r\n", 1)
        if len(parts) < 2:
            return None

        body = parts[1].decode("utf-8", errors="ignore").strip()
        data = json.loads(body)

        if not isinstance(data, dict):
            return None
        if not any(k in data for k in ("hashRate", "ASICModel", "boardVersion", "power", "coreVoltage")):
            return None

        hr_raw = float(data.get("hashRate", 0.0))
        hr_str = f"{hr_raw / 1000.0:.2f} TH/s" if hr_raw >= 1000.0 else f"{hr_raw:.2f} GH/s"

        asic_chip = data.get("ASICModel", "BM1366")
        board_ver = data.get("boardVersion", "Bitaxe")
        model = f"Bitaxe {board_ver} ({asic_chip})"
        firmware = data.get("version", "AxeOS")

        temp = float(data.get("temp", 0.0))
        vr_temp = float(data.get("vrTemp", 0.0))
        temp_str = f"ASIC: {temp:.1f}°C | VR: {vr_temp:.1f}°C" if vr_temp > 0 else f"{temp:.1f} °C"

        power_w = float(data.get("power", 0.0))
        voltage_v = float(data.get("voltage", 0.0))
        current_a = float(data.get("current", 0.0))
        eff = (power_w / (hr_raw / 1000.0)) if (hr_raw > 0 and power_w > 0) else 0.0

        stratum_url = data.get("stratumURL", "")
        stratum_port = data.get("stratumPort", "")
        pool_full = f"{stratum_url}:{stratum_port}" if stratum_port else stratum_url

        return MinerMetrics(
            model=model,
            hardware=asic_chip,
            firmware_version=f"AxeOS {firmware}",
            hashrate_str=hr_str,
            hashrate_ghs=hr_raw,
            temperature_str=temp_str,
            power_watts=power_w,
            voltage=voltage_v,
            current_amps=current_a,
            efficiency_j_th=eff,
            frequency_mhz=int(data.get("coreFrequency", 0)),
            pool_stratum=pool_full,
            pool_user=data.get("stratumUser", ""),
            best_diff=str(data.get("bestDiff", "")),
            shares_accepted=int(data.get("sharesAccepted", 0)),
            shares_rejected=int(data.get("sharesRejected", 0)),
            uptime_seconds=int(data.get("uptimeSeconds", 0)),
            raw_payload=data,
        )
    except Exception:
        return None


async def probe_http_headers(ip: str, port: int = 80, use_ssl: bool = False, timeout: float = 1.0) -> tuple[bool, str, str, str]:
    """Inspect HTTP/HTTPS headers (WWW-Authenticate, Server, Title)."""
    try:
        ssl_ctx = None
        if use_ssl:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ssl_ctx),
            timeout=timeout,
        )

        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}:{port}\r\n"
            f"User-Agent: Mozilla/5.0 MinerScanner/1.0\r\n"
            f"Accept: text/html,*/*\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(req.encode("ascii"))
        await writer.drain()

        raw_response = b""
        while len(raw_response) < 16384:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            raw_response += chunk

        writer.close()
        await writer.wait_closed()

        header_text = raw_response.decode("utf-8", errors="ignore")

        auth_match = re.search(r"WWW-Authenticate:\s*(.+)", header_text, re.IGNORECASE)
        auth_val = auth_match.group(1).strip() if auth_match else ""

        if "antminer" in auth_val.lower():
            return True, "Antminer (Bitmain)", "Antminer Web UI", auth_val
        if "whatsminer" in auth_val.lower():
            return True, "WhatsMiner (MicroBT)", "WhatsMiner Web UI", auth_val
        if "avalon" in auth_val.lower():
            return True, "Avalon (Canaan)", "AvalonMiner Web UI", auth_val
        if "braiins" in auth_val.lower():
            return True, "Braiins OS", "Braiins OS Web UI", auth_val

        srv_match = re.search(r"Server:\s*(.+)", header_text, re.IGNORECASE)
        server_val = srv_match.group(1).strip() if srv_match else ""
        if "axeos" in server_val.lower():
            return True, "Bitaxe (AxeOS)", "AxeOS Server", server_val

        title_match = re.search(r"<title>(.*?)</title>", header_text, re.IGNORECASE | re.DOTALL)
        title_val = title_match.group(1).strip() if title_match else ""
        lower_title = title_val.lower()

        if "axeos" in lower_title or "bitaxe" in lower_title:
            return True, "Bitaxe (AxeOS)", title_val, server_val
        if "antminer" in lower_title:
            return True, "Antminer (Bitmain)", title_val, server_val
        if "whatsminer" in lower_title:
            return True, "WhatsMiner (MicroBT)", title_val, server_val
        if "avalon" in lower_title:
            return True, "Avalon (Canaan)", title_val, server_val
        if "braiins" in lower_title:
            return True, "Braiins OS", title_val, server_val

        return False, "", title_val, server_val
    except Exception:
        return False, "", "", ""


# =============================================================================
# 6. UNIFIED HOST FINGERPRINTING CONTROLLER
# =============================================================================

async def identify_device(host: HostScanResult) -> MinerDevice:
    """Perform deep protocol interrogation on discovered host."""
    ip = host.ip
    open_ports = host.open_ports
    mac = host.mac
    vendor = host.vendor

    # 1. Always Probe Port 4028 (CGMiner / BMMiner RPC) on active host
    cg_metrics = await probe_cgminer_full(ip, 4028)
    if cg_metrics:
        miner_type = cg_metrics.model
        if "antminer" in cg_metrics.model.lower():
            miner_type = f"Bitmain {cg_metrics.model}"
        web_port = 80 if 80 in open_ports else (443 if 443 in open_ports else 4028)
        scheme = "https" if web_port == 443 else "http"
        return MinerDevice(
            ip=ip,
            mac=mac,
            vendor=vendor or "Bitmain Technologies / Embedded ASIC",
            open_ports=open_ports,
            is_miner=True,
            miner_type=miner_type,
            model=cg_metrics.model,
            firmware=cg_metrics.firmware_version,
            metrics=cg_metrics,
            web_url=f"{scheme}://{ip}:{web_port}",
            detection_method="CGMiner / BMMiner RPC (Port 4028)",
        )

    # 2. Probe AxeOS / Bitaxe REST API (Ports 80 & 8080)
    for p in (80, 8080):
        if p in open_ports or len(open_ports) > 0:
            axe_metrics = await probe_axeos_http_api(ip, p)
            if axe_metrics:
                return MinerDevice(
                    ip=ip,
                    mac=mac,
                    vendor=vendor or "Espressif Inc. (Bitaxe / ESP32)",
                    open_ports=open_ports,
                    is_miner=True,
                    miner_type=axe_metrics.model,
                    model=axe_metrics.model,
                    firmware=axe_metrics.firmware_version,
                    metrics=axe_metrics,
                    web_url=f"http://{ip}:{p}",
                    detection_method="AxeOS REST API (/api/system/info)",
                )

    # 3. Probe Web Interfaces for ASIC Fingerprints (Ports 80, 443, 8080)
    for p in (80, 8080, 443):
        if p in open_ports:
            use_ssl = (p == 443)
            is_miner, brand, title, server = await probe_http_headers(ip, p, use_ssl=use_ssl)
            if is_miner:
                scheme = "https" if use_ssl else "http"
                return MinerDevice(
                    ip=ip,
                    mac=mac,
                    vendor=vendor,
                    open_ports=open_ports,
                    is_miner=True,
                    miner_type=brand,
                    model=title or brand,
                    firmware=server or "Custom ASIC Web UI",
                    metrics=MinerMetrics(model=title),
                    web_url=f"{scheme}://{ip}:{p}",
                    detection_method="HTTP Auth / Header Fingerprint",
                )

    # 4. Check for Espressif OUI
    if "espressif" in vendor.lower():
        web_port = 80 if 80 in open_ports else (8080 if 8080 in open_ports else 0)
        return MinerDevice(
            ip=ip,
            mac=mac,
            vendor=vendor,
            open_ports=open_ports,
            is_miner=True,
            miner_type="Potential Bitaxe / ESP-Miner Node",
            model="Espressif ESP32-S3",
            firmware="AxeOS / ESP-Miner",
            metrics=MinerMetrics(model="Espressif Device"),
            web_url=f"http://{ip}:{web_port}" if web_port else "",
            detection_method="MAC OUI (Espressif Inc.)",
        )

    # Non-miner generic network host
    return MinerDevice(
        ip=ip,
        mac=mac,
        vendor=vendor,
        open_ports=open_ports,
        is_miner=False,
        miner_type="Network Device / Host",
        model="Standard Node",
        firmware="N/A",
        metrics=MinerMetrics(),
        web_url=f"http://{ip}" if (80 in open_ports or 8080 in open_ports) else "",
        detection_method="Port Discovery",
    )


# =============================================================================
# 7. CLI EXECUTION & RICH REPORTING
# =============================================================================

def format_banner() -> str:
    return r"""
================================================================================
   ____ ___ _____ ____ ___  ___ _   _   __  __ ___ _   _ _____ ____  
  | __ )_ _|_   _/ ___/ _ \|_ _| \ | | |  \/  |_ _| \ | | ____|  _ \ 
  |  _ \| |  | || |  | | | || ||  \| | | |\/| || ||  \| |  _| | |_) |
  | |_) | |  | || |__| |_| || || |\  | | |  | || || |\  | |___|  _ < 
  |____/___| |_| \____\___/|___|_| \_| |_|  |_|___|_| \_|_____|_| \_\
================================================================================
  HIGH-SPEED ASIC & BITAXE LOCAL SUBNET DISCOVERY ENGINE (v1.0)
================================================================================
"""


async def run_discovery_sweep(target_subnets: list[ipaddress.IPv4Network], verbose: bool = False):
    print(format_banner())
    start_time = time.perf_counter()

    all_hosts: list[HostScanResult] = []

    for subnet in target_subnets:
        print(f"[*] Scanning Subnet: {subnet} (254 hosts across ports {TARGET_PORTS})...")
        sub_start = time.perf_counter()
        discovered = await scan_subnet(subnet, TARGET_PORTS, concurrency=100, timeout=0.45)
        sub_elapsed = time.perf_counter() - sub_start
        print(f"[+] Subnet {subnet} complete in {sub_elapsed:.2f}s -- Found {len(discovered)} responsive host(s).")
        all_hosts.extend(discovered)

    print(f"\n[*] Interrogating {len(all_hosts)} active host(s) for ASIC & AxeOS protocols...")
    ident_tasks = [identify_device(h) for h in all_hosts]
    devices = await asyncio.gather(*ident_tasks)

    elapsed_total = time.perf_counter() - start_time

    miners = [d for d in devices if d.is_miner]
    others = [d for d in devices if not d.is_miner]

    print("\n" + "=" * 80)
    print("                     DISCOVERY SWEEP RESULTS")
    print("=" * 80)

    if miners:
        print(f"\n[+] BITCOIN MINER(S) DISCOVERED: {len(miners)} LOCATED ON LAN\n")
        for idx, m in enumerate(miners, 1):
            print(f"[{idx}] {m.miner_type.upper()} @ {m.ip}")
            print(f"    |-- IP Address:        {m.ip}")
            print(f"    |-- MAC Address:       {m.mac or 'Unknown'} ({m.vendor})")
            print(f"    |-- Open Ports:        {', '.join(str(p) for p in m.open_ports)}")
            print(f"    |-- Hardware Model:    {m.model}")
            print(f"    |-- Firmware / Build:  {m.firmware}")
            print(f"    |-- Detection Method:  {m.detection_method}")

            if m.metrics.hashrate_ghs > 0:
                ideal_str = f" (Rated: {m.metrics.ideal_hashrate_ghs/1000.0:.0f} TH/s)" if m.metrics.ideal_hashrate_ghs > 0 else ""
                print(f"    |-- Real-Time Hashrate: {m.metrics.hashrate_str}{ideal_str}")
            elif m.metrics.uptime_seconds > 0:
                print(f"    |-- Real-Time Hashrate: 0.00 H/s (Standby / Idle)")

            if m.metrics.frequency_mhz > 0:
                print(f"    |-- Core Frequency:    {m.metrics.frequency_mhz} MHz")

            if m.metrics.temperature_str:
                print(f"    |-- Operating Temps:   {m.metrics.temperature_str}")

            if m.metrics.fan_speeds:
                fans_str = ", ".join(f"{rpm} RPM" for rpm in m.metrics.fan_speeds)
                print(f"    |-- Fan Speeds:        {fans_str}")

            if m.metrics.power_watts > 0:
                eff_str = f" ({m.metrics.efficiency_j_th:.1f} J/TH)" if m.metrics.efficiency_j_th > 0 else ""
                print(f"    |-- Power Usage:       {m.metrics.power_watts:.1f} W @ {m.metrics.voltage:.2f} V / {m.metrics.current_amps:.2f} A{eff_str}")

            if m.metrics.pool_stratum:
                print(f"    |-- Stratum Pool:      {m.metrics.pool_stratum} ({m.metrics.pool_status})")
                if m.metrics.pool_user:
                    print(f"    |-- Worker / User:     {m.metrics.pool_user}")

            if m.metrics.shares_accepted > 0:
                best_str = f" (Best: {m.metrics.best_diff})" if m.metrics.best_diff else ""
                diff_str = f" [Diff: {m.metrics.difficulty}]" if m.metrics.difficulty else ""
                print(f"    |-- Shares Solved:     {m.metrics.shares_accepted} Accepted / {m.metrics.shares_rejected} Rejected{diff_str}{best_str}")

            if m.metrics.uptime_seconds > 0:
                hours = m.metrics.uptime_seconds / 3600.0
                print(f"    |-- System Uptime:     {m.metrics.uptime_seconds}s ({hours:.1f} hours)")

            if m.metrics.chains:
                print(f"    |-- ASIC Hashboards:   {len(m.metrics.chains)} Active Chains")
                for c in m.metrics.chains:
                    th = c.hashrate_ghs / 1000.0
                    print(f"    |   Chain #{c.chain_id}: {c.asics} ASICs @ {th:.2f} TH/s | {c.frequency_mhz}MHz | PCB: {c.pcb_temp} | Chip: {c.chip_temp} | HW Errs: {c.hw_errors}")

            if m.web_url:
                print(f"    \\-- Web Management UI: {m.web_url}")
            print()
    else:
        print("\n[!] No active ASIC or Bitaxe miner responded on the probed subnet(s).")

    if verbose and others:
        print("-" * 80)
        print(" OTHER RESPONSIVE LAN HOSTS:")
        print("-" * 80)
        for o in others:
            ports_str = ", ".join(str(p) for p in o.open_ports)
            mac_str = f"[{o.mac}]" if o.mac else ""
            print(f"  • {o.ip:<15} Ports: {ports_str:<18} MAC: {mac_str:<20} Vendor: {o.vendor}")

    print("-" * 80)
    print(f"Total Sweep Duration: {elapsed_total:.2f}s | Subnets: {len(target_subnets)} | Responsive Hosts: {len(all_hosts)} | Miners Found: {len(miners)}")
    print("=" * 80 + "\n")

    return miners


def main():
    parser = argparse.ArgumentParser(description="High-Speed Local Subnet Bitcoin Miner & ASIC Discovery")
    parser.add_argument("subnet", nargs="?", default=None, help="Target IPv4 subnet (e.g. 192.168.1.0/24)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Display all responsive non-miner network hosts")
    args = parser.parse_args()

    if args.subnet:
        try:
            subnets = [ipaddress.IPv4Network(args.subnet, strict=False)]
        except ValueError as e:
            print(f"[ERROR] Invalid subnet '{args.subnet}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        subnets = get_active_ipv4_subnets()

    if not subnets:
        print("[ERROR] No active physical IPv4 subnets detected.", file=sys.stderr)
        sys.exit(1)

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(run_discovery_sweep(subnets, verbose=args.verbose))


if __name__ == "__main__":
    main()
