# Antminer Power Saver & Hardware Diagnostic Toolkit

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](requirements.txt)
[![Hardware: S19 / S19j / S19 Pro](https://img.shields.io/badge/hardware-Bitmain%20S19%20Series-orange.svg)]()

A comprehensive, zero-dependency diagnostic, discovery, and power-optimization toolkit for **Bitmain Antminer** (S19, S19j, S19 Pro, S19j Pro, S21, T19) and other Bitcoin ASICs.

Engineered to solve real-world mining hardware challenges: identifying rogue miner IPs, listening for physical "IP Report" button presses, diagnosing false temperature errors, resolving ribbon cable CRC faults, bypassing locked stock Bitmain firmware, and unlocking dynamic power saving via Braiins OS.

---

## Table of Contents
1. [Core Features](#core-features)
2. [Toolkit Architecture](#toolkit-architecture)
3. [Quick Start Guide](#quick-start-guide)
   - [1. Subnet Discovery (`find_miner.py`)](#1-subnet-discovery-find_minerpy)
   - [2. IP Report Button Listener (`listen_ip_report.py`)](#2-ip-report-button-listener-listen_ip_reportpy)
   - [3. Deep-Dive Log Diagnostics (`diagnose_miner.py`)](#3-deep-dive-log-diagnostics-diagnose_minerpy)
   - [4. Automated Braiins Toolbox Downloader (`download_toolbox.py`)](#4-automated-braiins-toolbox-downloader-download_toolboxpy)
   - [5. MicroSD Recovery & Boot Creator (`prepare_sd_recovery.py`)](#5-microsd-recovery--boot-creator-prepare_sd_recoverypy)
4. [Hardware Diagnostic Knowledge Base](#hardware-diagnostic-knowledge-base)
   - [The False 255°C / "Miner Temperature: Abnormal" Bug](#the-false-255c--miner-temperature-abnormal-bug)
   - [Control Board Pinout & Hashboard Mapping (J1, J2, J3)](#control-board-pinout--hashboard-mapping-j1-j2-j3)
   - [Ribbon Cable Integrity & CRC Errors](#ribbon-cable-integrity--crc-errors)
   - [Stock Firmware Mismatched Board Lockout (`BHB42603` vs `BHB42601`)](#stock-firmware-mismatched-board-lockout-bhb42603-vs-bhb42601)
   - [Single-Board & Dual-Board Degraded Mode](#single-board--dual-board-degraded-mode)
5. [Power Saving & Efficiency Optimization](#power-saving--efficiency-optimization)
6. [Contributing & License](#contributing--license)

---

## Core Features

- **Zero External Dependencies**: All core scripts run directly on standard Python 3.8+ using built-in standard library modules (`asyncio`, `socket`, `urllib`, `dataclasses`, `argparse`).
- **High-Speed Async Discovery**: Scans entire `/24` or `/16` subnets in under 3 seconds, probing CGMiner/BMMiner JSON-RPC (port 4028) and web interfaces (port 80).
- **Physical IP Report Event Sniffing**: UDP broadcast listener on port 14235 catches instant IP discovery beacons emitted when pressing the front faceplate button.
- **Automated Root-Cause Diagnostic Engine**: Connects via HTTP Digest/Basic Auth, downloads `/cgi-bin/log.cgi` and `/cgi-bin/get_system_info.cgi`, isolates dead ASIC chains, explains false temperature sensor readouts, and suggests specific hardware remediation.
- **Firmware Bypass & SD Card Creator**: Prepares bootable MicroSD cards to run Braiins OS directly, bypassing stock NAND locks, password resets, and model mismatch restrictions.

---

## Toolkit Architecture

```
Antminer-power-saver/
├── find_miner.py          # High-speed async miner discovery (RPC 4028, HTTP 80/8080)
├── listen_ip_report.py    # Zero-dependency UDP 14235 broadcast listener
├── diagnose_miner.py      # Automated Bitmain log analyzer & hardware failure decoder
├── download_toolbox.py    # Fetches official Braiins Toolbox binaries on-demand
├── prepare_sd_recovery.py # Formats/extracts Braiins OS boot image to MicroSD
├── requirements.txt       # Optional extensions documentation
├── .gitignore             # Excludes large binaries (>50MB), caches, and logs
└── README.md              # Complete hardware & power-saving documentation
```

---

## Quick Start Guide

### 1. Subnet Discovery (`find_miner.py`)
Quickly find all Bitcoin miners on your local network:

```bash
# Auto-detect your local subnet and scan:
python find_miner.py --auto

# Scan a specific subnet with high concurrency:
python find_miner.py --target 192.168.1.0/24 -c 200

# Scan a specific IP address:
python find_miner.py --target 192.168.1.100
```

**Supported Hardware & Firmwares:**
- Bitmain Antminer (S9, S17, S19, S19 Pro, S19j Pro, S21, T19, L7)
- Braiins OS / BOSminer nodes
- MicroBT WhatsMiner (M20, M30, M50, M60 series)
- Canaan Avalon (A11, A12, A13, A14 series)
- Bitaxe (Ultra, Supra, Gamma, Hex running AxeOS)

---

### 2. IP Report Button Listener (`listen_ip_report.py`)
When setting up a new or unconfigured Antminer, simply press the physical **IP Report** button on the front faceplate:

```bash
python listen_ip_report.py
```

The script listens on UDP port `14235` and immediately prints the miner's IP address, MAC address, and hardware payload upon button press.

---

### 3. Deep-Dive Log Diagnostics (`diagnose_miner.py`)
Run automated root-cause analysis on an Antminer experiencing errors or refusing to hash:

```bash
python diagnose_miner.py --ip 192.168.1.100 --save-log
```

**Diagnostic Output Sample:**
```
===========================================================================
      ANTMINER HARDWARE DIAGNOSTIC & ROOT-CAUSE REPORT
===========================================================================
Target Host:       192.168.1.100
Miner Type:        Antminer S19j Pro
Firmware Version:  Bitmain Linux Release
---------------------------------------------------------------------------
1. HASHBOARD & ASIC CHIP STATUS (PINOUT MAPPING):
  • Connector J1 (Chain 0)    -> 126 ASICs detected [HEALTHY]
  • Connector J2 (Chain 1)    -> 0 ASICs detected (Comms Failed) [DEAD / NO COMMS]
  • Connector J3 (Chain 2)    -> 0 ASICs detected (Comms Failed) [DEAD / NO COMMS]
---------------------------------------------------------------------------
2. THERMAL SENSOR READINGS & BUG VERIFICATION:
  [!] FALSE 255°C BUG DETECTED!
  Stock Bitmain firmware reports 'Miner Temperature: Abnormal' when an ASIC
  chain fails to initialize. Disconnected sensor registers return 0xFF (255°C).
  The hashboards are NOT overheating; the control board is reading uninitialized
  data bus lines from the disconnected chain!
---------------------------------------------------------------------------
3. SIGNAL INTEGRITY & RIBBON CABLE DIAGNOSTICS:
  [!] CRC / Register Comms Errors Detected on Chain 1!
  Remediation: Reseat or replace the ribbon cable on connector J2.
===========================================================================
```

---

### 4. Automated Braiins Toolbox Downloader (`download_toolbox.py`)
To prevent bloating the Git repository with 87MB binaries, use the automated downloader to fetch the official Braiins Toolbox directly:

```bash
# Automatically detects your OS (Windows, Linux, or macOS):
python download_toolbox.py

# Launch the toolbox (Windows):
.\braiins_toolbox\braiins-toolbox.exe
```

---

### 5. MicroSD Recovery & Boot Creator (`prepare_sd_recovery.py`)
When stock firmware is locked or refuses to hash due to mismatched boards, prepare a bootable MicroSD card:

```bash
# Prepare an SD card for an Amlogic-based S19j Pro on drive E:
python prepare_sd_recovery.py --board amlogic --target-drive E:
```

---

## Hardware Diagnostic Knowledge Base

### The False 255°C / "Miner Temperature: Abnormal" Bug
One of the most confusing errors in Bitmain stock firmware is the **"Miner Temperature: Abnormal"** alert accompanied by sensor readouts of **`255°C`**.

#### The Underlying Mechanism:
1. Each hashboard communicates temperature sensor data via an I2C / serial bus to the control board.
2. During boot, the control board checks for ASIC chips on each chain (`Chain[0]`, `Chain[1]`, `Chain[2]`).
3. If a hashboard fails chip enumeration (`find 0 asic`) or suffers ribbon cable signal loss, the control board receives no telemetry.
4. The register values on uninitialized lines float high (`0xFF`), which translates in decimal to **`255`**.
5. Stock firmware logic checks if any sensor temperature exceeds safety limits (typically 85°C). Because `255 > 85`, the firmware trips `ERROR_TEMP_TOO_HIGH` and initiates emergency shutdown.
6. **Verdict**: The chips are **cold and completely idle**. The temperature reading is an uninitialized register artifact, not an actual thermal event.

---

### Control Board Pinout & Hashboard Mapping (J1, J2, J3)
On the Antminer S19 / S19j Pro control board, the three ribbon cable headers correspond directly to the hashboard chains:

| Control Board Port | Software Chain ID | Physical Hashboard Location |
|:-------------------|:------------------|:----------------------------|
| **J1**             | `Chain[0]`        | Board 1 (Right / Outer)     |
| **J2**             | `Chain[1]`        | Board 2 (Middle)            |
| **J3**             | `Chain[2]`        | Board 3 (Left / Inner)      |

*Pinout Note*: Always power down the miner completely before unplugging or reseating ribbon cables.

---

### Ribbon Cable Integrity & CRC Errors
In `/cgi-bin/log.cgi`, errors such as:
```
!!! reg crc error
board_i2c_read failed on chain 1
```
indicate that high-frequency clock or data pulses along the ribbon cable are experiencing interference, poor pin contact, or a damaged ground wire.
- **Troubleshooting Step**: Swap the ribbon cable between `J1` (known healthy) and `J2`. If the error moves from Chain 1 to Chain 0, the cable is defective. If the error stays on Chain 1, the fault is on the hashboard's input buffer or level shifter.

---

### Stock Firmware Mismatched Board Lockout (`BHB42603` vs `BHB42601`)
When replacing a failed hashboard with a spare from another S19 revision, stock Bitmain firmware will inspect the EEPROM model strings:
```
get a different board name for chain:2, pre board_name:BHB42603, current board_name:BHB42601
ERROR_SOC_INIT: basic init failed!
stop mining: SOC init failed!
```
- **Bitmain Stock Limitation**: Refuses to operate if board model codes do not match 100%.
- **Solution**: **Braiins OS** tunes each hashboard chain as an isolated frequency, voltage, and temperature domain. It natively supports running mixed boards (e.g. two `BHB42603` boards and one `BHB42601` board) in the same chassis without error.

---

### Single-Board & Dual-Board Degraded Mode
If one hashboard has shorted ASIC chips or physical damage, the miner can still operate profitably in **degraded mode** (running 1 or 2 boards):

1. **Power Off**: Disconnect both AC power cords from the APW12 power supply.
2. **Disconnect Ribbon**: Unplug the ribbon cable connecting the damaged board to the control board (e.g. `J2`).
3. **Isolate Busbars**: Remove the copper busbar mounting screws connecting the power supply to the damaged board. Wrap or insulate the disconnected terminal to prevent any accidental chassis shorts.
4. **Boot**: Power on the miner. Braiins OS will detect only the connected chains and automatically scale fan curves and power targets to match the active boards.

---

## Power Saving & Efficiency Optimization

### Why Stock Firmware Wastes Power
Stock Bitmain firmware operates on rigid, fixed-voltage profiles (typically ~3100W – 3250W for 90-100 TH/s). It applies the same high voltage to every chip regardless of individual silicon binning.

### Braiins OS Autotuning & Dynamic Power Scaling (DPS)
Installing Braiins OS unlocks per-chip voltage and frequency autotuning:
- **Target Wattage Mode**: Set an exact power limit (e.g., `2100W` instead of `3250W`). The autotuner finds the optimal efficiency sweet spot for each ASIC chip.
- **Efficiency Gains**: Drops consumption from ~34 J/TH down to **~23 - 26 J/TH** on standard air cooling.
- **Dynamic Power Scaling (DPS)**: Automatically scales hashrate up during cheap off-peak electricity hours and scales down during peak electricity pricing.

### Recommended Stratum Pool Configuration (Lincoin)
In the Braiins OS web UI (`http://<MINER_IP>`):
1. Navigate to **Configuration -> Mining**.
2. Add Lincoin primary and backup stratum endpoints:
   - **Pool 1**: `stratum+tcp://btc-us.lincoin.com:3333`
   - **Pool 2**: `stratum+tcp://btc-eu.lincoin.com:3333`
3. Enter your worker username: `your_username.worker_name`
4. Enable **Dynamic Power Scaling (DPS)** and set target power consumption.

---

## Contributing & License

Contributions, bug reports, and pull requests are welcome!
Licensed under the [MIT License](LICENSE).
