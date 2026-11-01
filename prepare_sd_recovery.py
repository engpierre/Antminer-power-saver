#!/usr/bin/env python3
"""
prepare_sd_recovery.py
======================
Automated SD Card Preparation Utility for Antminer S19 / S19j / S19 Pro Recovery.

Bypasses locked Bitmain stock NAND firmware, mismatched hashboard models
(BHB42603 vs BHB42601), and the false 255°C temperature lockout bug by preparing
a bootable Braiins OS MicroSD card.

Hardware Supported:
- Antminer S19 / S19j / S19 Pro / S19j Pro
- Control boards: Amlogic A113D, Xilinx Zynq 7000, BeagleBone (BB)
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import string
import subprocess
import sys
import urllib.request
import zipfile
import tarfile

SD_IMAGE_URLS = {
    "s19-amlogic": "https://feeds.braiins-os.com/amlogic/braiins-os_amlogic_latest.tar.gz",
    "s19-xilinx": "https://feeds.braiins-os.com/xilinx/braiins-os_xilinx_latest.tar.gz",
    "s19-beaglebone": "https://feeds.braiins-os.com/bb/braiins-os_bb_latest.tar.gz",
}


def list_removable_drives() -> list[str]:
    """Detect removable drives on Windows or mount points on Unix."""
    drives = []
    if sys.platform == "win32":
        try:
            import ctypes
            drive_bits = ctypes.windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if drive_bits & 1:
                    drive_path = f"{letter}:\\"
                    drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
                    # DRIVE_REMOVABLE = 2
                    if drive_type == 2:
                        drives.append(f"{letter}:")
                drive_bits >>= 1
        except Exception:
            pass
    return drives


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Automated MicroSD Card Preparation for Antminer Braiins OS Boot"
    )
    parser.add_argument(
        "--board",
        "-b",
        choices=["amlogic", "xilinx", "beaglebone"],
        default="amlogic",
        help="Control board architecture (default: amlogic for modern S19/S19j Pro)",
    )
    parser.add_argument(
        "--target-drive",
        "-d",
        type=str,
        help="Target SD drive letter (e.g. E: on Windows, or /Volumes/SD on macOS)",
    )
    parser.add_argument(
        "--temp-dir",
        "-t",
        default="downloads",
        help="Cache directory for downloaded images (default: downloads)",
    )

    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("       ANTMINER MICROSD BOOT & RECOVERY PREPARATION UTILITY")
    print("=" * 70)
    print("This tool prepares a bootable MicroSD card running Braiins OS to:")
    print("  1. Completely bypass stock Bitmain NAND firmware and locked passwords.")
    print("  2. Allow mixed hashboard models (e.g. BHB42603 + BHB42601) to hash together.")
    print("  3. Eliminate the false 255°C 'Miner Temperature: Abnormal' shutdown bug.")
    print("=" * 70 + "\n")

    # 1. Drive Detection
    detected = list_removable_drives()
    if detected:
        print(f"[✓] Detected removable drives: {', '.join(detected)}")
    else:
        print("[*] No removable drives automatically detected (or none inserted yet).")

    target_drive = args.target_drive
    if not target_drive:
        if detected:
            target_drive = detected[0]
            print(f"[*] Defaulting to detected drive: {target_drive}")
        else:
            prompt = input("Enter your MicroSD drive letter (e.g. E: or D:): ").strip().upper()
            if prompt:
                target_drive = prompt if prompt.endswith(":") else f"{prompt}:"
            else:
                print("[!] No target drive provided. Aborting.")
                return 1

    # Format verification reminder
    print(f"\n[!] TARGET DRIVE: {target_drive}")
    print("CRITICAL REQUIREMENTS FOR THE MICROSD CARD:")
    print("  • Capacity: 4 GB to 32 GB (MicroSDHC recommended)")
    print("  • Filesystem: FAT32 (Allocation unit size: 32KB or 4096 bytes)")
    print("  • Partition style: MBR (Master Boot Record)")
    print()

    # 2. Control Board Architecture Selection
    key = f"s19-{args.board}"
    image_url = SD_IMAGE_URLS.get(key, SD_IMAGE_URLS["s19-amlogic"])
    print(f"[*] Target Architecture: {args.board.upper()}")
    print(f"[*] Download Source:     {image_url}")

    os.makedirs(args.temp_dir, exist_ok=True)
    archive_name = os.path.basename(image_url)
    dest_archive = os.path.join(args.temp_dir, archive_name)

    print("\nStep 1: Downloading Braiins OS bootable recovery package...")
    print(f"[*] URL: {image_url}")

    try:
        req = urllib.request.Request(image_url, headers={"User-Agent": "AntminerPowerSaver/1.0"})
        with urllib.request.urlopen(req) as resp:
            total_size = int(resp.headers.get("content-length", 0))
            downloaded = 0
            with open(dest_archive, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        mb = downloaded / (1024 * 1024)
                        total_mb = total_size / (1024 * 1024)
                        print(f"\r    Downloading: {mb:.1f} MB / {total_mb:.1f} MB [{downloaded/total_size*100:.1f}%]", end="", flush=True)
            print("\n[✓] Download finished.")
    except Exception as e:
        print(f"\n[!] Could not automatically download image ({e}).")
        print("[*] You can manually download the SD archive from:")
        print("    https://braiins.com/os/plus/download")
        print("    Select 'S19 / S19j / S19 Pro' -> 'MicroSD Card Boot Image'")

    # Target path validation
    target_path = target_drive if target_drive.endswith("\\") else f"{target_drive}\\"
    if not os.path.exists(target_path):
        print(f"\n[!] Target drive path {target_path} is not accessible right now.")
        print("    Ensure the card reader is plugged in and recognized in Windows Explorer.")
        return 1

    # Extract directly to SD card if archive exists
    if os.path.exists(dest_archive):
        print(f"\nStep 2: Unpacking boot files to SD card root ({target_path})...")
        try:
            if dest_archive.endswith((".tar.gz", ".tgz")):
                with tarfile.open(dest_archive, "r:gz") as tf:
                    tf.extractall(target_path)
            elif dest_archive.endswith(".zip"):
                with zipfile.ZipFile(dest_archive, "r") as zf:
                    zf.extractall(target_path)
            print(f"[✓] Successfully wrote boot files to {target_path}")
        except Exception as e:
            print(f"[!] Extraction error: {e}")
            return 1

    print("\n" + "=" * 70)
    print("                  NEXT STEPS TO BOOT THE MINER")
    print("=" * 70)
    print("1. Safely Eject the MicroSD card from your PC.")
    print("2. Power OFF the Antminer completely (unplug both PSU C19/C20 power cables).")
    print("3. Insert the MicroSD card into the front faceplate SD Card slot.")
    print("4. Power ON the Antminer.")
    print("5. Watch the front LEDs:")
    print("   • Normal boot takes ~90-120 seconds.")
    print("   • The miner will obtain a DHCP IP address.")
    print("6. Run discovery to locate the new Braiins OS interface:")
    print("   python find_miner.py --auto")
    print("7. Open http://<MINER_IP> in your browser.")
    print("   • Default credentials: root / root")
    print("   • Configure your Lincoin stratum pool and target wattage in the web GUI!")
    print("=" * 70 + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
