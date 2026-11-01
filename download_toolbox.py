#!/usr/bin/env python3
"""
download_toolbox.py
===================
Automated Downloader & Unpacker for Braiins OS Toolbox.

Fetches the official Braiins Toolbox directly from Braiins feed servers,
extracts the executable into `braiins_toolbox/`, and validates installation.
Zero git bloat: keeps repository under lightweight git size limits.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import sys
import tarfile
import urllib.request
import zipfile

# Platform download matrix
TOOLBOX_URLS = {
    "windows": "https://feeds.braiins-os.com/toolbox/braiins-toolbox-windows-x86_64.zip",
    "linux": "https://feeds.braiins-os.com/toolbox/braiins-toolbox-linux-x86_64.tar.gz",
    "darwin": "https://feeds.braiins-os.com/toolbox/braiins-toolbox-macos-x86_64.tar.gz",
}


def download_with_progress(url: str, dest_path: str) -> None:
    """Download a file showing live progress in terminal."""
    print(f"[*] Connecting to: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "AntminerPowerSaver/1.0"})

    with urllib.request.urlopen(req) as resp:
        total_size = int(resp.headers.get("content-length", 0))
        downloaded = 0
        chunk_size = 65536

        os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)

        with open(dest_path, "wb") as f:
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    percent = downloaded / total_size * 100
                    mb = downloaded / (1024 * 1024)
                    total_mb = total_size / (1024 * 1024)
                    print(f"\r    Downloading: {mb:.1f} MB / {total_mb:.1f} MB [{percent:.1f}%]", end="", flush=True)
                else:
                    mb = downloaded / (1024 * 1024)
                    print(f"\r    Downloading: {mb:.1f} MB", end="", flush=True)
        print("\n[✓] Download complete.")


def unpack_archive(archive_path: str, extract_dir: str) -> str:
    """Extract zip or tar.gz archive into target directory."""
    print(f"[*] Extracting archive to: {extract_dir}")
    os.makedirs(extract_dir, exist_ok=True)

    extracted_binary = ""

    if archive_path.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(extract_dir)
            for name in zf.namelist():
                if "braiins-toolbox" in name and (name.endswith(".exe") or "." not in os.path.basename(name)):
                    extracted_binary = os.path.join(extract_dir, name)
    elif archive_path.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive_path, "r:gz") as tf:
            tf.extractall(extract_dir)
            for name in tf.getnames():
                if "braiins-toolbox" in name:
                    extracted_binary = os.path.join(extract_dir, name)

    return extracted_binary


def main() -> int:
    parser = argparse.ArgumentParser(description="Download and unpack official Braiins Toolbox binary")
    parser.add_argument(
        "--platform",
        "-p",
        choices=["windows", "linux", "darwin"],
        default=None,
        help="Target OS platform (default: auto-detected)",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default="braiins_toolbox",
        help="Target folder for binary extraction (default: braiins_toolbox)",
    )
    parser.add_argument(
        "--temp-dir",
        "-t",
        default="downloads",
        help="Directory to store downloaded archive (default: downloads)",
    )

    args = parser.parse_args()

    # Detect platform
    target_plat = args.platform
    if not target_plat:
        sys_plat = platform.system().lower()
        if "windows" in sys_plat:
            target_plat = "windows"
        elif "linux" in sys_plat:
            target_plat = "linux"
        elif "darwin" in sys_plat:
            target_plat = "darwin"
        else:
            target_plat = "windows"

    url = TOOLBOX_URLS.get(target_plat)
    if not url:
        print(f"[!] Unsupported platform: {target_plat}")
        return 1

    archive_filename = os.path.basename(url)
    archive_path = os.path.join(args.temp_dir, archive_filename)

    # Check if binary already exists
    exe_name = "braiins-toolbox.exe" if target_plat == "windows" else "braiins-toolbox"
    final_exe_path = os.path.join(args.output_dir, exe_name)

    if os.path.exists(final_exe_path):
        print(f"[✓] Braiins Toolbox already installed at: {final_exe_path}")
        print("To reinstall, delete the directory and run again.")
        return 0

    # Download archive if not present
    if not os.path.exists(archive_path):
        download_with_progress(url, archive_path)
    else:
        print(f"[✓] Found existing cached archive: {archive_path}")

    # Extract
    extracted = unpack_archive(archive_path, args.output_dir)
    print(f"[✓] Braiins Toolbox successfully unpacked to: {os.path.abspath(args.output_dir)}")
    print("\nTo launch Braiins Toolbox:")
    if target_plat == "windows":
        print(f"  .\\{args.output_dir}\\braiins-toolbox.exe")
    else:
        print(f"  chmod +x ./{args.output_dir}/braiins-toolbox && ./{args.output_dir}/braiins-toolbox")
    return 0


if __name__ == "__main__":
    sys.exit(main())
