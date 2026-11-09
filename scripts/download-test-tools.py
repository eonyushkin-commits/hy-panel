#!/usr/bin/env python3
"""Download pinned integration-test tools; verify hashes before extraction."""
import gzip
import hashlib
import io
from pathlib import Path
import sys
import subprocess
import zipfile

ASSETS = (
    ("hysteria", "https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-linux-amd64",
     "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691", "raw"),
    ("xray", "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip",
     "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82", "zip"),
    ("xray-minimum", "https://github.com/XTLS/Xray-core/releases/download/v25.3.6/Xray-linux-64.zip",
     "82d4be3a5ed8bd2621df9c9913c3a2761b86a42ae8485da836f7447ff2ec3d4d", "zip"),
    ("mihomo", "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-v1-v1.19.33.gz",
     "8ec92e7b2fdc6b853ba00156bab7e4e965c8b0d843b8c4ac8ab98795f02ad524", "gzip"),
)


def main():
    destination = Path(sys.argv[1]).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    for name, url, expected, kind in ASSETS:
        archive_path = destination / f"{name}.download"
        data = archive_path.read_bytes() if archive_path.exists() else b""
        if hashlib.sha256(data).hexdigest() != expected:
            print(f"Downloading/resuming {name}: {url}", flush=True)
            subprocess.run([
                "curl", "--fail", "--location", "--show-error",
                "--connect-timeout", "20", "--speed-time", "120", "--speed-limit", "1024",
                "--continue-at", "-", "--max-filesize", str(200 * 1024 * 1024),
                "--output", str(archive_path), url,
            ], check=True)
            data = archive_path.read_bytes()
        if len(data) > 200 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"{name}: SHA-256 mismatch or oversized archive")
        if kind == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                data = archive.read("xray")
        elif kind == "gzip":
            data = gzip.decompress(data)
        target = destination / name
        target.write_bytes(data)
        target.chmod(0o755)
        print(f"Verified {name}", flush=True)


if __name__ == "__main__":
    main()
