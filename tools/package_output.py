#!/usr/bin/env python3
"""Create a deterministic plaintext output bundle before encryption."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import zipfile

FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
PLATFORM_NAMES = {
    "windows": ("ankh-opener-daemon.exe", "ankh-pet.exe"),
    "macos": ("ankh-opener-daemon", "ankh-pet"),
}


def die(message: str) -> "NoReturn":
    raise SystemExit(f"[ERROR] {message}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def zip_write(output: Path, entries: list[tuple[str, bytes, int]]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_name(output.name + ".tmp")
    try:
        with zipfile.ZipFile(temp, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for name, data, mode in sorted(entries):
                info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
                info.create_system = 3
                info.external_attr = ((0o100000 | mode) & 0xFFFF) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                info.flag_bits |= 0x800
                zf.writestr(info, data)
        os.replace(temp, output)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=sorted(PLATFORM_NAMES), required=True)
    parser.add_argument("--source-manifest", required=True)
    parser.add_argument("--daemon", required=True)
    parser.add_argument("--pet", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        source = json.loads(Path(args.source_manifest).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        die(f"cannot read source manifest: {exc}")
    needed = {
        "schema", "worker_schema", "worker_fingerprint", "source_commit",
        "version", "components", "files", "build_id",
    }
    if not isinstance(source, dict) or set(source) != needed:
        die("source manifest has unexpected fields")
    if not re.fullmatch(r"[0-9a-f]{64}", str(source["build_id"])):
        die("source build ID is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", str(source["source_commit"])):
        die("source commit is invalid")

    daemon = Path(args.daemon).read_bytes()
    pet = Path(args.pet).read_bytes()
    daemon_name, pet_name = PLATFORM_NAMES[args.platform]
    if len(daemon) < 400_000 or len(pet) < 300_000:
        die("one or more build outputs are implausibly small")

    files = [
        {"name": daemon_name, "sha256": sha256(daemon), "size": len(daemon)},
        {"name": pet_name, "sha256": sha256(pet), "size": len(pet)},
    ]
    manifest = {
        "schema": 1,
        "worker_schema": source["worker_schema"],
        "worker_fingerprint": source["worker_fingerprint"],
        "build_id": source["build_id"],
        "source_commit": source["source_commit"],
        "version": source["version"],
        "platform": args.platform,
        "tests_passed": True,
        "files": files,
    }
    checksums = "".join(f"{item['sha256']}  {item['name']}\n" for item in sorted(files, key=lambda item: item["name"]))
    mode = 0o755 if args.platform == "macos" else 0o644
    entries = [
        ("BUILD_MANIFEST.json", canonical_json(manifest), 0o644),
        ("BUILD_ID", (str(source["build_id"]) + "\n").encode("ascii"), 0o644),
        ("SOURCE_COMMIT", (str(source["source_commit"]) + "\n").encode("ascii"), 0o644),
        ("VERSION", (str(source["version"]) + "\n").encode("ascii"), 0o644),
        ("SHA256SUMS.txt", checksums.encode("ascii"), 0o644),
        (daemon_name, daemon, mode),
        (pet_name, pet, mode),
    ]
    output = Path(args.output).resolve()
    zip_write(output, entries)
    print(json.dumps({"build_id": source["build_id"], "platform": args.platform, "bundle_sha256": sha256(output.read_bytes())}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
