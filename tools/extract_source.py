#!/usr/bin/env python3
"""Verify and safely extract a decrypted ANKH source capsule."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

MAX_FILE_COUNT = 2000
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
ALLOWED_FILES = {
    "daemon/Cargo.toml", "daemon/Cargo.lock",
    "pet/Cargo.toml", "pet/Cargo.lock",
}
ALLOWED_PREFIXES = ("daemon/src/", "pet/src/")


def die(message: str) -> "NoReturn":
    raise SystemExit(f"[ERROR] {message}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def allowed(name: str) -> bool:
    return name in ALLOWED_FILES or name.startswith(ALLOWED_PREFIXES)


def safe_name(info: zipfile.ZipInfo) -> str:
    name = info.filename
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "\\" in name or "\x00" in name:
        die(f"unsafe source archive path: {name!r}")
    mode = (info.external_attr >> 16) & 0xFFFF
    if stat.S_ISLNK(mode):
        die(f"symlink is forbidden in source capsule: {name}")
    if name != "SOURCE_MANIFEST.json" and not allowed(name):
        die(f"source path is outside the allowlist: {name}")
    return name


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--expected-build-id", required=True)
    parser.add_argument("--expected-worker-fingerprint", required=True)
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_build_id):
        die("expected build ID is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_worker_fingerprint):
        die("expected worker fingerprint is invalid")

    archive = Path(args.archive).resolve()
    output = Path(args.output).resolve()
    if output.exists() and any(output.iterdir()):
        die(f"source output directory must be empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    payload: dict[str, bytes] = {}
    with zipfile.ZipFile(archive, "r") as zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILE_COUNT + 1:
            die("source capsule contains too many entries")
        names = [safe_name(info) for info in infos]
        if len(names) != len(set(names)):
            die("source capsule contains duplicate entries")
        if "SOURCE_MANIFEST.json" not in names:
            die("source capsule has no SOURCE_MANIFEST.json")
        total = 0
        for info, name in zip(infos, names):
            if info.file_size > MAX_MEMBER_BYTES:
                die(f"source member is too large: {name}")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                die("source capsule exceeds the total size limit")
            payload[name] = zf.read(info)

    try:
        manifest = json.loads(payload["SOURCE_MANIFEST.json"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        die(f"invalid source manifest: {exc}")
    fields = {
        "schema", "worker_schema", "worker_fingerprint", "source_commit",
        "version", "components", "files", "build_id",
    }
    if not isinstance(manifest, dict) or set(manifest) != fields:
        die("source manifest has unexpected fields")
    if manifest["schema"] != 1 or manifest["worker_schema"] != 1:
        die("unsupported source manifest schema")
    if manifest["worker_fingerprint"] != args.expected_worker_fingerprint:
        die("source manifest worker fingerprint mismatch")
    if manifest["build_id"] != args.expected_build_id:
        die("source manifest build ID mismatch")
    if not re.fullmatch(r"[0-9a-f]{40}", str(manifest["source_commit"])):
        die("source manifest commit is invalid")
    if manifest["components"] != ["daemon", "pet"]:
        die("source manifest components are invalid")

    manifest_base = dict(manifest)
    del manifest_base["build_id"]
    if sha256(canonical_json(manifest_base)) != args.expected_build_id:
        die("BUILD_ID does not authenticate the source manifest")

    items = manifest["files"]
    if not isinstance(items, list) or not items:
        die("source manifest files must be a non-empty list")
    described: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            die("invalid source manifest file entry")
        name = item["path"]
        if not isinstance(name, str) or not allowed(name) or name in described:
            die(f"unexpected or duplicate source manifest path: {name!r}")
        described.add(name)
        if name not in payload:
            die(f"source manifest references a missing file: {name}")
        data = payload[name]
        if item["size"] != len(data) or item["sha256"] != sha256(data):
            die(f"source file integrity mismatch: {name}")
    actual = set(payload) - {"SOURCE_MANIFEST.json"}
    if described != actual:
        die(f"source manifest/archive mismatch: missing={sorted(described - actual)}, extra={sorted(actual - described)}")

    for name in sorted(actual):
        target = output.joinpath(*PurePosixPath(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload[name])
        os.chmod(target, 0o600)
    (output / "SOURCE_MANIFEST.json").write_bytes(canonical_json(manifest))
    os.chmod(output / "SOURCE_MANIFEST.json", 0o600)
    print(json.dumps({"build_id": manifest["build_id"], "version": manifest["version"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
