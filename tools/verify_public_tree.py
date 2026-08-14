#!/usr/bin/env python3
"""Reject anything except the reviewed ciphertext-only public worker tree."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_FILES = {
    ".github/workflows/build.yml",
    ".gitignore",
    "README.md",
    "REQUEST.json",
    "source.enc",
    "tools/capsule-crypt/Cargo.toml",
    "tools/capsule-crypt/Cargo.lock",
    "tools/capsule-crypt/src/main.rs",
    "tools/extract_source.py",
    "tools/package_output.py",
    "tools/run_macos.sh",
    "tools/run_windows.ps1",
    "tools/verify_public_tree.py",
    "tools/verify_release.py",
}
TEXT_FILES = EXPECTED_FILES - {"source.enc"}
MAX_CIPHER_BYTES = 320 * 1024 * 1024
FORBIDDEN = re.compile("|".join([
    "github_" + "pat_[A-Za-z0-9_]+",
    "gh" + "[pousr]_[A-Za-z0-9_]{20,}",
    "BEGIN " + "[A-Z ]*PRIVATE KEY",
    "client_" + "secret",
    "refresh_" + "token",
]))


def die(message: str) -> "NoReturn":
    raise SystemExit(f"[ERROR] {message}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def worker_fingerprint() -> str:
    h = hashlib.sha256()
    for rel in sorted(TEXT_FILES - {"REQUEST.json"}):
        data = (ROOT / rel).read_bytes()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(hashlib.sha256(data).digest())
        h.update(b"\n")
    return h.hexdigest()


def main() -> int:
    actual: set[str] = set()
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT).as_posix()
        if rel == ".git" or rel.startswith(".git/"):
            continue
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode):
            die(f"symlink is forbidden in public worker: {rel}")
        if path.is_file():
            posix = PurePosixPath(rel)
            if posix.is_absolute() or ".." in posix.parts or "\\" in rel:
                die(f"unsafe public path: {rel}")
            actual.add(rel)
    if actual != EXPECTED_FILES:
        die(f"unexpected public files: missing={sorted(EXPECTED_FILES - actual)}, extra={sorted(actual - EXPECTED_FILES)}")

    cipher = ROOT / "source.enc"
    if cipher.stat().st_size > MAX_CIPHER_BYTES:
        die("encrypted source capsule is too large")
    with cipher.open("rb") as f:
        if f.read(8) != b"ANKHCAP1":
            die("source.enc is not an authenticated ANKH capsule")

    try:
        request = json.loads((ROOT / "REQUEST.json").read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        die(f"invalid REQUEST.json: {exc}")
    expected_request_fields = {
        "schema", "worker_schema", "build_id", "worker_fingerprint",
        "workflow_sha256", "source_cipher_sha256", "source_cipher_bytes",
    }
    if not isinstance(request, dict) or set(request) != expected_request_fields:
        die("REQUEST.json has unexpected fields")
    if request["schema"] != 1 or request["worker_schema"] != 1:
        die("unsupported request schema")
    for key in ("build_id", "worker_fingerprint", "workflow_sha256", "source_cipher_sha256"):
        if not isinstance(request[key], str) or not re.fullmatch(r"[0-9a-f]{64}", request[key]):
            die(f"invalid request digest: {key}")
    if request["source_cipher_bytes"] != cipher.stat().st_size:
        die("encrypted source size does not match REQUEST.json")
    if request["source_cipher_sha256"] != sha256_file(cipher):
        die("encrypted source hash does not match REQUEST.json")
    if request["workflow_sha256"] != sha256_file(ROOT / ".github/workflows/build.yml"):
        die("workflow hash does not match REQUEST.json")
    if request["worker_fingerprint"] != worker_fingerprint():
        die("worker tooling fingerprint does not match REQUEST.json")

    for rel in sorted(TEXT_FILES):
        text = (ROOT / rel).read_text(encoding="utf-8")
        match = FORBIDDEN.search(text)
        if match:
            die(f"forbidden private or secret-like text in {rel}: {match.group(0)}")
    print("public worker policy passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
