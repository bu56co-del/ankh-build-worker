#!/usr/bin/env python3
"""Verify encrypted platform artifacts before creating a public release."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

PLATFORMS = ("windows", "macos")
FAILURE_STAGES = {
    "windows": {
        "decrypt", "extract", "daemon_test", "daemon_build", "pet_test",
        "pet_build", "packaging", "output_encryption",
    },
    "macos": {
        "decrypt", "extract", "daemon_test", "daemon_build", "pet_test",
        "pet_build", "universal_merge", "signing", "packaging",
        "output_encryption",
    },
}
FAILURE_CODES = {"command_failed"}
CAPSULE_MAGIC = b"ANKHCAP1"
MIN_CAPSULE_BYTES = len(CAPSULE_MAGIC) + 24 + 16


def die(message: str) -> "NoReturn":
    raise SystemExit(f"[ERROR] {message}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require_encrypted_capsule(path: Path) -> None:
    try:
        if path.stat().st_size < MIN_CAPSULE_BYTES:
            die("invalid encrypted worker artifact")
        with path.open("rb") as f:
            if f.read(len(CAPSULE_MAGIC)) != CAPSULE_MAGIC:
                die("invalid encrypted worker artifact")
    except OSError:
        die("invalid encrypted worker artifact")


def load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        die(f"cannot read {path.name}: {exc}")
    if not isinstance(value, dict):
        die(f"{path.name} must contain an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--artifacts", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    request_path = Path(args.request).resolve()
    artifacts = Path(args.artifacts).resolve()
    output = Path(args.output).resolve()
    request = load_json(request_path)
    build_id = request.get("build_id")
    if not isinstance(build_id, str) or not re.fullmatch(r"[0-9a-f]{64}", build_id):
        die("request build ID is invalid")

    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        die("release output directory must be empty")
    shutil.copy2(request_path, output / "REQUEST.json")
    all_success = True

    for platform in PLATFORMS:
        status_path = artifacts / f"{platform}-status.json"
        output_cipher = artifacts / f"{platform}-output.enc"
        log_cipher = artifacts / f"{platform}-log.enc"
        for path in (status_path, output_cipher, log_cipher):
            if not path.is_file():
                die(f"missing encrypted worker artifact: {path.name}")
        status = load_json(status_path)
        fields = {
            "schema", "build_id", "platform", "success",
            "failure_stage", "failure_code",
            "output_cipher_sha256", "output_cipher_bytes",
            "log_cipher_sha256", "log_cipher_bytes",
        }
        if set(status) != fields:
            die(f"unexpected fields in {status_path.name}")
        if status["schema"] != 2 or status["build_id"] != build_id or status["platform"] != platform:
            die(f"identity mismatch in {status_path.name}")
        if status["success"] not in (True, False):
            die(f"{platform} build status is not boolean")
        if status["success"] is True:
            if status["failure_stage"] is not None or status["failure_code"] is not None:
                die(f"{platform} successful status contains failure metadata")
        elif status["failure_stage"] not in FAILURE_STAGES[platform] or status["failure_code"] not in FAILURE_CODES:
            die(f"{platform} failure classification is invalid")
        all_success = all_success and status["success"] is True
        if status["output_cipher_sha256"] is None or status["output_cipher_bytes"] is None:
            die(f"{platform} output ciphertext metadata is missing")
        if status["log_cipher_sha256"] is None or status["log_cipher_bytes"] is None:
            die(f"{platform} log ciphertext metadata is missing")
        require_encrypted_capsule(output_cipher)
        require_encrypted_capsule(log_cipher)
        if status["output_cipher_sha256"] != sha256_file(output_cipher):
            die(f"{platform} output ciphertext hash mismatch")
        if status["log_cipher_sha256"] != sha256_file(log_cipher):
            die(f"{platform} log ciphertext hash mismatch")
        if status["output_cipher_bytes"] != output_cipher.stat().st_size:
            die(f"{platform} output ciphertext size mismatch")
        if status["log_cipher_bytes"] != log_cipher.stat().st_size:
            die(f"{platform} log ciphertext size mismatch")
        shutil.copy2(status_path, output / status_path.name)
        shutil.copy2(output_cipher, output / output_cipher.name)
        shutil.copy2(log_cipher, output / log_cipher.name)

    print(json.dumps({"build_id": build_id, "success": all_success, "release_files": sorted(path.name for path in output.iterdir())}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
