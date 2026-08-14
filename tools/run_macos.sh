#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

REQUEST_PATH="${1:?request path required}"
CIPHER_PATH="${2:?cipher path required}"
CRYPTO_PATH="${3:?crypto path required}"
WORK_ROOT="${4:?work root required}"
ARTIFACT_ROOT="${5:?artifact root required}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$WORK_ROOT" "$ARTIFACT_ROOT"
BUILD_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["build_id"])' "$REQUEST_PATH")"
WORKER_FINGERPRINT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["worker_fingerprint"])' "$REQUEST_PATH")"
[[ "$BUILD_ID" =~ ^[0-9a-f]{64}$ ]] || { echo '[ERROR] invalid build request'; exit 1; }
[[ "$WORKER_FINGERPRINT" =~ ^[0-9a-f]{64}$ ]] || { echo '[ERROR] invalid worker fingerprint'; exit 1; }

CAPSULE_KEY="${ANKH_CAPSULE_KEY_B64:-}"
[ -n "$CAPSULE_KEY" ] || { echo '[ERROR] worker capsule key is not configured'; exit 1; }
unset ANKH_CAPSULE_KEY_B64

crypt() {
    local mode="$1" input="$2" output="$3" aad="$4"
    ANKH_CAPSULE_KEY_B64="$CAPSULE_KEY" "$CRYPTO_PATH" "$mode" "$input" "$output" "$aad" >/dev/null
}

SOURCE_ZIP="$WORK_ROOT/source.zip"
SOURCE_ROOT="$WORK_ROOT/source"
SOURCE_MANIFEST="$SOURCE_ROOT/SOURCE_MANIFEST.json"
PRIVATE_LOG="$WORK_ROOT/private-build.log"
BUNDLE="$WORK_ROOT/macos-output.zip"
FAILURE_PAYLOAD="$WORK_ROOT/macos-failure.json"
OUTPUT_CIPHER="$ARTIFACT_ROOT/macos-output.enc"
LOG_CIPHER="$ARTIFACT_ROOT/macos-log.enc"
STATUS_PATH="$ARTIFACT_ROOT/macos-status.json"
SUCCESS=false

: > "$PRIVATE_LOG"
if crypt decrypt "$CIPHER_PATH" "$SOURCE_ZIP" "ankh-source-v1:$BUILD_ID" \
    && python3 "$SCRIPT_DIR/extract_source.py" \
        --archive "$SOURCE_ZIP" \
        --output "$SOURCE_ROOT" \
        --expected-build-id "$BUILD_ID" \
        --expected-worker-fingerprint "$WORKER_FINGERPRINT" \
        >>"$PRIVATE_LOG" 2>&1; then

    {
        cd "$SOURCE_ROOT/daemon"
        cargo test --locked --quiet
        cargo build --release --locked --quiet
        cargo build --release --locked --quiet --target x86_64-apple-darwin
        cargo build --release --locked --quiet --target aarch64-apple-darwin
        cd "$SOURCE_ROOT/pet"
        cargo test --lib --locked --quiet
        cargo build --release --locked --quiet --target x86_64-apple-darwin
        cargo build --release --locked --quiet --target aarch64-apple-darwin
    } >>"$PRIVATE_LOG" 2>&1 && {
        mkdir -p "$WORK_ROOT/universal"
        lipo -create \
            -output "$WORK_ROOT/universal/ankh-opener-daemon" \
            "$SOURCE_ROOT/daemon/target/x86_64-apple-darwin/release/ankh-opener-daemon" \
            "$SOURCE_ROOT/daemon/target/aarch64-apple-darwin/release/ankh-opener-daemon"
        lipo -create \
            -output "$WORK_ROOT/universal/ankh-pet" \
            "$SOURCE_ROOT/pet/target/x86_64-apple-darwin/release/ankh-pet" \
            "$SOURCE_ROOT/pet/target/aarch64-apple-darwin/release/ankh-pet"
        chmod 700 "$WORK_ROOT/universal/ankh-opener-daemon" "$WORK_ROOT/universal/ankh-pet"
        codesign --force --sign - "$WORK_ROOT/universal/ankh-opener-daemon"
        codesign --force --sign - "$WORK_ROOT/universal/ankh-pet"
        codesign --verify --strict "$WORK_ROOT/universal/ankh-opener-daemon"
        codesign --verify --strict "$WORK_ROOT/universal/ankh-pet"
        lipo -verify_arch x86_64 arm64 "$WORK_ROOT/universal/ankh-opener-daemon"
        lipo -verify_arch x86_64 arm64 "$WORK_ROOT/universal/ankh-pet"
    } >>"$PRIVATE_LOG" 2>&1 && python3 "$SCRIPT_DIR/package_output.py" \
        --platform macos \
        --source-manifest "$SOURCE_MANIFEST" \
        --daemon "$WORK_ROOT/universal/ankh-opener-daemon" \
        --pet "$WORK_ROOT/universal/ankh-pet" \
        --output "$BUNDLE" \
        >>"$PRIVATE_LOG" 2>&1 && SUCCESS=true
fi

if [ "$SUCCESS" != true ]; then
    printf '{"schema":1,"build_id":"%s","platform":"macos","success":false}\n' "$BUILD_ID" > "$FAILURE_PAYLOAD"
    BUNDLE="$FAILURE_PAYLOAD"
    printf 'build failed\n' >> "$PRIVATE_LOG"
fi

crypt encrypt "$BUNDLE" "$OUTPUT_CIPHER" "ankh-output-v1:$BUILD_ID:macos"
crypt encrypt "$PRIVATE_LOG" "$LOG_CIPHER" "ankh-log-v1:$BUILD_ID:macos"

python3 - "$BUILD_ID" "$SUCCESS" "$OUTPUT_CIPHER" "$LOG_CIPHER" "$STATUS_PATH" <<'PY'
import hashlib, json, pathlib, sys
build_id, success, output_path, log_path, status_path = sys.argv[1:]
def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
status = {
    "schema": 1,
    "build_id": build_id,
    "platform": "macos",
    "success": success == "true",
    "output_cipher_sha256": digest(output_path),
    "output_cipher_bytes": pathlib.Path(output_path).stat().st_size,
    "log_cipher_sha256": digest(log_path),
    "log_cipher_bytes": pathlib.Path(log_path).stat().st_size,
}
pathlib.Path(status_path).write_text(json.dumps(status, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY

CAPSULE_KEY=''
if [ "$SUCCESS" = true ]; then
    echo '[OK] encrypted macOS build completed'
else
    echo '[ERROR] encrypted macOS build failed; diagnostics remain encrypted'
fi
