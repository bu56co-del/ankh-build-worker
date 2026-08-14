use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"ANKHCAP1";
const NONCE_LEN: usize = 24;
const KEY_ENV: &str = "ANKH_CAPSULE_KEY_B64";

fn usage() -> ! {
    eprintln!("usage: ankh-capsule-crypt <encrypt|decrypt> <input> <output> <aad>");
    std::process::exit(2);
}

fn load_key() -> Result<Key, String> {
    let encoded = env::var(KEY_ENV).map_err(|_| format!("missing {KEY_ENV}"))?;
    env::remove_var(KEY_ENV);
    let decoded = STANDARD
        .decode(encoded.trim())
        .map_err(|_| "capsule key is not valid base64".to_string())?;
    if decoded.len() != 32 {
        return Err(format!("capsule key must decode to 32 bytes, got {}", decoded.len()));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(Key::from(bytes))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("capsule");
    let temp = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    fs::write(&temp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))?;
    }
    match fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&temp);
            Err(e)
        }
    }
}

fn encrypt(input: &Path, output: &Path, aad: &[u8], key: &Key) -> Result<(), String> {
    let plaintext = fs::read(input).map_err(|e| format!("read input: {e}"))?;
    let cipher = XChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), Payload { msg: &plaintext, aad })
        .map_err(|_| "encryption failed".to_string())?;
    let mut output_bytes = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    output_bytes.extend_from_slice(MAGIC);
    output_bytes.extend_from_slice(&nonce_bytes);
    output_bytes.extend_from_slice(&ciphertext);
    atomic_write(output, &output_bytes).map_err(|e| format!("write output: {e}"))
}

fn decrypt(input: &Path, output: &Path, aad: &[u8], key: &Key) -> Result<(), String> {
    let encoded = fs::read(input).map_err(|e| format!("read input: {e}"))?;
    if encoded.len() < MAGIC.len() + NONCE_LEN + 16 {
        return Err("encrypted capsule is truncated".to_string());
    }
    if &encoded[..MAGIC.len()] != MAGIC {
        return Err("encrypted capsule has an invalid magic header".to_string());
    }
    let nonce_start = MAGIC.len();
    let cipher_start = nonce_start + NONCE_LEN;
    let cipher = XChaCha20Poly1305::new(key);
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&encoded[nonce_start..cipher_start]),
            Payload { msg: &encoded[cipher_start..], aad },
        )
        .map_err(|_| "authentication failed".to_string())?;
    atomic_write(output, &plaintext).map_err(|e| format!("write output: {e}"))
}

fn main() {
    let mut args = env::args_os();
    let _program = args.next();
    let mode = args.next().and_then(|v| v.into_string().ok()).unwrap_or_else(|| usage());
    let input = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
    let output = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
    let aad = args.next().and_then(|v| v.into_string().ok()).unwrap_or_else(|| usage());
    if args.next().is_some() {
        usage();
    }

    let key = load_key().unwrap_or_else(|e| {
        eprintln!("[ERROR] {e}");
        std::process::exit(1);
    });
    let result = match mode.as_str() {
        "encrypt" => encrypt(&input, &output, aad.as_bytes(), &key),
        "decrypt" => decrypt(&input, &output, aad.as_bytes(), &key),
        _ => usage(),
    };
    if let Err(error) = result {
        eprintln!("[ERROR] {error}");
        std::process::exit(1);
    }
}
