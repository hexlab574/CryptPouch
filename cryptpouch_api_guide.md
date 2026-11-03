# cryptpouch_api.py - AI Callable API Guide

`cryptpouch_api.py` is the Python library wrapper for CryptPouch v2.9.0. AI
agents, scripts and notebooks can `import` it and call every core feature
directly. All console output of the underlying tool is silenced; every
function either returns a value or raises `CryptPouchAPIError` with a clear
message.

## Prerequisites

1. This file must sit in the SAME directory as `CryptPouch.py`.
2. Install dependencies once:

   ```bash
   pip install -r requirements.txt
   ```

3. NOTE: `pyzbar` (QR decoding) additionally needs the system library `libzbar`:
   - Windows: install the Zbar DLL and add its directory to the system PATH
   - Ubuntu/Debian: `sudo apt-get install libzbar0`
   - macOS: `brew install zbar`

## Quick Start

```python
import cryptpouch_api as cp

# Text encryption/decryption (gcm default / cbc / chacha20)
token = cp.encrypt_text("hello world", "my password", mode="gcm")
cp.decrypt_text(token, "my password")              # -> "hello world" (format auto-detected)
chacha = cp.encrypt_text("hello", "pwd", mode="chacha20")   # ChaCha20-Poly1305

# Key rotation: one step (old v2 / old password -> new format / new password)
new_token = cp.reencrypt_text(token, "my password", "new password", mode="chacha20")
new_file = cp.reencrypt_file("photo.jpg.enc", "old password", "new password")

# File encryption/decryption (streaming, v3 GCM)
out = cp.encrypt_file("photo.jpg", "my password")        # -> photo.jpg.enc
back = cp.decrypt_file("photo.jpg.enc", "my password")   # -> photo.jpg

# Batch encryption/decryption (recursive directory scan + glob filters)
res = cp.batch_encrypt("docs/", "my password", pattern="*.txt,*.md")
res = cp.batch_decrypt("docs/", "my password", pattern="*.txt,*.md")

# Configuration (config.json + CRYPTPOUCH_* environment variables)
cfg = cp.get_config()          # {"iterations": 600000, "rsa_bits": 2048, ...}
cp.set_config(iterations=1_000_000, rsa_bits=3072)  # persist (merge + validate + atomic write)
cp.set_config(iterations=1_000_000, reload=True)    # persist and refresh the process now

# Hashing
cp.hash_text("hello", "sha256")
cp.hash_file("photo.jpg", "sha256")

# Passwords
pw = cp.generate_password(20)
cp.check_password_strength(pw)      # {"level": "strong", "score_notes": [...]}

# Base64
cp.b64_encode("hello")               # "aGVsbG8="
cp.b64_decode("aGVsbG8=")            # "hello"

# RSA (keys may be PEM bytes, PEM strings or file paths)
keys = cp.rsa_generate_keys(key_bits=2048)
token = cp.rsa_encrypt(keys["public_key"], "secret")
cp.rsa_decrypt(keys["private_key"], token)

# Content analysis and encoding detection
cp.analyze_content(token)            # {"type": "aes_gcm", ...}
cp.detect_encoding(b"\xe4\xb8\xad\xe6\x87")   # {"text": "...", "encoding": "utf-8"}

# QR codes
cp.generate_qr("https://example.com", save_path="qr.png")
cp.decode_qr("qr.png")               # ["https://example.com"]
```

## Function Reference

| Function | Description | Returns |
| --- | --- | --- |
| `encrypt_text(text, password, mode="gcm")` | Text encryption (gcm/cbc/chacha20) | Base64 ciphertext string |
| `decrypt_text(ciphertext, password)` | Text decryption (auto-detects GCM/ChaCha20/CBC/legacy formats) | Plaintext string |
| `encrypt_file(path, password, output_path=None)` | File encryption (streaming) | Output path |
| `decrypt_file(path, password, output_path=None)` | File decryption | Output path |
| `reencrypt_text(ciphertext, old_pwd, new_pwd, mode="gcm")` | One-step key rotation / format upgrade (text) | New ciphertext |
| `reencrypt_file(path, old_pwd, new_pwd, output_path=None)` | One-step key rotation / format upgrade (file) | Output path |
| `batch_encrypt(path, password, pattern=None, recursive=True)` | Batch encryption (recursive + glob filter) | `{"encrypted", "failed"}` |
| `batch_decrypt(path, password, pattern=None, recursive=True)` | Batch decryption | `{"decrypted", "failed"}` |
| `get_config()` | Read effective config (config.json + environment) | Config dict |
| `set_config(reload=False, config_path=None, **kwargs)` | Validate, merge and atomically write config.json; `reload=True` refreshes the process immediately | Config dict |
| `hash_bytes(data, alg)` / `hash_text(text, alg)` / `hash_file(path, alg)` | Hashing (default sha256) | Hex digest |
| `generate_password(length=16, include_special=True)` | Random password | String |
| `check_password_strength(password)` | Password strength | `{"level", "score_notes"}` |
| `b64_encode(data)` / `b64_decode(data)` | Base64 encode/decode | String |
| `rsa_generate_keys(key_bits=2048, passphrase=None)` | RSA key pair | `{"private_key", "public_key"}` (PEM) |
| `rsa_encrypt(public_key, text)` / `rsa_decrypt(private_key, b64_text, passphrase=None)` | RSA encrypt/decrypt | String |
| `analyze_content(text)` | Content type detection | `{"type", "encoding", "base64_preview"}` |
| `detect_encoding(data: bytes)` | Encoding auto-detection | `{"text", "encoding"}` |
| `generate_qr(text, save_path=None)` | Generate QR code | Save path or None |
| `decode_qr(image_path)` | Decode QR codes | List of strings |

## Error Handling

- Wrong password / corrupted data / unsupported format raise
  `CryptPouchAPIError` (subclass of `Exception`).
- Invalid arguments (e.g. `mode`, `key_bits`, hash algorithm name) raise
  `ValueError`.
- All functions are pure calls: no interactive prompts, no console output.

## Validation Status

Unit and fuzz tests (68 total, CryptPouch v2.9.0) pass: GCM/CBC/ChaCha20 text
round-trips, wrong-password and non-ciphertext rejection, ciphertext tamper
rejection, streaming file round-trips and v2 compatibility, RSA, hashing,
Base64, content analysis, key rotation, batch operations, config loading with
environment overrides, and memory wiping. API regression tests live in
`tests/`. The two QR functions require `qrcode` / `pyzbar` / `libzbar`; they
work once those dependencies are installed.

## Configuration and Environment Variables (script automation)

CryptPouch reads `~/.cryptpouch/config.json` (built-in defaults apply when it
does not exist) and supports `CRYPTPOUCH_*` environment variables that override
the JSON file. Precedence: CLI argument > environment variable > config.json >
default.

`set_config(**kwargs)` persists updates programmatically: it reads the existing
JSON, merges the new values, schema-validates them (unknown keys and invalid
values raise `ValueError`) and writes back with an atomic replace. Only the
JSON layer is written, so an environment variable still overrides the file at
load time. Changes apply to the next process (derived constants are bound at
import time); pass `reload=True` to refresh the current process immediately.
Pass `config_path=` to target a different file instead of the default one.

| Config key | Environment variable | Default | Description |
| --- | --- | --- | --- |
| `iterations` | `CRYPTPOUCH_ITERATIONS` | 600000 | PBKDF2 iterations (legacy-format text) |
| `rsa_bits` | `CRYPTPOUCH_RSA_BITS` | 2048 | Default RSA key size (2048/3072/4096) |
| `lang` | `CRYPTPOUCH_LANG` | prompt | Default UI language (zh/en) |
| `argon2_time_cost` | `CRYPTPOUCH_ARGON2_TIME` | 3 | Argon2id time cost |
| `argon2_memory_kib` | `CRYPTPOUCH_ARGON2_MEM` | 65536 | Argon2id memory (KiB) |
| `argon2_parallelism` | `CRYPTPOUCH_ARGON2_PARALLEL` | 4 | Argon2id parallelism |
| `qr_max_len` | `CRYPTPOUCH_QR_MAX_LEN` | 5000 | QR content length limit |
| `password_max_len` | `CRYPTPOUCH_PASSWORD_MAX` | 128 | Password length limit |
| `score_strong` / `score_medium` | `CRYPTPOUCH_SCORE_STRONG` / `CRYPTPOUCH_SCORE_MEDIUM` | 5 / 3 | Password strength thresholds |
| `weak_password_file` | `CRYPTPOUCH_WEAK_PASSWORD_FILE` | (empty) | Optional external weak-password dictionary; missing/oversized/unreadable files are skipped with a warning |
| `check_keyboard_patterns` | `CRYPTPOUCH_CHECK_KEYBOARD_PATTERNS` | true | Sliding-window QWERTY adjacency detection (rows, columns, diagonals) |
| `keyboard_pattern_min_len` | `CRYPTPOUCH_KEYBOARD_PATTERN_MIN_LEN` | 4 | Minimum run length for a keyboard-pattern hit |
| `check_year_patterns` | `CRYPTPOUCH_CHECK_YEAR_PATTERNS` | true | Penalize only whole "word + year" passwords (years 1900-2099) |
| `color` | `CRYPTPOUCH_COLOR` | auto | ANSI color output for warnings/errors: `auto` (real terminal), `on`, `off` |
