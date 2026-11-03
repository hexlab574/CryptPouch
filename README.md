# CryptPouch

AES-256 encryption toolbox for local, single-user use. Version 2.9.0.

Interactive menu and command-line interface, with Chinese and English prompts.

## Features

- Text encryption: AES-256-GCM (Argon2id, v3 format), AES-256-CBC + HMAC and ChaCha20-Poly1305 (v2.8.0)
- One-step key rotation / format upgrade (re-encrypt with a new password)
- Batch recursive encryption/decryption of directories with glob filters
- Streaming file encryption/decryption, memory friendly for large files, with numbered copies to prevent overwrites
- RSA asymmetric encryption, 2048/3072/4096-bit keys, optional passphrase-protected private key
- Base64 encode/decode, text and file hashing, random password generation
- Password strength checker with external weak-password dictionary, QWERTY keyboard-pattern and word-plus-year detection (v2.9.0)
- Programmatic config write-back via `set_config()` (merge, validate, atomic write, keeps env priority)
- Zero-dependency ANSI color output (yellow warnings, red errors; `color` config auto/on/off)
- Zero-dependency test runner `run_tests.py` with green pass markers
- QR code generation and decoding
- Automatic ciphertext type detection, with a compatibility probe matrix for legacy ciphertext
- Automatic encoding detection (UTF-8, GBK, Big5, Shift_JIS)
- CLI mode, including --password-file for safe password handling

## Feature Overview & Use Cases

### What it does

| Area | Features |
| --- | --- |
| Symmetric encryption | AES-256-GCM (Argon2id, `$CP3$`), AES-256-CBC + HMAC (`$AC2$`), ChaCha20-Poly1305 (`$CC1$`, v2.8.0) for text and streaming files; automatic format detection on decrypt |
| Key rotation | One-step re-encryption to a new password / target format  -  v2 or legacy ciphertext is upgraded to v3 (Argon2id) without manual decrypt-then-encrypt |
| Batch operations | Recursive directory scan with glob filters (`*.txt,*.md`), skips existing `.enc`, in-place `<file>.enc` output |
| Asymmetric crypto | RSA 2048/3072/4096-bit keys, optional passphrase-protected private key, PKCS1_OAEP |
| Utilities | Base64, text/file hashing (md5..blake2b), random password generator, strength checker, QR code generate/decode, content type & encoding detection |
| Configuration | `~/.cryptpouch/config.json` + `CRYPTPOUCH_*` environment variables override defaults (CLI > env > config > defaults) |
| Interfaces | Interactive bilingual menu (Chinese/English) and full CLI (`-e/-d/-f/-o/--hash/--lang/--cipher/--password-file`) |

### Typical use cases

- **Personal vault**  -  encrypt notes, API keys or a password list as text; decrypt on demand with the menu.
- **Local file & folder protection**  -  encrypt photos, documents or a whole project directory in one pass (`batch_encrypt`); plaintext stays in place, `.enc` files can be moved anywhere.
- **Password / key change**  -  rotate a shared or expired password with `reencrypt_*`; old v2 ciphertext is upgraded to the v3 Argon2id format automatically.
- **Sending files across devices**  -  encrypt a file, transfer the `.enc` over any channel, decrypt at the destination; authenticated encryption catches any tampering.
- **Low-power devices**  -  ChaCha20-Poly1305 is faster than AES-GCM on devices without AES hardware acceleration (ARM, Raspberry Pi, routers).
- **Script automation / CI**  -  non-interactive CLI with `--password-file`, plus `config.json` / `CRYPTPOUCH_*` environment variables for deterministic runs in backup scripts or pipelines.
- **Key exchange**  -  use RSA to wrap a symmetric key or short message; keep the private key passphrase-protected.
- **Learning & research**  -  compare GCM vs CBC vs ChaCha20, Argon2id vs PBKDF2, or study authenticated-encryption failure modes (tamper is always rejected).

## Security

Threat model, audit history, accepted risks and tradeoffs are documented in
[SECURITY.md](./SECURITY.md). This tool is intended for learning, research and
personal local use only.

## Requirements

- Python 3.8 or later
- pycryptodome, argon2-cffi (core)
- pyzbar, Pillow, qrcode, pyperclip (optional, for QR and clipboard features)

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the interactive menu:

```bash
python CryptPouch.py
```

Command-line examples:

```bash
# Encrypt text
python CryptPouch.py -e "hello world" -p "your password"

# Encrypt text with password from a file (avoids process-list exposure)
python CryptPouch.py -e "hello world" --password-file pass.txt

# Decrypt text
python CryptPouch.py -d "<ciphertext>" -p "your password"

# Encrypt a file
python CryptPouch.py -e path/to/file -f -p "your password"

# Decrypt a file
python CryptPouch.py -d path/to/file.enc -f -o output.txt -p "your password"

# Compute a file hash
python CryptPouch.py --hash sha256 path/to/file

# Choose interface language
python CryptPouch.py --lang en
```

### Configuration

Configuration lives in `~/.cryptpouch/config.json` and can be overridden per run
with `CRYPTPOUCH_*` environment variables (priority: CLI > env > config > defaults).

Persist changes programmatically through the API:

```python
from cryptpouch_api import set_config
set_config(iterations=1_000_000, rsa_bits=3072)  # atomic write, schema-validated
# only the JSON layer is written: environment variables still win at load time
```

Changes take effect for the next process (derived constants are bound at import
time); pass `reload=True` to refresh the current process immediately, e.g.
`set_config(iterations=1_000_000, reload=True)`.

Password-strength options (configurable via config.json or environment variables):

| Key | Default | Meaning |
|---|---|---|
| `weak_password_file` | (empty) | optional external weak-password dictionary path; missing/oversized/unreadable files are skipped with a warning |
| `check_keyboard_patterns` | `true` | sliding-window QWERTY adjacency detection (rows, columns, diagonals) |
| `keyboard_pattern_min_len` | `4` | minimum run length for a keyboard-pattern hit |
| `check_year_patterns` | `true` | penalize only whole "word + year" passwords (years 1900-2099) |
| `color` | `auto` | ANSI color output for warnings/errors: `auto` (real terminal), `on`, `off` |

## License

MIT. See [LICENSE](./LICENSE).
