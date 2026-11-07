# CryptPouch

AES-256 encryption toolbox for local, single-user use. Version 2.11.4.

Interactive menu and command-line interface, with Chinese and English prompts.

## Features

- Modular codebase (v2.10.0): core engine, utilities, file operations and admin
  helpers are split into small single-purpose modules behind a thin `CryptPouch.py`
  entry point
- Text encryption: AES-256-GCM (Argon2id), AES-256-CBC + HMAC and ChaCha20-Poly1305
- Authenticated ciphertext headers (v2.11.0): the $CP4$ / $CC2$ / $AC3$ formats bind
  prefix, salt and nonce/IV as associated data, so header tampering or a prefix
  swap fails authentication instead of decrypting to garbage; older ciphertext
  still decrypts and upgrades on re-encrypt
- Symlink-safe file operations: symlinked input/output paths are refused by default
  (`reject_symlinks`)
- File size policy re-checked on the open handle, closing the stat-then-open gap
- Optional legacy decryption switch (`allow_legacy_decrypt`) and optional JSONL
  audit log (`audit_log`, metadata only, never passwords or plaintext)
- Configurable artifact directory (`artifact_dir`) for RSA keys and QR images
- Optional pinned dependency file `requirements-lock.txt` for reproducible installs
- One-step key rotation / format upgrade (re-encrypt with a new password)
- Batch recursive encryption/decryption of directories with glob filters
- Streaming file encryption/decryption, memory friendly for large files, with numbered copies to prevent overwrites
- Large-file throughput (v2.11.1): 1 MiB blocks and a throttled progress line
  (redrawn every 0.15 s, not once per block)
- In-place operation refused (v2.11.1): an output path that resolves to the input
  file is rejected, because it truncated the payload and still reported success
- Batch reports succeeded / failed / skipped counts; CLI failures exit non-zero,
  so scripts no longer read a failed run as a success
- Directories accepted in the single-file menu entries and in `-f`, so any file
  type or whole folder tree can be processed without switching menus
- Batch runs never rewrite an existing ciphertext (v2.11.2): it is kept and
  counted as "already had a .enc file", which makes repeat runs idempotent;
  pass `--overwrite` to replace it deliberately
- CLI refuses contradictory input (v2.11.3): `-e` together with `-d`, or `-f`
  with no target, exits 2 instead of quietly doing one thing (or nothing); an
  empty `-p` is rejected instead of falling into a prompt that hangs a script
- API library calls are safe to use from threads (v2.11.4): the output-silencing
  swap is serialized, every entry point reports known failures as
  `CryptPouchAPIError` (programming errors stay visible), `get_config()` hands
  back an independent copy, and RSA keys passed as PEM stay in memory
- Configurable file size cap (`max_file_size`) to protect against accidental processing of huge files (0 = no limit)
- Atomic decryption output: plaintext is written to a temp file and swapped in only after the tag verifies
- RSA asymmetric encryption, 2048/3072/4096-bit keys, optional passphrase-protected private key
- Base64 encode/decode, text and file hashing, random password generation
- Password strength checker with external weak-password dictionary, QWERTY keyboard-pattern and word-plus-year detection (v2.9.0)
- Programmatic config write-back via `set_config()` (merge, validate, atomic write, keeps env priority)
- Zero-dependency ANSI color output (yellow warnings, red errors; `color` config auto/on/off)
- Zero-dependency test runner `run_tests.py` with green pass markers
- Administrator elevation for dependency install, only after explicit user consent (UAC prompt)
- QR code generation and decoding
- Automatic ciphertext type detection, with a compatibility probe matrix for legacy ciphertext
- Automatic encoding detection (UTF-8, GBK, Big5, Shift_JIS)
- CLI mode, including --password-file for safe password handling

## Project structure

The v2.10.0 codebase is modular. `CryptPouch.py` is a thin shell that imports and
re-exports the public symbols; each module has a single responsibility:

| File | Responsibility |
| --- | --- |
| `CryptPouch.py` | Entry point: interactive menu, CLI parser, public symbol re-export |
| `cp_shared.py` | i18n, printer (ANSI), config loading/validation, constants, error classes |
| `cp_crypto.py` | Cipher tools (GCM/CBC/ChaCha20), key derivation, hashing, password strength |
| `cp_utils.py` | Safe input, password-length checks, permission restriction, decrypt retry |
| `cp_files.py` | Streaming file encrypt/decrypt (atomic output), batch and re-encrypt helpers |
| `cp_admin.py` | Dependency install with consent-gated UAC elevation; password-safe restart |

All modules are part of the same package and share state through `cp_shared`; there
are no circular imports (`cp_shared` <- `cp_crypto` <- `cp_utils` <- `cp_files`,
with `cp_admin` on top).

## Feature Overview & Use Cases

### What it does

| Area | Features |
| --- | --- |
| Symmetric encryption | AES-256-GCM (Argon2id, `$CP3$`), AES-256-CBC + HMAC (`$AC2$`), ChaCha20-Poly1305 (`$CC1$`, v2.8.0) for text and streaming files; automatic format detection on decrypt |
| Key rotation | One-step re-encryption to a new password / target format  -  v2 or legacy ciphertext is upgraded to v3 (Argon2id) without manual decrypt-then-encrypt |
| Batch operations | Recursive directory scan with glob filters (`*.txt,*.md`), skips existing `.enc`, in-place `<file>.enc` output |
| Asymmetric crypto | RSA 2048/3072/4096-bit keys, optional passphrase-protected private key, PKCS1_OAEP |
| Utilities | Base64, text/file hashing (md5..blake2b), random password generator, strength checker, QR code generate/decode, content type & encoding detection |
| Configuration | `~/.cryptpouch/config.json` + `CRYPTPOUCH_*` environment variables override defaults (CLI > env > config > defaults); optional `requirements-lock.txt` pins exact dependency versions |
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
[SECURITY.md](./SECURITY.md). Since v2.11.0 new ciphertext uses authenticated
headers ($CP4$ / $CC2$ / $AC3$): the prefix, salt and nonce/IV are covered by
the AEAD or MAC, so header edits and algorithm-downgrade swaps are rejected
instead of decrypted. This tool is intended for learning, research and
personal local use only.

## Requirements

- Python 3.8 or later
- pycryptodome, argon2-cffi (core)
- pyzbar, Pillow, qrcode, pyperclip (optional, for QR and clipboard features)

Install dependencies:

```bash
pip install -r requirements.txt
```

For reproducible installs, an optional pinned set is provided:

```bash
pip install -r requirements-lock.txt
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
| `max_file_size` | `0` | file size cap in bytes for file encrypt/decrypt; `0` = no limit (large files are supported) |
| `allow_legacy_decrypt` | `true` | allow older-prefix and prefixless legacy decryption; set `false` to refuse them entirely |
| `reject_symlinks` | `true` | refuse symlinked input/output paths for file operations |
| `audit_log` | (empty) | optional JSONL audit log path; records event, path, timestamp and outcome only |
| `artifact_dir` | (empty) | directory for RSA keys and QR images; empty = the script directory |

## License

MIT. See [LICENSE](./LICENSE).
