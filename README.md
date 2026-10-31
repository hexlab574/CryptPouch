# CryptPouch

AES-256 encryption toolbox for local, single-user use. Version 2.7.2.

Interactive menu and command-line interface, with Chinese and English prompts.

## Features

- Text encryption: AES-256-GCM (Argon2id, v3 format) and AES-256-CBC + HMAC
- Streaming file encryption/decryption, memory friendly for large files, with numbered copies to prevent overwrites
- RSA asymmetric encryption, 2048/3072/4096-bit keys, optional passphrase-protected private key
- Base64 encode/decode, text and file hashing, random password generation
- Password strength checker with weak-password, keyboard-pattern and word-plus-year detection
- QR code generation and decoding
- Automatic ciphertext type detection, with a compatibility probe matrix for legacy ciphertext
- Automatic encoding detection (UTF-8, GBK, Big5, Shift_JIS)
- CLI mode, including --password-file for safe password handling

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

## License

MIT. See [LICENSE](./LICENSE).
