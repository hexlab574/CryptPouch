#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cryptpouch_api.py — AI-friendly Python API for CryptPouch v2.11.4
================================================================

A clean, non-interactive wrapper around CryptPouch.py so that AI agents,
scripts and notebooks can call every core feature directly. All console
output of the underlying tool is silenced; every function returns a value
or raises ``CryptPouchAPIError`` with a clear message.

Place this file in the SAME directory as CryptPouch.py, then:

    import cryptpouch_api as cp

    # --- text encryption / decryption --------------------------------
    token = cp.encrypt_text("hello world", "my secret", mode="gcm")   # or mode="cbc" / "chacha20"
    cp.decrypt_text(token, "my secret")                               # -> "hello world"

    # --- key rotation (one step, v2/legacy -> target format) ----------
    new_token = cp.reencrypt_text(token, "old secret", "new secret", mode="chacha20")

    # --- file encryption / decryption (streaming, v3 GCM) ------------
    out = cp.encrypt_file("photo.jpg", "my secret")                   # -> photo.jpg.enc
    back = cp.decrypt_file("photo.jpg.enc", "my secret")              # -> photo.jpg

    # --- batch directory encryption -----------------------------------
    res = cp.batch_encrypt("docs/", "my secret", pattern="*.txt,*.md")
    res = cp.batch_decrypt("docs/", "my secret", pattern="*.txt,*.md")

    # --- hashing -----------------------------------------------------
    cp.hash_text("hello", "sha256")
    cp.hash_bytes(b"hello", "sha256")
    cp.hash_file("photo.jpg", "sha256")

    # --- passwords ---------------------------------------------------
    pw = cp.generate_password(length=20)                              # e.g. "Xq7!vD2@... "
    cp.check_password_strength(pw)                                    # {"level": "strong", "score_notes": [...]}

    # --- base64 ------------------------------------------------------
    cp.b64_encode("hello")                                            # "aGVsbG8="
    cp.b64_decode("aGVsbG8=")                                         # "hello"

    # --- RSA ---------------------------------------------------------
    keys = cp.rsa_generate_keys(key_bits=2048, passphrase=None)
    token = cp.rsa_encrypt(keys["public_key"], "hello")               # accepts PEM bytes or a file path
    cp.rsa_decrypt(keys["private_key"], token)                        # -> "hello"

    # --- analysis & encoding -----------------------------------------
    cp.analyze_content(token)               # {"type": "aes_gcm", "encoding": None, "base64_preview": None}
    cp.detect_encoding(b"\x68\x65\x6c\x6c\x6f")   # {"text": "hello", "encoding": "utf-8"}

    # --- QR ----------------------------------------------------------
    cp.generate_qr("https://example.com", save_path="qr.png")        # -> "qr.png"
    cp.decode_qr("qr.png")                                           # ["https://example.com"]

    # --- configuration (config.json + CRYPTPOUCH_* env) --------------
    cp.get_config()                                                   # {"iterations": 600000, "rsa_bits": 2048, ...}

Dependencies (install once):
    pip install pycryptodome argon2-cffi pyzbar Pillow qrcode pyperclip
    # pyzbar additionally needs the system library libzbar — see the README.
"""

from __future__ import annotations

import contextlib
import copy
import io
import os
import sys
import threading
from typing import Any, Dict, List, Optional, Union

_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

try:
    import CryptPouch as _cp
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "cryptpouch_api.py must sit in the same directory as CryptPouch.py "
        "(v2.11.4). Feature dependencies: pip install pycryptodome argon2-cffi "
        "pyzbar Pillow qrcode pyperclip"
    ) from exc

__version__ = "2.11.4"

__all__ = [
    "CryptPouchAPIError",
    "encrypt_text",
    "decrypt_text",
    "encrypt_file",
    "decrypt_file",
    "reencrypt_text",
    "reencrypt_file",
    "batch_encrypt",
    "batch_decrypt",
    "hash_bytes",
    "hash_text",
    "hash_file",
    "generate_password",
    "check_password_strength",
    "b64_encode",
    "b64_decode",
    "rsa_generate_keys",
    "rsa_encrypt",
    "rsa_decrypt",
    "analyze_content",
    "detect_encoding",
    "generate_qr",
    "decode_qr",
    "get_config",
    "set_config",
    "HASH_ALGORITHMS",
]


class CryptPouchAPIError(Exception):
    """Raised when an API call fails: wrong password, corrupted data, unsupported input, missing dependency..."""


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------

class _NullPrinter:
    """Silences CryptPouch's Printer so library calls produce no console noise."""

    def info(self, *a, **k):
        pass

    def ok(self, *a, **k):
        pass

    def warn(self, *a, **k):
        pass

    def fail(self, *a, **k):
        pass


# Re-entrant: reencrypt_text() enters _quiet_call, and the underlying
# implementation may enter again on the same thread.
_QUIET_LOCK = threading.RLock()


def _quiet_call(func, *args, **kwargs):
    """Run ``func(*args, **kwargs)`` with CryptPouch console output silenced.

    The process-wide ``sys.stdout`` and the module-level ``_cp.printer`` are
    swapped here, so the whole swap has to be serialized: with two concurrent
    callers, the second one saves the first one's placeholder object and then
    restores *that* on exit, leaving stdout or the printer silenced for good.
    A re-entrant lock keeps nested calls working (``reencrypt_text`` enters
    ``_quiet_call`` twice). Concurrent API calls therefore queue; they never
    interleave.
    """
    with _QUIET_LOCK:
        saved_printer = _cp.printer
        saved_stdout = sys.stdout
        sys.stdout = io.StringIO()
        _cp.printer = _NullPrinter()
        try:
            return func(*args, **kwargs)
        finally:
            sys.stdout = saved_stdout
            _cp.printer = saved_printer


# Errors the API knows how to explain. Anything else (TypeError, AttributeError,
# KeyError...) is a programming error and must surface unchanged so it is not
# hidden behind a generic "call failed" message.
_API_ERRORS = (_cp.CryptoToolError, ValueError, UnicodeError, OSError)


def _api_call(label, func, *args, **kwargs):
    """Silence output, wrap a *known* failure in CryptPouchAPIError, and let
    programming errors propagate untouched."""
    try:
        return _quiet_call(func, *args, **kwargs)
    except _API_ERRORS as exc:
        raise CryptPouchAPIError("%s failed: %s" % (label, exc)) from exc


# ----------------------------------------------------------------------
# Text encryption / decryption
# ----------------------------------------------------------------------

def encrypt_text(plaintext: str, password: str, mode: str = "gcm") -> str:
    """Encrypt text.

    Args:
        plaintext: text to encrypt (str).
        password:  passphrase (str).
        mode:      ``"gcm"`` (default; Argon2id + AES-256-GCM, ``$CP3$`` format),
                   ``"cbc"`` (AES-256-CBC + HMAC, ``$AC2$`` format) or
                   ``"chacha20"`` (ChaCha20-Poly1305, ``$CC1$`` format;
                   great on devices without AES hardware acceleration).

    Returns:
        The ciphertext as a single Base64 string, ready for ``decrypt_text``.

    Raises:
        CryptPouchAPIError: if encryption fails.
    """
    if mode == "gcm":
        tool = _cp.AESGCMTool(password)
    elif mode == "cbc":
        tool = _cp.AESCBCWithHMACTool(password)
    elif mode == "chacha20":
        tool = _cp.ChaCha20Poly1305Tool(password)
    else:
        raise ValueError("mode must be one of: gcm, cbc, chacha20")
    return _api_call("Encryption", tool.encrypt, plaintext)


def decrypt_text(ciphertext: str, password: str) -> str:
    """Decrypt text produced by ``encrypt_text`` (auto-detects GCM/ChaCha20/CBC/legacy formats).

    Args:
        ciphertext: the Base64 ciphertext string.
        password:   the passphrase used for encryption.

    Returns:
        The plaintext string.

    Raises:
        CryptPouchAPIError: wrong password, corrupted data, or unsupported format.
    """
    return _api_call("Decryption", _cp.try_text_decrypt, ciphertext, password)


# ----------------------------------------------------------------------
# File encryption / decryption (streaming, v3 GCM)
# ----------------------------------------------------------------------

def encrypt_file(input_path: str, password: str,
                 output_path: Optional[str] = None) -> str:
    """Encrypt a file in streaming mode (v3, AES-256-GCM + Argon2id).

    Args:
        input_path:  path of the file to encrypt.
        password:    passphrase.
        output_path: optional output path; defaults to ``<input_path>.enc``.

    Returns:
        The output file path.
    """
    if output_path is None:
        output_path = input_path + ".enc"
    _api_call("Encryption", _cp.encrypt_file, input_path, output_path, password)
    return output_path


def decrypt_file(input_path: str, password: str,
                 output_path: Optional[str] = None) -> str:
    """Decrypt a file encrypted by ``encrypt_file``.

    Args:
        input_path:  path of the ``.enc`` file.
        password:    passphrase.
        output_path: optional output path; defaults to stripping ``.enc``,
                     or ``<input_path>.dec`` when the suffix is absent.

    Returns:
        The output file path.
    """
    if output_path is None:
        output_path = (input_path[:-4] if input_path.lower().endswith(".enc")
                       else input_path + ".dec")
    _api_call("Decryption", _cp.decrypt_file, input_path, output_path, password)
    return output_path


# ----------------------------------------------------------------------
# Key rotation / re-encryption
# ----------------------------------------------------------------------

def reencrypt_text(ciphertext: str, old_password: str, new_password: str,
                   mode: str = "gcm") -> str:
    """Re-encrypt text in ONE step: decrypt with ``old_password`` (auto-detects
    GCM/ChaCha20/CBC/legacy so v2 ciphertext is upgraded on the fly), then encrypt
    with ``new_password`` in the target ``mode`` ("gcm" | "cbc" | "chacha20").

    Raises:
        CryptPouchAPIError: wrong old password, corrupted data, or unsupported mode.
    """
    if mode not in ("gcm", "cbc", "chacha20"):
        raise ValueError("mode must be one of: gcm, cbc, chacha20")
    return _api_call("Re-encryption", _cp.reencrypt_text, ciphertext,
                     old_password, new_password, mode)


def reencrypt_file(input_path: str, old_password: str, new_password: str,
                   output_path: Optional[str] = None) -> str:
    """Re-encrypt a file in ONE step (streaming, safe on large files).

    Args:
        input_path:   path of the encrypted file (any supported file format).
        old_password: current passphrase.
        new_password: new passphrase.
        output_path:  optional output; defaults to ``<original-stem>.enc``.

    Returns:
        The new encrypted file path.
    """
    if output_path is None:
        output_path = (input_path[:-4] if input_path.lower().endswith(".enc")
                       else input_path) + ".enc"
    _api_call("Re-encryption", _cp.reencrypt_file, input_path, old_password,
              new_password, output_path)
    return output_path


# ----------------------------------------------------------------------
# Batch encryption / decryption
# ----------------------------------------------------------------------

def batch_encrypt(path: str, password: str, pattern: Optional[str] = None,
                  recursive: bool = True, overwrite: bool = False) -> Dict[str, Any]:
    """Recursively encrypt every matching file in ``path`` in place as ``<file>.enc``.

    Args:
        path:    a directory (scanned recursively) or a single file.
        password: passphrase.
        pattern: comma-separated glob filters, e.g. ``"*.txt,*.md"``; None = all files.
        recursive: whether to descend into subdirectories.
        overwrite: replace an existing ``<file>.enc``. The default keeps it, so a
                   repeated run is idempotent and never destroys older ciphertext.

    Returns:
        ``{"encrypted": [output paths], "failed": [(path, error), ...],
        "skipped": [paths filtered out], "existing": [ciphertext kept]}``
    """
    return _cp.batch_encrypt(path, password, pattern, recursive, overwrite)


def batch_decrypt(path: str, password: str, pattern: Optional[str] = None,
                  recursive: bool = True) -> Dict[str, Any]:
    """Recursively decrypt every matching ``.enc`` file in ``path`` (strips the suffix).

    Args:
        path:    a directory (scanned recursively) or a single ``.enc`` file.
        password: passphrase.
        pattern: comma-separated glob filters matched against the original
                 filename (so ``"*.txt"`` matches ``a.txt.enc``); None = all files.
        recursive: whether to descend into subdirectories.

    Returns:
        ``{"decrypted": [output paths], "failed": [(path, error), ...],
        "skipped": [paths filtered out]}``
    """
    return _cp.batch_decrypt(path, password, pattern, recursive)


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

def get_config() -> Dict[str, Any]:
    """Return the effective configuration (built-in defaults, ``~/.cryptpouch/config.json``
    and ``CRYPTPOUCH_*`` environment variables merged).

    Example keys: ``iterations``, ``rsa_bits``, ``lang``, ``argon2_time_cost``,
    ``argon2_memory_kib``, ``argon2_parallelism``, ``qr_max_len``,
    ``password_max_len``, ``score_strong``, ``score_medium``,
    ``weak_password_file``, ``check_keyboard_patterns``, ``keyboard_pattern_min_len``,
    ``check_year_patterns``.
    """
    return copy.deepcopy(_cp.CONFIG)


def set_config(reload: bool = False, config_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """Persist config updates to ``~/.cryptpouch/config.json`` with an atomic write.

    Reads the existing JSON, deep-merges the new values, schema-validates them and
    writes back. Only the JSON layer is written - CLI > env > config.json > defaults
    priority is preserved, so an environment variable still overrides the file at load time.

    Example: ``set_config(iterations=1_000_000, rsa_bits=3072)``

    Changes take effect for the next process (derived constants are bound at import
    time); pass ``reload=True`` to refresh the in-process config and derived
    constants immediately.
    """
    return _cp.set_config(config_path=config_path, reload=reload, **kwargs)


# ----------------------------------------------------------------------
# Hashing
# ----------------------------------------------------------------------

HASH_ALGORITHMS = tuple(getattr(_cp, "HASH_ALGORITHMS", ()))


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Return the hex digest of ``data`` using the given algorithm."""
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm {algorithm!r}; available: {list(HASH_ALGORITHMS)}")
    return _cp.calc_hash(data, algorithm)


def hash_text(text: str, algorithm: str = "sha256") -> str:
    """Return the hex digest of ``text`` (UTF-8 encoded) using the given algorithm."""
    return hash_bytes(text.encode("utf-8"), algorithm)


def hash_file(file_path: str, algorithm: str = "sha256") -> str:
    """Return the hex digest of the file at ``file_path`` (streamed)."""
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm {algorithm!r}; available: {list(HASH_ALGORITHMS)}")
    return _api_call("Hashing", _cp.calc_file_hash, file_path, algorithm)


# ----------------------------------------------------------------------
# Passwords
# ----------------------------------------------------------------------

def generate_password(length: int = 16, include_special: bool = True) -> str:
    """Generate a cryptographically random password (secrets module).

    Guarantees at least one lowercase, one uppercase, one digit and
    (when ``include_special``) one special character.
    """
    return _cp.generate_random_password(length, include_special)


_LEVEL_MAP = {
    "strength_strong": "strong",
    "强": "strong",
    "strength_medium": "medium",
    "中": "medium",
    "strength_weak": "weak",
    "弱": "weak",
}


def check_password_strength(password: str) -> Dict[str, Any]:
    """Evaluate password strength.

    Returns:
        ``{"level": "strong"|"medium"|"weak", "score_notes": [human-readable tips, ...]}``
    """
    level_key, tip_keys = _cp.check_password_strength(password)
    return {
        "level": _LEVEL_MAP.get(level_key, level_key),
        "score_notes": [_cp.i18n.t(k) for k in tip_keys],
    }


# ----------------------------------------------------------------------
# Base64
# ----------------------------------------------------------------------

def b64_encode(data: Union[str, bytes]) -> str:
    """Base64-encode text (or bytes, assumed UTF-8)."""
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return _cp.b64_encode(data)


def b64_decode(data: str) -> str:
    """Base64-decode to text (raises ``CryptPouchAPIError`` on corrupt input).

    Only decoding failures are wrapped: a non-str argument is a programming
    error and surfaces as the original TypeError/AttributeError."""
    try:
        return _cp.b64_decode(data)
    except (ValueError, UnicodeError, OSError) as exc:
        raise CryptPouchAPIError(f"Base64 decode failed: {exc}") from exc


# ----------------------------------------------------------------------
# RSA
# ----------------------------------------------------------------------

def rsa_generate_keys(key_bits: int = 2048,
                      passphrase: Optional[str] = None) -> Dict[str, bytes]:
    """Generate an RSA key pair.

    Args:
        key_bits:  2048, 3072 or 4096.
        passphrase: optional passphrase protecting the private key.

    Returns:
        ``{"private_key": PEM bytes, "public_key": PEM bytes}``
    """
    if key_bits not in (2048, 3072, 4096):
        raise ValueError("key_bits must be 2048, 3072 or 4096")
    private, public = _cp.rsa_generate_keys(
        protect_passphrase=passphrase, key_bits=key_bits)
    return {"private_key": private, "public_key": public}


def rsa_encrypt(public_key: Union[str, bytes, os.PathLike], text: str) -> str:
    """Encrypt text with an RSA public key.

    Args:
        public_key: file path of the PEM public key, or PEM bytes/str directly.
        text:       plaintext (RSA is limited by key size; use for short messages).

    Returns:
        Base64 ciphertext.

    The PEM content handed in as bytes/str is imported in memory, so a key
    passed by value never touches the disk.
    """
    return _api_call("RSA encryption", _cp.rsa_encrypt, public_key, text)


def rsa_decrypt(private_key: Union[str, bytes, os.PathLike], b64_text: str,
                passphrase: Optional[str] = None) -> str:
    """Decrypt text encrypted by ``rsa_encrypt``.

    Args:
        private_key: file path of the PEM private key, or PEM bytes/str directly.
        b64_text:    Base64 ciphertext.
        passphrase:  passphrase of the private key, if any.

    A private key passed as PEM bytes/str is imported in memory and never
    written to a temporary file."""
    return _api_call("RSA decryption", _cp.rsa_decrypt,
                     private_key, b64_text, passphrase)


# ----------------------------------------------------------------------
# Analysis & encoding detection
# ----------------------------------------------------------------------

_TYPE_MAP = {
    "analyze_type_plain": "plain_text",
    "analyze_type_b64": "base64",
    "analyze_type_aes_gcm": "aes_gcm",
    "analyze_type_aes_cbc": "aes_cbc",
    "analyze_type_chacha20": "chacha20",
    "analyze_type_aes_legacy": "aes_legacy",
    "analyze_type_binary": "binary",
}


def analyze_content(text: str) -> Dict[str, Any]:
    """Classify an arbitrary string.

    Returns:
        ``{"type": "plain_text"|"base64"|"aes_gcm"|"aes_cbc"|"chacha20"|"aes_legacy"|"binary",
            "encoding": encoding name or None,
            "base64_preview": decoded Base64 preview or None}``
    """
    ctype, enc, preview = _cp.detect_content_type(text)
    return {
        "type": _TYPE_MAP.get(ctype, ctype),
        "encoding": enc,
        "base64_preview": preview,
    }


def detect_encoding(data: bytes) -> Dict[str, Any]:
    """Auto-detect the encoding of byte data and decode it.

    Returns:
        ``{"text": decoded text, "encoding": detected encoding name}``
    """
    text, enc = _cp.detect_decode(data)
    return {"text": text, "encoding": enc}


# ----------------------------------------------------------------------
# QR codes
# ----------------------------------------------------------------------

def generate_qr(text: str, save_path: Optional[str] = None) -> Optional[str]:
    """Generate a QR code.

    Args:
        text:      content to encode (max length enforced by the tool).
        save_path: optional image path (PNG). When omitted, only validates
                   the content (no image is produced and no output is printed).

    Returns:
        ``save_path`` when given, else ``None``.
    """
    _api_call("QR generation", _cp.generate_qr, text, save_path)
    return save_path


def decode_qr(image_path: str) -> List[str]:
    """Read all QR codes from an image file.

    Returns:
        List of decoded strings (may be empty).
    """
    return _cp.decode_qr(image_path)
