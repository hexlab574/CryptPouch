# -*- coding: utf-8 -*-
"""CryptPouch generic utilities: encoding detection, Base64, hashing, RSA,
QR codes, safe input, permission hardening, retry and clipboard helpers."""

import cp_shared
import base64
import getpass
import hashlib
import hmac
import os
import time
from typing import Optional, List, Tuple, Dict, Any, Union

def _encoding_score(text: str, enc: str) -> int:
    """Score decoded text for readability: normal characters add points, mojibake signals subtract.

    Key feature: GBK bytes misdecoded as Shift_JIS produce many half-width kana (U+FF61-U+FF9F),
    while genuine Japanese text is dominated by full-width kana (U+3040-U+30FF);
    candidates inconsistent with the target encoding are penalized accordingly.
    """
    score = 0
    full_kana = 0   # full-width hiragana/katakana
    half_kana = 0   # half-width kana
    latin_ext = 0   # Latin extended characters
    cjk = 0         # CJK ideographs
    for ch in text:
        o = ord(ch)
        if ch == "\ufffd":
            score -= 50
        elif o < 0x20 or 0x7F <= o < 0xA0:
            score -= 30
        elif 0xE000 <= o <= 0xF8FF:
            score -= 10
        elif 0x3040 <= o <= 0x30FF:
            full_kana += 1
            score += 1
        elif 0xFF60 <= o <= 0xFF9F:
            half_kana += 1
            score += 1
        elif 0x4E00 <= o <= 0x9FFF:
            cjk += 1
            score += 1
        else:
            score += 1
            if 0x0080 <= o <= 0x024F:
                latin_ext += 1

    total = len(text)
    if total == 0:
        return 0

    # Text in Chinese double-byte encodings should not contain many kana or Latin extended chars
    if enc in ("gbk", "big5"):
        if (full_kana + half_kana + latin_ext) >= total * 0.3:
            score -= total * 10
    # Shift_JIS text should be kana-dominated and not overwhelmingly half-width kana;
    # a high share of full-width kana is a strong Japanese signal (GBK misdecodes only half-width), worth bonus points
    elif enc == "shift_jis":
        if (full_kana + half_kana) < total * 0.4:
            score -= total * 5
        if half_kana > full_kana:
            score -= total * 5
        if full_kana >= total * 0.5:
            score += total * 5
    return score


def detect_decode(data: bytes) -> Tuple[str, str]:
    """Auto-detect the text encoding of byte data and decode it.

    Returns (decoded text, detected encoding name).
    1) Strict UTF-8 first - its multi-byte patterns are well designed and misdetection is rare;
    2) only when UTF-8 fails, pick the highest readability score among GBK / Big5 / Shift_JIS / Latin-1
       (loose double-byte encodings overlap, so this cannot be exact, but it avoids obvious mojibake);
    3) as a last resort, decode with lenient UTF-8 so no exception is raised.
    """
    try:
        return data.decode("utf-8"), "utf-8"
    except (UnicodeDecodeError, LookupError):
        pass

    best_text, best_enc, best_score = None, None, None
    for enc in cp_shared.ENCODING_PRIORITY:
        if enc == "utf-8":
            continue
        try:
            text = data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        s = _encoding_score(text, enc)
        if best_score is None or s > best_score:
            best_text, best_enc, best_score = text, enc, s
    if best_text is not None:
        return best_text, best_enc
    # Latin-1 fallback: map byte by byte, preserving information and never raising
    return data.decode(cp_shared.FALLBACK_ENCODING), cp_shared.FALLBACK_ENCODING


def _decode_with_hint(data: bytes) -> str:
    """Decode bytes to text; if the detected encoding is not UTF-8, print a hint."""
    text, enc = detect_decode(data)
    if enc != "utf-8":
        cp_shared.printer.info(cp_shared.i18n.t("auto_encoding", enc=enc))
    return text


def b64_encode(plain_text: str) -> str:
    return base64.b64encode(plain_text.encode("utf-8")).decode("utf-8")


def b64_decode(enc_str: str) -> str:
    try:
        data = base64.b64decode(enc_str, validate=True)
    except Exception:
        # Compatible with pasted input: strip whitespace and retry strict decoding;
        # non-whitespace junk is rejected (no lenient fallback)
        import re as _re
        cleaned = _re.sub(r"\s+", "", enc_str)
        try:
            data = base64.b64decode(cleaned, validate=True)
        except base64.binascii.Error:
            raise ValueError(cp_shared.i18n.t("err_b64_corrupted"))
    return _decode_with_hint(data)


def _decode_pack_b64(b64_str: str) -> bytes:
    """Decode ciphertext-pack Base64: strict mode first; on failure, remove whitespace (newlines/spaces/tabs)
    and retry strict decoding - tolerates pasted newlines but rejects non-whitespace junk."""
    try:
        return base64.b64decode(b64_str, validate=True)
    except Exception:
        import re as _re
        cleaned = _re.sub(r"\s+", "", b64_str)
        return base64.b64decode(cleaned, validate=True)


def calc_hash(data: bytes, algorithm: str) -> str:
    alg_map = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
        "sha3_256": hashlib.sha3_256,
        "blake2b": hashlib.blake2b,
    }
    if algorithm not in alg_map:
        raise ValueError(cp_shared.i18n.t("err_hash_alg"))
    return alg_map[algorithm](data).hexdigest()


def calc_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    if algorithm not in cp_shared.HASH_ALGORITHMS:
        raise ValueError(cp_shared.i18n.t("err_hash_alg"))
    h = hashlib.new(algorithm)
    file_size = os.path.getsize(file_path)
    read_size = 0

    with open(file_path, "rb") as f:
        next_report = 0.0
        show_progress = file_size > cp_shared.PROGRESS_THRESHOLD
        for chunk in iter(lambda: f.read(cp_shared.CHUNK_SIZE), b''):
            h.update(chunk)
            read_size += len(chunk)
            if show_progress:
                # Same throttle as file encrypt/decrypt: one line per 0.15 s,
                # not one per chunk (a 1 GiB hash used to print 1024 lines).
                now = time.monotonic()
                if now >= next_report:
                    percent = read_size / file_size * 100
                    print(f"\rProgress: {percent:.1f}%", end="", flush=True)
                    next_report = now + cp_shared.PROGRESS_MIN_INTERVAL

    if show_progress:
        print("\rProgress: 100.0%", end="", flush=True)
        print()

    return h.hexdigest()


def rsa_generate_keys(protect_passphrase: Optional[str] = None,
                      key_bits: int = cp_shared.RSA_KEY_BITS):
    from Crypto.PublicKey import RSA

    if protect_passphrase:
        _validate_password_len(protect_passphrase)
    key = RSA.generate(key_bits)
    # Strength self-check: ensure the generated key has the expected size
    if key.size_in_bits() != key_bits:
        raise ValueError(cp_shared.i18n.t("err_rsa_key_strength"))
    if protect_passphrase:
        private = key.export_key(
            passphrase=protect_passphrase,
            pkcs=8,
            protection="scryptAndAES128-CBC"
        )
    else:
        private = key.export_key()
    public = key.publickey().export_key()
    return private, public


def _read_rsa_key_source(key_source, passphrase: Optional[str] = None):
    """Load an RSA key from a file path or from PEM bytes/str held in memory.

    Passing the PEM itself (bytes, or a str containing the "BEGIN" armor) avoids
    writing key material to a temporary file, which otherwise leaves a window
    where the private key sits in the system temp directory."""
    from Crypto.PublicKey import RSA

    is_path = isinstance(key_source, (os.PathLike,)) or (
        isinstance(key_source, str) and "-----BEGIN" not in key_source
    )
    if is_path:
        with open(os.fspath(key_source), "rb") as f:
            data = f.read()
    else:
        data = key_source.encode("utf-8") if isinstance(key_source, str) else bytes(key_source)
    return RSA.import_key(data, passphrase=passphrase)


def rsa_encrypt(public_key_path: str, text: str) -> str:
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256

    key = _read_rsa_key_source(public_key_path)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    data = text.encode("utf-8")
    max_len = key.size_in_bytes() - 2 * SHA256.digest_size - 2
    if len(data) > max_len:
        raise ValueError(cp_shared.i18n.t("err_rsa_text_long"))
    ct = cipher.encrypt(data)
    return base64.b64encode(ct).decode()


def rsa_decrypt(private_key_path: str, b64_text: str, passphrase: Optional[str] = None) -> str:
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256

    if passphrase:
        _validate_password_len(passphrase)
    key = _read_rsa_key_source(private_key_path, passphrase)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    try:
        raw = base64.b64decode(b64_text)
    except base64.binascii.Error:
        raise ValueError(cp_shared.i18n.t("err_b64_corrupted"))
    pt = cipher.decrypt(raw)
    return _decode_with_hint(pt)


def generate_qr(text: str, save_path: Optional[str] = None):
    import qrcode

    # Content length limit: excessive content may fail to encode or cause DoS
    if len(text) > cp_shared.QR_MAX_LEN:
        raise ValueError(cp_shared.i18n.t("qr_too_long"))

    qr = qrcode.QRCode(border=2)
    qr.add_data(text)
    qr.make(fit=True)

    cp_shared.printer.info(cp_shared.i18n.t("qr_preview"))
    qr.print_ascii(invert=True)

    if save_path:
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(save_path)
        cp_shared.printer.ok(cp_shared.i18n.t("qr_saved_to", path=save_path))


def decode_qr(image_path: str) -> List[str]:
    from pyzbar.pyzbar import decode
    from PIL import Image

    with Image.open(image_path) as img:
        results = decode(img)
    return [_decode_with_hint(res.data) for res in results]


def _safe_input(prompt: str = "", max_len: int = 10 * 1024 * 1024) -> str:
    """_safe_input() with a length cap (guards against pasted-buffer DoS)."""
    value = input(prompt)
    if max_len and len(value) > max_len:
        raise ValueError(cp_shared.i18n.t("input_too_long", max=max_len))
    return value


def _validate_password_len(password: str) -> None:
    """Enforce the configured password length cap at every crypto entry point."""
    if len(password) > cp_shared.PASSWORD_MAX_LEN:
        raise ValueError(cp_shared.i18n.t("pwd_too_long", max=cp_shared.PASSWORD_MAX_LEN))


def _restrict_permissions(path: str) -> None:
    """Best-effort POSIX 0600 on sensitive outputs (no-op on Windows)."""
    try:
        if os.name != "nt":
            os.chmod(path, 0o600)
    except OSError:
        pass


def _text_decrypt_with_retry(attempt, max_attempts: int = cp_shared.MAX_PASSWORD_ATTEMPTS) -> None:
    """Run attempt(password) with user-supplied passwords, retrying on password/cipher errors."""
    for i in range(max_attempts):
        pwd = getpass.getpass(cp_shared.i18n.t("decrypt_pwd"))
        try:
            res = attempt(pwd)
        except (cp_shared.PasswordError, cp_shared.CipherCorruptedError) as e:
            cp_shared.printer.fail(str(e))
            if i < max_attempts - 1:
                cp_shared.printer.warn(cp_shared.i18n.t("attempts_left", left=max_attempts - i - 1))
            continue
        except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
            cp_shared.printer.fail(str(e))
            return
        except Exception as e:
            _handle_unexpected_error(e)
            return
        cp_shared.printer.ok(cp_shared.i18n.t("success"))
        print(res)
        return
    cp_shared.printer.fail(cp_shared.i18n.t("attempts_exceeded"))


def _handle_unexpected_error(e: Exception) -> None:
    """Handle unexpected exceptions: show a short message; print the full traceback
    only when CRYPTPOUCH_DEBUG=1 (keeps internal details out of normal output)."""
    if os.environ.get("CRYPTPOUCH_DEBUG") == "1":
        import traceback
        traceback.print_exception(type(e), e, e.__traceback__)
    cp_shared.printer.fail(str(e))


def get_password_with_confirm(prompt_key: str = "encrypt_pwd") -> str:
    """Prompt for a password with confirmation; re-prompt when they differ (prevents typos on the encryption path)."""
    while True:
        pwd = getpass.getpass(cp_shared.i18n.t(prompt_key))
        if len(pwd) > cp_shared.PASSWORD_MAX_LEN:
            cp_shared.printer.fail(cp_shared.i18n.t("pwd_too_long", max=cp_shared.PASSWORD_MAX_LEN))
            continue
        confirm = getpass.getpass(cp_shared.i18n.t("confirm_pwd"))
        # Constant-time comparison: same discipline everywhere passwords are compared
        if hmac.compare_digest(pwd, confirm):
            return pwd
        cp_shared.printer.warn(cp_shared.i18n.t("pwd_mismatch"))


def copy_to_clipboard(text: str):
    try:
        import pyperclip
        pyperclip.copy(text)
        cp_shared.printer.ok(cp_shared.i18n.t("copy_done"))
    except Exception:
        cp_shared.printer.warn(cp_shared.i18n.t("copy_fail"))

