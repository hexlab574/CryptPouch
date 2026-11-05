# -*- coding: utf-8 -*-
"""CryptPouch cryptographic primitives: key derivation, the three cipher
tools (AES-GCM / AES-CBC+HMAC / ChaCha20-Poly1305), password strength
scoring and memory hygiene helpers."""

import cp_shared
import cp_utils
import base64
import hmac
import os
import secrets
import string
from typing import Optional, List, Tuple, Dict, Any, Union

def _wipe_memory(buf) -> None:
    """Zero a mutable buffer (bytearray) in place.

    Used after derived keys are no longer needed. Python bytes/str objects are
    immutable and cannot be erased; wrapping them in a bytearray at the point of
    use and zeroing it here is the practical memory-hygiene step available."""
    if isinstance(buf, bytearray):
        buf[:] = b"\x00" * len(buf)


def normalize_path(path_str: str) -> str:
    """Normalize a user-provided path: strip drag-drop quotes/spaces and resolve ../ and . sequences.

    Note: this is a local single-user tool; the user supplies the target paths, and the attacker is the
    user, so no directory whitelist is enforced (it would prevent encrypting files in arbitrary locations).
    This function only rejects illegal characters such as NUL and resolves redundant . and .. so later
    file operations receive a clean, normalized path."""
    cleaned = path_str.strip().strip('"').strip("'")
    if "\x00" in cleaned:
        raise ValueError(cp_shared.i18n.t("err_bad_path"))
    return os.path.normpath(cleaned)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len] * padding_len)


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("PKCS7 padding error")
    padding_len = data[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("PKCS7 padding error")
    # Verify every padding byte equals the padding length (guards against Padding Oracle style errors)
    if not hmac.compare_digest(data[-padding_len:], bytes([padding_len] * padding_len)):
        raise ValueError("PKCS7 padding error")
    return data[:-padding_len]


def _get_hash_module(name: str):
    """Return the Crypto.Hash module by name; unknown names raise (no silent fallback)."""
    from Crypto.Hash import SHA256, SHA1, MD5
    modules = {"SHA256": SHA256, "SHA1": SHA1, "MD5": MD5}
    if name not in modules:
        raise ValueError(cp_shared.i18n.t("err_hash_alg"))
    return modules[name]


def derive_key(password: str, salt: bytes, iterations: int = cp_shared.DEFAULT_ITERATIONS,
               hash_module=None, dk_len: int = 32) -> bytes:
    """PBKDF2 key derivation. hash_module defaults to SHA256; dk_len selects AES-128/256."""
    from Crypto.Protocol.KDF import PBKDF2
    if hash_module is None:
        hash_module = _get_hash_module("SHA256")
    return PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=dk_len,
        count=iterations,
        hmac_hash_module=hash_module
    )


def derive_argon2_key(password: str, salt: bytes) -> bytes:
    """Argon2id key derivation (memory-hard, resistant to GPU/ASIC parallel cracking)."""
    from argon2.low_level import hash_secret_raw, Type
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=cp_shared.ARGON2_TIME_COST,
        memory_cost=cp_shared.ARGON2_MEMORY_COST_KIB,
        parallelism=cp_shared.ARGON2_PARALLELISM,
        hash_len=cp_shared.ARGON2_HASH_LEN,
        type=Type.ID
    )


def _cbc_derive_key_pair(password: str, salt: bytes, iterations: int = cp_shared.DEFAULT_ITERATIONS):
    """Derive the CBC encryption key pair: the master key is split by HKDF into an
    encryption key and a MAC key (key separation, Encrypt-then-MAC)."""
    from Crypto.Protocol.KDF import HKDF

    master = derive_key(password, salt, iterations)
    h = _get_hash_module("SHA256")
    enc_key = HKDF(master, 32, salt, h, context=b"CryptPouch-enc")
    mac_key = HKDF(master, 32, salt, h, context=b"CryptPouch-mac")
    return enc_key, mac_key


def _note_legacy_params(iterations: int, hash_name: str, dk_len: int):
    """When legacy decryption matches non-default parameters, inform the user of the parameters used."""
    if iterations != cp_shared.DEFAULT_ITERATIONS or hash_name != "SHA256" or dk_len != 32:
        cp_shared.printer.info(cp_shared.i18n.t("legacy_decrypt_hint", iters=iterations, hash=hash_name))


def _is_readable_text(raw: bytes) -> bool:
    """Roughly judge whether bytes are readable text (false-positive filter for CBC unauthenticated probing).
    A minimum length gate is applied: very short plaintext (1-3 bytes) cannot be reliably distinguished
    and is treated as unreadable, preventing binary data from being accepted due to a low threshold."""
    if len(raw) < 4:
        return False
    text, enc = cp_utils.detect_decode(raw)
    return cp_utils._encoding_score(text, enc) >= max(1, len(text) * 0.5)


class AESGCMTool:
    def __init__(self, password: str, iterations: int = cp_shared.DEFAULT_ITERATIONS):
        cp_utils._validate_password_len(password)
        self.password = password
        self.iterations = iterations

    def encrypt(self, plain_text: str) -> str:
        """v3 format: Argon2id derivation + AES-256-GCM, prefixed with $CP3$."""
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes

        salt = get_random_bytes(cp_shared.ARGON2_SALT_SIZE)
        nonce = get_random_bytes(cp_shared.NONCE_SIZE)
        key = bytearray(derive_argon2_key(self.password, salt))
        try:
            cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode("utf-8"))
        finally:
            _wipe_memory(key)

        pack = cp_shared.PREFIX_AES_V3 + salt + nonce + tag + ciphertext
        return base64.b64encode(pack).decode("utf-8")

    def decrypt(self, b64_str: str) -> str:
        from Crypto.Cipher import AES

        try:
            pack = cp_utils._decode_pack_b64(b64_str)
        except base64.binascii.Error:
            raise cp_shared.CipherCorruptedError(cp_shared.i18n.t("err_b64_corrupted"))

        # v3: Argon2id + $CP3$ prefix (formal format)
        if pack.startswith(cp_shared.PREFIX_AES_V3):
            data = pack[len(cp_shared.PREFIX_AES_V3):]
            if len(data) < cp_shared.ARGON2_SALT_SIZE + cp_shared.NONCE_SIZE + cp_shared.TAG_SIZE:
                raise cp_shared.CipherCorruptedError(cp_shared.i18n.t("err_len_invalid"))
            salt = data[:cp_shared.ARGON2_SALT_SIZE]
            nonce = data[cp_shared.ARGON2_SALT_SIZE:cp_shared.ARGON2_SALT_SIZE + cp_shared.NONCE_SIZE]
            tag = data[cp_shared.ARGON2_SALT_SIZE + cp_shared.NONCE_SIZE:cp_shared.ARGON2_SALT_SIZE + cp_shared.NONCE_SIZE + cp_shared.TAG_SIZE]
            ciphertext = data[cp_shared.ARGON2_SALT_SIZE + cp_shared.NONCE_SIZE + cp_shared.TAG_SIZE:]

            key = bytearray(derive_argon2_key(self.password, salt))
            try:
                cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
                try:
                    raw = cipher.decrypt_and_verify(ciphertext, tag)
                except ValueError:
                    raise cp_shared.PasswordError(cp_shared.i18n.t("err_pwd_or_tamper"))
            finally:
                _wipe_memory(key)
            return cp_utils._decode_with_hint(raw)

        # v2: PBKDF2 600k + $AG2$ prefix (fast path)
        is_v2 = pack.startswith(cp_shared.PREFIX_AES_GCM_V2)
        offset = len(cp_shared.PREFIX_AES_GCM_V2) if is_v2 else 0
        data = pack[offset:]

        min_len = cp_shared.SALT_SIZE + cp_shared.NONCE_SIZE + cp_shared.TAG_SIZE
        if len(data) < min_len:
            raise cp_shared.CipherCorruptedError(cp_shared.i18n.t("err_len_invalid"))

        salt = data[:cp_shared.SALT_SIZE]
        nonce = data[cp_shared.SALT_SIZE:cp_shared.SALT_SIZE + cp_shared.NONCE_SIZE]
        tag = data[cp_shared.SALT_SIZE + cp_shared.NONCE_SIZE:cp_shared.SALT_SIZE + cp_shared.NONCE_SIZE + cp_shared.TAG_SIZE]
        ciphertext = data[cp_shared.SALT_SIZE + cp_shared.NONCE_SIZE + cp_shared.TAG_SIZE:]

        if is_v2:
            # With version prefix: use the current iteration count (fast path)
            key = bytearray(derive_key(self.password, salt, self.iterations))
            try:
                cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
                try:
                    raw = cipher.decrypt_and_verify(ciphertext, tag)
                except ValueError:
                    raise cp_shared.PasswordError(cp_shared.i18n.t("err_pwd_or_tamper"))
            finally:
                _wipe_memory(key)
            return cp_utils._decode_with_hint(raw)

        # Prefixless legacy: iterate the compatibility probe matrix (iterations x hash x key length)
        for iterations, hash_name, dk_len in cp_shared.LEGACY_DECRYPT_PROBES:
            key = bytearray(derive_key(self.password, salt, iterations, _get_hash_module(hash_name), dk_len))
            try:
                cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
                try:
                    raw = cipher.decrypt_and_verify(ciphertext, tag)
                except ValueError:
                    continue
            finally:
                _wipe_memory(key)
            _note_legacy_params(iterations, hash_name, dk_len)
            return cp_utils._decode_with_hint(raw)

        raise cp_shared.PasswordError(cp_shared.i18n.t("err_pwd_or_tamper"))


class AESCBCWithHMACTool:
    def __init__(self, password: str, iterations: int = cp_shared.DEFAULT_ITERATIONS):
        cp_utils._validate_password_len(password)
        self.password = password
        self.iterations = iterations

    def encrypt(self, plain_text: str) -> str:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        from Crypto.Hash import HMAC, SHA256

        salt = get_random_bytes(cp_shared.SALT_SIZE)
        iv = get_random_bytes(cp_shared.IV_SIZE)
        enc_key, mac_key = _cbc_derive_key_pair(self.password, salt, self.iterations)
        enc_key = bytearray(enc_key)
        mac_key = bytearray(mac_key)
        try:
            cipher = AES.new(bytes(enc_key), AES.MODE_CBC, iv=iv)
            padded = pkcs7_pad(plain_text.encode("utf-8"))
            ciphertext = cipher.encrypt(padded)

            h = HMAC.new(bytes(mac_key), digestmod=SHA256)
            h.update(iv + ciphertext)
            mac = h.digest()
        finally:
            _wipe_memory(enc_key)
            _wipe_memory(mac_key)

        pack = cp_shared.PREFIX_AES_CBC_V2 + salt + iv + mac + ciphertext
        return base64.b64encode(pack).decode("utf-8")

    def decrypt(self, b64_str: str) -> str:
        from Crypto.Cipher import AES
        from Crypto.Hash import HMAC, SHA256

        try:
            pack = cp_utils._decode_pack_b64(b64_str)
        except base64.binascii.Error:
            raise cp_shared.CipherCorruptedError(cp_shared.i18n.t("err_b64_corrupted"))

        is_v2 = pack.startswith(cp_shared.PREFIX_AES_CBC_V2)
        offset = len(cp_shared.PREFIX_AES_CBC_V2) if is_v2 else 0
        data = pack[offset:]

        if is_v2:
            min_len = cp_shared.SALT_SIZE + cp_shared.IV_SIZE + cp_shared.HMAC_SIZE + 16
            if len(data) < min_len:
                raise cp_shared.CipherCorruptedError(cp_shared.i18n.t("err_len_invalid"))

            salt = data[:cp_shared.SALT_SIZE]
            iv = data[cp_shared.SALT_SIZE:cp_shared.SALT_SIZE + cp_shared.IV_SIZE]
            mac = data[cp_shared.SALT_SIZE + cp_shared.IV_SIZE:cp_shared.SALT_SIZE + cp_shared.IV_SIZE + cp_shared.HMAC_SIZE]
            ciphertext = data[cp_shared.SALT_SIZE + cp_shared.IV_SIZE + cp_shared.HMAC_SIZE:]

            # First verify with the separated-key scheme (new format);
            # fall back to the same-key scheme on failure (legacy $AC2$ compatibility, warns to re-encrypt)
            verified = False
            schemes = (
                _cbc_derive_key_pair(self.password, salt, self.iterations),
                (derive_key(self.password, salt, self.iterations),
                 derive_key(self.password, salt, self.iterations)),
            )
            for idx, (enc_key, mac_key) in enumerate(schemes):
                enc_key = bytearray(enc_key)
                mac_key = bytearray(mac_key)
                try:
                    h = HMAC.new(bytes(mac_key), digestmod=SHA256)
                    h.update(iv + ciphertext)
                    try:
                        h.verify(mac)
                    except ValueError:
                        continue
                    cipher = AES.new(bytes(enc_key), AES.MODE_CBC, iv=iv)
                    try:
                        raw_padded = cipher.decrypt(ciphertext)
                        raw = pkcs7_unpad(raw_padded)
                    except ValueError:
                        raise cp_shared.PasswordError(cp_shared.i18n.t("err_pwd_or_tamper"))
                finally:
                    _wipe_memory(enc_key)
                    _wipe_memory(mac_key)
                verified = True
                if idx == 1:
                    # Legacy same-key scheme matched: remind the user to re-encrypt
                    cp_shared.printer.warn(cp_shared.i18n.t("ac2_legacy_hint"))
                return cp_utils._decode_with_hint(raw)
            if not verified:
                raise cp_shared.PasswordError(cp_shared.i18n.t("err_pwd_or_tamper"))
        else:
            if len(data) < cp_shared.SALT_SIZE + cp_shared.IV_SIZE + 16:
                raise cp_shared.CipherCorruptedError(cp_shared.i18n.t("err_len_invalid"))

            salt = data[:cp_shared.SALT_SIZE]
            iv = data[cp_shared.SALT_SIZE:cp_shared.SALT_SIZE + cp_shared.IV_SIZE]
            ciphertext = data[cp_shared.SALT_SIZE + cp_shared.IV_SIZE:]
            # Prefixless legacy (no HMAC): iterate the compatibility probe matrix
            for iterations, hash_name, dk_len in cp_shared.LEGACY_DECRYPT_PROBES:
                key = bytearray(derive_key(self.password, salt, iterations, _get_hash_module(hash_name), dk_len))
                try:
                    cipher = AES.new(bytes(key), AES.MODE_CBC, iv=iv)
                    try:
                        raw_padded = cipher.decrypt(ciphertext)
                        raw = pkcs7_unpad(raw_padded)
                    except ValueError:
                        continue
                finally:
                    _wipe_memory(key)
                # CBC without authentication: a wrong candidate may produce valid padding by chance,
                # use readability to filter false positives and continue probing on garbage
                if not _is_readable_text(raw):
                    continue
                _note_legacy_params(iterations, hash_name, dk_len)
                return cp_utils._decode_with_hint(raw)
            raise cp_shared.PasswordError(cp_shared.i18n.t("err_pwd_or_tamper"))


class ChaCha20Poly1305Tool:
    """ChaCha20-Poly1305 AEAD (RFC 8439) with Argon2id key derivation ($CC1$ format).

    Modern authenticated encryption; it is notably faster than AES-GCM on devices
    without AES hardware acceleration (ARM, Raspberry Pi, ...)."""

    def __init__(self, password: str, iterations: int = cp_shared.DEFAULT_ITERATIONS):
        cp_utils._validate_password_len(password)
        self.password = password
        self.iterations = iterations

    def encrypt(self, plain_text: str) -> str:
        from Crypto.Cipher import ChaCha20_Poly1305
        from Crypto.Random import get_random_bytes

        salt = get_random_bytes(cp_shared.ARGON2_SALT_SIZE)
        nonce = get_random_bytes(cp_shared.NONCE_SIZE)  # 12-byte nonce (RFC 8439)
        key = bytearray(derive_argon2_key(self.password, salt))
        try:
            cipher = ChaCha20_Poly1305.new(key=bytes(key), nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode("utf-8"))
        finally:
            _wipe_memory(key)

        pack = cp_shared.PREFIX_CHACHA20 + salt + nonce + tag + ciphertext
        return base64.b64encode(pack).decode("utf-8")

    def decrypt(self, b64_str: str) -> str:
        from Crypto.Cipher import ChaCha20_Poly1305

        try:
            pack = cp_utils._decode_pack_b64(b64_str)
        except base64.binascii.Error:
            raise cp_shared.CipherCorruptedError(cp_shared.i18n.t("err_b64_corrupted"))

        if not pack.startswith(cp_shared.PREFIX_CHACHA20):
            # Not our format: report as wrong password / not ciphertext so the
            # caller can route to another cipher family without legacy probing
            raise cp_shared.PasswordError(cp_shared.i18n.t("err_pwd_or_tamper"))

        data = pack[len(cp_shared.PREFIX_CHACHA20):]
        if len(data) < cp_shared.ARGON2_SALT_SIZE + cp_shared.NONCE_SIZE + cp_shared.TAG_SIZE:
            raise cp_shared.CipherCorruptedError(cp_shared.i18n.t("err_len_invalid"))
        salt = data[:cp_shared.ARGON2_SALT_SIZE]
        nonce = data[cp_shared.ARGON2_SALT_SIZE:cp_shared.ARGON2_SALT_SIZE + cp_shared.NONCE_SIZE]
        tag = data[cp_shared.ARGON2_SALT_SIZE + cp_shared.NONCE_SIZE:cp_shared.ARGON2_SALT_SIZE + cp_shared.NONCE_SIZE + cp_shared.TAG_SIZE]
        ciphertext = data[cp_shared.ARGON2_SALT_SIZE + cp_shared.NONCE_SIZE + cp_shared.TAG_SIZE:]

        key = bytearray(derive_argon2_key(self.password, salt))
        try:
            cipher = ChaCha20_Poly1305.new(key=bytes(key), nonce=nonce)
            raw = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise cp_shared.PasswordError(cp_shared.i18n.t("err_pwd_or_tamper"))
        finally:
            _wipe_memory(key)
        return cp_utils._decode_with_hint(raw)


def generate_random_password(length: int = 16, include_special: bool = True) -> str:
    if length < 8:
        raise ValueError("Password length at least 8")

    base_chars = string.ascii_letters + string.digits
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    chars = base_chars + special_chars if include_special else base_chars

    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    if include_special:
        password.append(secrets.choice(special_chars))

    password += [secrets.choice(chars) for _ in range(length - len(password))]
    return ''.join(secrets.SystemRandom().sample(password, len(password)))


def _load_weak_password_dict(path: Optional[str] = None) -> set:
    """Load the external weak-password dictionary once (cached).

    Missing, oversized or unreadable dictionaries degrade gracefully to 'check skipped'
    with a warning - an optional feature must never break the main flow."""
    path = (path or "").strip() or (cp_shared.CONFIG.get("weak_password_file") or "").strip()
    if not path:
        return set()
    if _WEAK_DICT_CACHE["path"] == path and _WEAK_DICT_CACHE["words"] is not None:
        return _WEAK_DICT_CACHE["words"]
    words = set()
    try:
        if "\x00" in path:
            raise ValueError(cp_shared.i18n.t("err_bad_path"))
        dict_path = os.path.normpath(os.path.expanduser(path))
        if not os.path.isfile(dict_path):
            raise OSError(cp_shared.i18n.t("dict_missing", path=dict_path))
        if os.path.getsize(dict_path) > cp_shared.WEAK_PASSWORD_MAX_BYTES:
            raise OSError(cp_shared.i18n.t("dict_too_large", limit=cp_shared.WEAK_PASSWORD_MAX_BYTES))
        with open(dict_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip().lower()
                if w:
                    words.add(w)
                    if len(words) >= 1_000_000:
                        break  # hard safety cap on the in-memory set
    except (OSError, ValueError) as e:
        cp_shared.printer.warn(cp_shared.i18n.t("dict_skip", reason=str(e)[:100]))
        words = set()
    _WEAK_DICT_CACHE["path"] = path
    _WEAK_DICT_CACHE["words"] = words
    return words


def _keyboard_run_len(pwd: str) -> int:
    """Longest run of adjacent QWERTY keys (rows, columns and diagonals), both directions."""
    low = pwd.lower()
    best = run = 1
    for i in range(1, len(low)):
        prev = cp_shared._KEYBOARD_LAYOUT.get(low[i - 1])
        cur = cp_shared._KEYBOARD_LAYOUT.get(low[i])
        if prev is None or cur is None:
            run = 1
            continue
        dr = cur[0] - prev[0]
        dc = cur[1] - prev[1]
        if (dr == 0 and abs(dc) == 1.0) or (abs(dr) == 1 and abs(dc) <= 1.5):
            run += 1
        else:
            run = 1
        if run > best:
            best = run
    return best


def check_password_strength(pwd: str) -> Tuple[str, List[str]]:
    score = 0
    tips = []

    if len(pwd) >= 16:
        score += 3
    elif len(pwd) >= 12:
        score += 2
    elif len(pwd) >= 8:
        score += 1
    else:
        tips.append(cp_shared.i18n.t("tip_len_short"))

    has_lower = any(c.islower() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    has_special = any(not c.isalnum() for c in pwd)
    char_types = sum([has_lower, has_upper, has_digit, has_special])
    score += char_types

    if char_types < 3:
        tips.append(cp_shared.i18n.t("tip_char_types"))

    weak_list = {
        "123456", "password", "12345678", "qwerty", "abc123", "123456789",
        "1234567890", "admin", "letmein", "welcome", "monkey", "dragon",
        "111111", "000000", "123123", "1234567", "qwerty123", "password1",
        "iloveyou", "sunshine", "princess", "football", "baseball", "shadow",
        "master", "passw0rd", "p@ssw0rd", "qwertyuiop", "asdfghjkl",
        "zxcvbnm", "1qaz2wsx", "qazwsx", "1q2w3e4r", "zaq12wsx",
        "woaini", "5201314", "1314520", "abc", "abcd", "1234", "12345",
        "aaaaaa", "aaaaaaa", "a123456", "123456a",
        "asdf", "zxcv", "987654321", "qq123456", "a1b2c3", "pass1234",
        "admin123", "123abc", "abc1234", "123qwe", "qwe123", "a12345",
        "test123", "user123", "login123", "love1314", "woaini1314",
    }
    low = pwd.lower()
    if low in weak_list or low in _load_weak_password_dict():
        score = 0
        tips.append(cp_shared.i18n.t("tip_weak_common"))

    # Keyboard walk sequences: sliding-window adjacency over the QWERTY layout
    # (rows, columns and diagonals; single detector, not a parallel fixed-string list)
    if cp_shared.CONFIG.get("check_keyboard_patterns", True) and _keyboard_run_len(pwd) >= cp_shared.KEYBOARD_PATTERN_MIN_LEN:
        score = 0
        tips.append(cp_shared.i18n.t("tip_keyboard"))

    # Pure digits / single repeated character / consecutive ascending or descending sequences
    seq_ok = False
    if pwd.isdigit():
        seq_ok = True
    elif len(set(pwd)) == 1:
        seq_ok = True
    elif len(pwd) >= 4:
        import re as _re
        if _re.fullmatch(r"(?:0123456789|123456789|23456789|abcdefghijklmnopqrstuvwxyz|abcdefghijk|9876543210)", low):
            seq_ok = True
    if seq_ok and score > 0:
        score = max(1, score - 2)
        tips.append(cp_shared.i18n.t("tip_sequence"))

    # Word+year patterns (e.g. Summer2024): only when the whole password is 'word + year',
    # so a password that merely contains a year (birthdays, anniversaries) is not penalized.
    if cp_shared.CONFIG.get("check_year_patterns", True) and score > 0:
        import re as _re
        if len(pwd) <= 16 and _re.fullmatch(r"[A-Za-z]{2,}(?:19[0-9]{2}|20[0-9]{2})", pwd):
            score = max(1, score - 2)
            tips.append(cp_shared.i18n.t("tip_year"))

    if score >= cp_shared.SCORE_STRONG:
        level = cp_shared.i18n.t("strength_strong")
    elif score >= cp_shared.SCORE_MEDIUM:
        level = cp_shared.i18n.t("strength_medium")
    else:
        level = cp_shared.i18n.t("strength_weak")

    return level, tips

