# -*- coding: utf-8 -*-
"""CryptPouch file operations: streaming file encryption/decryption,
batch directory processing, key re-encryption and automatic ciphertext
detection/decryption."""

import cp_shared
import cp_crypto
import cp_utils
import base64
import fnmatch
import functools
import getpass
import json
import os
import tempfile
import time
from typing import Optional, List, Tuple, Dict, Any, Union

def _fsync_dir(dir_path: str) -> None:
    """Best-effort fsync of a directory so an already completed os.replace is
    persisted across a power loss. POSIX only; Windows cannot fsync a directory
    handle (the NTFS journal covers the rename itself). Failures are ignored on
    purpose: this is a durability hardening step, not a functional requirement."""
    if os.name != "posix":
        return
    try:
        fd = os.open(dir_path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _check_file_size(path: str) -> None:
    """Honor the configured max_file_size cap (0 = no limit). Raises ValueError
    with a user-facing message when the file is too large to process."""
    limit = cp_shared.CONFIG.get("max_file_size", 0)
    if limit:
        try:
            size = os.path.getsize(path)
        except OSError:
            return
        if size > limit:
            raise ValueError(cp_shared.i18n.t("file_too_large", size=limit))


def _check_open_size(size: int) -> None:
    """Re-check the size cap against a size taken from the open handle itself,
    so a replacement between the pre-check and the actual read is caught."""
    limit = cp_shared.CONFIG.get("max_file_size", 0) or 0
    if limit and size > limit:
        raise ValueError(cp_shared.i18n.t("file_too_large", size=limit))


def _reject_symlink(path: str) -> None:
    """Refuse symlinked paths when reject_symlinks is enabled (the default), so a
    link cannot silently redirect a file operation to an unintended target."""
    if not cp_shared.CONFIG.get("reject_symlinks", True):
        return
    try:
        if path and os.path.islink(path):
            raise ValueError(cp_shared.i18n.t("symlink_rejected", path=path))
    except OSError:
        pass


def _audit(action: str, **fields) -> None:
    """Append one JSONL audit record when audit_log is configured (best effort).

    Records only the event, the path, a timestamp and an outcome flag. Passwords,
    plaintext and key material are never written."""
    path = (cp_shared.CONFIG.get("audit_log") or "").strip()
    if not path:
        return
    try:
        absolute = os.path.abspath(os.path.expanduser(path))
        parent = os.path.dirname(absolute)
        if parent:
            os.makedirs(parent, exist_ok=True)
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "event": action}
        record.update(fields)
        with open(absolute, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
        cp_utils._restrict_permissions(absolute)
    except (OSError, ValueError, TypeError):
        pass  # auditing must never break the operation itself


def _audited(action: str):
    """Decorator writing one audit record for a file operation (success or failure)."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
            except Exception as exc:
                _audit(action, path=str(args[0]) if args else "", ok=False,
                       error=type(exc).__name__)
                raise
            _audit(action, path=str(args[0]) if args else "", ok=True)
            return result
        return wrapper
    return decorator


@_audited("encrypt")
def encrypt_file(input_path: str, output_path: str, password: str):
    """v4 streaming encryption: $CP4$ + Argon2id + AES-256-GCM with the header
    (prefix + salt + nonce) bound as associated data; the tag is written at the
    end of the file."""
    cp_utils._validate_password_len(password)
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    _reject_symlink(input_path)
    _reject_symlink(output_path)
    _check_file_size(input_path)

    salt = get_random_bytes(cp_shared.ARGON2_SALT_SIZE)
    nonce = get_random_bytes(cp_shared.NONCE_SIZE)
    header = cp_shared.PREFIX_AES_V4 + salt + nonce
    key = bytearray(cp_crypto.derive_argon2_key(password, salt))
    # The derived key is no longer needed as a standalone value once the cipher
    # object is built (the cipher keeps its own internal copy); zero it in place.
    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
    # Bind the header to the ciphertext: any header edit (salt, nonce, prefix
    # swap) now fails authentication instead of decrypting to garbage.
    cipher.update(header)
    cp_crypto._wipe_memory(key)

    try:
        file_size = os.path.getsize(input_path)
    except OSError:
        file_size = 0
    show_progress = file_size > cp_shared.PROGRESS_THRESHOLD

    try:
        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            # Authoritative size on the open handle: catches a swap between the
            # pre-check and the first read.
            actual_size = os.fstat(f_in.fileno()).st_size
            _check_open_size(actual_size)
            if actual_size != file_size:
                file_size = actual_size
                show_progress = file_size > cp_shared.PROGRESS_THRESHOLD
            f_out.write(header)
            read_size = 0
            while True:
                chunk = f_in.read(cp_shared.CHUNK_SIZE)
                if not chunk:
                    break
                f_out.write(cipher.encrypt(chunk))
                read_size += len(chunk)
                if show_progress:
                    percent = read_size / file_size * 100 if file_size else 100
                    print(f"\rProgress: {percent:.1f}%", end="", flush=True)
            f_out.write(cipher.digest())
            # Flush and fsync so the ciphertext is durable on disk, not just in
            # the OS write-back cache, when the process returns.
            f_out.flush()
            os.fsync(f_out.fileno())
    except Exception:
        # Encryption failed: remove the partial output so no truncated
        # ciphertext is left behind (same hygiene as decryption).
        try:
            if os.path.exists(output_path):
                os.remove(output_path)
        except OSError:
            pass
        raise

    if show_progress:
        print()
    cp_utils._restrict_permissions(output_path)


@_audited("decrypt")
def decrypt_file(input_path: str, output_path: str, password: str):
    cp_utils._validate_password_len(password)
    from Crypto.Cipher import AES

    _reject_symlink(input_path)
    _reject_symlink(output_path)
    _check_file_size(input_path)

    with open(input_path, "rb") as f_in:
        # Authoritative size from the open handle (no stat-then-open race window).
        file_size = os.fstat(f_in.fileno()).st_size
        _check_open_size(file_size)
        header = f_in.read(len(cp_shared.PREFIX_AES_V4))

        if header in (cp_shared.PREFIX_AES_V4, cp_shared.PREFIX_AES_V3):
            authenticated = header == cp_shared.PREFIX_AES_V4
            if not authenticated:
                cp_crypto._require_legacy_allowed()
            # v4/v3 streaming: salt + nonce + ciphertext + tag (at the end).
            # v4 binds the header as AAD; v3 (legacy) leaves it unauthenticated.
            if file_size < len(header) + cp_shared.ARGON2_SALT_SIZE + cp_shared.NONCE_SIZE + cp_shared.TAG_SIZE:
                raise cp_shared.CipherCorruptedError(cp_shared.i18n.t("err_len_invalid"))
            salt = f_in.read(cp_shared.ARGON2_SALT_SIZE)
            nonce = f_in.read(cp_shared.NONCE_SIZE)
            key = bytearray(cp_crypto.derive_argon2_key(password, salt))
            cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
            if authenticated:
                cipher.update(header + salt + nonce)
            cp_crypto._wipe_memory(key)

            data_len = file_size - len(header) - cp_shared.ARGON2_SALT_SIZE - cp_shared.NONCE_SIZE - cp_shared.TAG_SIZE
            show_progress = file_size > cp_shared.PROGRESS_THRESHOLD
            tmp_fd = None
            tmp_path = None
            try:
                # Decrypt to a temp file first, then atomically replace the target:
                # a crash or failure never leaves a half-written output behind.
                tmp_fd, tmp_path = tempfile.mkstemp(
                    prefix=os.path.basename(output_path) + ".", suffix=".cryptpouch.tmp",
                    dir=os.path.dirname(os.path.abspath(output_path)) or ".")
                with os.fdopen(tmp_fd, "wb") as f_out:
                    tmp_fd = None  # ownership moved to f_out
                    remaining = data_len
                    read_size = 0
                    while remaining > 0:
                        chunk = f_in.read(min(cp_shared.CHUNK_SIZE, remaining))
                        if not chunk:
                            break
                        f_out.write(cipher.decrypt(chunk))
                        read_size += len(chunk)
                        remaining -= len(chunk)
                        if show_progress:
                            percent = read_size / data_len * 100 if data_len else 100
                            print(f"\rProgress: {percent:.1f}%", end="", flush=True)
                    tag = f_in.read(cp_shared.TAG_SIZE)
                    try:
                        cipher.verify(tag)
                    except ValueError:
                        raise cp_shared.PasswordError(cp_shared.i18n.t("err_pwd_or_file_tamper"))
                    # Persist the verified plaintext before the atomic swap: the
                    # rename only guarantees "never half-written", so without an
                    # fsync a crash right after os.replace could surface an
                    # empty or short target file.
                    f_out.flush()
                    os.fsync(f_out.fileno())
                os.replace(tmp_path, output_path)
                tmp_path = None
                _fsync_dir(os.path.dirname(os.path.abspath(output_path)) or ".")
            except Exception:
                # Decryption failed: remove the partial temp output (and any replaced
                # target) so no corrupted file is left behind.
                if tmp_fd is not None:
                    try:
                        os.close(tmp_fd)
                    except OSError:
                        pass
                if tmp_path and os.path.exists(tmp_path):
                    os.remove(tmp_path)
                raise
            finally:
                if show_progress:
                    print()
            cp_utils._restrict_permissions(output_path)
            if not authenticated:
                cp_crypto._note_legacy_format()
            return

        elif header == cp_shared.PREFIX_AES_GCM_V2:
            cp_crypto._require_legacy_allowed()
            # v2: salt + nonce + tag + ciphertext
            salt = f_in.read(cp_shared.SALT_SIZE)
            nonce = f_in.read(cp_shared.NONCE_SIZE)
            tag = f_in.read(cp_shared.TAG_SIZE)
            ciphertext = f_in.read()

            key = bytearray(cp_crypto.derive_key(password, salt))
            cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
            cp_crypto._wipe_memory(key)

            try:
                plain_data = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError:
                raise cp_shared.PasswordError(cp_shared.i18n.t("err_pwd_or_file_tamper"))

            with open(output_path, "wb") as f_out:
                f_out.write(plain_data)
                f_out.flush()
                os.fsync(f_out.fileno())
            cp_utils._restrict_permissions(output_path)
            return

        raise cp_shared.FormatNotSupportedError(cp_shared.i18n.t("err_file_format"))


def get_decrypt_output_path(input_path: str) -> str:
    """Decryption output path: strip the .enc suffix to restore the original name; append .dec if it does not end with .enc."""
    if input_path.lower().endswith(".enc"):
        return input_path[:-4]
    return input_path + ".dec"


def next_available_copy_name(target_path: str) -> str:
    """When the target exists, generate the next available copy name: xxx (1).ext, xxx (2).ext ..."""
    root, ext = os.path.splitext(target_path)
    i = 1
    while True:
        candidate = f"{root} ({i}){ext}"
        if not os.path.exists(candidate):
            return candidate
        i += 1


def _encrypt_text_with_mode(plain_text: str, password: str, mode: str = "gcm") -> str:
    if mode == "gcm":
        return cp_crypto.AESGCMTool(password).encrypt(plain_text)
    if mode == "cbc":
        return cp_crypto.AESCBCWithHMACTool(password).encrypt(plain_text)
    if mode == "chacha20":
        return cp_crypto.ChaCha20Poly1305Tool(password).encrypt(plain_text)
    raise ValueError(cp_shared.i18n.t("err_cipher_mode"))


def reencrypt_text(ciphertext: str, old_password: str, new_password: str,
                   mode: str = "gcm") -> str:
    """Re-encrypt text in one step: decrypt with the old password (automatic format
    detection, so v2/legacy ciphertext is upgraded to the target format), then
    encrypt with the new password. No manual decrypt-then-encrypt required."""
    cp_utils._validate_password_len(old_password)
    cp_utils._validate_password_len(new_password)
    plain = try_text_decrypt(ciphertext, old_password)
    return _encrypt_text_with_mode(plain, new_password, mode)


def reencrypt_file(input_path: str, old_password: str, new_password: str,
                   output_path: Optional[str] = None) -> str:
    """Re-encrypt a file in one step (streaming, safe on large files).

    Decrypts to a temporary file, encrypts to the new output, then removes the
    temporary file. Default output: <original-stem>.enc (re-encrypt in place)."""
    if not os.path.isfile(input_path):
        raise ValueError(cp_shared.i18n.t("file_not_exist"))
    cp_utils._validate_password_len(old_password)
    cp_utils._validate_password_len(new_password)
    if output_path is None:
        output_path = get_decrypt_output_path(input_path) + ".enc"

    tmp_fd, tmp_path = tempfile.mkstemp(prefix="cryptpouch_reenc_", suffix=".tmp")
    os.close(tmp_fd)
    try:
        decrypt_file(input_path, tmp_path, old_password)
        encrypt_file(tmp_path, output_path, new_password)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    return output_path


def _collect_targets(input_path: str, patterns: Optional[List[str]],
                     recursive: bool, for_encrypt: bool) -> List[str]:
    """Collect files to process: a single file, or a recursive directory scan
    filtered by fnmatch patterns. When encrypting, files already ending in .enc are
    skipped; when decrypting, only .enc files are considered."""
    norm = cp_crypto.normalize_path(input_path)
    if os.path.isfile(norm):
        return [norm]
    if not os.path.isdir(norm):
        raise ValueError(cp_shared.i18n.t("file_not_exist"))

    matches: List[str] = []
    for root, dirs, files in os.walk(norm):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(root, name)
            is_enc = full.lower().endswith(".enc")
            if for_encrypt and is_enc:
                continue
            if not for_encrypt and not is_enc:
                continue
            if patterns:
                # Match the filter against the plain filename; when decrypting,
                # strip the .enc suffix so "*.txt" matches "a.txt.enc"
                match_name = name[:-4] if not for_encrypt and is_enc else name
                if not any(fnmatch.fnmatch(match_name, pat) for pat in patterns):
                    continue
            matches.append(full)
        if not recursive:
            break
    return matches


def batch_encrypt(path: str, password: str, pattern: Optional[str] = None,
                  recursive: bool = True) -> dict:
    """Encrypt every collected file in place as <file>.enc.

    Returns {"encrypted": [output paths], "failed": [(path, error)]}."""
    cp_utils._validate_password_len(password)
    patterns = [p.strip() for p in pattern.split(",") if p.strip()] if pattern else None
    files = _collect_targets(path, patterns, recursive, for_encrypt=True)
    encrypted, failed = [], []
    for f in files:
        try:
            out = f + ".enc"
            encrypt_file(f, out, password)
            encrypted.append(out)
        except Exception as e:
            failed.append((f, str(e)))
    return {"encrypted": encrypted, "failed": failed}


def batch_decrypt(path: str, password: str, pattern: Optional[str] = None,
                  recursive: bool = True) -> dict:
    """Decrypt every collected .enc file in place (strips the .enc suffix).

    Note: an existing file with the target name is overwritten (batch restore).
    Returns {"decrypted": [output paths], "failed": [(path, error)]}."""
    cp_utils._validate_password_len(password)
    patterns = [p.strip() for p in pattern.split(",") if p.strip()] if pattern else None
    files = _collect_targets(path, patterns, recursive, for_encrypt=False)
    decrypted, failed = [], []
    for f in files:
        try:
            out = get_decrypt_output_path(f)
            decrypt_file(f, out, password)
            decrypted.append(out)
        except Exception as e:
            failed.append((f, str(e)))
    return {"decrypted": decrypted, "failed": failed}


def detect_content_type(text: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Detect the type of the input.

    Returns (type key, encoding name or None, Base64 decode preview or None).
    Types: plain / b64 / aes_gcm / aes_cbc / binary.
    """
    stripped = text.strip()

    try:
        data = base64.b64decode(stripped, validate=True)
    except Exception:
        data = None

    if data is not None and data:
        # After prefix match, validate ciphertext structure length to avoid false positives from Base64 that happens to decode to the prefix
        # v3/GCM: prefix + salt16 + nonce12 + tag16; CBC: prefix + salt16 + iv16 + mac32 + at least 16 bytes of ciphertext
        gcm_min = len(cp_shared.PREFIX_AES_V3) + cp_shared.ARGON2_SALT_SIZE + cp_shared.NONCE_SIZE + cp_shared.TAG_SIZE
        cbc_min = len(cp_shared.PREFIX_AES_CBC_V2) + cp_shared.SALT_SIZE + cp_shared.IV_SIZE + cp_shared.HMAC_SIZE + 16

        if data.startswith((cp_shared.PREFIX_AES_V4, cp_shared.PREFIX_AES_V3)) and len(data) >= gcm_min:
            return "analyze_type_aes_gcm", None, None
        if data.startswith(cp_shared.PREFIX_AES_GCM_V2) and len(data) >= gcm_min:
            return "analyze_type_aes_gcm", None, None
        if data.startswith((cp_shared.PREFIX_AES_CBC_V3, cp_shared.PREFIX_AES_CBC_V2)) and len(data) >= cbc_min:
            return "analyze_type_aes_cbc", None, None
        chacha_min = len(cp_shared.PREFIX_CHACHA20) + cp_shared.ARGON2_SALT_SIZE + cp_shared.NONCE_SIZE + cp_shared.TAG_SIZE
        if data.startswith((cp_shared.PREFIX_CHACHA20_V2, cp_shared.PREFIX_CHACHA20)) and len(data) >= chacha_min:
            return "analyze_type_chacha20", None, None

        dec_text, enc = cp_utils.detect_decode(data)
        score = cp_utils._encoding_score(dec_text, enc)
        if score >= max(1, len(dec_text) * 0.5):
            return "analyze_type_b64", enc, dec_text

        # Unreadable: if the length matches legacy AES structure (salt16+nonce12+tag16=44,
        # CBC additionally needs a 16-byte IV and at least 16 bytes of ciphertext), treat as likely legacy ciphertext
        if len(data) >= 44:
            return "analyze_type_aes_legacy", None, None
        return "analyze_type_binary", None, None

    # Not Base64: check whether it is readable text
    if stripped and all(
        ord(c) >= 0x20 and ord(c) != 0x7F
        for c in stripped
    ):
        return "analyze_type_plain", "unicode", None
    return "analyze_type_binary", None, None


def analyze_and_show(text: str):
    """Print the analysis report; ask whether to attempt decryption for AES ciphertext."""
    ctype, enc, preview = detect_content_type(text)
    cp_shared.printer.info(cp_shared.i18n.t("analyze_title"))
    print(cp_shared.i18n.t(ctype))
    if enc:
        print(cp_shared.i18n.t("analyze_encoding", enc=enc))
    if preview is not None:
        cp_shared.printer.info(cp_shared.i18n.t("auto_b64_detected"))
        print(preview)
    if ctype in ("analyze_type_aes_gcm", "analyze_type_aes_cbc", "analyze_type_aes_legacy", "analyze_type_chacha20"):
        if cp_utils._safe_input(cp_shared.i18n.t("analyze_try_decrypt")).strip().lower() == "y":
            _try_all_aes_decrypt(text)


def auto_decrypt_text(enc_str: str):
    try:
        res = cp_utils.b64_decode(enc_str)
        cp_shared.printer.ok(cp_shared.i18n.t("auto_b64_detected"))
        print(res)

        force = cp_utils._safe_input(cp_shared.i18n.t("auto_force_aes")).strip().lower()
        if force == "y":
            _try_all_aes_decrypt(enc_str)
        return
    except (base64.binascii.Error, UnicodeDecodeError):
        pass

    cp_shared.printer.info(cp_shared.i18n.t("auto_try_aes"))
    _try_all_aes_decrypt(enc_str)


def _peek_pack_prefix(enc_str: str) -> bytes:
    """Best-effort Base64 decode of a ciphertext pack to inspect its format prefix.
    Returns b'' on failure so callers can fall back to legacy probing."""
    try:
        return cp_utils._decode_pack_b64(enc_str)
    except (base64.binascii.Error, ValueError):
        return b""


def _try_text_decrypt_family(enc_str: str, pwd: str) -> Tuple[str, str]:
    """Decrypt text with automatic cipher-family routing; returns (plaintext, family).

    Prefixed ciphertext ($CP4$/$CC2$/$AC3$ current; $CP3$/$AG2$/$AC2$/$CC1$ legacy)
    is routed directly to its own decoder - this avoids expensive legacy probing on
    the wrong family. Prefixless legacy ciphertext falls back to the GCM then CBC
    compatibility matrices."""
    pack = _peek_pack_prefix(enc_str)
    if pack.startswith((cp_shared.PREFIX_CHACHA20_V2, cp_shared.PREFIX_CHACHA20)):
        return cp_crypto.ChaCha20Poly1305Tool(pwd).decrypt(enc_str), "chacha20"
    if pack.startswith((cp_shared.PREFIX_AES_CBC_V3, cp_shared.PREFIX_AES_CBC_V2)):
        return cp_crypto.AESCBCWithHMACTool(pwd).decrypt(enc_str), "cbc"
    if pack.startswith((cp_shared.PREFIX_AES_V4, cp_shared.PREFIX_AES_V3,
                        cp_shared.PREFIX_AES_GCM_V2)):
        return cp_crypto.AESGCMTool(pwd).decrypt(enc_str), "gcm"

    # Prefixless: GCM compatibility probes first, then CBC compatibility probes
    try:
        return cp_crypto.AESGCMTool(pwd).decrypt(enc_str), "gcm"
    except (cp_shared.PasswordError, cp_shared.CipherCorruptedError):
        pass
    return cp_crypto.AESCBCWithHMACTool(pwd).decrypt(enc_str), "cbc"


def try_text_decrypt(enc_str: str, pwd: str) -> str:
    """Decrypt text with automatic cipher-family routing (returns the plaintext)."""
    plain, _ = _try_text_decrypt_family(enc_str, pwd)
    return plain


def _try_all_aes_decrypt(enc_str: str):
    for i in range(cp_shared.MAX_PASSWORD_ATTEMPTS):
        pwd = getpass.getpass(cp_shared.i18n.t("decrypt_pwd"))
        try:
            plain, family = _try_text_decrypt_family(enc_str, pwd)
        except (cp_shared.PasswordError, cp_shared.CipherCorruptedError) as e:
            cp_shared.printer.fail(str(e))
            if i < cp_shared.MAX_PASSWORD_ATTEMPTS - 1:
                cp_shared.printer.warn(cp_shared.i18n.t("attempts_left", left=cp_shared.MAX_PASSWORD_ATTEMPTS - i - 1))
            continue
        except (cp_shared.CryptoToolError, ValueError, OSError, UnicodeError) as e:
            cp_shared.printer.fail(str(e))
            return
        except Exception as e:
            cp_utils._handle_unexpected_error(e)
            return
        ok_key = {"gcm": "auto_gcm_ok", "cbc": "auto_cbc_ok", "chacha20": "auto_chacha_ok"}[family]
        cp_shared.printer.ok(cp_shared.i18n.t(ok_key))
        print(plain)
        return
    cp_shared.printer.fail(cp_shared.i18n.t("attempts_exceeded"))

