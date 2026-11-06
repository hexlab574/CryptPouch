# -*- coding: utf-8 -*-
"""Unit tests for CryptPouch v2.11.1.

Run from the CryptPouch package directory:
    python -m unittest discover -s tests -v
(no third-party test runner required; needs pycryptodome + argon2-cffi)
"""

import base64
import contextlib
import hashlib
import hmac
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import CryptPouch as cp  # noqa: E402


def _mkdtemp(prefix="cptest_"):
    return tempfile.mkdtemp(prefix=prefix)


class TextCryptoRoundtripTest(unittest.TestCase):
    """Every cipher family must round-trip text losslessly."""

    SAMPLES = [
        "hello world",
        "中文文本，包括标点！？",
        "emoji 🔐🔑🎉 mixed with text",
        "",
        "a" * 5000,
        "line1\nline2\r\nline3\ttab",
        "\u00e9\u00fc\u4e2d\u6587 latin-1 plus cjk",
    ]

    def test_gcm_roundtrip(self):
        tool = cp.AESGCMTool("p@ss-1")
        for s in self.SAMPLES:
            self.assertEqual(tool.decrypt(tool.encrypt(s)), s)

    def test_cbc_roundtrip(self):
        tool = cp.AESCBCWithHMACTool("p@ss-1")
        for s in self.SAMPLES:
            self.assertEqual(tool.decrypt(tool.encrypt(s)), s)

    def test_chacha20_roundtrip(self):
        tool = cp.ChaCha20Poly1305Tool("p@ss-1")
        for s in self.SAMPLES:
            self.assertEqual(tool.decrypt(tool.encrypt(s)), s)

    def test_random_text_roundtrip(self):
        import secrets
        tool = cp.ChaCha20Poly1305Tool("pw")
        for _ in range(30):
            n = secrets.randbelow(300)
            s = "".join(chr(secrets.randbelow(0x2FFF) + 0x20) for _ in range(n))
            self.assertEqual(tool.decrypt(tool.encrypt(s)), s)

    def test_output_is_base64_with_prefix(self):
        ct = cp.ChaCha20Poly1305Tool("pw").encrypt("x")
        raw = base64.b64decode(ct)
        self.assertTrue(raw.startswith(cp.PREFIX_CHACHA20_V2))
        ct3 = cp.AESGCMTool("pw").encrypt("x")
        raw3 = base64.b64decode(ct3)
        self.assertTrue(raw3.startswith(cp.PREFIX_AES_V4))
        ct_cbc = cp.AESCBCWithHMACTool("pw").encrypt("x")
        raw_cbc = base64.b64decode(ct_cbc)
        self.assertTrue(raw_cbc.startswith(cp.PREFIX_AES_CBC_V3))


class ErrorHandlingTest(unittest.TestCase):
    """Wrong passwords and tampered ciphertext must raise, never silently succeed."""

    def test_wrong_password_raises(self):
        ct = cp.AESGCMTool("right").encrypt("secret")
        with self.assertRaises(cp.PasswordError):
            cp.AESGCMTool("wrong").decrypt(ct)
        ct2 = cp.ChaCha20Poly1305Tool("right").encrypt("secret")
        with self.assertRaises(cp.PasswordError):
            cp.ChaCha20Poly1305Tool("wrong").decrypt(ct2)

    def test_tampered_ciphertext_raises(self):
        for tool in (cp.AESGCMTool("pw"), cp.AESCBCWithHMACTool("pw"), cp.ChaCha20Poly1305Tool("pw")):
            ct = tool.encrypt("attack at dawn")
            raw = bytearray(base64.b64decode(ct))
            raw[len(raw) // 2] ^= 0x01  # flip a bit in the middle
            mutated = base64.b64encode(bytes(raw)).decode()
            with self.assertRaises(cp.PasswordError):
                tool.decrypt(mutated)

    def test_not_ciphertext_raises(self):
        for tool in (cp.AESGCMTool("pw"), cp.AESCBCWithHMACTool("pw"), cp.ChaCha20Poly1305Tool("pw")):
            with self.assertRaises((cp.PasswordError, cp.CipherCorruptedError)):
                tool.decrypt("not base64 at all !!!")
            with self.assertRaises((cp.PasswordError, cp.CipherCorruptedError)):
                tool.decrypt("aGVsbG8gd29ybGQ=")  # valid b64, but not a ciphertext pack

    def test_bad_b64_raises_cipher_corrupted(self):
        with self.assertRaises(cp.CipherCorruptedError):
            cp.AESGCMTool("pw").decrypt("###not-b64###")


class AutoRoutingTest(unittest.TestCase):
    """Automatic family routing must pick the right decoder by prefix."""

    def test_route_by_family(self):
        gcm = cp.AESGCMTool("pw").encrypt("gcm text")
        cbc = cp.AESCBCWithHMACTool("pw").encrypt("cbc text")
        chacha = cp.ChaCha20Poly1305Tool("pw").encrypt("chacha text")
        self.assertEqual(cp._try_text_decrypt_family(gcm, "pw")[1], "gcm")
        self.assertEqual(cp._try_text_decrypt_family(cbc, "pw")[1], "cbc")
        self.assertEqual(cp._try_text_decrypt_family(chacha, "pw")[1], "chacha20")
        self.assertEqual(cp.try_text_decrypt(gcm, "pw"), "gcm text")
        self.assertEqual(cp.try_text_decrypt(cbc, "pw"), "cbc text")
        self.assertEqual(cp.try_text_decrypt(chacha, "pw"), "chacha text")

    def test_v2_gcm_prefix_still_decrypts(self):
        # $AG2$ fast path (PBKDF2 + GCM, prefix present)
        tool = cp.AESGCMTool("pw")
        salt = os.urandom(cp.SALT_SIZE)
        nonce = os.urandom(cp.NONCE_SIZE)
        key = cp.derive_key("pw", salt, cp.DEFAULT_ITERATIONS)
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(b"v2 style")
        pack = cp.PREFIX_AES_GCM_V2 + salt + nonce + tag + ct
        b64 = base64.b64encode(pack).decode()
        self.assertEqual(tool.decrypt(b64), "v2 style")


class FileCryptoTest(unittest.TestCase):
    """Streaming file encryption/decryption (v3) and v2 file compatibility."""

    def _roundtrip(self, size):
        d = _mkdtemp()
        try:
            src = os.path.join(d, "input.bin")
            with open(src, "wb") as f:
                f.write(os.urandom(size))
            enc = src + ".enc"
            cp.encrypt_file(src, enc, "pw")
            self.assertTrue(os.path.getsize(enc) > size)
            out = os.path.join(d, "output.bin")
            cp.decrypt_file(enc, out, "pw")
            with open(src, "rb") as f1, open(out, "rb") as f2:
                self.assertEqual(f1.read(), f2.read())
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_small_file(self):
        self._roundtrip(64)

    def test_medium_file(self):
        self._roundtrip(3 * 1024 * 1024)  # spans several 1 MiB blocks

    def test_wrong_password_file(self):
        d = _mkdtemp()
        try:
            src = os.path.join(d, "a.bin")
            with open(src, "wb") as f:
                f.write(b"data")
            enc = src + ".enc"
            cp.encrypt_file(src, enc, "pw")
            out = os.path.join(d, "out.bin")
            with self.assertRaises(cp.PasswordError):
                cp.decrypt_file(enc, out, "wrong")
            self.assertFalse(os.path.exists(out))  # partial output removed
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_v2_ag2_file_decrypts(self):
        # Hand-build a $AG2$ (PBKDF2 + GCM, non-streaming) file and decrypt it
        d = _mkdtemp()
        try:
            src = os.path.join(d, "v2.enc")
            salt = os.urandom(cp.SALT_SIZE)
            nonce = os.urandom(cp.NONCE_SIZE)
            key = cp.derive_key("pw", salt, cp.DEFAULT_ITERATIONS)
            from Crypto.Cipher import AES
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ct, tag = cipher.encrypt_and_digest(b"v2 file body")
            with open(src, "wb") as f:
                f.write(cp.PREFIX_AES_GCM_V2 + salt + nonce + tag + ct)
            out = os.path.join(d, "v2.out")
            cp.decrypt_file(src, out, "pw")
            with open(out, "rb") as f:
                self.assertEqual(f.read(), b"v2 file body")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class RSATest(unittest.TestCase):
    """RSA key generation, encryption and decryption round-trips."""

    def test_rsa_roundtrip(self):
        priv, pub = cp.rsa_generate_keys(key_bits=2048)
        d = _mkdtemp()
        try:
            priv_p, pub_p = os.path.join(d, "priv.pem"), os.path.join(d, "pub.pem")
            with open(priv_p, "wb") as f:
                f.write(priv)
            with open(pub_p, "wb") as f:
                f.write(pub)
            ct = cp.rsa_encrypt(pub_p, "rsa secret 中文")
            self.assertEqual(cp.rsa_decrypt(priv_p, ct), "rsa secret 中文")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_rsa_with_passphrase(self):
        priv, pub = cp.rsa_generate_keys("k1", key_bits=2048)
        d = _mkdtemp()
        try:
            priv_p, pub_p = os.path.join(d, "priv.pem"), os.path.join(d, "pub.pem")
            with open(priv_p, "wb") as f:
                f.write(priv)
            with open(pub_p, "wb") as f:
                f.write(pub)
            ct = cp.rsa_encrypt(pub_p, "protected")
            self.assertEqual(cp.rsa_decrypt(priv_p, ct, "k1"), "protected")
            with self.assertRaises(Exception):
                cp.rsa_decrypt(priv_p, ct, "wrong")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class HashTest(unittest.TestCase):
    def test_text_hashes_match_hashlib(self):
        data = b"hash me " + "中文".encode("utf-8")
        for alg in cp.HASH_ALGORITHMS:
            self.assertEqual(cp.calc_hash(data, alg), hashlib.new(alg, data).hexdigest())

    def test_file_hash(self):
        d = _mkdtemp()
        try:
            p = os.path.join(d, "f.txt")
            with open(p, "wb") as f:
                f.write(b"file content")
            self.assertEqual(cp.calc_file_hash(p, "sha256"),
                             hashlib.sha256(b"file content").hexdigest())
        finally:
            shutil.rmtree(d, ignore_errors=True)


class Base64Test(unittest.TestCase):
    def test_roundtrip(self):
        s = "base64 编码测试"
        self.assertEqual(cp.b64_decode(cp.b64_encode(s)), s)

    def test_lenient_fallback(self):
        # whitespace around the input is tolerated
        self.assertEqual(cp.b64_decode("  " + cp.b64_encode("x") + "\n"), "x")

    def test_pack_decode_strict(self):
        # _decode_pack_b64 rejects junk after cleaning whitespace
        with self.assertRaises(base64.binascii.Error):
            cp._decode_pack_b64("aGVsbG8=!!!")
        self.assertEqual(cp._decode_pack_b64("aGVs\nbG8=\n"), b"hello")


class PasswordToolTest(unittest.TestCase):
    def test_random_password_length_and_charset(self):
        p = cp.generate_random_password(16)
        self.assertEqual(len(p), 16)
        self.assertTrue(any(c.islower() for c in p))
        self.assertTrue(any(c.isupper() for c in p))
        self.assertTrue(any(c.isdigit() for c in p))

    def test_strength_levels(self):
        weak, _ = cp.check_password_strength("123456")
        strong, _ = cp.check_password_strength("K9!x@Tz#qW2mNp7$")
        self.assertNotEqual(weak, strong)

    def test_compare_digest_discipline(self):
        # get_password_with_confirm uses hmac.compare_digest; verify the helper is available
        self.assertTrue(hmac.compare_digest("abc", "abc"))
        self.assertFalse(hmac.compare_digest("abc", "abd"))


class DetectContentTypeTest(unittest.TestCase):
    def test_detect_types(self):
        self.assertEqual(cp.detect_content_type("plain text 中文")[0], "analyze_type_plain")
        self.assertEqual(cp.detect_content_type(cp.b64_encode("x"))[0], "analyze_type_b64")
        self.assertEqual(cp.detect_content_type(cp.AESGCMTool("p").encrypt("x"))[0], "analyze_type_aes_gcm")
        self.assertEqual(cp.detect_content_type(cp.AESCBCWithHMACTool("p").encrypt("x"))[0], "analyze_type_aes_cbc")
        self.assertEqual(cp.detect_content_type(cp.ChaCha20Poly1305Tool("p").encrypt("x"))[0], "analyze_type_chacha20")


class ReencryptTest(unittest.TestCase):
    """One-step key rotation / format upgrade."""

    def test_cbc_to_gcm_upgrade(self):
        old = cp.AESCBCWithHMACTool("oldpw").encrypt("upgrade me")
        new = cp.reencrypt_text(old, "oldpw", "newpw", mode="gcm")
        self.assertEqual(cp.AESGCMTool("newpw").decrypt(new), "upgrade me")
        # the result really is the new format
        self.assertTrue(base64.b64decode(new).startswith(cp.PREFIX_AES_V4))

    def test_gcm_to_chacha(self):
        old = cp.AESGCMTool("oldpw").encrypt("to chacha")
        new = cp.reencrypt_text(old, "oldpw", "newpw", mode="chacha20")
        self.assertEqual(cp.ChaCha20Poly1305Tool("newpw").decrypt(new), "to chacha")

    def test_reencrypt_wrong_old_password(self):
        old = cp.AESGCMTool("oldpw").encrypt("x")
        with self.assertRaises(cp.PasswordError):
            cp.reencrypt_text(old, "wrong", "newpw")

    def test_reencrypt_file(self):
        d = _mkdtemp()
        try:
            src = os.path.join(d, "f.bin")
            with open(src, "wb") as f:
                f.write(os.urandom(100 * 1024))
            enc = src + ".enc"
            cp.encrypt_file(src, enc, "oldpw")
            out = cp.reencrypt_file(enc, "oldpw", "newpw")
            dec = os.path.join(d, "back.bin")
            cp.decrypt_file(out, dec, "newpw")
            with open(src, "rb") as f1, open(dec, "rb") as f2:
                self.assertEqual(f1.read(), f2.read())
        finally:
            shutil.rmtree(d, ignore_errors=True)


class BatchTest(unittest.TestCase):
    """Recursive batch encryption/decryption with glob filters."""

    def _tree(self):
        d = _mkdtemp()
        for n in ("a.txt", "b.txt", "notes.md", "sub/c.txt", "sub/deep/d.log"):
            p = os.path.join(d, n)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                f.write("content of " + n)
        return d

    def test_recursive_encrypt_decrypt(self):
        d = self._tree()
        try:
            r = cp.batch_encrypt(d, "pw")
            self.assertEqual(len(r["failed"]), 0)
            self.assertEqual(len(r["encrypted"]), 5)  # all 5 files
            for p in r["encrypted"]:
                self.assertTrue(p.endswith(".enc"))
            r2 = cp.batch_decrypt(d, "pw")
            self.assertEqual(len(r2["failed"]), 0)
            self.assertEqual(len(r2["decrypted"]), 5)
            for n in ("a.txt", "b.txt", "notes.md", "sub/c.txt", "sub/deep/d.log"):
                with open(os.path.join(d, n), "r", encoding="utf-8") as f:
                    self.assertEqual(f.read(), "content of " + n)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_pattern_filter(self):
        d = self._tree()
        try:
            r = cp.batch_encrypt(d, "pw", pattern="*.txt")
            self.assertEqual(len(r["encrypted"]), 3)  # a.txt, b.txt, sub/c.txt
            r2 = cp.batch_decrypt(d, "pw", pattern="*.txt")
            self.assertEqual(len(r2["decrypted"]), 3)
            # non-txt files were never encrypted
            self.assertFalse(os.path.exists(os.path.join(d, "notes.md.enc")))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_single_file_batch(self):
        d = _mkdtemp()
        try:
            p = os.path.join(d, "solo.txt")
            with open(p, "w") as f:
                f.write("solo")
            r = cp.batch_encrypt(p, "pw")
            self.assertEqual(len(r["encrypted"]), 1)
            r2 = cp.batch_decrypt(p + ".enc", "pw")
            self.assertEqual(len(r2["decrypted"]), 1)
            with open(p, "r") as f:
                self.assertEqual(f.read(), "solo")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class SamePathGuardTest(unittest.TestCase):
    """Regression: opening the output on the input path truncated the payload to
    an empty stream and still wrote a valid-looking 49-byte ciphertext, so a
    1500-byte file became 49 bytes while every caller reported success."""

    def _victim(self, d):
        p = os.path.join(d, "victim.txt")
        with open(p, "wb") as f:
            f.write(b"x" * 1500)
        return p

    def test_encrypt_in_place_is_refused(self):
        d = _mkdtemp()
        try:
            p = self._victim(d)
            with self.assertRaises(ValueError):
                cp.encrypt_file(p, p, "pw")
            self.assertEqual(os.path.getsize(p), 1500)  # payload untouched
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_encrypt_in_place_through_dotted_path_is_refused(self):
        # ../victim.txt resolves to the same file: a plain string compare misses it.
        d = _mkdtemp()
        try:
            p = self._victim(d)
            alias = os.path.join(d, "sub", "..", "victim.txt")
            with self.assertRaises(ValueError):
                cp.encrypt_file(p, alias, "pw")
            self.assertEqual(os.path.getsize(p), 1500)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_decrypt_in_place_is_refused(self):
        d = _mkdtemp()
        try:
            p = self._victim(d)
            enc = p + ".enc"
            cp.encrypt_file(p, enc, "pw")
            before = os.path.getsize(enc)
            with self.assertRaises(ValueError):
                cp.decrypt_file(enc, enc, "pw")
            self.assertEqual(os.path.getsize(enc), before)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class BatchSkipReportingTest(unittest.TestCase):
    """Batch results must say what was skipped, not just what succeeded."""

    def test_collect_skips_dot_enc_when_encrypting(self):
        d = _mkdtemp()
        try:
            for n in ("a.txt", "b.enc", "c.jpg"):
                with open(os.path.join(d, n), "wb") as f:
                    f.write(b"data")
            files, skipped = cp._collect_targets(d, None, True, for_encrypt=True)
            self.assertEqual(sorted(os.path.basename(f) for f in files), ["a.txt", "c.jpg"])
            self.assertEqual(sorted(os.path.basename(f) for f in skipped), ["b.enc"])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_collect_skips_plain_when_decrypting(self):
        d = _mkdtemp()
        try:
            for n in ("a.txt", "a.txt.enc", "b.enc"):
                with open(os.path.join(d, n), "wb") as f:
                    f.write(b"data")
            files, skipped = cp._collect_targets(d, None, True, for_encrypt=False)
            self.assertEqual(sorted(os.path.basename(f) for f in files),
                             ["a.txt.enc", "b.enc"])
            self.assertEqual(sorted(os.path.basename(f) for f in skipped), ["a.txt"])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_pattern_miss_is_counted_as_skipped(self):
        d = _mkdtemp()
        try:
            for n in ("keep.txt", "drop.md"):
                with open(os.path.join(d, n), "wb") as f:
                    f.write(b"data")
            files, skipped = cp._collect_targets(d, ["*.txt"], True, for_encrypt=True)
            self.assertEqual([os.path.basename(f) for f in files], ["keep.txt"])
            self.assertEqual([os.path.basename(f) for f in skipped], ["drop.md"])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_batch_result_has_skipped_key(self):
        d = _mkdtemp()
        try:
            p = os.path.join(d, "x.txt")
            with open(p, "w") as f:
                f.write("x")
            with open(os.path.join(d, "already.enc"), "w") as f:
                f.write("x")
            r = cp.batch_encrypt(d, "pw")
            self.assertIn("skipped", r)
            self.assertEqual(len(r["skipped"]), 1)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class ThroughputDefaultsTest(unittest.TestCase):
    """Large-file defaults: 1 MiB blocks and a throttled progress line."""

    def test_chunk_size_is_at_least_one_mib(self):
        # 64 KiB blocks meant 16 Python-level calls and writes per megabyte.
        self.assertGreaterEqual(cp.CHUNK_SIZE, 1024 * 1024)

    def test_progress_interval_is_positive(self):
        self.assertGreater(cp.PROGRESS_MIN_INTERVAL, 0)


class ConfigTest(unittest.TestCase):
    """config.json + CRYPTPOUCH_* environment variable handling."""

    def test_defaults(self):
        cfg = cp.load_config("/nonexistent/config.json")
        self.assertEqual(cfg["iterations"], 600_000)
        self.assertEqual(cfg["rsa_bits"], 2048)
        self.assertIsNone(cfg["lang"])

    def test_json_file(self):
        d = _mkdtemp()
        try:
            p = os.path.join(d, "config.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"iterations": 123456, "rsa_bits": 4096, "lang": "en"}, f)
            cfg = cp.load_config(p)
            self.assertEqual(cfg["iterations"], 123456)
            self.assertEqual(cfg["rsa_bits"], 4096)
            self.assertEqual(cfg["lang"], "en")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_env_override_beats_json(self):
        d = _mkdtemp()
        try:
            p = os.path.join(d, "config.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"rsa_bits": 2048}, f)
            os.environ["CRYPTPOUCH_RSA_BITS"] = "3072"
            try:
                cfg = cp.load_config(p)
                self.assertEqual(cfg["rsa_bits"], 3072)
            finally:
                os.environ.pop("CRYPTPOUCH_RSA_BITS", None)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_corrupt_config_falls_back(self):
        d = _mkdtemp()
        try:
            p = os.path.join(d, "config.json")
            with open(p, "w", encoding="utf-8") as f:
                f.write("{not json!!")
            cfg = cp.load_config(p)
            self.assertEqual(cfg["iterations"], 600_000)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_sanity_clamp(self):
        d = _mkdtemp()
        try:
            p = os.path.join(d, "config.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"rsa_bits": 1024, "iterations": 10, "argon2_memory_kib": 1}, f)
            cfg = cp.load_config(p)
            self.assertEqual(cfg["rsa_bits"], 2048)      # invalid -> default
            self.assertEqual(cfg["iterations"], 1000)     # clamped to min
            self.assertEqual(cfg["argon2_memory_kib"], 8 * 1024)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class MemoryHygieneTest(unittest.TestCase):
    def test_wipe_memory_zeroes_buffer(self):
        buf = bytearray(b"0123456789")
        cp._wipe_memory(buf)
        self.assertEqual(buf, bytearray(b"\x00" * 10))

    def test_wipe_memory_ignores_bytes(self):
        data = b"0123456789"
        cp._wipe_memory(data)  # must not raise
        self.assertEqual(data, b"0123456789")

    def test_version_is_2111(self):
        self.assertIn("Version: 2.11.1", cp.__doc__)


class AutoDecryptRetryTest(unittest.TestCase):
    """The automatic decryption path must honor MAX_PASSWORD_ATTEMPTS."""

    def _enc_chacha(self, pwd):
        return cp.ChaCha20Poly1305Tool(pwd).encrypt("secret payload")

    def test_auto_decrypt_succeeds_on_first_try(self):
        enc = self._enc_chacha("correct horse battery staple")
        calls = []
        real = cp.getpass.getpass
        try:
            cp.getpass.getpass = lambda prompt: calls.append(prompt) or "correct horse battery staple"
            with contextlib.redirect_stdout(io.StringIO()):
                cp._try_all_aes_decrypt(enc)
        finally:
            cp.getpass.getpass = real
        self.assertEqual(len(calls), 1)

    def test_auto_decrypt_gives_up_after_max_attempts(self):
        enc = self._enc_chacha("correct horse battery staple")
        calls = []
        real = cp.getpass.getpass
        try:
            cp.getpass.getpass = lambda prompt: calls.append(prompt) or "wrong password"
            with contextlib.redirect_stdout(io.StringIO()):
                cp._try_all_aes_decrypt(enc)
        finally:
            cp.getpass.getpass = real
        self.assertEqual(len(calls), cp.MAX_PASSWORD_ATTEMPTS)


class FileSizeLimitTest(unittest.TestCase):
    """max_file_size config: 0 = unlimited (default), >0 blocks oversized file ops."""

    def _mk(self, d, size=1024):
        p = os.path.join(d, "payload.bin")
        with open(p, "wb") as f:
            f.write(b"x" * size)
        return p

    def test_zero_means_unlimited(self):
        d = _mkdtemp()
        try:
            src = self._mk(d)
            enc = os.path.join(d, "p.enc")
            cp.CONFIG["max_file_size"] = 0
            cp.encrypt_file(src, enc, "pw12345")
            self.assertTrue(os.path.isfile(enc))
        finally:
            cp.CONFIG["max_file_size"] = 0
            shutil.rmtree(d, ignore_errors=True)

    def test_encrypt_blocked_when_over_limit(self):
        d = _mkdtemp()
        try:
            src = self._mk(d)
            enc = os.path.join(d, "p.enc")
            cp.CONFIG["max_file_size"] = 512
            with self.assertRaises(ValueError):
                cp.encrypt_file(src, enc, "pw12345")
            self.assertFalse(os.path.exists(enc))
        finally:
            cp.CONFIG["max_file_size"] = 0
            shutil.rmtree(d, ignore_errors=True)

    def test_decrypt_blocked_when_over_limit(self):
        d = _mkdtemp()
        try:
            src = self._mk(d)
            enc = os.path.join(d, "p.enc")
            out = os.path.join(d, "p.out")
            cp.CONFIG["max_file_size"] = 0
            cp.encrypt_file(src, enc, "pw12345")
            cp.CONFIG["max_file_size"] = 128
            with self.assertRaises(ValueError):
                cp.decrypt_file(enc, out, "pw12345")
            self.assertFalse(os.path.exists(out))
        finally:
            cp.CONFIG["max_file_size"] = 0
            shutil.rmtree(d, ignore_errors=True)

    def test_config_validation_rejects_invalid_values(self):
        # rejected during validation, so nothing is written to the config file
        with self.assertRaises(ValueError):
            cp.set_config(max_file_size=-1)
        with self.assertRaises(ValueError):
            cp.set_config(max_file_size="many")


class AtomicDecryptTest(unittest.TestCase):
    """Decryption writes to a temp file and atomically replaces the target."""

    def test_wrong_password_leaves_no_output(self):
        d = _mkdtemp()
        try:
            src = os.path.join(d, "a.bin")
            with open(src, "wb") as f:
                f.write(b"secret data" * 100)
            enc = os.path.join(d, "a.enc")
            out = os.path.join(d, "a.out")
            cp.encrypt_file(src, enc, "right-pw")
            with self.assertRaises(cp.PasswordError):
                cp.decrypt_file(enc, out, "wrong-pw")
            self.assertFalse(os.path.exists(out))
            leftovers = [n for n in os.listdir(d) if ".cryptpouch.tmp" in n]
            self.assertEqual(leftovers, [])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_successful_decrypt_replaces_target(self):
        d = _mkdtemp()
        try:
            src = os.path.join(d, "a.bin")
            with open(src, "wb") as f:
                f.write(b"roundtrip payload" * 50)
            enc = os.path.join(d, "a.enc")
            out = os.path.join(d, "a.out")
            cp.encrypt_file(src, enc, "pw12345")
            cp.decrypt_file(enc, out, "pw12345")
            with open(out, "rb") as f:
                self.assertEqual(f.read(), b"roundtrip payload" * 50)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_encrypt_unreadable_source_leaves_no_output(self):
        d = _mkdtemp()
        try:
            missing = os.path.join(d, "nope.bin")
            enc = os.path.join(d, "nope.enc")
            with self.assertRaises(OSError):
                cp.encrypt_file(missing, enc, "pw12345")
            self.assertFalse(os.path.exists(enc))
        finally:
            shutil.rmtree(d, ignore_errors=True)


class AdminHelpersTest(unittest.TestCase):
    def test_restart_args_strips_password_options(self):
        import cp_admin  # underscore helpers are not re-exported by the shell
        real = sys.argv
        try:
            sys.argv = ["CryptPouch.py", "-e", "-p", "secret123", "-t", "hi"]
            self.assertEqual(cp_admin._restart_args(), ["CryptPouch.py", "-e", "-t", "hi"])
            sys.argv = ["CryptPouch.py", "--password=secret123", "-d"]
            self.assertEqual(cp_admin._restart_args(), ["CryptPouch.py", "-d"])
            sys.argv = ["CryptPouch.py", "-p", "-t", "hi"]  # -p with no value
            self.assertEqual(cp_admin._restart_args(), ["CryptPouch.py", "-t", "hi"])
        finally:
            sys.argv = real

    def test_is_admin_returns_bool(self):
        self.assertIsInstance(cp.is_admin(), bool)


class FsyncDurabilityTest(unittest.TestCase):
    def test_fsync_dir_is_noop_on_windows(self):
        # Directory fsync is POSIX-only; on Windows the helper must silently
        # return instead of failing the decrypt path.
        self.assertIsNone(cp._fsync_dir(tempfile.mkdtemp()))

    def test_fsync_dir_tolerates_missing_path(self):
        # Best-effort hardening: an unreachable directory must not raise.
        self.assertIsNone(cp._fsync_dir(os.path.join(tempfile.gettempdir(), "cp_no_such_dir_xyz")))


class AuthenticatedHeaderTest(unittest.TestCase):
    """Round 6: $CP4$ / $CC2$ / $AC3$ bind the ciphertext header as AAD."""

    def test_cp4_text_roundtrip(self):
        tool = cp.AESGCMTool("pw-cp4")
        self.assertEqual(cp.AESGCMTool("pw-cp4").decrypt(tool.encrypt("round trip")), "round trip")

    def test_cp4_detects_header_tamper(self):
        raw = bytearray(base64.b64decode(cp.AESGCMTool("pw").encrypt("x" * 32)))
        raw[22] ^= 0x01  # nonce byte inside the $CP4$ header
        with self.assertRaises(cp.CryptoToolError):
            cp.AESGCMTool("pw").decrypt(base64.b64encode(bytes(raw)).decode())

    def test_cc2_detects_header_tamper(self):
        raw = bytearray(base64.b64decode(cp.ChaCha20Poly1305Tool("pw").encrypt("x" * 32)))
        raw[26] ^= 0x01  # nonce byte inside the $CC2$ header
        with self.assertRaises(cp.CryptoToolError):
            cp.ChaCha20Poly1305Tool("pw").decrypt(base64.b64encode(bytes(raw)).decode())

    def test_ac3_detects_header_tamper(self):
        raw = bytearray(base64.b64decode(cp.AESCBCWithHMACTool("pw").encrypt("x" * 32)))
        raw[6] ^= 0x01  # salt byte covered by the HMAC
        with self.assertRaises(cp.CryptoToolError):
            cp.AESCBCWithHMACTool("pw").decrypt(base64.b64encode(bytes(raw)).decode())

    def test_cp3_legacy_ciphertext_still_decrypts(self):
        # A genuine $CP3$ payload (no AAD) must remain readable.
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        salt = get_random_bytes(cp.ARGON2_SALT_SIZE)
        nonce = get_random_bytes(cp.NONCE_SIZE)
        cipher = AES.new(cp.derive_argon2_key("pw", salt), AES.MODE_GCM, nonce=nonce)
        body, tag = cipher.encrypt_and_digest(b"legacy payload")
        pack = cp.PREFIX_AES_V3 + salt + nonce + tag + body
        self.assertEqual(cp.AESGCMTool("pw").decrypt(base64.b64encode(pack).decode()), "legacy payload")

    def test_file_encrypt_uses_cp4_and_roundtrips(self):
        d = _mkdtemp()
        try:
            src = os.path.join(d, "big.bin")
            enc = os.path.join(d, "big.bin.enc")
            dec = os.path.join(d, "big.out")
            with open(src, "wb") as f:
                f.write(os.urandom(4096) * 32)
            cp.encrypt_file(src, enc, "pw12345")
            with open(enc, "rb") as f:
                self.assertEqual(f.read(len(cp.PREFIX_AES_V4)), cp.PREFIX_AES_V4)
            cp.decrypt_file(enc, dec, "pw12345")
            with open(src, "rb") as a, open(dec, "rb") as b:
                self.assertEqual(a.read(), b.read())
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_legacy_gate_blocks_old_formats(self):
        old = cp.CONFIG["allow_legacy_decrypt"]
        try:
            cp.CONFIG["allow_legacy_decrypt"] = False
            pack = b"$CP3$" + b"\x00" * 44
            with self.assertRaises(cp.FormatNotSupportedError):
                cp.AESGCMTool("pw").decrypt(base64.b64encode(pack).decode())
        finally:
            cp.CONFIG["allow_legacy_decrypt"] = old

    def test_audit_log_writes_metadata_only(self):
        d = _mkdtemp()
        old = cp.CONFIG["audit_log"]
        try:
            log = os.path.join(d, "audit.jsonl")
            cp.CONFIG["audit_log"] = log
            src = os.path.join(d, "a.bin")
            enc = os.path.join(d, "a.bin.enc")
            with open(src, "wb") as f:
                f.write(b"audit")
            cp.encrypt_file(src, enc, "pw12345")
            with open(log, "r", encoding="utf-8") as f:
                lines = [json.loads(line) for line in f if line.strip()]
            self.assertEqual(len(lines), 1)
            self.assertEqual(lines[0]["event"], "encrypt")
            self.assertTrue(lines[0]["ok"])
            with open(log, "r", encoding="utf-8") as f:
                self.assertNotIn("pw12345", f.read())
        finally:
            cp.CONFIG["audit_log"] = old
            shutil.rmtree(d, ignore_errors=True)

    def test_symlink_input_rejected(self):
        d = _mkdtemp()
        try:
            target = os.path.join(d, "real.bin")
            link = os.path.join(d, "link.bin")
            with open(target, "wb") as f:
                f.write(b"data")
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError, AttributeError):
                self.skipTest("symlink creation not permitted on this platform")
            with self.assertRaises(ValueError):
                cp.encrypt_file(link, os.path.join(d, "link.enc"), "pw12345")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_symlink_checker_honors_config(self):
        """Deterministic coverage of the symlink gate without a real link."""
        from unittest import mock

        old = cp.CONFIG["reject_symlinks"]
        try:
            cp.CONFIG["reject_symlinks"] = True
            with mock.patch("cp_files.os.path.islink", return_value=True):
                with self.assertRaises(ValueError):
                    cp._reject_symlink("fake-link.bin")
            cp.CONFIG["reject_symlinks"] = False
            with mock.patch("cp_files.os.path.islink", return_value=True):
                self.assertIsNone(cp._reject_symlink("fake-link.bin"))
        finally:
            cp.CONFIG["reject_symlinks"] = old


if __name__ == "__main__":
    unittest.main(verbosity=2)
