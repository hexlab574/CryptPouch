# -*- coding: utf-8 -*-
"""Regression tests for the AI-friendly wrapper cryptpouch_api.py (v2.11.4).

Run: python -m unittest discover -s tests -v
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cryptpouch_api as api  # noqa: E402


def _mkdtemp(prefix="cpapi_"):
    return tempfile.mkdtemp(prefix=prefix)


class ApiTextTest(unittest.TestCase):
    def test_gcm_roundtrip(self):
        t = api.encrypt_text("hello 中文", "pw", mode="gcm")
        self.assertEqual(api.decrypt_text(t, "pw"), "hello 中文")

    def test_cbc_roundtrip(self):
        t = api.encrypt_text("cbc data", "pw", mode="cbc")
        self.assertEqual(api.decrypt_text(t, "pw"), "cbc data")

    def test_chacha20_roundtrip(self):
        t = api.encrypt_text("chacha data", "pw", mode="chacha20")
        self.assertEqual(api.decrypt_text(t, "pw"), "chacha data")

    def test_bad_mode_raises_valueerror(self):
        with self.assertRaises(ValueError):
            api.encrypt_text("x", "pw", mode="des")

    def test_wrong_password_raises_api_error(self):
        t = api.encrypt_text("secret", "right")
        with self.assertRaises(api.CryptPouchAPIError):
            api.decrypt_text(t, "wrong")

    def test_garbage_raises_api_error(self):
        with self.assertRaises(api.CryptPouchAPIError):
            api.decrypt_text("aGVsbG8gd29ybGQ=", "pw")  # valid b64, not ciphertext


class ApiFileTest(unittest.TestCase):
    def test_file_roundtrip(self):
        d = _mkdtemp()
        try:
            src = os.path.join(d, "f.bin")
            with open(src, "wb") as f:
                f.write(os.urandom(150 * 1024))
            enc = api.encrypt_file(src, "pw")
            self.assertEqual(enc, src + ".enc")
            back = api.decrypt_file(enc, "pw")
            self.assertEqual(back, src)
            with open(src, "rb") as f1, open(back, "rb") as f2:
                self.assertEqual(f1.read(), f2.read())
        finally:
            shutil.rmtree(d, ignore_errors=True)


class ApiReencryptTest(unittest.TestCase):
    def test_text_reencrypt(self):
        old = api.encrypt_text("data", "oldpw", mode="cbc")
        new = api.reencrypt_text(old, "oldpw", "newpw", mode="chacha20")
        self.assertEqual(api.decrypt_text(new, "newpw"), "data")

    def test_file_reencrypt(self):
        d = _mkdtemp()
        try:
            src = os.path.join(d, "a.bin")
            with open(src, "wb") as f:
                f.write(b"payload")
            enc = api.encrypt_file(src, "oldpw")
            out = api.reencrypt_file(enc, "oldpw", "newpw")
            back = api.decrypt_file(out, "newpw")
            with open(back, "rb") as f:
                self.assertEqual(f.read(), b"payload")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class ApiBatchTest(unittest.TestCase):
    def test_batch_roundtrip(self):
        d = _mkdtemp()
        try:
            for n in ("a.txt", "b.md", "sub/c.txt"):
                p = os.path.join(d, n)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w") as f:
                    f.write("content " + n)
            r = api.batch_encrypt(d, "pw", pattern="*.txt")
            self.assertEqual(len(r["encrypted"]), 2)
            self.assertEqual(r["failed"], [])
            r2 = api.batch_decrypt(d, "pw", pattern="*.txt")
            self.assertEqual(len(r2["decrypted"]), 2)
            with open(os.path.join(d, "a.txt"), "r") as f:
                self.assertEqual(f.read(), "content a.txt")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class ApiMiscTest(unittest.TestCase):
    def test_hash_matches_hashlib(self):
        import hashlib
        self.assertEqual(api.hash_text("hello", "sha256"),
                         hashlib.sha256(b"hello").hexdigest())

    def test_strength_level(self):
        res = api.check_password_strength("K9!x@Tz#qW2mNp7$")
        self.assertIn(res["level"], ("strong", "medium", "weak"))
        self.assertIsInstance(res["score_notes"], list)

    def test_b64(self):
        self.assertEqual(api.b64_encode("hello"), "aGVsbG8=")
        self.assertEqual(api.b64_decode("aGVsbG8="), "hello")

    def test_rsa_roundtrip(self):
        keys = api.rsa_generate_keys(key_bits=2048)
        token = api.rsa_encrypt(keys["public_key"], "rsa msg")
        self.assertEqual(api.rsa_decrypt(keys["private_key"], token), "rsa msg")

    def test_analyze_chacha(self):
        t = api.encrypt_text("x", "pw", mode="chacha20")
        self.assertEqual(api.analyze_content(t)["type"], "chacha20")

    def test_get_config(self):
        cfg = api.get_config()
        self.assertEqual(cfg["iterations"], 600_000)
        self.assertEqual(cfg["rsa_bits"], 2048)

    def test_version(self):
        self.assertEqual(api.__version__, "2.11.4")


class ApiThreadSafetyTest(unittest.TestCase):
    """_quiet_call swaps sys.stdout and the CryptPouch printer process-wide;
    concurrent callers used to restore each other's placeholder objects and
    leave output silenced for good."""

    def test_concurrent_calls_restore_globals(self):
        import io
        import threading
        import CryptPouch as cp

        orig_out = sys.stdout
        orig_printer = cp.printer
        errors = []

        def worker():
            try:
                for i in range(10):
                    api.encrypt_text("payload-%d" % i, "pw")
            except Exception as exc:  # pragma: no cover - reported below
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertIs(sys.stdout, orig_out)
        self.assertIs(cp.printer, orig_printer)


class ApiErrorContractTest(unittest.TestCase):
    """Known failures become CryptPouchAPIError; programming errors surface as-is."""

    def test_file_errors_are_wrapped(self):
        with self.assertRaises(api.CryptPouchAPIError):
            api.encrypt_file(os.path.join(tempfile.gettempdir(), "cp_missing_input.bin"), "pw")

    def test_corrupt_base64_is_wrapped(self):
        with self.assertRaises(api.CryptPouchAPIError):
            api.b64_decode("!!!not-base64!!!")

    def test_programming_errors_are_not_wrapped(self):
        with self.assertRaises(AttributeError):
            api.encrypt_text(123, "pw")
        with self.assertRaises(TypeError):
            api.b64_decode(123)


class ApiIsolationTest(unittest.TestCase):
    def test_get_config_copy_is_independent(self):
        import CryptPouch as cp
        cfg = api.get_config()
        cfg["color"] = "off"
        cfg["weak_password_file"] = "rockyou.txt"
        self.assertNotEqual(cp.CONFIG["color"], "off")
        self.assertNotEqual(cp.CONFIG["weak_password_file"], "rockyou.txt")

    def test_rsa_by_value_leaves_no_temp_file(self):
        import glob
        before = set(glob.glob(os.path.join(tempfile.gettempdir(), "cryptpouch_key_*")))
        keys = api.rsa_generate_keys(key_bits=2048)
        token = api.rsa_encrypt(keys["public_key"], "value mode")
        self.assertEqual(api.rsa_decrypt(keys["private_key"], token), "value mode")
        after = set(glob.glob(os.path.join(tempfile.gettempdir(), "cryptpouch_key_*")))
        self.assertEqual(after, before)


class ApiConfigMessageTest(unittest.TestCase):
    """A deleted-then-restored key: the message must be readable text, never
    the raw i18n key name."""

    def test_unknown_key_message_is_translated(self):
        import CryptPouch as cp
        path = os.path.join(tempfile.gettempdir(), "cp_api_cfg_guard.json")
        try:
            with self.assertRaises(ValueError) as ctx:
                cp.set_config(hacker_key="pwned", config_path=path)
            self.assertNotIn("cfg_unknown_key", str(ctx.exception))
            self.assertIn("hacker_key", str(ctx.exception))
        finally:
            if os.path.exists(path):
                os.remove(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
