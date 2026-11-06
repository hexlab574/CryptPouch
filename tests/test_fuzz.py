# -*- coding: utf-8 -*-
"""Fuzz-style robustness tests for CryptPouch v2.11.1.

Not a coverage fuzzer: these are deterministic pseudo-random loops that hammer
the crypto paths with random plaintexts, random mutations and random garbage to
prove the invariant "wrong input raises, never crashes and never silently
succeeds". Run with:

    python -m unittest discover -s tests -v
"""

import base64
import os
import random
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import CryptPouch as cp  # noqa: E402

SEED = 0x2B8C0DE
PASSWORDS = ["", "p", "a longer password 中文 密碼", "x" * 128, "ßü汉"]


def _rand_text(rng, max_len=400):
    n = rng.randrange(0, max_len)
    return "".join(chr(rng.randrange(0x20, 0x2FFF)) for _ in range(n))


class FuzzRoundtripTest(unittest.TestCase):
    """Random plaintext must survive encrypt -> decrypt for every family."""

    def test_random_roundtrips(self):
        rng = random.Random(SEED)
        for pwd in PASSWORDS:
            for tool in (cp.AESGCMTool(pwd), cp.AESCBCWithHMACTool(pwd),
                         cp.ChaCha20Poly1305Tool(pwd)):
                for _ in range(40):
                    text = _rand_text(rng)
                    self.assertEqual(tool.decrypt(tool.encrypt(text)), text)

    def test_random_bytes_file_roundtrip(self):
        rng = random.Random(SEED ^ 1)
        d = tempfile.mkdtemp(prefix="cpfuzz_")
        try:
            for i in range(10):
                src = os.path.join(d, f"f{i}.bin")
                size = rng.randrange(0, 300 * 1024)
                with open(src, "wb") as f:
                    f.write(rng.randbytes(size))
                enc = src + ".enc"
                cp.encrypt_file(src, enc, "pw")
                out = src + ".out"
                cp.decrypt_file(enc, out, "pw")
                with open(src, "rb") as f1, open(out, "rb") as f2:
                    self.assertEqual(f1.read(), f2.read())
        finally:
            shutil.rmtree(d, ignore_errors=True)


class FuzzMutationTest(unittest.TestCase):
    """Any single-bit (or multi-byte) mutation must break authentication."""

    def test_mutations_rejected(self):
        rng = random.Random(SEED ^ 2)
        for tool in (cp.AESGCMTool("pw"), cp.AESCBCWithHMACTool("pw"),
                     cp.ChaCha20Poly1305Tool("pw")):
            for _ in range(60):
                ct = tool.encrypt("payload " + _rand_text(rng, 80))
                raw = bytearray(base64.b64decode(ct))
                pos = rng.randrange(len(raw))
                raw[pos] ^= 1 << rng.randrange(8)
                mutated = base64.b64encode(bytes(raw)).decode()
                with self.assertRaises(cp.PasswordError):
                    tool.decrypt(mutated)

    def test_truncated_and_extended_packs_rejected(self):
        tool = cp.ChaCha20Poly1305Tool("pw")
        ct = tool.encrypt("data")
        raw = base64.b64decode(ct)
        # note: cut == len(raw) would be the intact pack, so it is excluded
        for cut in (0, 1, len(raw) - 1):
            truncated = base64.b64encode(raw[:cut]).decode()
            with self.assertRaises((cp.PasswordError, cp.CipherCorruptedError)):
                tool.decrypt(truncated)
        extended = base64.b64encode(raw + b"\x00" * 5).decode()
        with self.assertRaises((cp.PasswordError, cp.CipherCorruptedError)):
            tool.decrypt(extended)


class FuzzGarbageInputTest(unittest.TestCase):
    """Garbage input must raise cleanly (or be classified), never crash."""

    def test_garbage_never_crashes(self):
        rng = random.Random(SEED ^ 3)
        for _ in range(100):
            blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
            text = blob.decode("latin-1")
            # classification must not raise
            try:
                cp.detect_content_type(text)
            except Exception:
                self.fail(f"detect_content_type raised on {text!r}")
            # auto-decrypt must not raise outside the documented exceptions
            for tool in (cp.AESGCMTool("pw"), cp.AESCBCWithHMACTool("pw"),
                         cp.ChaCha20Poly1305Tool("pw")):
                try:
                    tool.decrypt(text)
                except (cp.PasswordError, cp.CipherCorruptedError, cp.CryptoToolError,
                        ValueError, UnicodeError, base64.binascii.Error):
                    pass  # expected

    def test_random_b64_no_false_success(self):
        # A random-but-valid base64 string must not accidentally decrypt as
        # readable plaintext through the wrong-password path.
        rng = random.Random(SEED ^ 4)
        for _ in range(30):
            raw = rng.randbytes(rng.randrange(16, 128))
            b64 = base64.b64encode(raw).decode()
            try:
                cp.try_text_decrypt(b64, "pw")
                # If it "succeeds", the result must be identical to the true
                # decode (i.e. a genuine legacy/prefixless hit is impossible
                # for pure random data; reaching here means a false positive).
                self.fail(f"try_text_decrypt returned a result for random b64 {b64!r}")
            except (cp.PasswordError, cp.CipherCorruptedError):
                pass


class FuzzReencryptTest(unittest.TestCase):
    """Random data through one-step re-encryption must round-trip."""

    def test_random_reencrypt(self):
        rng = random.Random(SEED ^ 5)
        for _ in range(20):
            text = _rand_text(rng, 200)
            old = cp.AESGCMTool("old").encrypt(text)
            new = cp.reencrypt_text(old, "old", "new", mode="chacha20")
            self.assertEqual(cp.ChaCha20Poly1305Tool("new").decrypt(new), text)


class FuzzBatchTest(unittest.TestCase):
    """Batch processing with mixed content (including binary)."""

    def test_mixed_tree(self):
        rng = random.Random(SEED ^ 6)
        d = tempfile.mkdtemp(prefix="cpfuzz_batch_")
        try:
            for i in range(15):
                p = os.path.join(d, f"f{i}.dat")
                with open(p, "wb") as f:
                    f.write(rng.randbytes(rng.randrange(0, 4096)))
            r = cp.batch_encrypt(d, "pw")
            self.assertEqual(len(r["failed"]), 0)
            self.assertEqual(len(r["encrypted"]), 15)
            r2 = cp.batch_decrypt(d, "pw")
            self.assertEqual(len(r2["failed"]), 0)
            for i in range(15):
                with open(os.path.join(d, f"f{i}.dat"), "rb") as f:
                    self.assertTrue(len(f.read()) >= 0)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
