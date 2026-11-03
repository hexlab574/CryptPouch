# CryptPouch Roadmap

## Released: v2.9.0 (2026-11)

Implemented in this release:

| # | Feature | Details |
| --- | --- | --- |
| 1 | Password strength extensions | Optional external weak-password dictionary (validated path, NUL rejected, normalized, 32 MB size cap, fail-safe skip with warning); whole "word + year" detection (1900-2099, only when the whole password matches, so birthdays are not penalized); sliding-window QWERTY keyboard patterns (rows, columns, diagonals, threshold configurable, merged with the existing fixed check). |
| 2 | set_config() write-back | Merge existing config -> deep merge new values -> schema validation -> atomic write via temp file + os.replace. Only the JSON layer is written, so CLI > env > config > defaults priority is preserved. reload=True refreshes the current process. |
| 3 | Color output | Zero-dependency ANSI colors: warnings yellow, errors red, everything else unchanged. `color` config key (auto/on/off) plus CRYPTPOUCH_COLOR; auto disables colors for redirected output. |
| 4 | Test runner | `run_tests.py`: zero-dependency runner with green pass markers (ok / OK), progress dots colored, and FAIL/ERROR in red, skipped in yellow; locates tests/ relative to the script so it runs from any directory. |
| 5 | Security consistency | Password retry cap (5) extended to the automatic decryption path; ChaCha20 menu decryption uses the same retry helper. |

## Released: v2.8.0 (2026-11)

Implemented in this release:

| # | Feature | Details |
| --- | --- | --- |
| 1 | Config file system | `~/.cryptpouch/config.json` overrides iterations / RSA bits / default language / Argon2 & scoring parameters; `CRYPTPOUCH_*` environment variables override the JSON file (CLI > env > config > defaults), for script automation. |
| 2 | ChaCha20-Poly1305 | Native authenticated encryption via pycryptodome (`Crypto.Cipher.ChaCha20_Poly1305`); new `$CC1$` ciphertext prefix, menu item, bilingual entries, type detection. Fast on devices without AES hardware acceleration (ARM, Raspberry Pi). |
| 3 | Key rotation (Re-encrypt) | One-step password change / format upgrade (v2 or legacy -> v3 target format) with `reencrypt_text` / `reencrypt_file`; no manual decrypt-then-encrypt needed. |
| 4 | Batch file / directory encryption | Recursive directory scan, optional comma-separated glob filters (`*.txt,*.md`), skips existing `.enc` files; in-place `<file>.enc` output. |
| 5 | Memory safety hardening | Passwords and key buffers are zeroed after use (`_wipe_memory`); password confirmation uses `hmac.compare_digest()` instead of `==`. |
| 6 | Test suite | `tests/` with unit tests + deterministic fuzz loops: round-trips, wrong password / tamper rejection, truncation, garbage input, batch + re-encryption fuzzing. 66 tests pass. |

## Planned: medium/long-term directions (not yet implemented)

These directions are recorded as a roadmap only. No implementation has started.

| # | Direction | Description |
| --- | --- | --- |
| 1 | Plugin architecture | Refactor the single file into a modular plugin system so ciphers, analyzers and CLI actions can be added/removed independently. |
| 2 | Post-quantum cryptography | Integrate NIST-standardized Kyber (KEM) and Dilithium (signatures) as an opt-in layer on top of the current symmetric schemes. |
| 3 | Docker image | Provide an official image so the tool can run headless in CI/CD pipelines. |
| 4 | Git integration | git-crypt style transparent encryption for files in a repository (`.gitattributes` driven). |
| 5 | Audit logging | JSON-lines operation log (encrypt/decrypt outcomes) for compliance scenarios; conflicts with the accepted-risk "no audit log" decision in SECURITY.md, so it stays planned until that decision is revisited. |

## Compatibility notes

- All ciphertext produced by v2.7.x and earlier remains decryptable (GCM / CBC /
  legacy prefixless probes are preserved).
- v2.8.0 / v2.9.0 default output format is unchanged: Argon2id + AES-256-GCM
  (`$CP3$`).
- ChaCha20 ciphertext uses the new `$CC1$` prefix; plaintext decryption
  auto-detects the family.
- New v2.9.0 config keys (`weak_password_file`, `check_keyboard_patterns`,
  `keyboard_pattern_min_len`, `check_year_patterns`, `color`) default to
  behavior identical to v2.8.0 when unset.
