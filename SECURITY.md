# Security Policy

CryptPouch is a local, single-user encryption toolbox. This document describes
the supported versions, security model, vulnerability reporting process, and
the known security considerations of the project.

## Supported Versions

The following version series currently receive security support:

- 2.9.x  -  actively supported (latest: 2.9.0)
- 2.8.x  -  supported
- 2.7.x  -  supported for migration only; users are encouraged to upgrade
- 2.6.x  -  supported for migration only; users are encouraged to upgrade

Earlier versions are no longer supported and may contain known issues that
have been fixed in later releases.

## Security Model

CryptPouch is designed as a local, single-user, interactive tool. It:

- does not provide any network service;
- does not listen on any port;
- does not accept remote input;
- runs entirely on the machine where the user operates it.

Because every path, text, and password input comes from the user on the same
machine, there is no untrusted remote input channel. As a result, network-style
attack surfaces such as timing side channels, TOCTOU races, and path traversal
exploitation are not reachable in this product. The threat model focuses on:

- data confidentiality (ciphertext captured by a third party);
- user error (wrong passwords, accidental file overwrites, missing dependencies).

Cryptographic defaults follow current baseline recommendations:
Argon2id with AES-256-GCM for new ciphertext, and PBKDF2 (600,000 iterations)
with AES-256-GCM as the legacy-compatible path.

## Reporting a Vulnerability

If you discover a security issue in CryptPouch, please report it privately:

- Open a GitHub Security Advisory (preferred), or
- Open an issue and mark it as sensitive; avoid including decrypted content or
  private keys in any report.

When reporting, please include:

- the affected version;
- a minimal reproduction of the issue;
- the impact you observed;
- any suggested fix, if available.

Maintainers will acknowledge the report and coordinate a fix before public
disclosure where appropriate.

## Security Audit History

CryptPouch has undergone four rounds of security review between versions
2.6.1 and 2.7.2. The defect count has been reduced from 23 to 14.

Round 1 (2.6.1 to 2.7.0) fixed 12 items:

- PKCS7 padding validation (byte-by-byte verification plus empty-input check);
- AES-CBC key separation (HKDF-derived encryption and MAC keys);
- CLI password exposure (added --password-file and risk notices);
- file handle management (context managers in RSA and QR code paths);
- path normalization (os.path.normpath);
- overly broad exception handling in the main loop (typed handling plus
  traceback output);
- strict-priority Base64 decoding;
- expanded weak-password detection;
- readable-text threshold for legacy probing;
- process restart via subprocess.Popen;
- ciphertext structure validation in content detection;
- dynamic RSA plaintext limit;
- hash algorithm whitelist, QR length limit, Ctrl+C behavior, RSA key
  strength self-check, and explicit password encoding.

Round 2 (2.7.0 to 2.7.1) fixed 6 items:

- normalize_path made honest about its scope, with NUL character rejection;
- runtime warning when -p is used on the CLI;
- legacy CBC same-key fallback now warns the user to re-encrypt;
- Base64 fallback refined (strip whitespace before a strict retry);
- password length limit (128 characters) enforced across all input paths;
- RSA key size extracted to a constant; weak-password list expanded.

Round 3 (2.7.1 to 2.7.2) fixed 5 items:

- menu option exception handling fully classified, with a helper that prints
  the complete traceback instead of silently swallowing unknown errors;
- ciphertext Base64 decoding hardened (strict mode after removing whitespace;
  non-whitespace junk is rejected);
- RSA key size made configurable (2048/3072/4096 bits);
- word-plus-year password pattern detection;
- password strength thresholds and QR length limit exposed as tunable
  constants.

Round 4 (2.8.0 to 2.9.0) added 6 items:

- external weak-password dictionary: validated path (NUL rejected, normalized),
  a 32 MB size cap, and fail-safe skip with a warning so an optional dictionary
  can never break the main flow;
- password retry cap (MAX_PASSWORD_ATTEMPTS = 5) extended to the automatic
  decryption path (analyze-and-decrypt and forced family attempts);
- sliding-window QWERTY keyboard-pattern detection (rows, columns, diagonals)
  merged with the existing fixed-pattern check, threshold configurable;
- whole "word + year" scoring (1900-2099) so birthdays and anniversaries are
  not penalized merely for containing a year;
- set_config() validates and atomically writes the config file (unknown keys
  and invalid values are rejected, preserving the CLI > env > config >
  defaults priority);
- ANSI color output is configurable and disabled by default for redirected
  output (color=auto/on/off).

## Known Security Considerations

The following items are accepted risks, deliberately chosen for a local
single-user tool. Each entry states the reason and the existing mitigation.

Path traversal in normalize_path

- Reason: the user is the operator; a directory whitelist would prevent
  encrypting files in arbitrary locations.
- Mitigation: NUL characters are rejected; paths are normalized; there is no
  remote input channel.

CLI password via -p

- Reason: disabling -p would break scripted automation.
- Mitigation: --password-file is provided; using -p prints a visible warning;
  help text documents the risk.

Timing side channel in legacy decryption probing

- Reason: no remote observer exists; running every probe at 600k iterations
  would slow compatible decryption by more than 6 times for no practical gain.
- Mitigation: probe order is fixed; failed candidates still run full tag
  verification.

Legacy CBC same-key fallback

- Reason: older AC2 ciphertext must remain decryptable; data availability
  takes priority.
- Mitigation: only new ciphertext uses separated keys; the fallback path warns
  the user to re-encrypt.

TOCTOU race in file naming

- Reason: a single user on a local machine does not concurrently write the
  same directory.
- Mitigation: decryption output uses a numbered copy rather than overwriting.

RSA keys and QR images written next to the script

- Reason: these are user-visible artifacts that must be kept; not temporary
  files.
- Mitigation: this also avoids permission errors under store versions of
  Python with read-only working directories.

Dependency version pinning and audit logging

- Reason: pinning inside the script may cause install failures; logging is
  better delivered as companion documentation.
- Mitigation: startup detects missing core dependencies and guides the user
  through installation.

## Recommended Practices

For deployments that need a stricter posture, consider:

- integrating static analysis (bandit or safegrep) into CI;
- optionally shipping a rockyou.txt subset for extended weak-password checks;
- publishing requirements.txt with pinned dependency versions;
- tightening the accepted items above (directory whitelist, disabling -p, or
  disabling legacy compatibility) when moving to a multi-user or controlled
  environment.

## License Compatibility

All runtime dependencies are compatible with the MIT license:

- pycryptodome (public domain / BSD-2-Clause)
- argon2-cffi (MIT / Apache-2.0)
- Pillow (HPND)
- qrcode (BSD-3-Clause)
- pyzbar (MIT)
- pyperclip (MIT)

The project is distributed under the MIT license. It is provided for learning
and research; the author is not liable for misuse.
