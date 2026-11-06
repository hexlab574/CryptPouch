# Security Policy

CryptPouch is a local, single-user encryption toolbox. This document describes
the supported versions, security model, vulnerability reporting process, and
the known security considerations of the project.

## Supported Versions

The following version series currently receive security support:

- 2.11.x  -  actively supported (latest: 2.11.0)
- 2.10.x  -  supported (latest: 2.10.2)
- 2.9.x  -  supported (latest: 2.9.0)
- 2.8.x  -  supported (latest: 2.8.0)
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

CryptPouch has undergone six rounds of security review between versions
2.6.1 and 2.11.0. Rounds 1 to 3 were defect fixes and reduced the defect
count from 23 to 14. Rounds 4, 5 and 6 are hardening additions (six, six and
seven items respectively, worded as "added" below): they strengthen the product
rather than fix known vulnerabilities, so the defect count is unchanged at 14.

All reviews to date are author self-review. There is no third-party or paid
security audit, and community validation is still limited; treat the
assessments here accordingly.

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

Round 5 (2.9.0 to 2.10.0) added 6 items:

- modular codebase: the single 2,600-line script was split into single-purpose
  modules (cp_shared / cp_crypto / cp_utils / cp_files / cp_admin) behind a thin
  entry shell, with the full 77-test suite passing against the deployed layout;
- configurable file size cap (max_file_size, default 0 = no limit) enforced at
  every file encrypt/decrypt entry point, so an accidentally targeted huge file
  is rejected with a clear message instead of consuming resources;
- atomic decryption output: plaintext is written to a temp file in the target
  directory and swapped in via os.replace only after the GCM tag verifies; a
  failed or interrupted decrypt never leaves a partial output file. Durability
  is covered too: the temp file is flushed and fsynced before the swap, and the
  directory is fsynced afterwards on POSIX, so a crash right after the rename
  cannot surface an empty or short target (Windows cannot fsync a directory
  handle; the NTFS journal covers the rename there). Encryption and the legacy
  v2 output path fsync their output as well;
- symmetric cleanup on encryption: a failed/interrupted encrypt removes the
  partial ciphertext instead of leaving a truncated file behind;
- administrator elevation for dependency install is gated on explicit user
  consent: elevation is offered only after a permission-denied install, never
  attempted silently, and a UAC prompt appears only when the user agrees;
- password-safe process restart: the restart argv strips -p/--password and
  --password=... so a command-line password is never re-exposed to a child
  process.

Round 6 (2.10.2 to 2.11.0) added 7 items:

- authenticated ciphertext headers: the new $CP4$ (AES-256-GCM), $CC2$
  (ChaCha20-Poly1305) and $AC3$ (AES-CBC + HMAC) formats feed prefix + salt +
  nonce (or IV) to the AEAD or MAC as associated data. Editing the header, or
  swapping a prefix to force a different algorithm, now fails authentication
  instead of merely producing undecryptable or garbled output. The previous
  $CP3$ / $CC1$ / $AC2$ formats remain readable, print a one-time notice and
  upgrade to the new format through reencrypt or the next re-encrypt;
- symlink rejection (reject_symlinks, default enabled): file encrypt and decrypt
  refuse a symlinked input or output path, so a link cannot silently redirect an
  operation to an unintended target;
- open-handle size recheck: the max_file_size cap is evaluated again on the
  os.fstat of the already-open handle, closing the stat-then-open window that
  allowed a file to grow between the check and the read;
- legacy decryption switch (allow_legacy_decrypt, default enabled for
  compatibility): when disabled, every older-prefix and prefixless legacy path
  is refused with an explicit error, so an operator who only needs new-format
  ciphertext can turn the compatibility surface off entirely;
- optional audit log (audit_log, default off): when a path is configured, each
  file encrypt/decrypt appends one JSONL record with event, path, timestamp and
  outcome. Passwords, plaintext and key material are never written, and audit
  failures never abort the operation;
- configurable artifact directory (artifact_dir, default empty = script
  directory): RSA key pairs and QR images can be written outside the code
  directory, so running from a read-only or shared folder no longer forces
  secrets to land next to the scripts;
- optional pinned dependency file: requirements-lock.txt pins the exact versions
  of the runtime-verified packages for reproducible installs, while
  requirements.txt keeps the lower-bound policy as the default.

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
- Mitigation: two separate mechanisms cover this, and they are not in conflict.
  (a) Naming: when the default output name is already taken,
  next_available_copy_name() chooses a numbered name ("file (1).txt"), so an
  existing user file is never overwritten. (b) Writing: the plaintext is
  written to a mkstemp temp file in the same directory and then moved onto the
  chosen name with one os.replace, so the target path holds either the
  previous file or the complete new file, never a half-written one. In short,
  (a) decides which name to use, (b) atomically replaces whatever sits at that
  name.
- Residual risk: between the existence check in (a) and the os.replace in (b)
  a concurrent writer could still win the race; accepted for the single-user
  local model. Additional hardening since v2.11.0 narrows the window further:
  symlinked inputs are refused by default, and the size cap is re-evaluated on
  the fstat of the already-open handle rather than on a path lookup.

RSA keys and QR images written next to the script

- Reason: these are user-visible artifacts that must be kept; not temporary
  files, and writing them beside the script keeps the default layout
  predictable.
- Mitigation: since v2.11.0 the output directory is configurable through
  artifact_dir (or CRYPTPOUCH_ARTIFACT_DIR), so keys and images can be kept
  outside a read-only or shared code directory. The default stays the script
  directory for backward compatibility.

Dependency version pinning and audit logging

- Reason: hard-pinning inside the installed package can cause install failures
  on platforms without matching wheels, and log volume is operator-specific.
- Mitigation: requirements.txt keeps the lower-bound policy as the default,
  while the optional requirements-lock.txt pins exact versions for reproducible
  installs; an optional JSONL audit log can be enabled through audit_log when
  an operation trail is required. Startup still detects missing core
  dependencies and guides the user through installation.

## Recommended Practices

For deployments that need a stricter posture, consider:

- integrating static analysis (bandit or safegrep) into CI;
- optionally shipping a rockyou.txt subset for extended weak-password checks;
- installing from requirements-lock.txt when reproducible versions are required;
- enabling audit_log when an operation trail is needed;
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
