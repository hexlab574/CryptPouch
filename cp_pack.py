# -*- coding: utf-8 -*-
"""Directory packing and batch result manifests (v2.12.0).

Two conveniences common to mature file-encryption tools, both built on the
Python standard library only (zipfile / json / hashlib):

- pack_encrypt / pack_decrypt: turn a whole directory into ONE encrypted
  volume (a zip written to a temporary file, encrypted with the same v4
  streaming format) and restore it later with a single command.
- build_manifest / write_manifest: export a machine-readable JSON report of a
  batch run (per-item status, size and SHA-256) so "what did this run actually
  produce" can be answered without re-walking the folder.

The temporary zip contains plaintext for a moment. It is created with
mkstemp in the system temp directory and removed in a finally block, so it
never survives an error; keep the volume itself somewhere the same trust
model applies (Picocrypt documents the same caveat for its zip-based merge).
"""
import hashlib
import json
import os
import shutil
import tempfile
import time
import zipfile

import cp_shared
import cp_utils
import cp_crypto
import cp_files


def _norm(path):
    return cp_crypto.normalize_path(path)


def _sha256_file(path, chunk_size=1024 * 1024):
    """SHA-256 of a file, read in chunks (works for multi-GB outputs)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def pack_encrypt(path, password, output_path=None, compress=True, overwrite=False):
    """Pack a directory into one encrypted volume.

    Returns {"output": path, "files": n, "bytes": n}.
    Raises ValueError for a non-directory input, FileExistsError when the
    output already exists and overwrite is False.
    """
    src = _norm(path)
    if not os.path.isdir(src):
        raise ValueError(cp_shared.i18n.t("pack_not_dir", path=src))

    src_clean = os.path.normpath(src)
    base = os.path.basename(src_clean.rstrip("\\/")) or "packed"
    out = _norm(output_path) if output_path else src_clean + ".zip.enc"
    if os.path.exists(out) and not overwrite:
        raise FileExistsError(cp_shared.i18n.t("pack_out_exists", path=out))

    tmp_fd, tmp_zip = tempfile.mkstemp(prefix="cryptpouch_pack_", suffix=".zip")
    os.close(tmp_fd)
    files = 0
    total = 0
    out_abs = os.path.abspath(out)
    try:
        compression = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
        with zipfile.ZipFile(tmp_zip, "w", compression, allowZip64=True) as zf:
            for dirpath, _dirnames, filenames in os.walk(src):
                for name in filenames:
                    full = os.path.join(dirpath, name)
                    if os.path.abspath(full) == out_abs:
                        continue
                    rel = os.path.relpath(full, src)
                    # Store with forward slashes: the archive must be readable
                    # on any platform, not only on the one that built it.
                    zf.write(full, rel.replace(os.sep, "/"))
                    files += 1
                    try:
                        total += os.path.getsize(full)
                    except OSError:
                        pass
        cp_files.encrypt_file(tmp_zip, out, password)
    finally:
        try:
            os.remove(tmp_zip)
        except OSError:
            pass
    return {"output": out, "files": files, "bytes": total, "base": base}


def _safe_entry_name(root, name):
    """Reject absolute paths, parent traversal and anything resolving outside root."""
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        raise ValueError(cp_shared.i18n.t("pack_unsafe_entry", name=name))
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ValueError(cp_shared.i18n.t("pack_unsafe_entry", name=name))
    target = os.path.abspath(os.path.join(root, *parts))
    root_abs = os.path.abspath(root)
    if os.path.commonpath([target, root_abs]) != root_abs:
        raise ValueError(cp_shared.i18n.t("pack_unsafe_entry", name=name))
    return target


def pack_decrypt(enc_path, password, output_dir=None):
    """Decrypt a packed volume and extract it into a directory.

    Returns {"output_dir": path, "files": n, "bytes": n}.
    """
    src = _norm(enc_path)
    if not os.path.isfile(src):
        raise ValueError(cp_shared.i18n.t("pack_not_file", path=src))

    if output_dir:
        out_dir = _norm(output_dir)
    else:
        base = os.path.basename(src)
        lowered = base.lower()
        if lowered.endswith(".enc"):
            base = base[:-4]
        if base.lower().endswith(".zip"):
            base = base[:-4]
        base = base or "unpacked"
        out_dir = os.path.join(os.path.dirname(src), base)
    if os.path.exists(out_dir):
        out_dir = cp_files.next_available_copy_name(out_dir)

    parent = os.path.dirname(os.path.abspath(src)) or "."
    tmp_fd, tmp_zip = tempfile.mkstemp(prefix="cryptpouch_unpack_", suffix=".zip", dir=parent)
    os.close(tmp_fd)
    files = 0
    total = 0
    try:
        cp_files.decrypt_file(src, tmp_zip, password)
        if not zipfile.is_zipfile(tmp_zip):
            raise ValueError(cp_shared.i18n.t("pack_invalid_archive"))
        with zipfile.ZipFile(tmp_zip, "r") as zf:
            # Validate every entry before writing anything: a refused entry
            # must not leave a half-extracted directory behind.
            entries = []
            for info in zf.infolist():
                target = _safe_entry_name(out_dir, info.filename)
                entries.append((info, target))
            for info, target in entries:
                if info.is_dir():
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target) or out_dir, exist_ok=True)
                with zf.open(info) as src_f, open(target, "wb") as dst_f:
                    shutil.copyfileobj(src_f, dst_f, 1024 * 1024)
                files += 1
                total += info.file_size
    finally:
        try:
            os.remove(tmp_zip)
        except OSError:
            pass
    return {"output_dir": out_dir, "files": files, "bytes": total}


def build_manifest(items, operation, tool_version="", include_hash=True):
    """Turn batch items into a JSON-serialisable report.

    items: [{"source", "output", "status", "error"}] where status is one of
    encrypted / decrypted / skipped / existing / failed.
    """
    rows = []
    counts = {}
    for item in items:
        source = item.get("source", "")
        output = item.get("output", "")
        status = item.get("status", "")
        counts[status] = counts.get(status, 0) + 1
        row = {"source": source, "output": output, "status": status,
               "size": None, "sha256": None, "error": item.get("error", "")}
        if output and os.path.isfile(output):
            try:
                row["size"] = os.path.getsize(output)
            except OSError:
                pass
            if include_hash:
                try:
                    row["sha256"] = _sha256_file(output)
                except (OSError, ValueError):
                    pass
        rows.append(row)
    ok = counts.get("encrypted", 0) + counts.get("decrypted", 0)
    report = {
        "tool": "CryptPouch",
        "tool_version": tool_version,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "operation": operation,
        "summary": {
            "total": len(rows),
            "ok": ok,
            "failed": counts.get("failed", 0),
            "skipped": counts.get("skipped", 0),
            "existing": counts.get("existing", 0),
        },
        "items": rows,
    }
    return report


def write_manifest(report, path):
    """Write the report as UTF-8 JSON; paths stay readable (no \\uXXXX escapes)."""
    path = _norm(path)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
        f.write("\n")
    try:
        cp_utils._restrict_permissions(path)
    except Exception:
        pass
    return path
