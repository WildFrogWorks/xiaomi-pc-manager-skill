#!/usr/bin/env python3
"""Known-build fast path: inspect, prepare, or verify one exact installer.

Python 3.10+; standard library only. Never downloads or executes a target.
The JSON profile is a readable reference; CLI checks are pinned in this script.
Other files belong to inspect_candidate.py and references/adapting-builds.md;
not matching this helper is not a rejection by the overall Skill.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile


@dataclass(frozen=True)
class _Profile:
    version: str
    size: int
    source_sha256: str
    output_sha256: str
    offset: int
    old: bytes
    new: bytes
    guard_offset: int
    guard: bytes


SUPPORTED = _Profile(
    version="5.8.1.130",
    size=766644624,
    source_sha256="d812cf30805d172474eb33b2f97f37129593f9d50f09d4224f73d530a2cb40e9",
    output_sha256="a7d35102dc1abdb5e8a5e45ba43c6a6b22f5b30cd9c456799a5bfea65f210e34",
    offset=0xD9600,
    old=bytes.fromhex("0f84fb010000"),
    new=bytes.fromhex("e99400000090"),
    guard_offset=0xD95EC,
    guard=bytes.fromhex("e88f5dfeff84c00f8409030000"),
)
CHUNK_SIZE = 4 * 1024 * 1024


class ValidationError(Exception):
    """Messages deliberately exclude supplied paths and machine identifiers."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _reject(code: str, message: str) -> None:
    raise ValidationError(code, message)


def _checked_path(value: str | Path, *, must_exist: bool) -> Path:
    """Reject symlinks, junctions, other reparse points, and multiply linked files."""
    path = Path(os.path.abspath(value))
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            if item == path and must_exist:
                _reject("missing_file", "A required input file does not exist.")
            continue
        attributes = getattr(info, "st_file_attributes", 0)
        if stat.S_ISLNK(info.st_mode) or attributes & 0x400:
            _reject("linked_path", "Symbolic links, junctions, and reparse points are not accepted.")
        if item == path:
            if not stat.S_ISREG(info.st_mode):
                _reject("not_regular_file", "Each supplied file must be a regular file.")
            if info.st_nlink != 1:
                _reject("hardlinked_file", "Multiply linked files are not accepted.")
        elif not stat.S_ISDIR(info.st_mode):
            _reject("invalid_parent", "A file parent is not a directory.")
    if not path.parent.is_dir():
        _reject("missing_parent", "Create the destination or report parent directory first.")
    return path


def _same_path(a: Path, b: Path) -> bool:
    if os.path.normcase(str(a)) == os.path.normcase(str(b)):
        return True
    return a.exists() and b.exists() and os.path.samefile(a, b)


def _validate_paths(source: Path, output: Path | None, report: Path | None):
    source = _checked_path(source, must_exist=True)
    output = _checked_path(output, must_exist=False) if output is not None else None
    report = _checked_path(report, must_exist=False) if report is not None else None
    items = [x for x in (source, output, report) if x is not None]
    for i, first in enumerate(items):
        for second in items[i + 1:]:
            if _same_path(first, second):
                _reject("path_collision", "Source, output, and report must be distinct files.")
    if report is not None and report.exists():
        _reject("report_exists", "Report already exists; choose a new report filename.")
    return source, output, report


def _inspect(source: Path, profile: _Profile) -> dict:
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        if os.fstat(stream.fileno()).st_size != profile.size:
            _reject("unsupported_size", "Size differs from the fixed-build fast path. Continue with inspect_candidate.py and adaptive analysis; no patch was applied.")
        for block in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(block)
        if digest.hexdigest() != profile.source_sha256:
            _reject("unsupported_hash", "Fingerprint differs from the fixed-build fast path. Continue with inspect_candidate.py and adaptive analysis; no patch was applied.")
        stream.seek(profile.offset)
        if stream.read(len(profile.old)) != profile.old:
            _reject("branch_mismatch", "Expected original branch bytes differ.")
        stream.seek(profile.guard_offset)
        if stream.read(len(profile.guard)) != profile.guard:
            _reject("guard_mismatch", "The preceding environment check differs.")
    return {
        "source_sha256": digest.hexdigest(),
        "source_size": profile.size,
        "source_matches_supported_build": True,
        "original_branch_verified": True,
        "preceding_environment_check_verified": True,
    }


def _verify(source: Path, output: Path, profile: _Profile) -> dict:
    """Hash both complete files and independently enforce the exact difference set."""
    expected = {
        profile.offset + i for i, (old, new) in enumerate(zip(profile.old, profile.new))
        if old != new
    }
    actual: set[int] = set()
    original_hash, modified_hash = hashlib.sha256(), hashlib.sha256()
    position = 0
    with source.open("rb") as original, output.open("rb") as modified:
        if os.fstat(original.fileno()).st_size != profile.size:
            _reject("source_changed", "Source size changed during verification.")
        if os.fstat(modified.fileno()).st_size != profile.size:
            _reject("output_size_mismatch", "Prepared copy size is incorrect.")
        while True:
            a, b = original.read(CHUNK_SIZE), modified.read(CHUNK_SIZE)
            if len(a) != len(b):
                _reject("size_changed", "Input lengths changed during verification.")
            if not a:
                break
            original_hash.update(a)
            modified_hash.update(b)
            if a != b:
                for i, (old, new) in enumerate(zip(a, b)):
                    if old != new:
                        offset = position + i
                        if offset not in expected:
                            _reject("unexpected_change", "Prepared copy contains a change outside the allowed bytes.")
                        actual.add(offset)
            position += len(a)
    if original_hash.hexdigest() != profile.source_sha256:
        _reject("source_changed", "Source no longer matches the official supported build.")
    if actual != expected:
        _reject("difference_mismatch", "Prepared copy does not have the exact expected byte changes.")
    if modified_hash.hexdigest() != profile.output_sha256:
        _reject("output_hash_mismatch", "Prepared copy SHA-256 does not match the expected result.")
    return {
        "output_sha256": modified_hash.hexdigest(),
        "output_size": position,
        "changed_offsets": [hex(offset) for offset in sorted(actual)],
        "changed_byte_count": len(actual),
        "source_unchanged_at_verification": True,
        "only_expected_bytes_changed": True,
        "size_unchanged": True,
    }


def _prepare(source: Path, output: Path, profile: _Profile) -> tuple[dict, bool]:
    if output.exists():
        return _verify(source, output, profile), True
    # The final destination appears only after full verification. Linking is an
    # atomic exclusive-create operation; it cannot overwrite an existing file.
    descriptor, temporary_name = tempfile.mkstemp(prefix=".xm-prepare-", suffix=".tmp", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w+b") as destination, source.open("rb") as original:
            for block in iter(lambda: original.read(CHUNK_SIZE), b""):
                destination.write(block)
            destination.seek(profile.offset)
            destination.write(profile.new)
            destination.flush()
            os.fsync(destination.fileno())
        checks = _verify(source, temporary, profile)
        try:
            os.link(temporary, output)
        except FileExistsError:
            _reject("output_appeared", "Output appeared during preparation; it was not overwritten.")
        except OSError:
            _reject("exclusive_publish_failed", "Cannot exclusively publish the verified copy; use a local NTFS destination.")
    finally:
        # Only this invocation's uniquely created temporary file is removed.
        temporary.unlink(missing_ok=True)
    return checks, False


def _run(command: str, source: Path, output: Path | None, report: Path | None,
         profile: _Profile = SUPPORTED) -> dict:
    """Internal profile injection exists solely for tiny, non-executable fixtures."""
    if command not in {"inspect", "prepare", "verify"}:
        _reject("invalid_command", "Unknown operation.")
    if command != "inspect" and output is None:
        _reject("missing_output", "Prepare and verify require an output file.")
    if command == "inspect" and output is not None:
        _reject("unexpected_output", "Inspect does not accept an output file.")
    source, output, report = _validate_paths(source, output, report)
    checks = _inspect(source, profile)
    result = {
        "schema_version": 1,
        "status": "ok",
        "operation": command,
        "supported_version": profile.version,
        "target_executed": False,
        "scope": "One silent-install OEM/model eligibility branch only.",
        "checks": checks,
        "prepared_copy_signature": "Original Authenticode signature is invalid after modification.",
        "original_signature_checked_by_this_script": False,
    }
    if command == "prepare":
        verification, reused = _prepare(source, output, profile)
        checks.update(verification)
        result["reused_verified_output"] = reused
    elif command == "verify":
        _checked_path(output, must_exist=True)
        checks.update(_verify(source, output, profile))
    if report is not None:
        with report.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "prepare", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--source", required=True, type=Path, help="User-supplied original official EXE")
        if name != "inspect":
            command.add_argument("--output", required=True, type=Path, help="Prepared copy, separate from source")
        command.add_argument("--report", type=Path, help="Optional new JSON file; never overwritten")
    args = parser.parse_args(argv)
    try:
        result = _run(args.command, args.source, getattr(args, "output", None), args.report)
    except ValidationError as error:
        result = {"schema_version": 1, "status": "error", "code": error.code,
                  "message": str(error), "target_executed": False}
        print(json.dumps(result, ensure_ascii=False, indent=2), file=sys.stderr)
        return 2
    except OSError:
        result = {"schema_version": 1, "status": "error", "code": "filesystem_error",
                  "message": "A filesystem operation failed. No target was executed; no existing file was intentionally overwritten.",
                  "target_executed": False}
        print(json.dumps(result, ensure_ascii=False, indent=2), file=sys.stderr)
        return 3
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
