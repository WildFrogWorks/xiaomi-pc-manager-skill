#!/usr/bin/env python3
"""Read package headers without a version whitelist, execution, or extraction.

Python 3.10+; standard library only. A recognized container/header is evidence
for choosing further analysis, never evidence that an installation patch fits.
SHA-256 identifies the supplied file; it is not compared with a known build.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from typing import BinaryIO

from prepare_installer import ValidationError, _validate_paths


CHUNK_SIZE = 1024 * 1024
PE_ARCH = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64",
           0xA641: "arm64ec", 0xA64E: "arm64x"}
MACH_ARCH = {7: "x86", 0x1000007: "x86_64", 12: "arm",
             0x100000C: "arm64", 0x200000C: "arm64_32"}
MACH_MAGIC = {b"\xce\xfa\xed\xfe": ("<", 28), b"\xfe\xed\xfa\xce": (">", 28),
              b"\xcf\xfa\xed\xfe": ("<", 32), b"\xfe\xed\xfa\xcf": (">", 32)}
FAT_MAGIC = {b"\xca\xfe\xba\xbe": (">", 20), b"\xbe\xba\xfe\xca": ("<", 20),
             b"\xca\xfe\xba\xbf": (">", 32), b"\xbf\xba\xfe\xca": ("<", 32)}
APPLE_PLATFORMS = {1: "macos", 2: "ios", 3: "tvos", 4: "watchos",
                   5: "bridgeos", 6: "maccatalyst", 7: "ios-simulator",
                   8: "tvos-simulator", 9: "watchos-simulator", 10: "driverkit",
                   11: "visionos", 12: "visionos-simulator"}


class _Malformed(Exception):
    pass


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise _Malformed(reason)


def _read(stream: BinaryIO, offset: int, length: int, end: int) -> bytes:
    _need(offset >= 0 and length >= 0 and offset + length <= end, "truncated_or_out_of_bounds")
    stream.seek(offset)
    data = stream.read(length)
    _need(len(data) == length, "truncated_or_changed")
    return data


def _package(kind: str, platform: str = "unknown", architectures: list[str] | None = None) -> dict:
    return {"format": kind, "header_status": "recognized", "platform": platform,
            "architectures": architectures or [], "validation_scope": "bounded_headers_only"}


def _pe(stream: BinaryIO, size: int) -> dict:
    dos = _read(stream, 0, 64, size)
    offset = struct.unpack_from("<I", dos, 60)[0]
    _need(offset >= 64, "invalid_pe_offset")
    coff = _read(stream, offset, 24, size)
    _need(coff[:4] == b"PE\0\0", "missing_pe_signature")
    machine, sections = struct.unpack_from("<HH", coff, 4)
    optional_size = struct.unpack_from("<H", coff, 20)[0]
    _need(1 <= sections <= 96, "invalid_pe_section_count")
    optional = _read(stream, offset + 24, optional_size, size)
    _need(len(optional) >= 2, "missing_optional_header")
    magic = struct.unpack_from("<H", optional)[0]
    _need(magic in (0x10B, 0x20B), "unsupported_optional_header")
    minimum = 96 if magic == 0x10B else 112
    _need(optional_size >= minimum, "short_optional_header")
    if machine in PE_ARCH:
        _need((machine == 0x14C) == (magic == 0x10B), "inconsistent_pe_architecture")
    directories = struct.unpack_from("<I", optional, minimum - 4)[0]
    _need(directories <= 16 and minimum + directories * 8 <= optional_size, "invalid_data_directories")
    section_start = offset + 24 + optional_size
    section_end = section_start + sections * 40
    header_size = struct.unpack_from("<I", optional, 60)[0]
    _need(section_end <= header_size <= size, "invalid_pe_header_size")
    for index in range(sections):
        section = _read(stream, section_start + index * 40, 40, size)
        raw_size, raw_offset = struct.unpack_from("<II", section, 16)
        if raw_size:
            _need(raw_offset >= header_size and raw_offset + raw_size <= size, "invalid_pe_section_range")
    # PE is also used for EFI. Do not label those images as Windows software.
    subsystem = struct.unpack_from("<H", optional, 68)[0]
    platform = "uefi" if subsystem in (10, 11, 12, 13) else "windows" if subsystem in (1, 2, 3, 9, 16) else "unknown"
    result = _package("pe", platform, [PE_ARCH.get(machine, "unknown")])
    result["machine_code"] = f"0x{machine:04x}"
    return result


def _mach(stream: BinaryIO, start: int, length: int) -> tuple[dict, int]:
    end = start + length
    magic = _read(stream, start, 4, end)
    _need(magic in MACH_MAGIC, "invalid_mach_slice_magic")
    endian, header_size = MACH_MAGIC[magic]
    header = _read(stream, start, header_size, end)
    cpu, _, filetype, commands, command_size = struct.unpack_from(endian + "IIIII", header, 4)
    _need(1 <= filetype <= 12, "invalid_mach_filetype")
    _need(commands <= 4096 and command_size <= 64 * 1024 * 1024, "mach_header_limit")
    _need(commands * 8 <= command_size and start + header_size + command_size <= end, "invalid_load_command_range")
    cursor, command_end = start + header_size, start + header_size + command_size
    platforms: set[str] = set()
    for _ in range(commands):
        command, count = struct.unpack(endian + "II", _read(stream, cursor, 8, command_end))
        _need(count >= 8 and count % (8 if header_size == 32 else 4) == 0 and cursor + count <= command_end,
              "invalid_load_command_size")
        if command == 0x32:  # LC_BUILD_VERSION includes the target Apple platform.
            data = _read(stream, cursor, 24, cursor + count)
            platform_code = struct.unpack_from(endian + "I", data, 8)[0]
            tools = struct.unpack_from(endian + "I", data, 20)[0]
            _need(24 + tools * 8 <= count, "invalid_build_tool_count")
            platforms.add(APPLE_PLATFORMS.get(platform_code, "apple-unspecified"))
        elif command in (0x24, 0x25, 0x2F, 0x30):
            _need(count >= 16, "short_version_command")
            platforms.add({0x24: "macos", 0x25: "ios", 0x2F: "tvos", 0x30: "watchos"}[command])
        cursor += count
    _need(cursor == command_end, "inconsistent_load_command_count")
    platform = next(iter(platforms)) if len(platforms) == 1 else "apple-unspecified"
    return _package("mach-o", platform, [MACH_ARCH.get(cpu, "unknown")]), cpu


def _fat(stream: BinaryIO, size: int, magic: bytes) -> dict:
    endian, entry_size = FAT_MAGIC[magic]
    count = struct.unpack(endian + "I", _read(stream, 4, 4, size))[0]
    _need(1 <= count <= 128 and 8 + count * entry_size <= size, "invalid_fat_arch_count")
    table_end = 8 + count * entry_size
    spans: list[tuple[int, int]] = []
    architectures, platforms = set(), set()
    for index in range(count):
        entry = _read(stream, 8 + index * entry_size, entry_size, size)
        cpu = struct.unpack_from(endian + "I", entry)[0]
        offset, length, alignment = struct.unpack_from(endian + ("III" if entry_size == 20 else "QQI"), entry, 8)
        _need(alignment <= 31 and offset >= table_end and length >= 28 and offset + length <= size,
              "invalid_fat_slice_range")
        _need(offset % (1 << alignment) == 0, "invalid_fat_slice_alignment")
        _need(all(offset + length <= a or offset >= b for a, b in spans), "overlapping_fat_slices")
        spans.append((offset, offset + length))
        package, actual_cpu = _mach(stream, offset, length)
        _need(actual_cpu == cpu, "inconsistent_fat_slice_architecture")
        architectures.update(package["architectures"])
        platforms.add(package["platform"])
    return _package("mach-o-universal", next(iter(platforms)) if len(platforms) == 1 else "apple-unspecified",
                    sorted(architectures))


def _zip(stream: BinaryIO, size: int) -> dict:
    # Scan only the bounded EOCD/comment region and directory headers. Never
    # decode filenames, allocate member data, or decompress any member.
    start = max(0, size - 65557)
    tail = _read(stream, start, size - start, size)
    index = tail.rfind(b"PK\x05\x06")
    while index >= 0 and (index + 22 > len(tail) or
                         index + 22 + struct.unpack_from("<H", tail, index + 20)[0] != len(tail)):
        index = tail.rfind(b"PK\x05\x06", 0, index)
    _need(index >= 0, "missing_zip_directory_end")
    disk, directory_disk, disk_count, count, directory_size, directory_offset = struct.unpack_from("<HHHHII", tail, index + 4)
    result = _package("zip")
    if count == 0xFFFF or directory_size == 0xFFFFFFFF or directory_offset == 0xFFFFFFFF or disk or directory_disk:
        result.update(header_status="unsupported", reason="zip64_or_multidisk_requires_further_analysis")
        return result
    _need(count == disk_count and directory_offset + directory_size <= start + index, "invalid_zip_directory_range")
    cursor, end = directory_offset, directory_offset + directory_size
    for _ in range(count):
        entry = _read(stream, cursor, 46, end)
        _need(entry[:4] == b"PK\x01\x02", "invalid_zip_directory_signature")
        compressed = struct.unpack_from("<I", entry, 20)[0]
        name_len, extra_len, comment_len, member_disk = struct.unpack_from("<HHHH", entry, 28)
        local_offset = struct.unpack_from("<I", entry, 42)[0]
        if compressed == 0xFFFFFFFF or local_offset == 0xFFFFFFFF or member_disk:
            result.update(header_status="unsupported", reason="zip64_or_multidisk_requires_further_analysis")
            return result
        local = _read(stream, local_offset, 30, directory_offset)
        _need(local[:4] == b"PK\x03\x04", "invalid_zip_local_signature")
        local_name, local_extra = struct.unpack_from("<HH", local, 26)
        _need(local_offset + 30 + local_name + local_extra + compressed <= directory_offset, "invalid_zip_member_range")
        cursor += 46 + name_len + extra_len + comment_len
        _need(cursor <= end, "truncated_zip_directory")
    _need(cursor == end, "inconsistent_zip_directory_size")
    return result


def _xar(stream: BinaryIO, size: int) -> dict:
    header = _read(stream, 0, 28, size)
    header_size, version, compressed, expanded = struct.unpack_from(">HHQQ", header, 4)
    _need(header_size >= 28 and compressed > 0 and expanded > 0 and header_size + compressed <= size,
          "invalid_xar_toc_range")
    result = _package("xar")
    if version != 1:
        result.update(header_status="unsupported", reason="unrecognized_xar_container_version")
    return result


def _udif(stream: BinaryIO, size: int) -> dict:
    footer = _read(stream, size - 512, 512, size)
    version, header_size = struct.unpack_from(">II", footer, 4)
    _need(header_size == 512, "invalid_udif_footer_size")
    for offset in (24, 40, 216):
        start, length = struct.unpack_from(">QQ", footer, offset)
        _need(start + length <= size - 512, "invalid_udif_data_range")
    result = _package("udif")
    if version != 4:
        result.update(header_status="unsupported", reason="unrecognized_udif_container_version")
    return result


def _identify(stream: BinaryIO, size: int) -> dict:
    magic = _read(stream, 0, min(4, size), size)
    kind = "unknown"
    try:
        if magic[:2] == b"MZ":
            kind = "pe"
            return _pe(stream, size)
        if magic in MACH_MAGIC:
            kind = "mach-o"
            return _mach(stream, 0, size)[0]
        if magic in FAT_MAGIC:
            kind = "mach-o-universal"
            return _fat(stream, size, magic)
        if magic in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
            kind = "zip"
            return _zip(stream, size)
        if magic == b"xar!":
            kind = "xar"
            return _xar(stream, size)
        if size >= 512 and _read(stream, size - 512, 4, size) == b"koly":
            kind = "udif"
            return _udif(stream, size)
    except _Malformed as error:
        result = _package(kind)
        result.update(header_status="malformed", reason=str(error))
        return result
    result = _package("unknown")
    result["header_status"] = "unrecognized"
    return result


def _run(source: Path, report: Path | None = None) -> dict:
    source, _, report = _validate_paths(source, None, report)
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        before = os.fstat(stream.fileno())
        for block in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(block)
        package = _identify(stream, before.st_size)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValidationError("source_changed", "Input changed during inspection; retry with a stable copy.")
    result = {
        "schema_version": 1, "status": "ok", "operation": "inspect_candidate",
        "version_gate_applied": False, "target_executed": False, "patch_ready": False,
        "source_size": before.st_size, "source_sha256": digest.hexdigest(),
        "sha256_purpose": "evidence_only_not_a_whitelist", "package": package,
        "next_step": "Analyze the actual model-eligibility logic before preparing any adapted copy.",
        "limitations": "Headers do not verify publisher, payload integrity, host compatibility, installation, or features.",
    }
    if report is not None:
        with report.open("x", encoding="utf-8", newline="\n") as destination:
            json.dump(result, destination, indent=2, ensure_ascii=False)
            destination.write("\n")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        result = _run(args.source, args.report)
    except (ValidationError, OSError) as error:
        print(json.dumps({"status": "error", "code": error.code if isinstance(error, ValidationError) else "io_error",
                          "message": str(error) if isinstance(error, ValidationError) else "Cannot read the input or create a new report.",
                          "target_executed": False, "patch_ready": False}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
