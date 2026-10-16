"""Tiny synthetic headers/containers only; no installer is run or unpacked."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
import zlib


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import inspect_candidate as probe


def pe(machine=0x8664, marker=0):
    """Structurally bounded PE headers plus inert zero data, not a real program."""
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)
    data[64:68] = b"PE\0\0"
    optional_size = 224 if machine == 0x14C else 240
    struct.pack_into("<HHIIIHH", data, 68, machine, 1, marker, 0, 0, optional_size, 0x0002)
    optional = 88
    struct.pack_into("<H", data, optional, 0x10B if machine == 0x14C else 0x20B)
    struct.pack_into("<II", data, optional + 32, 4096, 512)
    struct.pack_into("<II", data, optional + 56, 8192, 512)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, optional + (92 if machine == 0x14C else 108), 16)
    section = optional + optional_size
    data[section:section + 5] = b".data"
    struct.pack_into("<IIII", data, section + 8, 32, 4096, 512, 512)
    return bytes(data)


def mach(cpu=0x100000C, platform=1, endian="<"):
    is64 = cpu not in (7, 12)
    command = struct.pack(endian + "IIIIII", 0x32, 24, platform, 0, 0, 0) if platform is not None else b""
    values = [0xFEEDFACF if is64 else 0xFEEDFACE, cpu, 0, 1, bool(command), len(command), 0]
    if is64:
        values.append(0)
    return struct.pack(endian + "I" * len(values), *values) + command


def fat(is64=False, endian=">"):
    first, second = mach(0x1000007), mach(0x100000C)
    # A fat64 table ends at 72; its first slice therefore starts at 80.
    first_offset = 80 if is64 else 64
    second_offset = 144 if is64 else 128
    data = bytearray(second_offset + len(second))
    struct.pack_into(endian + "II", data, 0, 0xCAFEBABF if is64 else 0xCAFEBABE, 2)
    entry_size = 32 if is64 else 20
    for i, (cpu, offset, content) in enumerate(((0x1000007, first_offset, first), (0x100000C, second_offset, second))):
        values = [cpu, 0, offset, len(content), 4]
        if is64:
            values.append(0)
        struct.pack_into(endian + ("IIQQII" if is64 else "IIIII"), data, 8 + i * entry_size, *values)
        data[offset:offset + len(content)] = content
    return bytes(data)


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="xm-candidate-test-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.source = self.root / "untrusted-name.exe"
        self.report = self.root / "report.json"

    def inspect(self, content):
        self.source.write_bytes(content)
        return probe._run(self.source)

    def assert_candidate_only(self, result):
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["version_gate_applied"])
        self.assertFalse(result["target_executed"])
        self.assertFalse(result["patch_ready"])
        self.assertNotIn("supported_version", result)

    def test_different_pe_hashes_are_both_candidates_without_whitelist(self):
        first, second = self.inspect(pe(marker=1)), self.inspect(pe(marker=2))
        for result in (first, second):
            self.assert_candidate_only(result)
            self.assertEqual(result["package"]["header_status"], "recognized")
            self.assertEqual(result["package"]["platform"], "windows")
            self.assertEqual(result["package"]["architectures"], ["x64"])
        self.assertNotEqual(first["source_sha256"], second["source_sha256"])

    def test_pe_architectures(self):
        for code, expected in ((0x14C, "x86"), (0xAA64, "arm64"), (0xA641, "arm64ec"), (0xA64E, "arm64x")):
            with self.subTest(code=code):
                result = self.inspect(pe(code))
                self.assert_candidate_only(result)
                self.assertEqual(result["package"]["architectures"], [expected])
                self.assertEqual(result["package"]["header_status"], "recognized")

    def test_efi_pe_is_not_claimed_as_windows(self):
        data = bytearray(pe())
        struct.pack_into("<H", data, 88 + 68, 10)
        self.assertEqual(self.inspect(data)["package"]["platform"], "uefi")

    def test_unknown_contents_ignore_executable_suffix(self):
        for data in (b"", b"not a package, version 999.0", b"PK", b"M"):
            result = self.inspect(data)
            self.assert_candidate_only(result)
            self.assertEqual(result["package"]["format"], "unknown")
            self.assertEqual(result["package"]["platform"], "unknown")
            self.assertEqual(result["package"]["architectures"], [])

    def test_magic_only_and_malformed_pe_are_not_recognized(self):
        cases = [b"MZ", b"MZ" + b"\0" * 62, pe()[:100]]
        for offset, value, fmt in ((60, 0xFFFFFFF0, "I"), (70, 0xFFFF, "H"), (84, 0xFFFF, "H"),
                                   (88 + 60, 1, "I"), (88 + 108, 0xFFFFFFFF, "I"),
                                   (88 + 240 + 20, 0xFFFFFFFF, "I")):
            data = bytearray(pe())
            struct.pack_into("<" + fmt, data, offset, value)
            cases.append(data)
        for data in cases:
            result = self.inspect(data)
            self.assert_candidate_only(result)
            self.assertEqual(result["package"]["header_status"], "malformed")
            self.assertEqual(result["package"]["architectures"], [])

    def test_mach_thin_arch_and_platform_come_from_headers(self):
        for cpu, name in ((7, "x86"), (0x1000007, "x86_64"), (0x100000C, "arm64")):
            for endian in ("<", ">"):
                with self.subTest(cpu=cpu, endian=endian):
                    package = self.inspect(mach(cpu, endian=endian))["package"]
                    self.assertEqual(package["format"], "mach-o")
                    self.assertEqual(package["header_status"], "recognized")
                    self.assertEqual(package["platform"], "macos")
                    self.assertEqual(package["architectures"], [name])
        self.assertEqual(self.inspect(mach(platform=2))["package"]["platform"], "ios")
        self.assertEqual(self.inspect(mach(platform=None))["package"]["platform"], "apple-unspecified")

    def test_mach_universal_validates_each_slice(self):
        for is64 in (False, True):
            for endian in ("<", ">"):
                with self.subTest(is64=is64, endian=endian):
                    result = self.inspect(fat(is64, endian))
                    self.assert_candidate_only(result)
                    self.assertEqual(result["package"]["format"], "mach-o-universal")
                    self.assertEqual(result["package"]["header_status"], "recognized")
                    self.assertEqual(result["package"]["architectures"], ["arm64", "x86_64"])
                    self.assertEqual(result["package"]["platform"], "macos")

    def test_malformed_mach_offsets_counts_and_architectures(self):
        cases = [mach()[:4], fat()[:8]]
        for data, endian, offset, value in ((mach(), "<", 16, 0xFFFFFFFF), (mach(), "<", 36, 0xFFFFFFFF),
                                            (fat(), ">", 4, 0xFFFFFFFF), (fat(), ">", 16, 0xFFFFFFFF),
                                            (fat(), ">", 36, 64), (fat(), ">", 8, 7)):
            changed = bytearray(data)
            struct.pack_into(endian + "I", changed, offset, value)
            cases.append(changed)
        for data in cases:
            result = self.inspect(data)
            self.assert_candidate_only(result)
            self.assertEqual(result["package"]["header_status"], "malformed")
            self.assertEqual(result["package"]["architectures"], [])

    def test_zip_header_scan_never_extracts_or_infers_payload_architecture(self):
        for empty in (True, False):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                if not empty:
                    archive.writestr("payload.exe", b"inert text only")
            result = self.inspect(buffer.getvalue())
            self.assert_candidate_only(result)
            self.assertEqual(result["package"]["format"], "zip")
            self.assertEqual(result["package"]["header_status"], "recognized")
            self.assertEqual(result["package"]["platform"], "unknown")
            self.assertEqual(sorted(x.name for x in self.root.iterdir()), [self.source.name])
        self.assertEqual(self.inspect(b"PK\x03\x04")["package"]["header_status"], "malformed")

    def test_xar_and_udif_bounded_container_headers(self):
        toc = zlib.compress(b"<xar><toc/></xar>")
        xar = b"xar!" + struct.pack(">HHQQI", 28, 1, len(toc), 17, 0) + toc
        footer = bytearray(512)
        footer[:4] = b"koly"
        struct.pack_into(">II", footer, 4, 4, 512)
        struct.pack_into(">QQ", footer, 24, 0, 8)
        for data, kind in ((xar, "xar"), (b"inert!!!" + footer, "udif")):
            result = self.inspect(data)
            self.assert_candidate_only(result)
            self.assertEqual(result["package"]["format"], kind)
            self.assertEqual(result["package"]["header_status"], "recognized")
            self.assertEqual(result["package"]["platform"], "unknown")
        self.assertEqual(self.inspect(xar[:28])["package"]["header_status"], "malformed")
        struct.pack_into(">Q", footer, 224, 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(self.inspect(b"inert!!!" + footer)["package"]["header_status"], "malformed")

    def test_report_is_new_path_private_and_source_remains_unchanged(self):
        data = pe()
        self.source.write_bytes(data)
        before = self.source.stat()
        self.source.chmod(stat.S_IREAD)
        self.addCleanup(lambda: self.source.chmod(stat.S_IWRITE | stat.S_IREAD))
        result = probe._run(self.source, self.report)
        self.assertEqual(self.source.read_bytes(), data)
        self.assertEqual(self.source.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(result["source_sha256"], hashlib.sha256(data).hexdigest())
        text = self.report.read_text(encoding="utf-8")
        self.assertNotIn(str(self.root), text)
        self.assertNotIn(self.source.name, text)
        self.assertEqual(json.loads(text), result)

    def test_existing_report_and_path_collisions_never_overwrite(self):
        self.source.write_bytes(b"private source")
        self.report.write_text("preserve report", encoding="utf-8")
        for report, code in ((self.report, "report_exists"), (self.source, "path_collision")):
            with self.assertRaises(probe.ValidationError) as caught:
                probe._run(self.source, report)
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(self.report.read_text(encoding="utf-8"), "preserve report")
        self.assertEqual(self.source.read_bytes(), b"private source")

    def test_report_appearing_after_validation_is_not_overwritten(self):
        self.source.write_bytes(b"unknown candidate")
        real_identify = probe._identify
        def race(*args):
            self.report.write_text("other writer", encoding="utf-8")
            return real_identify(*args)
        with mock.patch.object(probe, "_identify", side_effect=race), self.assertRaises(FileExistsError):
            probe._run(self.source, self.report)
        self.assertEqual(self.report.read_text(encoding="utf-8"), "other writer")

    def test_cli_unknown_is_success_and_error_excludes_paths(self):
        self.source.write_bytes(b"unknown version")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(probe.main(["--source", str(self.source)]), 0)
        self.assert_candidate_only(json.loads(output.getvalue()))
        with contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(probe.main(["--source", str(self.root / "secret-missing.exe")]), 2)
        self.assertNotIn(str(self.root), error.getvalue())
        self.assertNotIn("secret-missing", error.getvalue())


if __name__ == "__main__":
    unittest.main()
