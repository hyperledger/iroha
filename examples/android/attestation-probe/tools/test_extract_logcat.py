"""Tests for bounded recovery of untrusted public diagnostic log exports."""

import base64
import hashlib
import io
from pathlib import Path
import stat
import tempfile
import unittest
import warnings
import zipfile

from extract_logcat import decode_log, save_captures, validated_members


def make_zip(extra=None):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("report.txt", "verification=not_performed_capture_only\n" + "x" * 3000)
        archive.writestr("challenge.bin", bytes(range(32)))
        if extra is not None:
            name, data = extra
            archive.writestr(name, data)
    return buffer.getvalue()


def frames(raw, name="test-capture"):
    encoded = base64.b64encode(raw).decode("ascii")
    chunks = [encoded[index:index + 1200] for index in range(0, len(encoded), 1200)]
    metadata = f"id={name} bytes={len(raw)} sha256={hashlib.sha256(raw).hexdigest()} chunks={len(chunks)}"
    return (
        ["IROHA_ATTESTATION BEGIN " + metadata]
        + [f"IROHA_ATTESTATION CHUNK id={name} index={index} data={chunk}" for index, chunk in enumerate(chunks)]
        + ["IROHA_ATTESTATION END " + metadata]
    )


class ExtractLogcatTest(unittest.TestCase):
    def test_log_prefixes_reordered_chunks_and_identical_reemission(self):
        raw = make_zip()
        lines = frames(raw)
        text = "\n".join("10-20 18:00:00.000 100 200 I IrohaAttestation: " + item for item in lines + lines[::-1])
        self.assertEqual({"test-capture": raw}, decode_log("unrelated log\n" + text))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capture"
            save_captures(decode_log(text), output)
            self.assertEqual(raw, (output / "test-capture.zip").read_bytes())
            self.assertEqual(bytes(range(32)), (output / "test-capture/challenge.bin").read_bytes())
            with self.assertRaises(FileExistsError):
                save_captures(decode_log(text), output)

    def test_truncated_frames_and_missing_chunks_are_rejected(self):
        lines = frames(make_zip())
        for incomplete in (lines[1:], lines[:-1], lines[:2] + lines[3:]):
            with self.assertRaisesRegex(ValueError, "Incomplete"):
                decode_log("\n".join(incomplete))
        with self.assertRaisesRegex(ValueError, "Base64"):
            decode_log("\n".join(lines[:-2] + [lines[-2][:-5], lines[-1]]))

    def test_conflicting_duplicates_metadata_and_altered_payload_are_rejected(self):
        lines = frames(make_zip())
        altered = lines[1][:-1] + ("A" if lines[1][-1] != "A" else "B")
        with self.assertRaisesRegex(ValueError, "Conflicting duplicate"):
            decode_log("\n".join(lines + [altered]))
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            decode_log("\n".join([lines[0], altered] + lines[2:]))
        with self.assertRaisesRegex(ValueError, "BEGIN and END disagree"):
            digest = hashlib.sha256(make_zip()).hexdigest()
            changed_digest = ("0" if digest[0] != "0" else "1") + digest[1:]
            decode_log("\n".join(lines[:-1] + [lines[-1].replace(digest, changed_digest)]))

    def test_noncanonical_base64_is_rejected(self):
        # One-byte ZIP transport is deliberately invalid; non-canonical pad bits fail first.
        digest = hashlib.sha256(b"\x00").hexdigest()
        text = (
            f"IROHA_ATTESTATION BEGIN id=x bytes=1 sha256={digest} chunks=1\n"
            "IROHA_ATTESTATION CHUNK id=x index=0 data=AB==\n"
            f"IROHA_ATTESTATION END id=x bytes=1 sha256={digest} chunks=1"
        )
        with self.assertRaisesRegex(ValueError, "Non-canonical"):
            decode_log(text)

    def test_zip_traversal_unknown_files_symlinks_duplicates_and_expansion_are_rejected(self):
        for name in ("../escape", "/escape", "android-keystore/../report.txt", "private-key.der"):
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                decode_log("\n".join(frames(make_zip((name, b"x")))))
        symlink = zipfile.ZipInfo("android-keystore/public-key.pem")
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            validated_members(make_zip((symlink, b"/tmp/target")))
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("report.txt", "x" * (1024 * 1024 + 1))
            archive.writestr("challenge.bin", bytes(32))
        with self.assertRaisesRegex(ValueError, "expanded"):
            validated_members(buffer.getvalue())
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                validated_members(make_zip(("report.txt", b"duplicate")))

    def test_bounds_and_capture_selection(self):
        raw = make_zip()
        lines = frames(raw)
        with self.assertRaisesRegex(ValueError, "bounds"):
            decode_log("\n".join(lines).replace("index=0", "index=999"))
        with self.assertRaisesRegex(ValueError, "No public"):
            decode_log("IROHA_ATTESTATION ERROR stage=capture kind=ProviderException")
        text = "\n".join(lines + frames(make_zip(), "second")[:-1])
        self.assertEqual({"test-capture": raw}, decode_log(text, "test-capture"))
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            decode_log(text)


if __name__ == "__main__":
    unittest.main()
