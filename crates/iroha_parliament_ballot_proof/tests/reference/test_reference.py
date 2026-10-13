"""Fast regressions for the independent final ballot reference.

Run with Python 3.10+ and its standard library:
    python3.11 -I crates/iroha_parliament_ballot_proof/tests/reference/test_reference.py

These tests exercise public layout, hash domains, early malformed-proof rejection
and the generator's process/output contract. Full proof reproduction is separate.
"""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import multiprocessing
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ballot as BL
import faest as FZ
import fixtures as FX
import gen_vectors as GV


SUITE = (
    b"KECCAK-F1600/2R-FWD/SEL-32X32-PREFIX/PAD-256/TAPE-112/CTR-U20-LE32/NS-PREFIX77"
    b"/NF-1024/VAUTH-512/SALT-256/H5-SALT/LEAF-AFFINE-896"
)


def probe_output_dir(spec):
    """A cheap child-process action in place of generating a complete proof."""
    name = "-".join(map(str, spec))
    (Path(GV.VEC) / name).write_text("child inherited the selected output directory\n")
    return name, 0, 0, "test", 0.0


class FinalReferenceTests(unittest.TestCase):
    """The frozen construction's observable byte and failure behavior."""

    def test_final_descriptor_and_all_four_proof_lengths(self):
        rows = {
            "fast": (
                (256, 33, 8, 229, 7, 704),
                "a9c572a7c8f2cc735218123c6456e1e016e78b06aa2d03192ef801bf7fdb93ae"
                "014a9e16555e6bad81382c630467e45e76c9b1c3948f9dfea41a7a1435bcffea",
                (160148, 233012),
            ),
            "comparator": (
                (256, 22, 6, 225, 7, 696),
                "792f81bf102cac84b7c559595342b6b23ad27dab9065651feb928dd0a649a3f4"
                "bd1da3d350fbd4c62f1707d441d46ef084430b5f00b53a1af7088281d6a7386e",
                (109498, 158074),
            ),
        }
        self.assertEqual((BL.TAPE_BYTES, BL.SUITE, BL.DESC_BYTES), (112, SUITE, 286))
        for row, (parameters, crt_digest, lengths) in rows.items():
            with self.subTest(row=row):
                # Build the expected frame independently of ballot.frame and its
                # constants. Every length word and the suite bytes are pinned.
                fields = (
                    b"PARL-SHAKE-V1\0\0\0",
                    b"FAEST-3.0",
                    struct.pack("<6H", *parameters),
                    bytes.fromhex(crt_digest),
                    struct.pack("<4I", 35840, 72576, 53504, 108931),
                    SUITE,
                )
                tag = b"PARL/DESC/v1"
                expected = struct.pack("<H", len(tag)) + tag + struct.pack("<H", 6)
                expected += b"".join(struct.pack("<I", len(value)) + value for value in fields)
                self.assertEqual(len(expected), 286)
                self.assertEqual(BL.descriptor(row), expected)
                self.assertEqual(BL.descriptor_digest(row), hashlib.sha3_512(expected).digest())
                for kind, length in zip(("reg", "vote"), lengths):
                    self.assertEqual(BL.proof_bytes(row, kind), length)
                    layout = BL.backend_params(row, kind).sig_layout()
                    self.assertEqual(layout[-3:], [
                        ("iv_pre", length - 52, 16),
                        ("salt", length - 36, 32),
                        ("ctr", length - 4, 4),
                    ])

    def test_h5_absorbs_salt_between_iv_and_gate(self):
        prefix = bytes((7 * i + 1) % 256 for i in range(77))
        iv = bytes(range(0xA0, 0xB0))
        label = bytes(range(0x10, 0x30))
        salts = (bytes(range(0xC0, 0xE0)), bytes(32))
        outputs = []
        for salt in salts:
            body = prefix + iv + salt + struct.pack("<I", 5) + label + b"\x05"
            self.assertEqual(len(body), 162)
            expected = int.from_bytes(hashlib.shake_256(body).digest(2), "little") & 1023
            actual = FZ.H5(256, iv, 5, label, prefix, salt)
            self.assertEqual(actual, expected)
            outputs.append(actual)
        self.assertNotEqual(*outputs)
        self.assertEqual(outputs[0], 0x12F)
        self.assertNotEqual(outputs[0], FZ.H5(256, iv, 5, label, prefix))

    def test_counter_boundary_and_rejection_before_reconstruction(self):
        exhausted = BL.GrindingExhausted()
        self.assertEqual(exhausted.last, 0xFFFFF)
        self.assertEqual(str(exhausted), "grinding exhausted at 0x000fffff")
        for row in ("fast", "comparator"):
            cases = (FX.reg_case(row), FX.vote_case(row, 3, 1))
            for case in cases:
                kind = case["kind"]
                params = BL.backend_params(row, kind)
                proof = bytearray(params.sig_bytes)
                proof[-36:-4] = bytes(range(32))
                with self.subTest(row=row, kind=kind):
                    for counter in (0, 0xFFFFF):
                        proof[-4:] = struct.pack("<I", counter)
                        parsed = FZ.parse_signature(params, proof)
                        self.assertIsNotNone(parsed)
                        self.assertEqual(parsed["salt"], bytes(range(32)))
                        self.assertEqual(int.from_bytes(parsed["ctr"], "little"), counter)
                        # At the allowed boundary a syntactically valid proof
                        # reaches reconstruction. It is not an authentic proof.
                        with patch.object(FZ, "vole_reconstruct", return_value=None) as reconstruct:
                            self.assertFalse(BL.verify(row, kind, case["stmt"], proof))
                            reconstruct.assert_called_once()
                    for counter in (0x100000, 0xFFFFFFFF):
                        proof[-4:] = struct.pack("<I", counter)
                        self.assertIsNone(FZ.parse_signature(params, proof))
                        with patch.object(FZ, "vole_reconstruct", side_effect=AssertionError(
                            "an out-of-range counter reached reconstruction"
                        )) as reconstruct:
                            self.assertFalse(BL.verify(row, kind, case["stmt"], proof))
                            reconstruct.assert_not_called()
                    self.assertIsNone(FZ.parse_signature(params, proof[:-32]))
                    self.assertIsNone(FZ.parse_signature(params, proof + b"\0"))

    @unittest.skipUnless("fork" in multiprocessing.get_all_start_methods(), "generator uses fork")
    def test_generator_children_inherit_explicit_output_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "selected"
            with patch.object(GV, "gen", probe_output_dir), patch.object(GV, "VEC", "unused"):
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(GV.main([
                        "--output-dir", str(output), "--jobs", "2",
                        "--row", "fast", "--row", "fast", "--seats", "3",
                    ]), 0)
            self.assertEqual({path.name for path in output.iterdir()}, {
                "fast-reg", "fast-vote-3-1",
            })
            self.assertEqual(list(Path(directory).iterdir()), [output])
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
            GV.main(["--row", "fast"])
        self.assertEqual(failure.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
