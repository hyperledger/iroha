"""Independent RP56 corpus acceptance and corruption controls."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/check_poseidon_reference.py"
SPEC = importlib.util.spec_from_file_location("poseidon_reference", SCRIPT)
REFERENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REFERENCE)


class PoseidonReferenceTests(unittest.TestCase):
    """Check complete coverage and failures against the independently derived banks."""

    @classmethod
    def setUpClass(cls):
        cls.expected = REFERENCE.expected_corpus()

    def test_frozen_corpus_matches_every_derived_field_and_frame(self):
        REFERENCE.verify_directory(SCRIPT.parents[1] / "fixtures/poseidon")
        self.assertEqual(len(self.expected["bn254-w3-rp56.hex"].splitlines()), 201)
        self.assertEqual(len(self.expected["bn254-w6-rp56.hex"].splitlines()), 420)
        self.assertEqual(len(self.expected["pasta-fp-w3-rp56.hex"].splitlines()), 201)
        self.assertEqual(len(self.expected["kaigi-framed-rp56.hex"].splitlines()), 102)

    def test_field_changes_reordering_truncation_and_line_endings_are_rejected(self):
        name = "bn254-w3-rp56.hex"
        original = self.expected[name]
        rows = original.splitlines(keepends=True)
        changed_byte = ("1" if original[0] == "0" else "0") + original[1:]
        for damaged in [changed_byte, "".join([rows[1], rows[0], *rows[2:]]), "".join(rows[:-1]), original.replace("\n", "\r\n")]:
            with self.subTest(damaged=damaged[:65]), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                for file, text in self.expected.items():
                    (directory / file).write_bytes(text.encode("ascii"))
                (directory / name).write_bytes(damaged.encode("ascii"))
                with self.assertRaisesRegex(ValueError, name):
                    REFERENCE.verify_directory(directory)

    def test_missing_reference_is_not_treated_as_an_empty_bank(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(FileNotFoundError):
                REFERENCE.verify_directory(Path(temp))


if __name__ == "__main__":
    unittest.main()
