#!/usr/bin/env python3
"""Authenticate the first-release typed `InstructionBox` conversion surface."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "crates/iroha_data_model/src/isi/mod.rs"
DIRECT_CALL = re.compile(r"impl_direct_instruction_box!\(([^)]+)\);")


class InstructionBoxMacroSourceTest(unittest.TestCase):
    """Require the canonical wallet ledger and deny retired KAGEMUSHA V1 ISIs."""

    def test_typed_direct_conversions_are_unique(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("macro_rules! impl_direct_instruction_box", source)
        calls = DIRECT_CALL.findall(source)
        self.assertTrue(calls)
        self.assertEqual(len(calls), len(set(calls)))

    def test_retired_kagemusha_instructions_are_not_boxable(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        kagemusha_calls = {
            call for call in DIRECT_CALL.findall(source)
            if "kagemusha" in call.lower()
        }
        self.assertEqual(
            kagemusha_calls,
            {"crate::isi::kagemusha_wallet::KagemushaWalletLedgerV1"},
        )
        for retired in ("TopUpKagemushaV1", "TopUpKagemushaOrdinaryV1", "RedeemKagemushaV1"):
            self.assertNotIn(retired, source)


if __name__ == "__main__":
    unittest.main()
