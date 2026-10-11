#!/usr/bin/env python3
"""Synthetic adversarial happy-day contract tests; no measured or valid BLS data."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
spec = importlib.util.spec_from_file_location("happy_day_fixture", HERE / "private_settlement_smoke_campaign_test.py")
assert spec and spec.loader
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)
import private_settlement_happy_day_campaign as H


class HappyDayEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="synthetic-happy-day-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        self.sha = "b" * 64
        evidence, self.result = F.evidence_fixture(0, self.sha)
        self.evidence = {k: v for k, v in evidence.items() if k in H.EVIDENCE_NAMES}
        self.request = F.request(0)
        self.request.pop("request_id")
        self.request["kind"] = "happy_day"
        self.request["request_id"] = H.shared.sha(H.shared.canonical(self.request))
        self.evidence["request.json"] = self.request
        self.evidence["processes-after.json"] = copy.deepcopy(self.evidence["processes-before.json"])
        self.result.update(kind="happy_day", restarted=0, request=self.request,
                           request_sha256=H.shared.sha(H.shared.canonical(self.request) + b"\n"))

    def validate(self):
        F.store_evidence(self.root, self.evidence, self.result)
        return H.validate_run(self.root, self.request, self.sha)

    def test_exact_happy_day_contract(self):
        self.assertEqual(len(H.EVIDENCE_NAMES), 79)
        self.assertEqual(self.validate()["continuous_checks"], 64)
        H.validate_request(self.request, F.COMMIT, 0)

    def test_scope_is_bound_to_request_and_terminal_marker(self):
        with self.assertRaises(H.CampaignError):
            H.validate_request(F.request(0), F.COMMIT, 0)
        output = f"running 1 test\ntest {H.TEST_NAME} ... APS happy_day completed: synthetic\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n"
        H.terminal_success(output)
        for bad in (output.replace("happy_day", "smoke"), output + "APS smoke completed: synthetic\n",
                    output.replace("1 passed", "0 passed")):
            with self.assertRaises(H.CampaignError):
                H.terminal_success(bad)

    def test_restart_or_missing_finality_cannot_enter_happy_day_population(self):
        for mutation in ("restart", "missing", "pid", "result"):
            with self.subTest(mutation=mutation):
                evidence, result = copy.deepcopy(self.evidence), copy.deepcopy(self.result)
                if mutation == "restart":
                    self.evidence["restarts.json"] = []
                elif mutation == "missing":
                    del self.evidence["finality-before-15.json"]
                elif mutation == "pid":
                    self.evidence["processes-after.json"][0]["pid"] += 100
                else:
                    self.result["restarted"] = 16
                with self.assertRaises((H.CampaignError, H.shared.release_runner.RunnerError)):
                    self.validate()
                for path in (self.root / "evidence").glob("*.json"):
                    path.unlink()
                self.evidence, self.result = evidence, result

    def test_partial_financial_state_rejected_after_outer_rehash(self):
        self.evidence["state-finalized.json"]["validators"][15] = F.observation(15, False)
        with self.assertRaises((H.CampaignError, H.shared.release_runner.RunnerError)):
            self.validate()

    def test_pending_terminal_then_clean_terminal_is_rejected(self):
        bundle = bytes(32)
        value = F.continuous(0, bundle, reconciling=True, terminal_staged=True)
        clean = F.observation(0, True)
        value["observations"].append(clean)
        summary = value["summary"]
        summary.update(check_count=5, finalized_observations=3, last_response_sha256=clean["response_sha256"])
        chain = hashlib.sha256(b"iroha:aps-fault-continuous-observation:v1\0" + bundle + struct.pack("<Q", 0))
        for row in value["observations"]:
            chain.update(bytes.fromhex(row["response_sha256"]))
        summary["response_chain_sha256"] = chain.hexdigest()
        phase = summary["phase_coverage"][2]
        phase.update(successful_observations=2, finalized_observations=2)
        phase["attempts"].append({"class": "finalized", "evidence": clean["response_hex"], "repetitions": 1})
        chain = hashlib.sha256(b"iroha:aps-fault-continuous-observation-phase:v1\0" + bundle
            + struct.pack("<QQQ", 0, 2, 8) + b"terminal" + bytes((0, 1)))
        for row in value["observations"][3:]:
            chain.update(bytes((2,)))
            chain.update(bytes.fromhex(row["response_sha256"]))
        chain.update(b"checkpoint\0" + struct.pack("<Q", 0) + b"checkpoint-controls\0" + struct.pack("<Q", 0))
        phase["attempt_chain_sha256"] = chain.hexdigest()
        before = H.shared.state_identity(F.observation(0, False), 0, "before")
        after = H.shared.state_identity(clean, 0, "after")
        with self.assertRaisesRegex(H.CampaignError, "terminal phase observation"):
            H.shared.validate_continuous(value, 0, bundle, before, after)


if __name__ == "__main__":
    unittest.main()
