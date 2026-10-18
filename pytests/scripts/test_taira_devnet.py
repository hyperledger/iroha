"""SORA Parliament seating in the disposable Taira devnet (specs/sccp.md §4.14.5, §4.18)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import tomllib
import unittest
from fractions import Fraction
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "taira_devnet.py"
TAIRA_PROFILE = ROOT / "configs" / "soranexus" / "taira" / "config.toml"
SPEC = importlib.util.spec_from_file_location("taira_devnet_parliament_under_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
devnet = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = devnet
sys.path.insert(0, str(SCRIPT.parent))
try:
    SPEC.loader.exec_module(devnet)
finally:
    sys.path.remove(str(SCRIPT.parent))

# Stands for the fresh escrow literal `iroha taira seat-parliament` generates.
FRESH_ESCROW = "fresh-citizenship-escrow"
ATTEMPT = "11" * 32
ELECTION = "22" * 32
INSTANCE = "33" * 32
ROOT_HASH = "ab" * 32


def canonical_config() -> dict[str, Any]:
    return tomllib.loads(TAIRA_PROFILE.read_text(encoding="utf-8"))


def seated_peer_text() -> str:
    """The seating keys of the canonical profile as one validator config."""

    config = canonical_config()
    gov = config["gov"]
    faucet = config["torii"]["faucet"]
    lines = ["[torii.faucet]", "enabled = true", f'amount = "{faucet["amount"]}"']
    lines += [
        f"{key} = {faucet[key]}"
        for key in (
            "pow_max_anchor_age_blocks",
            "pow_adaptive_lookback_blocks",
            "pow_adaptive_claims_per_extra_bit",
            "pow_adaptive_max_extra_bits",
        )
    ]
    lines.append("[gov]")
    lines.append(f'citizenship_escrow_account = "{FRESH_ESCROW}"')
    lines.append(f'citizenship_bond_amount = "{gov["citizenship_bond_amount"]}"')
    lines += [
        f"{key} = {gov[key]}"
        for key in (*devnet.PARLIAMENT_PUBLIC_BODY_KEYS, "policy_jury_size", "confirmation_jury_size")
    ]
    return "\n".join(lines) + "\n"


class FakeRunner:
    """Record commands; answer `--help` from a fixed option list."""

    def __init__(self, *, help_text: str = "", fail_for: set[str] | None = None) -> None:
        self.commands: list[list[str]] = []
        self.help_text = help_text
        self.fail_for = fail_for or set()
        self.stdout = ""

    def __call__(self, command, **_kwargs):
        command = [str(part) for part in command]
        self.commands.append(command)
        if "--help" in command:
            if not self.help_text:
                raise devnet.DevnetError("unrecognized subcommand 'respond-invitation'")
            return subprocess.CompletedProcess(command, 0, self.help_text, "")
        config = command[command.index("-c") + 1] if "-c" in command else ""
        if any(marker in config for marker in self.fail_for):
            raise devnet.DevnetError("transaction rejected: not an invited member")
        return subprocess.CompletedProcess(command, 0, self.stdout, "")


class SigningRunner(FakeRunner):
    """Like Kagami, publish the seated identity at ``--expected-hash-out`` when signing."""

    def __init__(self, target: Path) -> None:
        super().__init__()
        self.target = target

    def __call__(self, command, **kwargs):
        command = [str(part) for part in command]
        if "--expected-hash-out" in command:
            Path(command[command.index("--expected-hash-out") + 1]).write_text(
                "seated\n", encoding="utf-8"
            )
        return super().__call__(command, **kwargs)


class SeatedNetwork:
    """One owner-only fake network directory with seated validators and citizens."""

    def __init__(self, citizens: int = 16, peer_text: str | None = None) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.target = Path(self.temporary.name) / "network"
        self.target.mkdir(mode=0o700)
        text = seated_peer_text() if peer_text is None else peer_text
        for index in range(devnet.PEER_COUNT):
            (self.target / f"peer{index}.toml").write_text(text, encoding="utf-8")
        (self.target / "client.toml").write_text(
            'torii_url = "http://127.0.0.1:29080/"\n'
            '[account]\nchain_discriminant = 369\npublic_key = "ed0120' + "A5" * 32 + '"\n',
            encoding="utf-8",
        )
        self.write_citizens(citizens)

    def write_citizens(self, citizens: int, bond: str = "1000000") -> None:
        directory = self.target / devnet.PARLIAMENT_CITIZEN_DIRECTORY
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        directory.chmod(0o700)
        entries = []
        for index in range(citizens):
            for suffix in ("private_key", "client.toml"):
                path = directory / f"citizen-{index:02d}.{suffix}"
                path.write_text("secret\n", encoding="utf-8")
                path.chmod(0o600)
            entries.append(
                {
                    "index": index,
                    "account_id": f"citizen-{index}",
                    "public_key": f"key-{index}",
                    "private_key_file": f"citizen-{index:02d}.private_key",
                    "client_config_file": f"citizen-{index:02d}.client.toml",
                }
            )
        manifest = directory / devnet.PARLIAMENT_CITIZEN_MANIFEST
        manifest.write_text(
            json.dumps(
                {
                    "schema": devnet.PARLIAMENT_CITIZEN_MANIFEST_SCHEMA,
                    "chain": devnet.DEFAULT_CHAIN_ID,
                    "citizenship_asset_id": "6TEAJqbb8oEPmLncoNiMRbLEK6tw",
                    "citizenship_bond_amount": bond,
                    "citizenship_escrow_account": FRESH_ESCROW,
                    "fee_float": "1000",
                    "sccp_proposer": "operator",
                    "citizens": entries,
                }
            ),
            encoding="utf-8",
        )
        manifest.chmod(0o600)

    def close(self) -> None:
        self.temporary.cleanup()


class TairaDevnetParliamentProfileTests(unittest.TestCase):
    def test_taira_devnet_canonical_profile_is_the_recommended_table(self) -> None:
        config = canonical_config()
        gov = config["gov"]
        for key in devnet.PARLIAMENT_PUBLIC_BODY_KEYS:
            self.assertEqual(gov[key], 5, key)
        self.assertEqual(gov["policy_jury_size"], 9)
        self.assertEqual(gov["confirmation_jury_size"], 7)
        self.assertEqual(gov["parliament_alternate_size"], 3)
        self.assertEqual(gov["parliament_invitation_phase_blocks"], 300)
        self.assertEqual(gov["parliament_public_finding_phase_blocks"], 900)
        self.assertEqual(gov["min_enactment_delay"], 50)
        self.assertEqual(gov["citizenship_bond_amount"], "1000000")
        faucet = config["torii"]["faucet"]
        self.assertGreater(faucet["pow_adaptive_claims_per_extra_bit"], 0)
        self.assertGreater(faucet["pow_adaptive_max_extra_bits"], 0)
        self.assertGreater(faucet["pow_adaptive_lookback_blocks"], 0)
        # The anchor age stays far below the lookback, so a bond-sized burst is counted.
        self.assertEqual(faucet["pow_max_anchor_age_blocks"], 6)
        burst = devnet.faucet_burst_cost(
            faucet["pow_max_anchor_age_blocks"],
            faucet["pow_adaptive_lookback_blocks"],
            faucet["pow_adaptive_claims_per_extra_bit"],
            faucet["pow_adaptive_max_extra_bits"],
            devnet.PARLIAMENT_BOND_FAUCET_CLAIMS,
        )
        # README figures: 81 984 scrypt evaluations at 4 base bits instead of 640.
        self.assertEqual(burst << faucet["pow_difficulty_bits"], 81_984)
        self.assertEqual(
            devnet.PARLIAMENT_BOND_FAUCET_CLAIMS << faucet["pow_difficulty_bits"], 640
        )
        # The checked-in escrow is the published sample account seating replaces.
        self.assertIn(gov["citizenship_escrow_account"], devnet.PARLIAMENT_PUBLISHED_ESCROW_ACCOUNTS)
        self.assertGreaterEqual(
            Fraction(gov["citizenship_bond_amount"]),
            Fraction(faucet["amount"]) * devnet.PARLIAMENT_BOND_FAUCET_CLAIMS,
        )

    def test_taira_devnet_canonical_profile_seats_sixteen_citizens(self) -> None:
        profile = devnet.parliament_seating_profile(canonical_config(), "canonical")
        self.assertEqual(
            devnet.parliament_seating_failures(profile, devnet.PARLIAMENT_GENESIS_CITIZENS),
            [],
        )
        failures = devnet.parliament_seating_failures(profile, 8)
        self.assertEqual(len(failures), 1)
        self.assertTrue(failures[0].startswith("citizens_cover_bodies"))

    def test_taira_devnet_refusal_rules(self) -> None:
        def failures(text: str, citizens: int = 16) -> list[str]:
            profile = devnet.parliament_seating_profile(tomllib.loads(text), "peer")
            return [
                failure.split(":", 1)[0]
                for failure in devnet.parliament_seating_failures(profile, citizens)
            ]

        seated = seated_peer_text()
        self.assertEqual(failures(seated), [])
        self.assertEqual(
            failures(seated.replace('"1000000"', '"999999"')),
            ["bond_beyond_faucet_reach"],
        )
        self.assertEqual(
            failures(
                seated.replace("pow_adaptive_max_extra_bits = 8", "pow_adaptive_max_extra_bits = 0")
            ),
            ["adaptive_faucet_difficulty"],
        )
        self.assertEqual(
            failures(seated.replace("confirmation_jury_size = 7", "confirmation_jury_size = 2")),
            ["hidden_ballot_anonymity"],
        )
        large = seated.replace("policy_jury_size = 9", "policy_jury_size = 25")
        self.assertEqual(failures(large, 27), ["policy_jury_confirmation_margin"])
        self.assertEqual(failures(large, 28), [])
        self.assertEqual(
            failures(
                seated.replace("pow_max_anchor_age_blocks = 6", "pow_max_anchor_age_blocks = 256")
            ),
            ["faucet_anchor_age_below_lookback"],
        )
        self.assertEqual(
            failures(
                seated.replace("pow_max_anchor_age_blocks = 6", "pow_max_anchor_age_blocks = 40")
            ),
            ["faucet_anchor_age_below_lookback"],
        )
        with self.assertRaisesRegex(devnet.DevnetError, "pow_max_anchor_age_blocks"):
            failures(seated.replace("pow_max_anchor_age_blocks = 6\n", ""))
        disabled = seated.replace("enabled = true", "enabled = false")
        self.assertEqual(failures(disabled.replace('"1000000"', '"10"')), [])
        with self.assertRaisesRegex(devnet.DevnetError, "coordination_council_size"):
            failures(seated.replace("coordination_council_size = 5\n", ""))
        with self.assertRaisesRegex(devnet.DevnetError, "no \\[gov\\]"):
            failures("[torii.faucet]\nenabled = false\n")


class TairaDevnetParliamentSeatingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.network = SeatedNetwork()
        self.target = self.network.target

    def tearDown(self) -> None:
        self.network.close()

    def test_taira_devnet_seated_network_is_accepted(self) -> None:
        report = devnet.require_parliament_seating(self.target)
        self.assertEqual(report["citizens"], 16)
        self.assertEqual(report["citizenship_bond_amount"], "1000000")
        self.assertEqual(report["citizenship_escrow_account"], FRESH_ESCROW)
        self.assertEqual(
            report["citizen_directory"], str(self.target / devnet.PARLIAMENT_CITIZEN_DIRECTORY)
        )
        citizens = devnet.parliament_citizens(self.target)
        self.assertEqual([citizen["index"] for citizen in citizens], list(range(16)))
        self.assertTrue(
            str(citizens[3]["client_config"]).endswith("citizen-03.client.toml")
        )

    def test_taira_devnet_refuses_too_few_citizens(self) -> None:
        self.network.write_citizens(8)
        with self.assertRaisesRegex(devnet.DevnetError, "citizens_cover_bodies"):
            devnet.require_parliament_seating(self.target)

    def test_taira_devnet_refuses_underbonded_manifest(self) -> None:
        self.network.write_citizens(16, bond="10000")
        with self.assertRaisesRegex(devnet.DevnetError, "below citizenship_bond_amount"):
            devnet.require_parliament_seating(self.target)

    def test_taira_devnet_refuses_a_published_or_foreign_escrow(self) -> None:
        published = next(iter(devnet.PARLIAMENT_PUBLISHED_ESCROW_ACCOUNTS))
        for text, reason in (
            (seated_peer_text().replace(FRESH_ESCROW, published), "published in this repository"),
            (seated_peer_text().replace(f'citizenship_escrow_account = "{FRESH_ESCROW}"\n', ""), "unset"),
            (seated_peer_text().replace(FRESH_ESCROW, "another-escrow"), "generated by the seating run"),
        ):
            for index in range(devnet.PEER_COUNT):
                (self.target / f"peer{index}.toml").write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(devnet.DevnetError, "citizenship_escrow_is_custodial"):
                devnet.require_parliament_seating(self.target)
            with self.assertRaisesRegex(devnet.DevnetError, reason):
                devnet.require_parliament_seating(self.target)

    def test_taira_devnet_refuses_disagreeing_validators(self) -> None:
        (self.target / "peer2.toml").write_text(
            seated_peer_text().replace("policy_jury_size = 9", "policy_jury_size = 7"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(devnet.DevnetError, "do not share"):
            devnet.require_parliament_seating(self.target)

    def test_taira_devnet_refuses_exposed_citizen_keys(self) -> None:
        key = self.target / devnet.PARLIAMENT_CITIZEN_DIRECTORY / "citizen-05.private_key"
        key.chmod(0o644)
        with self.assertRaisesRegex(devnet.DevnetError, "citizen 5 private key"):
            devnet.require_parliament_seating(self.target)
        key.chmod(0o600)
        manifest = self.target / devnet.PARLIAMENT_CITIZEN_DIRECTORY / devnet.PARLIAMENT_CITIZEN_MANIFEST
        document = json.loads(manifest.read_text(encoding="utf-8"))
        document["citizens"][1]["account_id"] = document["citizens"][0]["account_id"]
        manifest.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(devnet.DevnetError, "entry 1 is not exact V1"):
            devnet.require_parliament_seating(self.target)

    def test_taira_devnet_seat_parliament_runs_native_seating_and_resigns(self) -> None:
        runner = SigningRunner(self.target)
        runner.stdout = json.dumps({"schema": devnet.PARLIAMENT_SEAT_REPORT_SCHEMA}) + "\n"
        iroha = Path("/opt/iroha")
        kagami = Path("/opt/kagami")
        (self.target / "genesis.expected_hash").write_text("pre-seating\n", encoding="utf-8")
        report = devnet.seat_parliament(self.target, iroha, kagami, runner)
        self.assertEqual(report["citizens"], 16)
        seat, sign = runner.commands
        self.assertEqual(seat[:4], [str(iroha), "-c", str(self.target / "client.toml"), "taira"])
        self.assertEqual(seat[4], "seat-parliament")
        self.assertEqual(seat[seat.index("--citizens") + 1], "16")
        self.assertEqual(seat[seat.index("--fee-float") + 1], "1000")
        self.assertEqual(
            seat[seat.index("--sccp-proposer-public-key") + 1], "ed0120" + "A5" * 32
        )
        self.assertEqual(sign[:3], [str(kagami), "genesis", "sign"])
        self.assertEqual(sign[sign.index("--config") + 1], str(self.target / "peer0.toml"))
        self.assertEqual(
            sign[sign.index("--sccp-reset-history") + 1],
            str(self.target.parent / "sccp-reset-history"),
        )
        self.assertIn("--fresh-sccp-reset-nonce", sign)
        self.assertEqual(
            sign[sign.index("--bound-manifest-out") + 1], str(self.target / "genesis.json")
        )
        self.assertEqual(
            sign[sign.index("--nexus-context-output") + 1],
            str(self.target / "nexus-amx-context.v1.bin"),
        )
        # Kagami refuses to replace a different identity, so it signs beside the old one.
        self.assertEqual(
            sign[sign.index("--expected-hash-out") + 1],
            str(self.target / devnet.PARLIAMENT_NEXT_IDENTITY_FILE),
        )
        self.assertEqual(
            (self.target / "genesis.expected_hash").read_text(encoding="utf-8"), "seated\n"
        )
        self.assertFalse((self.target / devnet.PARLIAMENT_NEXT_IDENTITY_FILE).exists())

        runner = SigningRunner(self.target)
        runner.stdout = json.dumps({"schema": devnet.PARLIAMENT_SEAT_REPORT_SCHEMA}) + "\n"
        devnet.seat_parliament(self.target, iroha, kagami, runner, grant_sccp_proposer=False)
        self.assertNotIn("--sccp-proposer-public-key", runner.commands[0])

        unsigned = FakeRunner()
        unsigned.stdout = json.dumps({"schema": devnet.PARLIAMENT_SEAT_REPORT_SCHEMA}) + "\n"
        with self.assertRaisesRegex(devnet.DevnetError, "did not publish the seated"):
            devnet.seat_parliament(self.target, iroha, kagami, unsigned)

        runner = SigningRunner(self.target)
        runner.stdout = "not json\n"
        with self.assertRaisesRegex(devnet.DevnetError, "did not return a JSON report"):
            devnet.seat_parliament(self.target, iroha, kagami, runner)
        with self.assertRaisesRegex(devnet.DevnetError, "differs from the requested"):
            runner = SigningRunner(self.target)
            runner.stdout = json.dumps({"schema": devnet.PARLIAMENT_SEAT_REPORT_SCHEMA})
            devnet.seat_parliament(self.target, iroha, kagami, runner, citizens=20)


ALL_CITIZEN_OPTIONS = "\n".join(
    sorted(
        {
            option
            for _subcommands, options in devnet.PARLIAMENT_CITIZEN_COMMANDS.values()
            for option in options
        }
    )
)


class ScriptedRunner(FakeRunner):
    """A fake CLI that documents every citizen command option."""

    def __init__(self, *, fail_for: set[str] | None = None) -> None:
        super().__init__(help_text=ALL_CITIZEN_OPTIONS, fail_for=fail_for)


def citizen_config(command: list[str]) -> str:
    return command[command.index("-c") + 1]


class TairaDevnetCitizenHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.network = SeatedNetwork()
        self.target = self.network.target
        self.iroha = Path("/opt/iroha")

    def tearDown(self) -> None:
        self.network.close()

    def test_taira_devnet_invitation_responses_continue_past_uninvited_citizens(self) -> None:
        runner = ScriptedRunner(fail_for={"citizen-02.client.toml"})
        results = devnet.respond_to_invitations(
            self.target,
            self.iroha,
            runner,
            governance_attempt_id=ATTEMPT,
            election_attempt_id=ELECTION,
            body="policy-jury",
            indices=[1, 2, 3],
        )
        self.assertEqual([result["ok"] for result in results], [True, False, True])
        self.assertIn("not an invited member", results[1]["detail"])
        help_command, command = runner.commands[:2]
        self.assertEqual(help_command[1:], ["gov", "parliament", "respond-invitation", "--help"])
        self.assertEqual(command[:2], [str(self.iroha), "--machine"])
        self.assertEqual(command[4:7], ["gov", "parliament", "respond-invitation"])
        self.assertEqual(command[command.index("--body") + 1], "policy-jury")
        self.assertEqual(command[command.index("--decision") + 1], "accept")
        self.assertTrue(citizen_config(command).endswith("citizen-01.client.toml"))
        declined = ScriptedRunner()
        devnet.respond_to_invitations(
            self.target,
            self.iroha,
            declined,
            governance_attempt_id=ATTEMPT,
            election_attempt_id=ELECTION,
            body="rules-committee",
            accept=False,
        )
        self.assertEqual(len(declined.commands), 1 + 16)
        last = declined.commands[-1]
        self.assertEqual(last[last.index("--decision") + 1], "decline")
        with self.assertRaisesRegex(devnet.DevnetError, "unknown Parliament body"):
            devnet.respond_to_invitations(
                self.target,
                self.iroha,
                declined,
                governance_attempt_id=ATTEMPT,
                election_attempt_id=ELECTION,
                body="jury",
            )
        with self.assertRaisesRegex(devnet.DevnetError, "64 lowercase"):
            devnet.respond_to_invitations(
                self.target,
                self.iroha,
                declined,
                governance_attempt_id=ROOT_HASH.upper(),
                election_attempt_id=ELECTION,
                body="policy-jury",
            )
        with self.assertRaisesRegex(devnet.DevnetError, "no Parliament citizen 99"):
            devnet.respond_to_invitations(
                self.target,
                self.iroha,
                declined,
                governance_attempt_id=ATTEMPT,
                election_attempt_id=ELECTION,
                body="policy-jury",
                indices=[99],
            )
        with self.assertRaisesRegex(devnet.DevnetError, "selected twice"):
            devnet.respond_to_invitations(
                self.target,
                self.iroha,
                declined,
                governance_attempt_id=ATTEMPT,
                election_attempt_id=ELECTION,
                body="policy-jury",
                indices=[4, 4],
            )

    def test_taira_devnet_endorsements_use_each_citizen_config(self) -> None:
        runner = ScriptedRunner()
        runner.stdout = json.dumps({"hash": "submitted"}) + "\n"
        results = devnet.endorse_public_finding(
            self.target,
            self.iroha,
            runner,
            governance_attempt_id=ATTEMPT,
            body_instance_id=INSTANCE,
            result_root=ROOT_HASH,
            indices=[0, 15],
        )
        self.assertEqual([result["index"] for result in results], [0, 15])
        self.assertEqual(results[1]["output"], {"hash": "submitted"})
        endorse = runner.commands[2]
        self.assertEqual(endorse[4:7], ["gov", "parliament", "endorse"])
        self.assertTrue(citizen_config(endorse).endswith("citizen-15.client.toml"))
        self.assertEqual(endorse[endorse.index("--result-root") + 1], ROOT_HASH)

    def test_taira_devnet_citizen_commands_require_the_documented_cli(self) -> None:
        with self.assertRaisesRegex(devnet.DevnetError, "not available in this CLI build"):
            devnet.endorse_public_finding(
                self.target,
                self.iroha,
                FakeRunner(),
                governance_attempt_id=ATTEMPT,
                body_instance_id=INSTANCE,
                result_root=ROOT_HASH,
            )
        with self.assertRaisesRegex(devnet.DevnetError, "lacks its documented options: --result-root"):
            devnet.endorse_public_finding(
                self.target,
                self.iroha,
                FakeRunner(help_text="--governance-attempt-id\n--body-instance-id"),
                governance_attempt_id=ATTEMPT,
                body_instance_id=INSTANCE,
                result_root=ROOT_HASH,
            )
        with self.assertRaisesRegex(devnet.DevnetError, "unknown Parliament citizen action"):
            devnet.require_citizen_command(self.iroha, "vote", ScriptedRunner())

    def test_taira_devnet_citizens_parser(self) -> None:
        args = devnet.parser().parse_args(
            [
                "citizens",
                "endorse",
                "--iroha",
                "/opt/iroha",
                "--governance-attempt-id",
                ATTEMPT,
                "--body-instance-id",
                INSTANCE,
                "--result-root",
                ROOT_HASH,
                "--citizen",
                "2",
                "--citizen",
                "5",
            ]
        )
        self.assertIs(args.handler, devnet.citizens)
        self.assertEqual(args.citizen, [2, 5])
        self.assertEqual(args.result_root, ROOT_HASH)
        args = devnet.parser().parse_args(["citizens", "list"])
        self.assertEqual(args.action, "list")
        with self.assertRaises(SystemExit):
            devnet.parser().parse_args(
                ["citizens", "respond-invitation", "--iroha", "/x", "--body", "jury"]
            )

    def test_taira_devnet_cli_surfaces_cover_seating(self) -> None:
        surfaces = {(binary, subcommands) for binary, subcommands, _ in devnet.CLI_SURFACES}
        for surface in (
            ("iroha", ("taira", "seat-parliament")),
            ("kagami", ("genesis", "sign")),
        ):
            self.assertIn(surface, surfaces)
        # Citizen commands come with `iroha gov parliament` and are proven lazily, so a
        # devnet can start before the citizen commands ship.
        self.assertFalse(any(subcommands[:1] == ("gov",) for _, subcommands in surfaces))
        for subcommands, _options in devnet.PARLIAMENT_CITIZEN_COMMANDS.values():
            self.assertEqual(subcommands[:2], ("gov", "parliament"))


if __name__ == "__main__":
    unittest.main()
