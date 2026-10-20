"""Tests for scripts/check_zk_primitive_workloads.py and its reference modules."""

from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import check_zk_primitive_workloads as checker  # noqa: E402
import zk_blake3_reference as blake3_reference  # noqa: E402
import zk_bn254_poseidon_reference as poseidon  # noqa: E402
import zk_pq_kat_reference as kat  # noqa: E402
import zk_rust_lexical_index as rust_index  # noqa: E402
import zk_semantic_profile_reference as profile_reference  # noqa: E402

SPEC_PATH = ROOT / checker.DEFAULT_SPEC


def load_spec() -> dict:
    return json.loads(SPEC_PATH.read_text(encoding="utf-8"))


class TreeFixture(unittest.TestCase):
    """The tracked specification with the tables derived from the tree, computed once."""

    spec: dict
    derived: dict
    files: list

    _cache: tuple | None = None

    @classmethod
    def setUpClass(cls) -> None:
        if TreeFixture._cache is None:
            spec = load_spec()
            files = checker.tree_files(ROOT)
            TreeFixture._cache = (spec, files, checker.derive(ROOT, spec, files))
        cls.spec, cls.files, cls.derived = TreeFixture._cache

    def errors(self, function, spec: dict, *arguments) -> list:
        report = checker.Report()
        function(*arguments, spec, *self._tail(function), report)
        return report.errors

    def _tail(self, function) -> tuple:
        needs_derived = {
            checker.check_primitives,
            checker.check_roles,
            checker.check_poseidon,
        }
        if function in needs_derived:
            return (self.derived,)
        return ()

    def mutated(self) -> dict:
        return copy.deepcopy(self.spec)

    @staticmethod
    def role(spec: dict, key: str) -> dict:
        return next(role for role in spec["digest_roles"] if role["key"] == key)

    def assertReported(self, errors: list, text: str) -> None:  # noqa: N802
        self.assertTrue(any(text in error for error in errors), f"{text!r} not in {errors[:5]}")


class TrackedSpecification(TreeFixture):
    def check(self, spec: dict) -> list:
        return checker.check(ROOT, spec, files=self.files, derived=self.derived)

    def test_tracked_specification_matches_the_tree(self) -> None:
        self.assertEqual(self.check(self.spec), [])

    def test_refresh_is_a_fixed_point(self) -> None:
        self.assertEqual(checker.refreshed(self.spec, self.derived), self.spec)

    def test_header_fields_are_required(self) -> None:
        for key, value in (("schema_version", 1), ("scope", "qualified"), ("task", "H.2")):
            spec = self.mutated()
            spec[key] = value
            self.assertEqual(len(self.check(spec)), 1, key)
        for section in ("workloads", "producer_ledger"):
            spec = self.mutated()
            del spec[section]
            self.assertIn(f"section `{section}` is missing", checker.check(ROOT, spec))

    def test_every_named_consumer_and_family_is_present(self) -> None:
        consumers = set(self.spec["consumers"])
        for key in ("privacy-catalog", "kaigi", "confidential", "mkhe", "fastpq", "halo2-ipa", "bulletproofs", "vole-in-the-head", "parliament-ballot", "ivm"):
            self.assertIn(key, consumers)
        roles = {role["key"]: role for role in self.spec["digest_roles"]}
        for key in (
            "catalog.exact12-commitment",
            "kaigi.authorization-identity",
            "confidential.spentness-tree",
            "mkhe.proof-digest",
            "mkhe.parameter-identity-keccak",
            "mkhe.release-identity-keccak",
            "mkhe.source-receipt-identity-keccak",
            "mkhe.ceremony-identity-keccak",
            "privacy.statement-digest-blake3",
            "fastpq.transcript-shake256",
            "halo2.transcript-blake2b",
            "bulletproofs.fcmp-transcript-blake2b",
            "ivm.syscall-sha256-hash",
            "ivm.syscall-memory-merkle",
            "ram-lfe.public-commitment-blake2b",
        ):
            self.assertIn(key, roles)
        # SDK and fixture carriers of the catalog commitment are listed by path,
        # including the shared base64 bundle that no hexadecimal search finds.
        carriers = roles["catalog.exact12-commitment"]["pinned_value"]["carriers"]
        for prefix in ("IrohaSwift/", "kotlin/", "javascript/", "python/", "csharp/", "crates/iroha_data_model/tests/fixtures/"):
            self.assertTrue(any(path.startswith(prefix) for path in carriers), prefix)
        self.assertEqual(carriers["fixtures/privacy/exact12_typed_fixture_bundle_v1.norito.b64"], ["bytes-base64"])

    def test_corrected_role_facts(self) -> None:
        roles = {role["key"]: role for role in self.spec["digest_roles"]}
        # The 13 public RAM-LFE commitments are marked BLAKE2b, not BLAKE3.
        self.assertEqual(roles["ram-lfe.public-commitment-blake2b"]["primitive"], "iroha-hash")
        self.assertEqual(roles["ram-lfe.public-commitment-blake2b"]["canonical_native"]["decision"], "retained-family")
        self.assertIn("RAM_LFE_V1_PRIVATE_CONTEXTS", roles["ram-lfe.private-commitment-blake3"]["sites"][0]["symbol"])
        # The admitted Pasta relations use 57 partial rounds; the 56-round owner is a candidate.
        self.assertIn("57 partial rounds", roles["halo2.pasta-poseidon"]["domain_separation"])
        self.assertIn("57 partial rounds", roles["confidential.note-poseidon"]["domain_separation"])
        self.assertIn("no production caller", roles["halo2.pasta-poseidon-rp56-candidate"]["role"])
        # The X509 role is anchored on the word-oriented SHA-256 AIR.
        self.assertTrue(roles["x509.certificate-sha2"]["sites"][0]["path"].endswith("zk_x509/sha256_word_air.rs"))
        # The execution catalog identity binds every frame of its fork.
        native = roles["execution.catalog-identity-sha384"]["canonical_native"]
        self.assertEqual(native["decision"], "changes-with-profile")
        self.assertTrue(native["transcript_seed_check"]["binds_proof_internals"])
        # MKHE payload digests exist in test-only code only.
        self.assertEqual(roles["mkhe.payload-blake3"]["sites"][0]["compiled"], "test-only")


class ScanChecks(TreeFixture):
    def scan_errors(self, spec: dict) -> list:
        report = checker.Report()
        checker.check_scan(spec, self.derived, report)
        return report.errors

    def consumer_errors(self, spec: dict) -> list:
        report = checker.Report()
        checker.check_consumers(spec, self.derived, report)
        return report.errors

    def test_vole_backend_and_ballot_candidate_have_distinct_file_owners(self) -> None:
        scanner = checker.Scanner(self.spec)
        owners = {
            "crates/iroha_zkp_vole/": "vole-in-the-head",
            "crates/iroha_parliament_ballot_proof/": "parliament-ballot",
        }
        for prefix, consumer in owners.items():
            paths = [path for path in self.derived["scan"]["files"] if path.startswith(prefix)]
            self.assertTrue(paths, prefix)
            for path in paths:
                self.assertEqual(scanner.consumer_of(path), consumer, path)
                self.assertEqual(scanner.unit_of(path)[1], "file", path)
        # Owner rules precede incidental algorithm names in future module paths.
        for prefix, consumer in owners.items():
            self.assertEqual(scanner.consumer_of(prefix + "src/poseidon_relation.rs"), consumer)

    def test_vole_proof_internals_and_ballot_constraints_keep_distinct_roles(self) -> None:
        uses = self.spec["consumers"]
        for primitive in ("keccak", "sha3", "shake"):
            self.assertEqual(uses["vole-in-the-head"]["uses"][primitive]["class"], "proof-internal")
        # The ballot owner implements Keccak constraint groups. Its SHAKE and
        # SHA3 consumers remain proof internals, without selecting a profile.
        self.assertEqual(uses["parliament-ballot"]["uses"]["keccak"]["class"], "in-circuit")
        for primitive in ("sha3", "shake"):
            self.assertEqual(uses["parliament-ballot"]["uses"][primitive]["class"], "proof-internal")
        for consumer in ("vole-in-the-head", "parliament-ballot"):
            spec = self.mutated()
            del spec["consumers"][consumer]["uses"]["shake"]
            self.assertReported(self.consumer_errors(spec), f"consumer {consumer}: use of shake")

    def test_vole_and_ballot_digest_files_cannot_disappear_from_the_inventory(self) -> None:
        expected_uses = {
            "crates/iroha_zkp_vole/src/hash.rs": ["keccak", "sha3", "shake"],
            "crates/iroha_parliament_ballot_proof/src/keccak_relation.rs": ["keccak", "shake"],
        }
        for path, primitives in expected_uses.items():
            self.assertEqual(self.spec["scan"]["files"][path], primitives)
            spec = self.mutated()
            del spec["scan"]["files"][path]
            self.assertReported(self.scan_errors(spec), f"scan: {path} uses {primitives!r} and is not listed")

    def test_an_unlisted_digest_use_in_a_file_fails(self) -> None:
        spec = self.mutated()
        path = "crates/iroha_data_model/src/kaigi/authorization.rs"
        del spec["scan"]["files"][path]
        self.assertTrue(any(path in error and "is not listed" in error for error in self.scan_errors(spec)))

    def test_a_new_primitive_in_a_listed_file_fails(self) -> None:
        spec = self.mutated()
        path = "crates/iroha_data_model/src/kaigi/authorization.rs"
        spec["scan"]["files"][path].remove("digest384")
        self.assertTrue(any(path in error and "but uses" in error for error in self.scan_errors(spec)))

    def test_a_stale_file_entry_fails(self) -> None:
        spec = self.mutated()
        spec["scan"]["files"]["crates/kaigi_zk/src/removed.rs"] = ["poseidon"]
        self.assertReported(self.scan_errors(spec), "names no primitive now")

    def test_a_new_primitive_in_a_tree_unit_fails(self) -> None:
        spec = self.mutated()
        spec["scan"]["tree_units"]["crates/sorafs_car#other"].remove("blake3")
        self.assertReported(self.scan_errors(spec), "tree unit crates/sorafs_car#other")
        spec = self.mutated()
        del spec["scan"]["tree_units"]["vendor"]
        self.assertReported(self.scan_errors(spec), "tree unit vendor")
        spec = self.mutated()
        spec["scan"]["oversized_files"] = ["fixtures/huge.bin"]
        self.assertReported(self.scan_errors(spec), "are not read and must be listed")

    def test_wrapper_uses_are_listed_and_classified(self) -> None:
        files = self.spec["scan"]["files"]
        # Files that reach SHA3-384 only through the typed outer hash.
        self.assertIn("sha3", files["crates/iroha_core_privacy/src/privacy_engines/zk_x509/stark.rs"])
        for consumer in ("x509", "engine-ivm-private-note", "engine-private-settlement", "engine-zk-ace", "engine-pq-masp"):
            use = self.spec["consumers"][consumer]["uses"]["sha3"]
            self.assertEqual(use["class"], "proof-internal", consumer)
            self.assertIn("privacy-substrate.outer-sha3-384", use["roles"], consumer)
        # IVM syscall primitives are classified under the ivm consumer.
        for primitive in ("blake2b", "blake2s", "keccak", "sha3", "sm3", "sha2-256", "iroha-hash", "pedersen"):
            self.assertEqual(self.spec["consumers"]["ivm"]["uses"][primitive]["class"], "role", primitive)
        self.assertIn("streebog", files["crates/iroha_crypto/src/signature/gost.rs"])
        self.assertIn("crates/ivm/src/host.rs", files)
        self.assertIn(
            "poseidon",
            files["crates/iroha_core_zk/src/kagemusha_wallet_state_v1/native_worker/incoming_inputs.rs"],
        )

    def test_an_unclassified_consumer_use_fails(self) -> None:
        spec = self.mutated()
        del spec["consumers"]["kaigi"]["uses"]["digest384"]
        self.assertReported(self.consumer_errors(spec), "consumer kaigi: use of digest384")

    def test_a_stale_classification_fails(self) -> None:
        spec = self.mutated()
        spec["consumers"]["kaigi"]["uses"]["sm3"] = {"class": "label-only", "note": "stale"}
        self.assertIn(
            "consumer kaigi: classified use of sm3 no longer occurs", self.consumer_errors(spec)
        )

    def test_a_classification_needs_a_known_class_note_and_matching_role(self) -> None:
        spec = self.mutated()
        spec["consumers"]["kaigi"]["uses"]["digest384"]["class"] = "approved"
        self.assertReported(self.consumer_errors(spec), "unknown class")
        spec = self.mutated()
        spec["consumers"]["kaigi"]["uses"]["digest384"]["note"] = ""
        self.assertReported(self.consumer_errors(spec), "note is missing")
        spec = self.mutated()
        spec["consumers"]["kaigi"]["uses"]["digest384"]["roles"] = ["kaigi.relation-poseidon"]
        self.assertReported(self.consumer_errors(spec), "needs a role whose primitive is digest384")
        spec = self.mutated()
        spec["consumers"]["kaigi"]["uses"]["digest384"]["roles"] = ["kaigi.missing"]
        self.assertReported(self.consumer_errors(spec), "does not exist")

    def test_a_role_must_be_listed_by_its_consumer(self) -> None:
        spec = self.mutated()
        spec["consumers"]["ivm"]["uses"]["blake2s"]["roles"] = []
        spec["consumers"]["ivm"]["uses"]["blake2s"]["class"] = "label-only"
        self.assertReported(
            self.consumer_errors(spec),
            "role ivm.opcode-blake2s: consumer ivm does not list it under its use of blake2s",
        )
        spec = self.mutated()
        self.role(spec, "kaigi.authorization-identity")["consumer"] = "axt"
        self.assertReported(self.consumer_errors(spec), "consumer axt does not list it")

    def test_an_undescribed_consumer_fails(self) -> None:
        spec = self.mutated()
        del spec["consumers"]["kaigi"]
        self.assertReported(self.consumer_errors(spec), "consumer 'kaigi'")

    def test_a_file_without_a_consumer_rule_fails(self) -> None:
        spec = self.mutated()
        spec["scan"]["consumer_rules"] = [
            rule for rule in spec["scan"]["consumer_rules"] if rule["consumer"] != "ledger-crypto"
        ]
        self.assertReported(self.consumer_errors(spec), "matches no consumer rule")

    def test_in_use_follows_the_scan_and_needs_an_owner(self) -> None:
        spec = self.mutated()
        unused = next(
            primitive for primitive in spec["digest_primitives"] if not primitive["in_use"]
        )
        unused["in_use"] = True
        for primitive in spec["digest_primitives"]:
            if primitive["id"] == "blake3":
                primitive["owners"] = []
            if primitive["id"] == "rescue":
                primitive["owners"] = []
            if primitive["id"] == "md5":
                primitive["owners"][0]["symbol"] = "md5"
            if primitive["id"] == "sm3":
                primitive["kind"] = "approved"
        errors = self.errors(checker.check_primitives, spec, ROOT)
        self.assertReported(errors, f"primitive {unused['id']}: in_use")
        self.assertIn("primitive blake3: an owner site is required", errors)
        # A primitive in use needs an owner whatever its kind.
        self.assertIn("primitive rescue: an owner site is required", errors)
        self.assertReported(errors, "primitive md5: owner symbol 'md5' is too short")
        self.assertIn("primitive sm3: unknown kind", errors)

    def test_a_wrapper_needs_an_anchored_owner(self) -> None:
        spec = self.mutated()
        sha3 = next(primitive for primitive in spec["digest_primitives"] if primitive["id"] == "sha3")
        sha3["token"]["wrappers"][0]["owner"]["symbol"] = "pub(crate) struct RenamedOuterDigestV1"
        self.assertReported(self.errors(checker.check_primitives, spec, ROOT), "RenamedOuterDigestV1")
        del sha3["token"]["wrappers"][0]["owner"]
        self.assertReported(self.errors(checker.check_primitives, spec, ROOT), "has no owner site")

    def test_the_checker_does_not_scan_itself(self) -> None:
        for path in self.spec["scan"]["exclude_files"]:
            self.assertTrue((ROOT / path).is_file(), path)
            self.assertNotIn(path, self.spec["scan"]["files"])
        watch = {
            primitive["id"]: primitive["in_use"]
            for primitive in self.spec["digest_primitives"]
            if primitive["kind"] == "watch"
        }
        self.assertFalse(watch["sinsemilla"] or watch["merlin"] or watch["ripemd"])


class ScannerUnits(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scanner = checker.Scanner(load_spec())

    def test_tokens_respect_their_boundaries(self) -> None:
        cases = {
            "use sha2::Sha256;": ["sha2-256"],
            "sha3_256(x)": ["sha3"],
            "sha2_256": ["sha2-256"],
            "Sha384::digest": ["sha2-512"],
            "blscrypto::new()": [],
            "transaction_result_hash": [],
            "lt_hash16": ["lthash"],
            "a monolithic index": [],
            "monolith64": ["monolith"],
            "poseidon2_simd": ["poseidon2"],
            "poseidon6": ["poseidon"],
            "shake256_into": ["shake"],
            "hashof<block>": ["iroha-hash"],
            "HashOf::from_untyped_unchecked(x)": ["iroha-hash"],
            "hash::new(bytes)": ["iroha-hash"],
            "content_hash::new(bytes)": [],
            "PoseidonHashOf<T>": ["poseidon"],
            "asm3": [],
            "sm3_hash": ["sm3"],
            "rescue_prime": ["rescue"],
            "rescued: 0": [],
            "use tiny_keccak::Sha3;": ["keccak"],
            # Hyphenated algorithm names in prose and labels.
            "FIPS202:SHA3-256:suffix06": ["sha3"],
            "native-goldilocks-sha3-384-stark-fri-v1": ["sha3"],
            "SHA-256 of the body": ["sha2-256"],
            "strict dalek/SHA-512 traversal": ["sha2-512"],
            "SHA-384 object identifier": ["sha2-512"],
            "lowercase Git SHA-1 object": ["sha1"],
            "shake-256 tape": ["shake"],
            # CamelCase type names.
            "DaProofScheme::MerkleSha256": ["sha2-256"],
            "PrivacyEngineIdV1::NativeGoldilocksSha3_384StarkFri": ["sha3"],
            "starkFriSha3_384Goldilocks": ["sha3"],
            "ed25519::Ed25519Sha512::parse": ["sha2-512"],
            "EcdsaSecp256k1Sha256": ["sha2-256"],
            "neonSm3: boolean": ["sm3"],
            "KeyedHmac::new": ["hmac"],
            "AccountLtHash preimage": ["lthash"],
            "BLSCrypto": [],
            "use streebog::{Digest, Streebog256};": ["streebog"],
            "GOST R 34.11-2012": ["streebog"],
            # Wrapper symbols reach a primitive without naming it.
            "leaf: PrivacyOuterDigestV1,": ["sha3"],
            "privacy_outer_digest_frame_v1(context)": ["sha3"],
            "roots: &[Sha3Digest256V1]": ["sha3"],
            "MyPrivacyOuterDigestV1x": [],
            "tape: RawTapeV1,": ["shake"],
            "state: RnsNativeProofDigestV1,": ["digest384"],
            "hash_bytes_384_v1(domain, fields)": ["digest384"],
            "cell: WorldStateAccumulator,": ["lthash"],
            "shielded_leaf_from_commitment(cm)": ["iroha-hash"],
        }
        for text, expected in cases.items():
            self.assertEqual(self.scanner.primitives_in(text), expected, text)

    def test_path_scoped_wrappers(self) -> None:
        text = "transcript: &mut TransparentTranscriptV1,"
        substrate = "crates/iroha_core_privacy/src/privacy_engines/zk_x509/stark.rs"
        fork = "crates/iroha_core_privacy/src/execution_proofs/stark/aggregate_stark.rs"
        self.assertEqual(self.scanner.primitives_in(text, substrate), ["sha3"])
        self.assertEqual(self.scanner.primitives_in(text, fork), ["digest384"])
        self.assertEqual(self.scanner.primitives_in(text, "crates/other/src/lib.rs"), [])

    def test_literal_starts(self) -> None:
        cases = {
            r"sha(?:[-_]?2)?[-_]?256": ["sha"],
            r"lt_?hash": ["lt"],
            r"rpo_?(?:128|256)": ["rpo"],
            r"rescue_?(?:prime|hash|permutation|sponge)": ["rescue"],
            r"hashof(?![a-z0-9_])|hash::new(?:_from_[a-z_]+)?\(|cryptohash": ["hashof", "hash::new", "cryptohash"],
            r"streebog|gost[-_ ]?r?[-_ ]?34[.-]?11": ["streebog", "gost"],
            r"PrivacyOuter[A-Za-z0-9]+V1|PRIVACY_OUTER_[A-Z0-9_]+": ["PrivacyOuter", "PRIVACY_OUTER_"],
            r"(?:a|b)c": [""],
            r"ab*c": ["a"],
            r"a[|]b|c": ["a", "c"],
        }
        for pattern, expected in cases.items():
            self.assertEqual(checker.literal_starts(pattern), expected, pattern)
        # A finder with several starts finds the same positions as the pattern itself.
        finder = checker._Finder(r"hashof(?![a-z0-9_])|hash::new\(", r"hashof(?![a-z0-9_])|hash::new\(")
        data = b"hashofx hashof< hash::new( hash::newer hashof"
        self.assertEqual(sorted(finder.positions(data)), [8, 16, 39])
        self.assertTrue(finder.occurs(data))
        self.assertFalse(finder.occurs(b"hash::newer"))

    def test_units_follow_the_declared_scope(self) -> None:
        cases = {
            ("crates/fastpq_isi/src/lib.rs", ()): ("crates/fastpq_isi#zk", "file"),
            ("crates/iroha_core/src/smartcontracts/isi/kaigi/privacy.rs", ()): ("crates/iroha_core#zk", "file"),
            ("crates/iroha_core/src/sumeragi/main_loop.rs", ("blake3",)): ("crates/iroha_core#other", "tree"),
            # A file outside the proof paths that names an algebraic primitive is listed per file.
            ("crates/iroha_core/src/kiso.rs", ("pedersen", "poseidon")): ("crates/iroha_core#zk", "file"),
            ("crates/iroha_data_model/src/block/header.rs", ("iroha-hash", "poseidon")): ("crates/iroha_data_model#zk", "file"),
            # KAGEMUSHA files inside a proof crate are listed per file; elsewhere they are one set.
            ("crates/iroha_core_zk/src/kagemusha_wallet_proofs_v1/tests.rs", ("poseidon",)): ("crates/iroha_core_zk#zk", "file"),
            ("crates/iroha_core/src/kagemusha_wallet_v1/ledger.rs", ("poseidon",)): ("kagemusha", "tree"),
            ("vendor/vega-prover/src/traits/transcript.rs", ("poseidon",)): ("vendor", "tree"),
            ("crates/fastpq_prover/src/state_commitment_prototypes/hash.rs", ("rescue",)): ("state-candidates", "tree"),
            ("crates/ivm/src/host.rs", ("sm3",)): ("crates/ivm#zk", "file"),
            ("crates/ivm_abi/src/syscalls.rs", ("sha3",)): ("crates/ivm_abi#zk", "file"),
            ("crates/iroha_core/src/smartcontracts/ivm/host.rs", ("keccak",)): ("crates/iroha_core#zk", "file"),
            ("scripts/check_zk_delivery_plan.py", ("poseidon",)): ("scripts#other", "tree"),
            ("xtask/src/fastpq.rs", ()): ("xtask#other", "tree"),
            ("integration_tests/tests/privacy_exact12_zk_ams_vega_network.rs", ()): ("integration_tests#zk", "file"),
            ("kotlin/core-jvm/src/main/java/privacy/ConfidentialNote.kt", ()): ("kotlin#zk", "file"),
            ("scripts/release.py", ()): ("scripts#other", "tree"),
        }
        for (path, found), expected in cases.items():
            self.assertEqual(self.scanner.unit_of(path, found), expected, path)

    def test_first_consumer_rule_wins(self) -> None:
        cases = {
            "crates/soranet_pq/src/mlkem.rs": "pq",
            "crates/iroha_data_model/src/kaigi/authorization.rs": "kaigi",
            "crates/iroha_zkp_halo2/src/vega/zk_ams/mkhe/wire.rs": "mkhe",
            "crates/iroha_zkp_halo2/src/vega/sponge.rs": "vega",
            "crates/iroha_data_model/src/confidential/spentness.rs": "confidential",
            "crates/iroha_core_privacy/src/privacy_engines/privacy_outer_hash.rs": "privacy-substrate",
            "crates/iroha_core_privacy/src/privacy_profiles.rs": "privacy-catalog",
            "crates/iroha_crypto/src/hash.rs": "ledger-crypto",
            "crates/fastpq_prover/src/backend/fri_fold.rs": "fastpq",
            "crates/iroha_core_zk/src/kagemusha_wallet_proofs_v1.rs": "kagemusha",
            "crates/ivm/src/host.rs": "ivm",
            "crates/iroha_core/src/smartcontracts/ivm/host.rs": "ivm",
            "crates/kotodama_lang/src/ir.rs": "ivm",
            "crates/iroha_core/src/kiso.rs": "ledger-core",
            "crates/iroha_data_model/src/block/header.rs": "ledger-data-model",
            "crates/iroha_config/src/parameters/actual.rs": "node-config",
            "crates/iroha_torii/src/routing.rs": "node-services",
            "IrohaSwift/Sources/IrohaSwift/ToriiClient.swift": "sdk-surface",
            "docs/notes.rs": None,
        }
        for path, expected in cases.items():
            self.assertEqual(self.scanner.consumer_of(path), expected, path)

    def test_scan_and_walk_on_a_tree_without_git(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "crates/kaigi_zk/src").mkdir(parents=True)
            (root / "crates/other/src").mkdir(parents=True)
            (root / "target/debug").mkdir(parents=True)
            (root / "crates/kaigi_zk/src/lib.rs").write_text("use blake3::Hasher;\n")
            (root / "crates/other/src/lib.rs").write_text("let d = Sha256::digest(x);\n")
            (root / "crates/other/src/more.rs").write_text("fn plain() {}\n")
            (root / "crates/other/src/params.rs").write_text("let p = pedersen_params_id;\n")
            (root / "crates/other/src/notes.md").write_text("blake3\n")
            (root / "target/debug/ignored.rs").write_text("blake3\n")
            files = checker.tree_files(root)
            self.assertNotIn("target/debug/ignored.rs", files)
            self.assertEqual(
                self.scanner.scan(root, files),
                {
                    "files": {
                        "crates/kaigi_zk/src/lib.rs": ["blake3"],
                        "crates/other/src/params.rs": ["pedersen"],
                    },
                    "tree_units": {"crates/other#other": ["sha2-256"]},
                },
            )


class RoleChecks(TreeFixture):
    def role_errors(self, spec: dict) -> list:
        return self.errors(checker.check_roles, spec, ROOT)

    def test_already_blake3_cannot_relabel_another_native_hash(self) -> None:
        for key in ("mkhe.parameter-identity-keccak", "ram-lfe.public-commitment-blake2b"):
            with self.subTest(role=key):
                spec = self.mutated()
                self.role(spec, key)["canonical_native"]["decision"] = "already-blake3"
                self.assertReported(self.role_errors(spec), "already-blake3 requires the blake3 primitive")

    def test_current_native_transcript_roles_are_separate_from_retained_profiles(self) -> None:
        roles = {role["key"]: role for role in self.spec["digest_roles"]}
        transcript = roles["pipa-r.transcript-poseidon-base"]
        binding = roles["pipa-r.vk-binding-blake2b"]
        self.assertEqual(transcript["primitive"], "poseidon")
        self.assertEqual(binding["primitive"], "blake2b")
        self.assertEqual(transcript["family"], "proof-internal")
        self.assertEqual(binding["family"], "proof-internal")
        self.assertIn("pipa-rb1", transcript["domain_separation"])
        self.assertIn("Iroha-PlonkVK-v2", binding["domain_separation"])
        workload = next(workload for workload in self.spec["workloads"]["definitions"]
                        if workload["id"] == "h1.family.halo2-ipa")
        self.assertIn(transcript["key"], workload["roles"])
        self.assertIn(binding["key"], workload["roles"])
        self.assertNotIn("halo2.transcript-blake2b", workload["roles"])
        for key in (transcript["key"], binding["key"]):
            spec = self.mutated()
            self.role(spec, key)["sites"][0]["literals"].append('b"unimplemented-profile-domain"')
            self.assertReported(self.role_errors(spec), "unimplemented-profile-domain")

    def test_pgc_account_roots_record_their_proof_binding(self) -> None:
        role = self.role(self.spec, "privacy.state-digest-blake3")
        seed = role["canonical_native"]["transcript_seed_check"]
        self.assertTrue(seed["binds_proof_internals"])
        self.assertTrue(seed["coordination"])
        self.assertTrue(any(site["path"].endswith("pgc_account_root.rs") for site in role["sites"]))
        spec = self.mutated()
        del self.role(spec, role["key"])["canonical_native"]["transcript_seed_check"]["coordination"]
        self.assertReported(self.role_errors(spec), "names the profile it changes with")

    def test_a_missing_path_symbol_or_literal_fails(self) -> None:
        for field, value, expected in (
            ("path", "crates/iroha_data_model/src/kaigi/missing.rs", "does not exist"),
            ("symbol", "fn renamed_identity_hash", "no longer contains"),
        ):
            spec = self.mutated()
            self.role(spec, "kaigi.authorization-identity")["sites"][0][field] = value
            self.assertReported(self.role_errors(spec), expected)
        spec = self.mutated()
        self.role(spec, "kaigi.authorization-identity")["sites"][0]["literals"].append('b"other-domain"')
        self.assertReported(self.role_errors(spec), "other-domain")

    def test_role_fields_are_checked(self) -> None:
        cases = (
            ("primitive", "blake9", "unknown primitive"),
            ("output_bytes", 20, "is not one of"),
            ("consumer", "nobody", "unknown consumer"),
            ("domain_separation", "", "`domain_separation` is missing"),
            ("key", "Kaigi Identity", "not a stable key"),
            ("family", "banana", "unknown family 'banana'"),
            ("family", "in-circuit", "decision changes-with-profile does not apply to a role of family in-circuit"),
        )
        for field, value, expected in cases:
            spec = self.mutated()
            self.role(spec, "kaigi.authorization-identity")[field] = value
            self.assertReported(self.role_errors(spec), expected)
        spec = self.mutated()
        self.role(spec, "kaigi.authorization-identity")["canonical_native"]["decision"] = "approved"
        self.assertReported(self.role_errors(spec), "decision is invalid")
        spec = self.mutated()
        spec["digest_roles"].append(copy.deepcopy(spec["digest_roles"][0]))
        self.assertReported(self.role_errors(spec), "listed twice")
        # The output length is checked for every primitive, variable output or not.
        spec = self.mutated()
        self.role(spec, "mkhe.payload-blake3")["output_bytes"] = 64
        self.assertReported(self.role_errors(spec), "output of 64 bytes is not one of [32] for blake3")
        # A key derivation cannot serve a native commitment role.
        spec = self.mutated()
        self.role(spec, "catalog.exact12-commitment")["primitive"] = "hmac"
        self.assertReported(self.role_errors(spec), "family native cannot be served by a primitive of kind kdf-mac")

    def test_compile_status_is_read_from_the_source(self) -> None:
        spec = self.mutated()
        self.role(spec, "mkhe.payload-blake3")["sites"][0]["compiled"] = "production"
        self.assertReported(self.role_errors(spec), "is recorded as production but the source shows test-only")
        spec = self.mutated()
        self.role(spec, "kaigi.authorization-identity")["sites"][0]["compiled"] = "test-only"
        self.assertReported(self.role_errors(spec), "is recorded as test-only but the source shows production")
        spec = self.mutated()
        self.role(spec, "kaigi.authorization-identity")["sites"][0]["compiled"] = "sometimes"
        self.assertReported(self.role_errors(spec), "unknown compile status")
        source = (
            "#[cfg(test)]\nconst TEST_DOMAIN: &[u8] = b\"t\";\n"
            "/// Doc.\npub const PROD_DOMAIN: &[u8] = b\"p\";\n"
            "#[cfg(test)]\nmod tests {\n    fn inner_helper() {}\n}\n"
            "impl Thing {\n    fn digest(&self) -> u8 { 1 }\n    #[cfg(test)]\n    fn only_in_tests(&self) {}\n}\n"
        )
        self.assertEqual(checker.compile_status(source, "const TEST_DOMAIN"), "test-only")
        self.assertEqual(checker.compile_status(source, "pub const PROD_DOMAIN"), "production")
        self.assertEqual(checker.compile_status(source, "fn inner_helper"), "test-only")
        self.assertEqual(checker.compile_status(source, "fn digest"), "production")
        self.assertEqual(checker.compile_status(source, "fn only_in_tests"), "test-only")
        self.assertIsNone(checker.compile_status(source, "fn absent"))

    def test_an_unlisted_carrier_of_a_pinned_value_fails(self) -> None:
        spec = self.mutated()
        carriers = self.role(spec, "catalog.exact12-commitment")["pinned_value"]["carriers"]
        removed = "fixtures/privacy/exact12_typed_fixture_bundle_v1.norito.b64"
        del carriers[removed]
        errors = self.role_errors(spec)
        self.assertTrue(any("pinned-value carriers differ" in error and removed in error for error in errors))
        spec = self.mutated()
        carriers = self.role(spec, "catalog.exact12-commitment")["pinned_value"]["carriers"]
        carriers["javascript/iroha_js/src/norito.js"] = ["word-hex"]
        self.assertReported(self.role_errors(spec), "changed forms ['javascript/iroha_js/src/norito.js']")

    def test_pinned_value_forms(self) -> None:
        pinned = {"words": ["0x7c30a00439f137e0", "0x6b40fb5cd815db00"]}
        WORD = 0x7C30A00439F137E0  # noqa: N806
        needles = checker.pinned_needles(pinned)
        raw = bytes.fromhex("e037f13904a0307c00db15d85cfb406b")
        self.assertEqual(needles["bytes-raw"], [raw])
        cases = {
            b"const W: u64 = 0x7c30_a004_39f1_37e0;": ["word-hex"],
            b"0x7C30A00439F137E0": ["word-hex"],
            b'"e037f13904a0307c00db15d85cfb406b"': ["word-hex-reversed", "bytes-hex"],
            b"[%d, 1]" % WORD: ["word-decimal"],
            b"1%d0" % WORD: [],
            b"prefix" + raw + b"suffix": ["bytes-raw"],
            b"nothing here": [],
        }
        for data, expected in cases.items():
            self.assertEqual(checker.carrier_forms(data, needles), expected, data)
        # Base64 is found at every byte alignment and in both alphabets.
        for pad in (b"", b"a", b"ab", b"abc", b"\xff\xfe\xfd\xfc"):
            for encode in (base64.b64encode, base64.urlsafe_b64encode):
                data = encode(pad + raw + b"tail")
                self.assertEqual(checker.carrier_forms(data, needles), ["bytes-base64"], (pad, encode))

    def test_a_moving_role_needs_its_transcript_seed_check(self) -> None:
        spec = self.mutated()
        del self.role(spec, "catalog.exact12-commitment")["canonical_native"]["transcript_seed_check"]
        self.assertReported(self.role_errors(spec), "needs `transcript_seed_check`")
        spec = self.mutated()
        self.role(spec, "catalog.exact12-commitment")["canonical_native"]["decision"] = "changes"
        self.assertReported(self.role_errors(spec), "changes only with the proof profile")
        spec = self.mutated()
        seed = self.role(spec, "catalog.exact12-commitment")["canonical_native"]["transcript_seed_check"]
        seed["binds_proof_internals"] = False
        self.assertReported(self.role_errors(spec), "needs a value that binds proof internals")
        spec = self.mutated()
        seed = self.role(spec, "catalog.exact12-commitment")["canonical_native"]["transcript_seed_check"]
        seed["sites"][0]["symbol"] = "fn renamed_catalog_source()"
        self.assertReported(self.role_errors(spec), "transcript-seed evidence")
        spec = self.mutated()
        seed = self.role(spec, "privacy.statement-digest-blake3")["canonical_native"]["transcript_seed_check"]
        del seed["coordination"]
        self.assertReported(self.role_errors(spec), "names the profile it changes with")
        spec = self.mutated()
        self.role(spec, "confidential.spentness-tree")["canonical_native"]["transcript_seed_check"]["sites"] = []
        self.assertReported(self.role_errors(spec), "needs evidence sites")

    def test_surfaces_follow_the_tree(self) -> None:
        key = "catalog.exact12-commitment"
        spec = self.mutated()
        removed = self.role(spec, key)["surface"]["type_files"].pop()
        errors = self.role_errors(spec)
        self.assertTrue(any("files that name the commitment type differ" in error and removed in error for error in errors))
        # An anchored SDK owner that disappears fails.
        spec = self.mutated()
        owners = self.role(spec, key)["surface"]["sdk_owners"]
        kotlin = next(owner for owner in owners if owner["sdk"] == "kotlin")
        kotlin["symbol"] = "class RenamedCommitmentV1"
        self.assertReported(self.role_errors(spec), "SDK owner")
        # An SDK needs an owner or a reason, and a reason is refused while its tree names the type.
        spec = self.mutated()
        surface = self.role(spec, key)["surface"]
        surface["sdk_owners"] = [owner for owner in surface["sdk_owners"] if owner["sdk"] != "python"]
        self.assertReported(self.role_errors(spec), "SDK python has neither an owner nor a recorded reason")
        surface["sdks_without_owner"]["python"] = "none"
        self.assertReported(self.role_errors(spec), "SDK python is recorded without an owner but")
        spec = self.mutated()
        self.role(spec, key)["surface"]["sdk_owners"][1]["path"] = "IrohaSwift/Sources/IrohaSwift/Halo2IPA.swift"
        self.assertReported(self.role_errors(spec), "neither names the type nor carries the value")
        # Generated fixtures are anchored with their generator.
        spec = self.mutated()
        fixture = self.role(spec, key)["surface"]["fixtures"][0]
        fixture["generator"]["symbol"] = "const BUNDLE_PATH: &str = \"elsewhere\";"
        self.assertReported(self.role_errors(spec), "fixture generator")
        spec = self.mutated()
        del self.role(spec, key)["surface"]["fixtures"][0]["generator"]
        self.assertReported(self.role_errors(spec), "names no generator")
        # A changing role cannot drop its surface.
        spec = self.mutated()
        del self.role(spec, "confidential.spentness-tree")["surface"]
        self.assertReported(self.role_errors(spec), "a changing role needs its `surface`")
        surface = self.role(self.spec, key)["surface"]
        self.assertEqual({owner["sdk"] for owner in surface["sdk_owners"]}, set(checker.SDKS))
        self.assertIn("kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/privacy/PrivacyCapabilitiesV1.kt", surface["type_files"])
        self.assertIn("javascript/iroha_js/privacy-capabilities.d.ts", surface["type_files"])


class ProducerLedgerChecks(TreeFixture):
    def producer_errors(self, spec: dict) -> list:
        report = checker.Report()
        checker.check_producers(spec, self.derived, report)
        return report.errors

    def test_the_ledger_lists_the_named_outer_identities(self) -> None:
        production = self.spec["producer_ledger"]["production"]
        manifest = production["crates/iroha_zkp_halo2/src/vega/zk_ams/mkhe/manifest.rs"]
        entry = manifest["release_manifest_digest_v1"]
        self.assertEqual(entry["primitives"], ["keccak"])
        self.assertEqual(entry["domains"], ["iroha.zk-ams.v1.mkhe.release-manifest"])
        self.assertEqual(entry["returns"], "[u8; 32]")
        self.assertEqual(entry["role"], "mkhe.release-identity-keccak")
        kaigi = production["crates/iroha_data_model/src/kaigi/authorization.rs"]["hash_canonical_identity_v1"]
        self.assertEqual(kaigi["role"], "kaigi.authorization-identity")
        self.assertIn("iroha-kaigi-first-release-v1", kaigi["domains"])
        # The ceremony digests are compiled for tests only, so they are counted, not listed.
        active = "crates/iroha_zkp_halo2/src/vega/zk_ams/mkhe/active.rs"
        self.assertNotIn(active, production)
        self.assertGreater(self.spec["producer_ledger"]["test_only_counts"][active], 0)

    def test_an_unlisted_or_stale_producer_fails(self) -> None:
        path = "crates/iroha_data_model/src/privacy/statements.rs"
        spec = self.mutated()
        del spec["producer_ledger"]["production"][path]["PrivacyStatementV1::digest"]
        self.assertReported(self.producer_errors(spec), f"producer {path} PrivacyStatementV1::digest: calls ['blake3'] and is not listed")
        spec = self.mutated()
        spec["producer_ledger"]["production"][path]["removed_digest"] = {"primitives": ["blake3"], "domains": [], "returns": "", "role": "privacy.record-digest-blake3"}
        self.assertReported(self.producer_errors(spec), "is listed but no longer calls a digest in production")
        spec = self.mutated()
        spec["producer_ledger"]["production"][path]["PrivacyStatementV1::digest"]["domains"] = ["other"]
        self.assertReported(self.producer_errors(spec), "recorded domains")
        spec = self.mutated()
        spec["producer_ledger"]["test_only_counts"] = {}
        self.assertReported(self.producer_errors(spec), "`test_only_counts` differs from the tree")

    def test_a_producer_needs_a_role_of_its_primitive(self) -> None:
        path = "crates/iroha_data_model/src/privacy/statements.rs"
        spec = self.mutated()
        spec["producer_ledger"]["production"][path]["PrivacyStatementV1::digest"]["role"] = ""
        self.assertReported(self.producer_errors(spec), "role '' does not exist")
        spec = self.mutated()
        spec["producer_ledger"]["production"][path]["PrivacyStatementV1::digest"]["role"] = "kaigi.relation-poseidon"
        self.assertReported(self.producer_errors(spec), "which the function does not call")
        # Every named consumer keeps at least one assigned producer.
        spec = self.mutated()
        for functions in spec["producer_ledger"]["production"].values():
            for entry in functions.values():
                if entry["role"] == "confidential.spentness-tree":
                    entry["role"] = "catalog.exact12-commitment"
        self.assertReported(self.producer_errors(spec), "no production producer is assigned to a role of consumer confidential")

    def test_refresh_keeps_role_assignments_and_leaves_new_producers_unassigned(self) -> None:
        path = "crates/iroha_data_model/src/privacy/statements.rs"
        spec = self.mutated()
        del spec["producer_ledger"]["production"][path]["PrivacyStatementV1::digest"]
        fresh = checker.refreshed(spec, self.derived)["producer_ledger"]["production"][path]
        self.assertEqual(fresh["PrivacyStatementV1::digest"]["role"], "")
        self.assertEqual(
            fresh["BootleLanternIssuerPolicyV1::computed_record_digest"]["role"], "privacy.record-digest-sha256"
        )

    def test_producers_are_derived_lexically(self) -> None:
        ledger = {
            "detectors": {"blake3": r"\bblake3::", "keccak": r"\bkeccak256\("},
            "scopes": [{"consumer": "x", "crate": "crates/demo/", "prefixes": ["crates/demo/src/"]}],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/demo/src"
            (source / "inner").mkdir(parents=True)
            (root / "crates/demo/tests").mkdir()
            (source / "lib.rs").write_text(
                "mod owner;\n#[cfg(test)]\nmod only_tests;\nmod inner;\n"
            )
            (source / "owner.rs").write_text(
                'const DOMAIN_V1: &[u8] = b"iroha.demo.v1.statement";\n'
                'const UNUSED_V1: &[u8] = b"iroha.demo.v1.unused";\n'
                "pub fn statement_digest(bytes: &[u8]) -> [u8; 32] {\n"
                "    fn helper(x: &[u8]) -> [u8; 32] { keccak256(x) }\n"
                '    let mut hasher = blake3::Hasher::new();\n    hasher.update(DOMAIN_V1);\n    hasher.update(b"inline-tag");\n'
                '    let _message = "not a domain literal";\n'
                "    *hasher.finalize().as_bytes()\n}\n"
                "impl Record {\n    pub fn digest(&self) -> Hash { blake3::hash(b\"x\").into() }\n"
                "    #[cfg(test)]\n    fn fixture_digest(&self) -> Hash { blake3::hash(b\"y\").into() }\n}\n"
                "fn forwards(bytes: &[u8]) -> [u8; 32] { statement_digest(bytes) }\n"
            )
            (source / "only_tests.rs").write_text("fn test_digest() -> [u8; 32] { keccak256(b\"t\") }\n")
            (source / "inner.rs").write_text("mod leaf;\n")
            (source / "inner/leaf.rs").write_text("pub(crate) fn leaf_digest() -> [u8; 32] { keccak256(b\"leaf-domain\") }\n")
            (source / "orphan.rs").write_text("fn orphan_digest() -> [u8; 32] { keccak256(b\"o\") }\n")
            (root / "crates/demo/tests/integration.rs").write_text("fn it() { blake3::hash(b\"z\"); }\n")
            files = checker.tree_files(root)
            derived = checker.ProducerLedger(ledger).derive(root, files)
        self.assertEqual(
            derived["production"],
            {
                "crates/demo/src/inner/leaf.rs": {
                    "leaf_digest": {"primitives": ["keccak"], "domains": ["leaf-domain"], "returns": "[u8; 32]"}
                },
                "crates/demo/src/owner.rs": {
                    "statement_digest": {
                        "primitives": ["blake3"],
                        "domains": ["inline-tag", "iroha.demo.v1.statement"],
                        "returns": "[u8; 32]",
                    },
                    "statement_digest::helper": {"primitives": ["keccak"], "domains": [], "returns": "[u8; 32]"},
                    "Record::digest": {"primitives": ["blake3"], "domains": [], "returns": "Hash"},
                },
            },
        )
        self.assertEqual(
            derived["test_only_counts"], {"crates/demo/src/only_tests.rs": 1, "crates/demo/src/owner.rs": 1}
        )
        self.assertEqual(derived["unreached_files"], ["crates/demo/src/orphan.rs"])


class LexicalIndex(unittest.TestCase):
    SOURCE = (
        "//! doc { brace\n"
        'const D: &[u8] = b"iroha.x{"; const E: &str = "a\\"b{";\n'
        "/* block /* nested { */ } */\n"
        "#[cfg(test)]\n"
        'fn test_only(a: [u8; 32]) -> [u8; 32] { let s = "}"; a }\n'
        "pub(crate) fn prod<'a, F: Fn(u8) -> u8>(x: &'a [u8; 4], f: F) -> Result<[u8; 32], Error>\n"
        "where\n    F: Copy,\n{\n"
        "    let c = '{'; let e = '\\''; let u = '\\u{7b}';\n"
        '    let r = r#"}{"#; let rr = br##"x"#}"##;\n'
        "    call(|y| { y; 1 });\n    Ok([0; 32])\n}\n"
        "impl<T: Clone> Foo<T> for Bar<T> {\n"
        '    fn digest(&self) -> Hash { Hash::new(b"x") }\n'
        '    #[cfg(all(test, feature = "x"))]\n    fn only(&self) {}\n}\n'
        "#[cfg(test)]\nmod tests {\n    use super::*;\n    #[test]\n    fn works() { assert!(true); }\n}\n"
        '#[cfg(any(test, feature = "dev"))]\nfn development() {}\n'
    )

    def test_mask_preserves_offsets_and_blanks_literals(self) -> None:
        masked = rust_index.mask(self.SOURCE)
        self.assertEqual(len(masked), len(self.SOURCE))
        self.assertEqual(masked.count("\n"), self.SOURCE.count("\n"))
        for hidden in ("iroha.x", "nested", "doc", "a\\"):
            self.assertNotIn(hidden, masked)
        self.assertIn("&'a [u8; 4]", masked)
        self.assertEqual(masked.count("{"), masked.count("}"))

    def test_functions_carry_names_return_types_and_test_status(self) -> None:
        found = {
            function.qualified_name(): (function.returns, function.test_only())
            for function in rust_index.functions(self.SOURCE)
        }
        self.assertEqual(
            found,
            {
                "test_only": ("[u8; 32]", True),
                "prod": ("Result<[u8; 32], Error>", False),
                "Bar::digest": ("Hash", False),
                "Bar::only": ("", True),
                "tests::works": ("", True),
                # `any(test, feature = ..)` is not a test-only guard.
                "development": ("", False),
            },
        )
        kinds = [block.kind for block in rust_index.blocks(self.SOURCE)]
        self.assertEqual(kinds.count("fn"), 6)
        self.assertIn("impl", kinds)
        self.assertIn("mod", kinds)
        self.assertEqual(rust_index._impl_name("<T> Trait<T> for Owner<T> where T: Copy "), "Owner")
        self.assertEqual(rust_index._normalize("a/b/../c/./d.rs"), "a/c/d.rs")

    def test_file_status_follows_module_declarations(self) -> None:
        sources = {
            "crates/c/src/lib.rs": "mod a;\n#[cfg(test)]\nmod t;\n#[path = \"moved/place.rs\"]\nmod placed;\nmod inline { mod deep; }\n",
            "crates/c/src/a.rs": "mod child;\n#[cfg(test)]\nmod tests { include!(\"a_cases.rs\"); }\ninclude!(\"a_part.rs\");\n",
            "crates/c/src/a/child.rs": "fn x() {}\n",
            "crates/c/src/a_cases.rs": "fn case() {}\n",
            "crates/c/src/a_part.rs": "fn part() {}\n",
            "crates/c/src/t.rs": "mod nested;\n",
            "crates/c/src/t/nested.rs": "fn y() {}\n",
            "crates/c/src/moved/place.rs": "fn z() {}\n",
            "crates/c/src/inline/deep.rs": "fn d() {}\n",
            "crates/c/src/orphan.rs": "fn o() {}\n",
            "crates/c/src/bin/tool.rs": "fn main() {}\n",
            "crates/c/tests/it.rs": "fn it() {}\n",
            "crates/c/benches/b.rs": "fn b() {}\n",
        }
        modules = rust_index.CrateModules(sources, sources.get)
        expected = {
            "crates/c/src/lib.rs": "production",
            "crates/c/src/a.rs": "production",
            "crates/c/src/a/child.rs": "production",
            "crates/c/src/a_cases.rs": "test-only",
            "crates/c/src/a_part.rs": "production",
            "crates/c/src/t.rs": "test-only",
            "crates/c/src/t/nested.rs": "test-only",
            "crates/c/src/moved/place.rs": "production",
            "crates/c/src/inline/deep.rs": "production",
            "crates/c/src/orphan.rs": "unreached",
            "crates/c/src/bin/tool.rs": "production",
            "crates/c/tests/it.rs": "test-only",
            "crates/c/benches/b.rs": "test-only",
        }
        for path, status in expected.items():
            self.assertEqual(modules.status(path), status, path)

    def test_command_line_lists_functions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.rs"
            path.write_text(self.SOURCE)
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                self.assertEqual(rust_index.main([str(path)]), 0)
            self.assertIn("test-only\ttest_only\t[u8; 32]", printed.getvalue())
            self.assertIn("item\tprod\tResult<[u8; 32], Error>", printed.getvalue())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(rust_index.main([str(Path(directory) / "missing.rs")]), 1)


class CandidateChecks(TreeFixture):
    def candidate_errors(self, spec: dict) -> list:
        return self.errors(checker.check_canonical, spec, ROOT)

    def test_every_changing_role_is_listed_and_the_reverse(self) -> None:
        spec = self.mutated()
        spec["canonical_native_commitment"]["consumers_that_change"].pop()
        self.assertReported(self.candidate_errors(spec), "consumers_that_change")
        spec = self.mutated()
        spec["canonical_native_commitment"]["consumers_that_change"].append(
            {"role": "ledger.identity-hash", "change": "everything"}
        )
        self.assertReported(self.candidate_errors(spec), "consumers_that_change")
        spec = self.mutated()
        spec["canonical_native_commitment"]["provisional"] = []
        self.assertReported(self.candidate_errors(spec), "provisional")
        spec = self.mutated()
        spec["canonical_native_commitment"]["already_blake3"].pop()
        self.assertReported(self.candidate_errors(spec), "already_blake3")
        spec = self.mutated()
        del spec["canonical_native_commitment"]["consumers_that_change"][0]["coordination"]
        self.assertReported(self.candidate_errors(spec), "names what it changes with")
        listed = {entry["role"] for entry in self.spec["canonical_native_commitment"]["consumers_that_change"]}
        for key in ("mkhe.parameter-identity-keccak", "mkhe.release-identity-keccak", "mkhe.source-receipt-identity-keccak"):
            self.assertIn(key, listed)

    def test_a_retained_family_cannot_hold_a_changing_role(self) -> None:
        spec = self.mutated()
        spec["canonical_native_commitment"]["distinct_families_retained"][0]["roles"].append(
            "catalog.exact12-commitment"
        )
        self.assertReported(self.candidate_errors(spec), "is marked as changing")
        # A role that does not move belongs to a retained family.
        spec = self.mutated()
        spec["canonical_native_commitment"]["distinct_families_retained"][0]["roles"].remove("ledger.identity-hash")
        self.assertReported(self.candidate_errors(spec), "role ledger.identity-hash is in no retained family")

    def test_each_named_consumer_needs_a_moving_role_and_a_reading(self) -> None:
        self.assertEqual(checker.REQUIRED_CONSUMERS, ("privacy-catalog", "kaigi", "confidential", "mkhe"))
        # The list of named consumers is not read from the specification.
        spec = self.mutated()
        spec["canonical_native_commitment"]["required_consumers"] = ["privacy-catalog"]
        del spec["canonical_native_commitment"]["consumer_readings"]["mkhe"]
        self.assertReported(self.candidate_errors(spec), "consumer mkhe has no recorded reading")
        spec = self.mutated()
        spec["canonical_native_commitment"]["consumer_readings"]["mkhe"]["roles"].remove("mkhe.release-identity-keccak")
        self.assertReported(self.candidate_errors(spec), "reading of mkhe lists")
        spec = self.mutated()
        for role in spec["digest_roles"]:
            if role["consumer"] == "kaigi":
                role["canonical_native"]["decision"] = "retained-family"
        self.assertReported(self.candidate_errors(spec), "no role of consumer kaigi moves to the candidate")

    def test_a_changed_frame_example_no_longer_matches_the_vectors(self) -> None:
        spec = self.mutated()
        spec["canonical_native_commitment"]["frame"]["examples"][0]["role"] = "other"
        self.assertReported(self.candidate_errors(spec), "differs from the frame")

    def test_the_stated_layout_bounds_and_semantics_are_bound_to_the_encoders(self) -> None:
        frame = lambda spec: spec["canonical_native_commitment"]["frame"]  # noqa: E731
        spec = self.mutated()
        frame(spec)["layout"][7]["kind"] = "bytes-u32-le"
        self.assertReported(self.candidate_errors(spec), "the layout differs from frame version 1")
        spec = self.mutated()
        frame(spec)["layout"][2]["order"], frame(spec)["layout"][3]["order"] = 4, 3
        self.assertReported(self.candidate_errors(spec), "the layout differs from frame version 1")
        spec = self.mutated()
        del frame(spec)["layout"]
        self.assertReported(self.candidate_errors(spec), "the layout differs from frame version 1")
        spec = self.mutated()
        frame(spec)["layout"][4]["tag"] = 40
        self.assertReported(self.candidate_errors(spec), "the layout differs from frame version 1")
        spec = self.mutated()
        frame(spec)["bounds"]["domain_field_max_bytes"] = 8192
        self.assertReported(self.candidate_errors(spec), "bound domain_field_max_bytes differs from MAX_DOMAIN_FIELD_BYTES_V1")
        spec = self.mutated()
        frame(spec)["bounds"]["payload_field_count_max"] = 1
        self.assertReported(self.candidate_errors(spec), "bound payload_field_count_max differs")
        spec = self.mutated()
        frame(spec)["bounds"]["payload_field_max_bytes"] = 16
        self.assertReported(self.candidate_errors(spec), "payload field bound differs")
        spec = self.mutated()
        del frame(spec)["semantics"]
        self.assertReported(self.candidate_errors(spec), "semantics are missing")
        spec = self.mutated()
        frame(spec)["magic_ascii"] = "iroha:native-commitment:frame:v2"
        self.assertReported(self.candidate_errors(spec), "magic differs")
        spec = self.mutated()
        frame(spec)["version"] = 2
        self.assertReported(self.candidate_errors(spec), "version differs")
        # The examples that show the field-boundary semantics must stay and stay distinct.
        spec = self.mutated()
        frame(spec)["examples"] = [example for example in frame(spec)["examples"] if example["name"] != "joined-abcdef"]
        self.assertReported(self.candidate_errors(spec), "examples split-abc-def and joined-abcdef are required")
        spec = self.mutated()
        joined = next(example for example in frame(spec)["examples"] if example["name"] == "joined-abcdef")
        joined["fields_hex"] = ["616263", "646566"]
        self.assertReported(self.candidate_errors(spec), "encode to the same frame")

    def test_candidate_measurements_must_be_exploratory(self) -> None:
        spec = self.mutated()
        measurements = spec["canonical_native_commitment"]["exploratory_measurements"]
        self.assertTrue(measurements, "the exploratory measurement is recorded")
        measurements[0]["label"] = "final"
        self.assertReported(self.candidate_errors(spec), "not labelled exploratory")
        spec = self.mutated()
        spec["canonical_native_commitment"]["exploratory_measurements"][0]["qualification"] = True
        self.assertReported(self.candidate_errors(spec), "claims qualification")

    def test_frame_encoding_is_exact(self) -> None:
        frame = self.spec["canonical_native_commitment"]["frame"]
        example = {
            "algorithm": "a", "catalog": "", "protocol": "p", "profile": "", "role": "r", "phase": "",
            "level": 1, "index": 2, "counter": 3, "fields_hex": ["", "ff"],
        }  # fmt: skip
        expected = (
            b"iroha:native-commitment:frame:v1\0"
            + b"\x01\x01\x00\x00\x00a"
            + b"\x02\x00\x00\x00\x00"
            + b"\x03\x01\x00\x00\x00p"
            + b"\x04\x00\x00\x00\x00"
            + b"\x05\x01\x00\x00\x00r"
            + b"\x06\x00\x00\x00\x00"
            + b"\x07" + (1).to_bytes(8, "little")
            + b"\x08" + (2).to_bytes(8, "little")
            + b"\x09" + (3).to_bytes(8, "little")
            + b"\x0a\x02\x00\x00\x00"
            + b"\x0b" + (0).to_bytes(8, "little")
            + b"\x0b" + (1).to_bytes(8, "little") + b"\xff"
        )  # fmt: skip
        self.assertEqual(checker.encode_candidate_frame(example, frame), expected)
        # The encoder follows the stated layout and enforces the stated bounds.
        swapped = copy.deepcopy(frame)
        swapped["layout"][7]["order"], swapped["layout"][8]["order"] = 9, 8
        self.assertNotEqual(checker.encode_candidate_frame(example, swapped), expected)
        with self.assertRaises(ValueError):
            checker.encode_candidate_frame(dict(example, catalog="c" * 4097), frame)
        tight = copy.deepcopy(frame)
        tight["bounds"]["payload_field_count_max"] = 1
        with self.assertRaises(ValueError):
            checker.encode_candidate_frame(example, tight)
        tight["bounds"].update(payload_field_count_max=2, payload_field_max_bytes=0)
        with self.assertRaises(ValueError):
            checker.encode_candidate_frame(example, tight)
        unknown = copy.deepcopy(frame)
        unknown["layout"][1]["kind"] = "varint"
        with self.assertRaises(ValueError):
            checker.encode_candidate_frame(example, unknown)

    def test_rendered_vectors_are_recomputed_here(self) -> None:
        fixture = self.spec["canonical_native_commitment"]["frame"]["vectors"]
        existing = (ROOT / fixture).read_text(encoding="utf-8")
        self.assertEqual(checker.render_candidate_vectors(self.spec), existing)
        rows = {
            line.split(" ")[1]: line.split(" ") for line in existing.splitlines() if line.startswith("example ")
        }
        self.assertNotEqual(rows["split-abc-def"][-4], rows["joined-abcdef"][-4])
        self.assertNotEqual(rows["no-fields"][-4], rows["one-empty-field"][-4])
        frame = bytes.fromhex(rows["catalog-commitment"][-4])
        self.assertEqual(rows["catalog-commitment"][-3], blake3_reference.blake3(frame).hex())
        self.assertEqual(rows["catalog-commitment"][-2], hashlib.blake2b(frame, digest_size=32).hexdigest())
        self.assertEqual(rows["catalog-commitment"][-1], hashlib.shake_256(frame).hexdigest(48))

    def test_rust_constants_and_label_grammar_are_read_from_source(self) -> None:
        text = "const MAX_PAYLOAD_FIELDS_V1: usize = 65_535;\nconst OTHER: u8 = 1;\n"
        self.assertEqual(checker.rust_usize_constant(text, "MAX_PAYLOAD_FIELDS_V1"), 65535)
        self.assertIsNone(checker.rust_usize_constant(text, "OTHER"))
        grammar = checker.label_grammar(ROOT)
        self.assertTrue(grammar.match("h1.native-digest:frame_1"))
        self.assertIsNone(grammar.match("has space"))
        self.assertIsNone(grammar.match("a" * 97))
        self.assertTrue(grammar.match("a" * 96))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / checker.LABEL_GRAMMAR_SOURCE
            target.parent.mkdir(parents=True)
            source = (ROOT / checker.LABEL_GRAMMAR_SOURCE).read_text(encoding="utf-8")
            target.write_text(source.replace("b'_' | b'.' | b':' | b'-'", "b'_' | b'/'").replace("= 96;", "= 8;"))
            narrowed = checker.label_grammar(root)
            self.assertTrue(narrowed.match("a_b/c"))
            self.assertIsNone(narrowed.match("a.b"))
            self.assertIsNone(narrowed.match("a" * 9))
            target.write_text("pub const MAX_LABEL_BYTES: usize = 96;\n")
            with self.assertRaises(ValueError):
                checker.label_grammar(root)


class Blake3Reference(unittest.TestCase):
    def test_published_vectors_and_tree_shapes(self) -> None:
        self.assertEqual(blake3_reference.self_check(), [])
        self.assertEqual(
            blake3_reference.blake3(b"").hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        )
        # The extended output starts with the default output, and every prefix length is served.
        message = bytes(index % 251 for index in range(1025))
        long = blake3_reference.blake3(message, 131)
        self.assertEqual(long[:32], blake3_reference.blake3(message))
        self.assertEqual(len(long), 131)
        self.assertNotEqual(blake3_reference.blake3(message), blake3_reference.blake3(message[:-1]))

    def test_a_wrong_implementation_is_reported(self) -> None:
        original = blake3_reference.MESSAGE_PERMUTATION
        try:
            blake3_reference.MESSAGE_PERMUTATION = tuple(range(16))
            # The empty input hashes an all-zero block, which no permutation changes.
            self.assertGreaterEqual(len(blake3_reference.self_check()), 4)
            with contextlib.redirect_stderr(io.StringIO()) as printed:
                self.assertEqual(blake3_reference.main([]), 1)
            self.assertIn("published", printed.getvalue())
        finally:
            blake3_reference.MESSAGE_PERMUTATION = original

    def test_command_line_hashes_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.bin"
            path.write_bytes(b"")
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                self.assertEqual(blake3_reference.main([str(path)]), 0)
            self.assertTrue(printed.getvalue().startswith("af1349b9f5f9a1a6"))
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                self.assertEqual(blake3_reference.main([]), 0)
            self.assertIn("published BLAKE3 vectors match", printed.getvalue())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(blake3_reference.main([str(Path(directory) / "missing")]), 1)


class PoseidonChecks(TreeFixture):
    def poseidon_errors(self, spec: dict) -> list:
        return self.errors(checker.check_poseidon, spec, ROOT)

    def test_recorded_facts_must_equal_the_regeneration(self) -> None:
        spec = self.mutated()
        spec["bn254_poseidon"]["regeneration"]["widths"]["6"]["margin_rule_partial_rounds"] = 56
        self.assertReported(self.poseidon_errors(spec), "regeneration facts differ")

    def test_every_defect_must_stay_recorded(self) -> None:
        for identifier in checker.REQUIRED_BN254_DEFECTS:
            spec = self.mutated()
            spec["bn254_poseidon"]["defects"] = [
                defect for defect in spec["bn254_poseidon"]["defects"] if defect["id"] != identifier
            ]
            self.assertReported(self.poseidon_errors(spec), f"defect {identifier} is missing")
        spec = self.mutated()
        spec["bn254_poseidon"]["defects"][0]["owner_task"] = "H.1"
        self.assertReported(self.poseidon_errors(spec), "belong to F.5")
        # The mode finding is anchored on the helper bodies.
        spec = self.mutated()
        mode = next(defect for defect in spec["bn254_poseidon"]["defects"] if defect["id"] == "BN254-POSEIDON-D3")
        mode["sites"][0]["literals"] = ["let mut state = [Fr::from(a), Fr::from(b), DOMAIN_TAG];"]
        self.assertReported(self.poseidon_errors(spec), "BN254-POSEIDON-D3")

    def test_an_unlisted_helper_consumer_fails(self) -> None:
        spec = self.mutated()
        consumers = spec["bn254_poseidon"]["consumers"]
        removed = sorted(consumers)[0]
        del consumers[removed]
        errors = self.poseidon_errors(spec)
        self.assertTrue(any("helper consumers differ" in error and removed in error for error in errors))
        self.assertTrue(any("poseidon6" in needles for needles in self.spec["bn254_poseidon"]["consumers"].values()))

    def test_generator_reproduces_the_repository_and_the_published_tables(self) -> None:
        tables = poseidon.parse_repository_table(ROOT)
        for width in (3, 6):
            generated = poseidon.generate_parameters(width, 8, poseidon.PARTIAL_ROUNDS_BY_WIDTH[width])
            self.assertEqual(generated, tables[width])
            self.assertEqual(poseidon.table_sha256(*generated), poseidon.REPOSITORY_TABLE_SHA256[width])
        published = poseidon.generate_parameters(3, 8, 57)
        self.assertEqual(
            tuple(published[0][0] + published[0][1]), poseidon.PUBLISHED_WIDTH3_FIRST_ROUND_CONSTANTS
        )
        self.assertEqual(tuple(tuple(row) for row in published[1]), poseidon.PUBLISHED_WIDTH3_MDS)
        self.assertEqual(published[1], tables[3][1])

    def test_round_number_rule(self) -> None:
        self.assertEqual(poseidon.minimum_partial_rounds(3, 8), {"without_margin": 52, "with_margin": 56})
        self.assertEqual(poseidon.minimum_partial_rounds(6, 8), {"without_margin": 53, "with_margin": 57})
        self.assertEqual(poseidon.recommended_round_numbers(3)["partial_rounds"], 56)
        self.assertEqual(poseidon.recommended_round_numbers(6)["partial_rounds"], 57)
        self.assertTrue(poseidon.round_number_bounds(6, 6, 53)["satisfied"])
        self.assertFalse(poseidon.round_number_bounds(6, 6, 52)["satisfied"])

    def test_linear_algebra_helpers(self) -> None:
        identity = [[1, 0], [0, 1]]
        self.assertEqual(poseidon.determinant(identity), 1)
        self.assertEqual(poseidon.determinant([[1, 2], [2, 4]]), 0)
        self.assertEqual(poseidon.square_minor_report(identity), {"square_minors": 5, "zero_minors": 2})
        tables = poseidon.parse_repository_table(ROOT)
        self.assertEqual(poseidon.square_minor_report(tables[3][1]), {"square_minors": 19, "zero_minors": 0})
        # A matrix that keeps the plane x_0 = 0 invariant fails the inactive screen.
        blocked = [[1, 0, 0], [0, 2, 1], [0, 1, 1]]
        self.assertEqual(poseidon.linear_layer_screens(blocked)["inactive_invariant_dimension"], 2)
        self.assertFalse(poseidon.linear_layer_screens(blocked)["krylov_ranks_all_full"])
        self.assertEqual(poseidon.linear_layer_screens(tables[3][1])["inactive_invariant_dimension"], 0)

    def test_permutation_and_helpers_agree_with_the_pinned_rust_vectors(self) -> None:
        tables = poseidon.parse_repository_table(ROOT)
        # Vectors of the Rust test `hash_bytes_known_vectors`.
        self.assertEqual(
            poseidon.hash_bytes(b"", tables[3]).to_bytes(32, "little").hex(),
            "bd329b0ff084555f0f93c53e8d7a00cb8d8989214f112c26e5e52782bb38eb00",
        )
        self.assertEqual(
            poseidon.hash_bytes(b"poseidon", tables[3]).to_bytes(32, "little").hex(),
            "dea4301e1991400e415eb269a3e56c6d17a2acd1b8418a9eac89e604a145380e",
        )
        self.assertEqual(poseidon.hash2(1, 2, tables[3]), poseidon.permute([2 << 64, 1, 2], *tables[3])[1])
        state = poseidon.permute([6 << 64, 1, 1, 1, 1, 1], *tables[6])
        state[1] = (state[1] + 1) % poseidon.BN254_FR
        self.assertEqual(poseidon.hash6([1] * 6, tables[6]), poseidon.permute(state, *tables[6])[1])
        report = poseidon.build_report(ROOT)
        fixture = poseidon.render_vector_fixture(report["vectors"])
        self.assertEqual((ROOT / poseidon.VECTOR_FIXTURE).read_text(encoding="utf-8"), fixture)
        self.assertEqual(report["total_field_elements"], 648)
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            self.assertEqual(poseidon.main(["--root", str(ROOT), "--print-vectors"]), 0)
        self.assertEqual(json.loads(printed.getvalue()), report["vectors"])

    def test_a_changed_table_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / poseidon.REPOSITORY_TABLE
            target.parent.mkdir(parents=True)
            text = (ROOT / poseidon.REPOSITORY_TABLE).read_text(encoding="utf-8")
            target.write_text(text.replace("0x6e, 0x8e, 0xcd", "0x6f, 0x8e, 0xcd", 1), encoding="utf-8")
            with self.assertRaises(ValueError):
                poseidon.build_report(root)
            with contextlib.redirect_stderr(io.StringIO()) as printed:
                self.assertEqual(poseidon.main(["--root", str(root)]), 1)
            self.assertIn("differs from the Grain/Cauchy regeneration", printed.getvalue())


class PostQuantumChecks(TreeFixture):
    def pq_errors(self, spec: dict, root: Path = ROOT, files: list | None = None) -> list:
        report = checker.Report()
        checker.check_post_quantum(
            root, spec, self.derived, self.files if files is None else files, report
        )
        return report.errors

    def test_lock_packages_call_sites_and_labels_follow_the_tree(self) -> None:
        spec = self.mutated()
        spec["post_quantum"]["lock_packages"][0]["version"] = "9.9.9"
        self.assertReported(self.pq_errors(spec), "Cargo.lock packages")
        spec = self.mutated()
        removed = spec["post_quantum"]["call_sites"].pop()
        self.assertTrue(any("call sites differ" in error and removed in error for error in self.pq_errors(spec)))
        spec = self.mutated()
        removed = spec["post_quantum"]["legacy_labels"]["files"].pop()
        self.assertTrue(any("superseded algorithm label" in error and removed in error for error in self.pq_errors(spec)))
        names = [package["name"] for package in self.spec["post_quantum"]["lock_packages"]]
        self.assertEqual(names, ["pqcrypto-internals", "pqcrypto-mldsa", "pqcrypto-mlkem", "pqcrypto-traits"])

    def test_parameter_sets_and_tests_are_checked(self) -> None:
        spec = self.mutated()
        spec["post_quantum"]["parameter_sets"][0]["official_nistkat_sha256"] = "00" * 32
        self.assertReported(self.pq_errors(spec), "digest differs")
        spec = self.mutated()
        spec["post_quantum"]["parameter_sets"][0]["encoded_bytes"]["public_key"] = 801
        self.assertReported(self.pq_errors(spec), "encoded lengths differ")
        spec = self.mutated()
        spec["post_quantum"]["parameter_sets"].pop()
        self.assertReported(self.pq_errors(spec), "is not recorded")
        spec = self.mutated()
        spec["post_quantum"]["tests"][0]["name"] = "renamed_test"
        self.assertReported(self.pq_errors(spec), "renamed_test")
        spec = self.mutated()
        spec["post_quantum"]["legacy_labels"]["wire_visible"][0]["replacement_changes"] = ""
        self.assertReported(self.pq_errors(spec), "wire change is missing")
        # The official digests are pinned in the Rust tests as well as in the script.
        spec = self.mutated()
        spec["post_quantum"]["parameter_sets"][0]["rust_pin"]["path"] = "crates/soranet_pq/src/mlkem.rs"
        self.assertReported(self.pq_errors(spec), "ml-kem-512 Rust pin")
        for suite, digest in kat.OFFICIAL_NISTKAT_SHA256.items():
            entry = next(item for item in self.spec["post_quantum"]["parameter_sets"] if item["id"] == suite)
            self.assertIn(digest, (ROOT / entry["rust_pin"]["path"]).read_text(encoding="utf-8"), suite)

    def test_required_findings_and_in_tree_implementations(self) -> None:
        for identifier in checker.REQUIRED_PQ_FINDINGS:
            spec = self.mutated()
            spec["post_quantum"]["findings"] = [
                finding for finding in spec["post_quantum"]["findings"] if finding["id"] != identifier
            ]
            self.assertReported(self.pq_errors(spec), f"finding {identifier} is missing")
        spec = self.mutated()
        spec["post_quantum"]["findings"] = []
        self.assertEqual(sum("is missing" in error for error in self.pq_errors(spec)), len(checker.REQUIRED_PQ_FINDINGS) + 0)
        spec = self.mutated()
        spec["post_quantum"]["in_tree_implementations"][0]["symbol"] = "//! A standard FN-DSA implementation."
        self.assertReported(self.pq_errors(spec), "in-tree implementation")
        spec = self.mutated()
        spec["post_quantum"]["in_tree_implementations"][0]["finding"] = "PQ-D9"
        self.assertReported(self.pq_errors(spec), "unknown finding")
        self.assertRegex("fn-dsa", checker.PQ_PACKAGE)
        self.assertRegex("falcon-rust", checker.PQ_PACKAGE)

    def test_a_bouncycastle_post_quantum_import_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "kotlin/core-jvm/src/main/java/Pq.kt"
            source.parent.mkdir(parents=True)
            source.write_text("import org.bouncycastle.pqc.crypto.crystals.kyber.KyberEngine\n")
            plain = root / "kotlin/core-jvm/src/main/java/Digest.kt"
            plain.write_text("import org.bouncycastle.crypto.digests.SHA256Digest\n")
            files = ["kotlin/core-jvm/src/main/java/Digest.kt", "kotlin/core-jvm/src/main/java/Pq.kt"]
            errors = self.pq_errors(self.mutated(), root=root, files=files)
            self.assertReported(errors, "Pq.kt uses the BouncyCastle post-quantum class")
            self.assertFalse(any("Digest.kt" in error for error in errors))
        spec = self.mutated()
        spec["post_quantum"]["jvm_bouncycastle"]["manifests"][0]["symbol"] = 'bouncycastle = "0.0.0"'
        self.assertReported(self.pq_errors(spec), "BouncyCastle manifest")

    def test_superseded_package_names(self) -> None:
        for name in ("pqcrypto-kyber", "pqcrypto-dilithium", "kyber", "crystals-dilithium", "ntru", "sphincsplus", "sphincs-plus", "pqcrypto-sphincsplus"):
            self.assertTrue(checker.SUPERSEDED_PQ_PACKAGES.search(name) or name == "sphincsplus", name)
        for name in ("untrusted", "pqcrypto-mlkem", "pqcrypto-mldsa", "pqcrypto-internals", "pqcrypto-traits", "sabertooth"):
            self.assertIsNone(checker.SUPERSEDED_PQ_PACKAGES.search(name), name)

    def test_a_superseded_package_in_the_lockfile_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.lock").write_text(
                '[[package]]\nname = "pqcrypto-kyber"\nversion = "0.8.1"\nchecksum = "aa"\n\n'
                '[[package]]\nname = "untrusted"\nversion = "0.9.0"\n',
                encoding="utf-8",
            )
            self.assertEqual(
                checker.lock_packages(root),
                [
                    {"name": "pqcrypto-kyber", "version": "0.8.1", "checksum": "aa"},
                    {"name": "untrusted", "version": "0.9.0"},
                ],
            )
            errors = self.pq_errors(self.mutated(), root=root, files=[])
            self.assertIn("post-quantum: Cargo.lock holds superseded package pqcrypto-kyber", errors)
            self.assertFalse(any("untrusted" in error for error in errors))

    def test_drbg_and_aes_match_published_values(self) -> None:
        self.assertEqual(
            kat.aes256_encrypt_block(bytes(range(32)), bytes.fromhex("00112233445566778899aabbccddeeff")).hex(),
            "8ea2b7ca516745bfeafc49904b496089",
        )
        inputs = kat.kat_inputs()
        self.assertEqual(
            inputs["seed"].hex().upper(),
            "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7"
            "056A8C266F9EF97ED08541DBD2E1FFA1",
        )
        self.assertEqual(inputs["mlkem_keypair_coins"][:32], inputs["mldsa_keygen_seed"])
        self.assertEqual([len(value) for value in inputs.values()], [48, 64, 32, 33, 32, 32])
        with self.assertRaises(ValueError):
            kat.NistKatDrbg(bytes(47))
        with self.assertRaises(ValueError):
            kat.aes256_encrypt_block(bytes(31), bytes(16))

    def test_response_fixtures_match_and_a_changed_response_fails(self) -> None:
        self.assertEqual(kat.check_fixtures(ROOT), [])
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            self.assertEqual(kat.main(["--root", str(ROOT)]), 0)
        self.assertIn("6 responses match", printed.getvalue())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / kat.FIXTURE_DIR
            target.mkdir(parents=True)
            for name in ["inputs.txt"] + [f"{suite}.rsp" for suite in kat.OFFICIAL_NISTKAT_SHA256]:
                (target / name).write_bytes((ROOT / kat.FIXTURE_DIR / name).read_bytes())
            self.assertEqual(kat.check_fixtures(root), [])
            changed = target / "ml-kem-768.rsp"
            changed.write_text(changed.read_text().replace("ss = ", "ss = 00", 1))
            errors = kat.check_fixtures(root)
            self.assertEqual(len(errors), 1)
            self.assertIn("differs from the official nistkat-sha256", errors[0])
            (target / "ml-dsa-65.rsp").unlink()
            (target / "inputs.txt").write_text("seed 00\n")
            errors = kat.check_fixtures(root)
            self.assertEqual(len(errors), 3)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(kat.main(["--root", str(root)]), 1)
            self.assertEqual(kat.main(["--root", str(root), "--write-inputs"]), 0)
            self.assertEqual((target / "inputs.txt").read_text(), kat.render_inputs_fixture())


class WorkloadAndTranscriptChecks(TreeFixture):
    def workload_errors(self, spec: dict) -> list:
        return self.errors(checker.check_workloads, spec, ROOT)

    def transcript_errors(self, spec: dict) -> list:
        return self.errors(checker.check_transcript, spec, ROOT)

    def test_workloads_are_exploratory_and_complete(self) -> None:
        cases = (
            (lambda w: w["definitions"][0].__setitem__("label", "final"), "not labelled exploratory"),
            (lambda w: w["definitions"][0].__setitem__("phases", ["has space"]), "outside the label grammar"),
            (lambda w: w["definitions"][0].__setitem__("id", "bad id"), "outside the measurement label grammar"),
            (lambda w: w["definitions"][0].__setitem__("shapes", {}), "`shapes` is missing"),
            (lambda w: w["definitions"][0].__setitem__("measured", []), "`measured` is missing"),
            (lambda w: w["definitions"][0].__setitem__("primitives", ["blake9"]), "unknown primitive"),
            (lambda w: w["definitions"][0].__setitem__("roles", ["missing.role"]), "unknown role"),
            (lambda w: w["definitions"].append(copy.deepcopy(w["definitions"][0])), "listed twice"),
            (lambda w: w.__setitem__("label", "final"), "section is not labelled exploratory"),
            (lambda w: w.__setitem__("final_measurement_task", "H.1"), "belongs to H.3"),
            (lambda w: w["state_candidates"].__setitem__("owner_task", "H.1"), "belongs to G.2"),
            (lambda w: w.__setitem__("backend_inventory", "specs/missing.json"), "backend inventory"),
        )
        for mutate, expected in cases:
            spec = self.mutated()
            mutate(spec["workloads"])
            self.assertReported(self.workload_errors(spec), expected)

    def test_a_state_workload_is_rejected(self) -> None:
        workload = {
            "id": "wg.state-tree", "label": "exploratory", "kind": "state", "question": "q", "shapes": ["s"],
            "measured": ["m"], "phases": ["p"], "flow": "f", "backend_consumers": [],
        }  # fmt: skip
        spec = self.mutated()
        spec["workloads"]["definitions"].append(workload)
        errors = self.workload_errors(spec)
        self.assertReported(errors, "kind 'state' is not a workload kind of this file")
        self.assertReported(errors, "State tree and hash candidates are measured by G.2")
        # Declaring the kind, or disguising the workload under another kind, does not admit it.
        spec = self.mutated()
        spec["workloads"]["kinds"]["state"] = "State trees"
        spec["workloads"]["definitions"].append(workload)
        self.assertReported(self.workload_errors(spec), "the workload kinds are missing or include State")
        spec = self.mutated()
        spec["workloads"]["definitions"].append(
            dict(workload, id="h1.native.tree", kind="native-digest", question="Cost of the keyed State root per update")
        )
        self.assertReported(self.workload_errors(spec), "State tree and hash candidates are measured by G.2")
        self.assertFalse(any(checker.STATE_WORKLOAD.search(item["id"] + " " + item["question"]) for item in self.spec["workloads"]["definitions"]))

    def test_every_backend_consumer_has_a_workload(self) -> None:
        spec = self.mutated()
        spec["workloads"]["definitions"] = [
            workload for workload in spec["workloads"]["definitions"] if workload["id"] != "h1.shared-backend.pq-masp"
        ]
        self.assertReported(self.workload_errors(spec), "no workload for backend consumers ['pq-masp']")
        spec = self.mutated()
        spec["workloads"]["definitions"][3]["backend_consumers"] = ["unknown-consumer"]
        self.assertReported(self.workload_errors(spec), "'unknown-consumer' is not in")

    def test_a_workload_measurement_cannot_claim_qualification(self) -> None:
        measurement = {
            "label": "exploratory", "qualification": False, "source_commit": "c", "hardware": "h",
            "command": "x", "conditions": "y", "results": {"a": 1},
        }  # fmt: skip
        spec = self.mutated()
        spec["workloads"]["definitions"][0]["exploratory_measurements"] = [measurement]
        self.assertEqual(self.workload_errors(spec), [])
        spec["workloads"]["definitions"][0]["exploratory_measurements"][0]["qualification"] = True
        self.assertReported(self.workload_errors(spec), "claims qualification")
        spec["workloads"]["definitions"][0]["exploratory_measurements"][0] = {"label": "exploratory", "qualification": False}
        self.assertReported(self.workload_errors(spec), "`hardware` is missing")

    def test_transcript_requirements_keep_their_order_and_claims(self) -> None:
        cases = (
            (lambda t: t["binding_order"].pop(2), "not a complete sequence"),
            (lambda t: t["binding_order"][0].__setitem__("before", ""), "`binds` or `before` is missing"),
            (lambda t: t["security_claims"].__setitem__("qrom", ""), "the qrom claim is missing"),
            (lambda t: t.__setitem__("grinding", []), "`grinding` is missing"),
            (lambda t: t.__setitem__("consumed_by", "H.3"), "the consumer is H.2"),
            (lambda t: t["current_implementations"][0].__setitem__("symbol", "struct Missing"), "no longer contains"),
        )
        for mutate, expected in cases:
            spec = self.mutated()
            mutate(spec["shared_transcript_requirements"])
            self.assertReported(self.transcript_errors(spec), expected)
        order = self.spec["shared_transcript_requirements"]["binding_order"]
        self.assertIn("grinding nonce", order[5]["binds"])
        self.assertEqual(order[5]["before"], "query positions")

    def test_transcript_engines_follow_the_backend_inventory(self) -> None:
        section = self.spec["shared_transcript_requirements"]
        inventory = json.loads((ROOT / section["engine_inventory"]).read_text(encoding="utf-8"))
        self.assertEqual(
            sorted(site["engine"] for site in section["current_implementations"]),
            sorted(entry["id"] for entry in inventory["engines"]),
        )
        spec = self.mutated()
        spec["shared_transcript_requirements"]["current_implementations"].pop()
        self.assertReported(self.transcript_errors(spec), "differ from those of")
        spec = self.mutated()
        implementations = spec["shared_transcript_requirements"]["current_implementations"]
        implementations.append(copy.deepcopy(implementations[0]))
        self.assertReported(self.transcript_errors(spec), "listed twice")
        spec = self.mutated()
        driver = next(site for site in spec["shared_transcript_requirements"]["current_implementations"] if site["engine"] == "zk-x509-driver")
        driver["own_transcript"] = True
        self.assertReported(self.transcript_errors(spec), "own_transcript is True")
        spec = self.mutated()
        spec["shared_transcript_requirements"]["engine_inventory"] = "specs/missing.json"
        self.assertReported(self.transcript_errors(spec), "engine inventory")


class SemanticProfiles(TreeFixture):
    """The H.2 section: identities, dispositions, the frozen transcript and measurement binding."""

    TRANSCRIPT = "fastpq.transcript.q77.v1"
    NATIVE = "native.commitment.blake3-256.frame-v1"

    def profile_errors(self, spec: dict) -> list:
        return self.errors(checker.check_semantic_profiles, spec, ROOT)

    @staticmethod
    def profile(spec: dict, name: str) -> dict:
        section = spec["semantic_profiles"]
        return next(entry for entry in section["profiles"] + section["retained_profiles"] if entry["name"] == name)

    @staticmethod
    def parameter(profile: dict, key: str) -> dict:
        return next(entry for entry in profile["parameters"] if entry["key"] == key)

    @staticmethod
    def measurement(identities: dict) -> dict:
        return {
            "id": "test/measurement", "label": "exploratory", "qualification": False, "source_commit": "c",
            "hardware": "h", "command": "x", "conditions": "y", "results": {"a": 1}, "profile_identities": identities,
            "measurement_scope": "workload-profiles",
        }  # fmt: skip

    @staticmethod
    def workload(spec: dict, identifier: str) -> dict:
        return next(entry for entry in spec["workloads"]["definitions"] if entry["id"] == identifier)

    def test_tracked_section_is_consistent(self) -> None:
        self.assertEqual(self.profile_errors(self.spec), [])
        section = self.spec["semantic_profiles"]
        self.assertEqual(set(section["role_dispositions"]), {role["key"] for role in self.spec["digest_roles"]})
        self.assertEqual(len(section["profiles"]), 7)
        self.assertEqual(section["shared_transcript"]["grinding"]["bits"], 0)

    def test_reference_frame_and_identity_vectors(self) -> None:
        profile_reference.self_test()
        frame = profile_reference.encode_profile("key-derivation", "x", [])
        self.assertEqual(frame.hex(), "69726f68613a73656d616e7469632d70726f66696c653a7631000e0000006b65792d64657269766174696f6e010000007800000000")
        self.assertEqual(profile_reference.profile_identity(frame), "3d7890a841af88bace65d95a3a7edcdbb8091b2ce94c9ecd9325fc67ea7b8467")
        # The Norito framing subset reproduces a statement context that the Rust tests pin independently.
        statement = b"complete public context without a private witness"
        model = profile_reference.TranscriptModel(
            self.profile(self.spec, self.TRANSCRIPT),
            "iroha-privacy-exact12-v1",
            "profile-binding:fixed-candidate:v1",
            self.spec["semantic_profiles"]["shared_transcript"]["known_answers"]["inputs"]["layout"],
            statement,
        )
        self.assertEqual(len(model.context), 401)
        self.assertEqual(model.context[:22].hex(), "4e52543000001ec15f6de0edd014c1b2850c0a244fad")
        self.assertEqual(model.context[31:39].hex(), "8d93a47c1df47da9")
        self.assertEqual(model.leaf(1, 0, 0, bytes(301 * 8)).hex(), "38ef710754bc29fa9c8b489157fb669c84db05d3f4f63189f21cee014a0b0e29")
        with self.assertRaises(profile_reference.Abort):
            model.commit(bytes(32))
        with self.assertRaises(profile_reference.Abort):
            model.queries(bytes(744))
        with self.assertRaises(profile_reference.Abort):
            model.ood_point(bytes(80))

    def test_every_identity_is_recomputed_from_its_parameters(self) -> None:
        for name in [entry["name"] for entry in self.spec["semantic_profiles"]["profiles"]]:
            spec = self.mutated()
            self.profile(spec, name)["parameters"][0]["value"] = 2
            self.assertReported(self.profile_errors(spec), f"profile {name}: recorded identity")
        spec = self.mutated()
        self.profile(spec, self.NATIVE)["parameters"].append({"key": "Bad Key", "type": "u64", "value": 1})
        self.assertReported(self.profile_errors(spec), "not a canonical profile")
        spec = self.mutated()
        spec["semantic_profiles"]["profiles"].append(copy.deepcopy(self.profile(spec, self.NATIVE)))
        self.assertReported(self.profile_errors(spec), "listed twice")

    def test_a_changed_frozen_profile_invalidates_its_measurements(self) -> None:
        current = self.profile(self.spec, self.TRANSCRIPT)["identity"]
        spec = self.mutated()
        workload = self.workload(spec, "h1.transcript.candidates")
        tracked = [entry["id"] for entry in workload["exploratory_measurements"]]
        self.assertTrue(tracked)
        workload["exploratory_measurements"].append(self.measurement({self.TRANSCRIPT: current}))
        self.assertEqual([error for error in self.profile_errors(spec) if "inapplicable" in error], [])
        # Change one frozen parameter and re-identify the profile: the measurement names the old identity.
        profile = self.profile(spec, self.TRANSCRIPT)
        self.parameter(profile, "queries")["value"] = 78
        profile["identity"] = profile_reference.identity_of(profile)
        self.assertNotEqual(profile["identity"], current)
        errors = self.profile_errors(spec)
        self.assertReported(errors, "measurement test/measurement: inapplicable")
        self.assertReported(errors, f"it names identity {current}")
        # The measurement the tracked record holds is invalidated in the same way.
        for identifier in tracked:
            self.assertReported(errors, f"measurement {identifier}: inapplicable")
        # Moving it to the inapplicable list clears that error; nothing else is needed.
        moved = workload["exploratory_measurements"].pop()
        spec["semantic_profiles"]["measurement_binding"]["inapplicable_measurements"].append(moved)
        self.assertEqual([error for error in self.profile_errors(spec) if "test/measurement" in error], [])
        # An inapplicable entry whose identities are all current belongs with its workload.
        spec = self.mutated()
        spec["semantic_profiles"]["measurement_binding"]["inapplicable_measurements"].append(self.measurement({self.TRANSCRIPT: current}))
        self.assertReported(self.profile_errors(spec), "every identity it names is current")

    def test_a_measurement_names_the_identities_it_measured(self) -> None:
        current = self.profile(self.spec, self.TRANSCRIPT)["identity"]
        cases = (
            (lambda m: m.pop("profile_identities"), "`profile_identities` is missing"),
            (lambda m: m.__setitem__("profile_identities", {}), "must name the complete profile set"),
            (lambda m: m.__setitem__("profile_identities", {"unknown.profile": current}), "names the unknown profile"),
            (lambda m: m.__setitem__("profile_identities", {self.NATIVE: current}), "that its workload does not depend on"),
        )
        for mutate, expected in cases:
            spec = self.mutated()
            measurement = self.measurement({self.TRANSCRIPT: current})
            mutate(measurement)
            self.workload(spec, "h1.transcript.candidates")["exploratory_measurements"] = [measurement]
            self.assertReported(self.profile_errors(spec), expected)
        spec = self.mutated()
        measurement = self.measurement({})
        measurement["profile_binding"] = "none: bare primitives"
        self.workload(spec, "h1.transcript.candidates")["exploratory_measurements"] = [measurement]
        self.assertReported(self.profile_errors(spec), "must name the complete profile set")
        self.assertReported(self.profile_errors(spec), "retired `profile_binding`")
        # The tracked record binds at least one real measurement to a frozen identity.
        bound = [
            identities
            for _, _, _, entry in checker.recorded_measurements(self.spec)
            if (identities := entry.get("profile_identities"))
        ]
        self.assertTrue(bound)

    def test_measurement_scope_cannot_downgrade_a_frozen_run(self) -> None:
        for scope in (None, "bare-primitives", "unknown"):
            spec = self.mutated()
            measurement = self.workload(spec, "h1.transcript.candidates")["exploratory_measurements"][0]
            measurement["measurement_scope"] = scope
            measurement["profile_identities"] = {}
            measurement["scope_note"] = "No frozen profile was measured."
            errors = self.profile_errors(spec)
            self.assertReported(errors, "`measurement_scope` must be 'workload-profiles'")
            self.assertReported(errors, "must name the complete profile set")

    def test_workload_measurement_cannot_omit_one_of_multiple_profiles(self) -> None:
        spec = self.mutated()
        workload = self.workload(spec, "h1.transcript.candidates")
        workload["roles"].append("catalog.exact12-commitment")
        checker.refresh_semantic_profiles(spec)
        self.assertEqual(set(workload["profiles"]), {self.TRANSCRIPT, self.NATIVE})
        measurement = workload["exploratory_measurements"][0]
        self.assertReported(self.profile_errors(spec), "must name the complete profile set")
        measurement["profile_identities"][self.NATIVE] = self.profile(spec, self.NATIVE)["identity"]
        self.assertEqual([error for error in self.profile_errors(spec) if "measurement " in error], [])

    def test_bare_primitive_comparisons_cannot_claim_profile_evidence(self) -> None:
        spec = self.mutated()
        measurement = spec["canonical_native_commitment"]["exploratory_measurements"][0]
        self.assertEqual(measurement["measurement_scope"], "bare-primitives")
        self.assertEqual(measurement["profile_identities"], {})
        self.assertEqual(self.profile_errors(spec), [])
        measurement["profile_identities"][self.NATIVE] = self.profile(spec, self.NATIVE)["identity"]
        measurement["measurement_scope"] = "workload-profiles"
        errors = self.profile_errors(spec)
        self.assertReported(errors, "`measurement_scope` must be 'bare-primitives'")
        self.assertReported(errors, "must name the complete profile set")
        measurement["profile_identities"] = {}
        measurement["measurement_scope"] = "bare-primitives"
        measurement.pop("scope_note")
        self.assertReported(self.profile_errors(spec), "explains its scope in `scope_note`")

    def test_workloads_name_the_profiles_of_their_roles(self) -> None:
        for workload in self.spec["workloads"]["definitions"]:
            names, pending = checker.workload_profiles(self.spec, workload)
            self.assertEqual(workload["profiles"], names)
            self.assertEqual(workload.get("profiles_not_frozen", []), pending)
            if workload["kind"] == "shared-backend":
                self.assertIn(self.TRANSCRIPT, names)
        spec = self.mutated()
        self.workload(spec, "h1.shared-backend.axt")["profiles"] = []
        self.assertReported(self.profile_errors(spec), "`profiles` differs from the profiles of its roles")
        spec = self.mutated()
        self.workload(spec, "h1.in-circuit-digest.air-cost").pop("profiles_not_frozen")
        self.assertReported(self.profile_errors(spec), "`profiles_not_frozen` differs")
        # One identity names the ordered profiles of a workload in the bounded harness field.
        workload = self.workload(self.spec, "h1.shared-backend.axt")
        self.assertEqual(workload["profiles"], [self.TRANSCRIPT])
        transcript = self.profile(self.spec, self.TRANSCRIPT)["identity"]
        self.assertEqual(workload["profile_set_identity"], profile_reference.profile_set_identity([transcript]))
        self.assertNotEqual(workload["profile_set_identity"], transcript)
        field = f"semantic={workload['profile_set_identity']}+release"
        self.assertLessEqual(len(field), 160)
        self.assertRegex(field, r"\A[A-Za-z0-9_.:/+@=,-]+\Z")
        spec = self.mutated()
        self.workload(spec, "h1.shared-backend.axt")["profile_set_identity"] = "00" * 32
        self.assertReported(self.profile_errors(spec), "`profile_set_identity` differs")
        spec = self.mutated()
        profile = self.profile(spec, self.TRANSCRIPT)
        self.parameter(profile, "queries")["value"] = 78
        profile["identity"] = profile_reference.identity_of(profile)
        self.assertReported(self.profile_errors(spec), "workload h1.shared-backend.axt: `profile_set_identity` differs")
        checker.refresh_semantic_profiles(spec)
        self.assertNotEqual(self.workload(spec, "h1.shared-backend.axt")["profile_set_identity"], workload["profile_set_identity"])
        with self.assertRaises(profile_reference.ProfileError):
            profile_reference.profile_set_identity(["00"])
        self.assertIsNone(checker.workload_profile_set(self.spec, ["unknown.profile"]))
        self.assertIsNone(checker.workload_profile_set(self.spec, []))

    def test_retained_algorithm_is_owned_by_the_role_not_global_prose(self) -> None:
        spec = self.mutated()
        before = copy.deepcopy(spec["semantic_profiles"]["retained_profiles"])
        next(p for p in spec["digest_primitives"] if p["id"] == "poseidon")["algorithm"] = "unrelated primitive summary"
        checker.refresh_semantic_profiles(spec)
        self.assertEqual(spec["semantic_profiles"]["retained_profiles"], before)
        self.assertEqual(self.profile_errors(spec), self.profile_errors(self.spec))
        role = self.role(spec, "kaigi.relation-poseidon")
        role["algorithm"] += "; changed relation semantics"
        self.assertReported(self.profile_errors(spec), "parameters differ from the role record")
        checker.refresh_semantic_profiles(spec)
        changed = [p["name"] for p, q in zip(spec["semantic_profiles"]["retained_profiles"], before, strict=True) if p != q]
        self.assertEqual(changed, ["retained.kaigi.relation-poseidon"])

    def test_retained_algorithm_never_falls_back_when_missing_or_empty(self) -> None:
        for value in (None, "", " ", 57):
            spec = self.mutated()
            role = self.role(spec, "kaigi.relation-poseidon")
            if value is None:
                del role["algorithm"]
            else:
                role["algorithm"] = value
            self.assertReported(self.profile_errors(spec), "retained role algorithm is missing or empty")
            with self.assertRaises(profile_reference.ProfileError):
                checker.refresh_semantic_profiles(spec)

    def test_a_retained_profile_follows_its_role_record(self) -> None:
        spec = self.mutated()
        self.role(spec, "halo2.transcript-blake2b")["output_bytes"] = 32
        self.assertReported(self.profile_errors(spec), "parameters differ from the role record")
        before = self.profile(spec, "retained.halo2.transcript-blake2b")["identity"]
        checker.refresh_semantic_profiles(spec)
        after = self.profile(spec, "retained.halo2.transcript-blake2b")["identity"]
        self.assertNotEqual(before, after)
        self.assertEqual(self.profile_errors(spec), self.profile_errors(self.spec))
        spec = self.mutated()
        self.profile(spec, "retained.halo2.transcript-blake2b")["kind"] = "native-commitment"
        self.assertReported(self.profile_errors(spec), "kind does not follow the role family")

    def test_refresh_decides_only_roles_that_are_already_retained(self) -> None:
        self.assertEqual(self.spec, (lambda spec: (checker.refresh_semantic_profiles(spec), spec)[1])(self.mutated()))
        spec = self.mutated()
        retained = copy.deepcopy(self.role(spec, "halo2.transcript-blake2b"))
        retained["key"] = "halo2.second-transcript"
        six_lane = copy.deepcopy(self.role(spec, "zk-ace.identity-digest384"))
        six_lane["key"] = "new.six-lane-role"
        spec["digest_roles"] += [retained, six_lane]
        spec["semantic_profiles"]["role_dispositions"]["removed.role"] = {"disposition": "retained", "profiles": ["retained.removed.role"]}
        checker.refresh_semantic_profiles(spec)
        dispositions = spec["semantic_profiles"]["role_dispositions"]
        self.assertEqual(dispositions["halo2.second-transcript"], {"disposition": "retained", "profiles": ["retained.halo2.second-transcript"]})
        self.assertEqual(self.profile(spec, "retained.halo2.second-transcript")["status"], "retained")
        self.assertNotIn("new.six-lane-role", dispositions)
        self.assertNotIn("removed.role", dispositions)
        self.assertReported(self.profile_errors(spec), "role dispositions differ from the digest roles: ['new.six-lane-role']")
        without = self.mutated()
        without.pop("semantic_profiles")
        checker.refresh_semantic_profiles(without)
        self.assertNotIn("semantic_profiles", without)

    def test_the_six_lane_digest_is_never_retained_or_frozen(self) -> None:
        spec = self.mutated()
        section = spec["semantic_profiles"]
        section["role_dispositions"]["zk-ace.identity-digest384"] = {"disposition": "retained", "profiles": ["retained.x"]}
        self.assertReported(self.profile_errors(spec), "the unqualified six-lane digest is retained or frozen")
        spec = self.mutated()
        spec["semantic_profiles"]["role_dispositions"]["catalog.exact12-commitment"].pop("replaces")
        self.assertReported(self.profile_errors(spec), "the unqualified six-lane digest is retained or frozen")
        spec = self.mutated()
        profile = self.profile(spec, self.NATIVE)
        self.parameter(profile, "algorithm")["value"] = "GoldilocksDigest384V1"
        profile["identity"] = profile_reference.identity_of(profile)
        self.assertReported(self.profile_errors(spec), "a frozen profile names the unqualified six-lane digest")
        for entry in self.spec["semantic_profiles"]["not_frozen"]:
            self.assertTrue(entry["missing"] and entry["excluded"], entry["id"])

    def test_every_role_and_defect_has_a_disposition(self) -> None:
        cases = (
            (lambda s: s["role_dispositions"].pop("kaigi.authorization-identity"), "role dispositions differ from the digest roles"),
            (lambda s: s["role_dispositions"]["kaigi.authorization-identity"].pop("accepted_level"), "`accepted_level` of the selected native commitment is missing"),
            (lambda s: s["role_dispositions"]["privacy.statement-digest-blake3"].pop("required_property"), "`required_property` is missing"),
            (lambda s: s["role_dispositions"]["kaigi.authorization-identity"].__setitem__("profiles", ["unknown"]), "unknown profile 'unknown'"),
            (lambda s: s["role_dispositions"].__setitem__("confidential.spentness-tree", {"disposition": "frozen-profile", "profiles": [self.NATIVE], "replaces": "x", "required_property": "p", "accepted_level": "l"}), "a provisional role must stay deferred"),
            (lambda s: s["role_dispositions"]["zk-ace.identity-digest384"].__setitem__("not_frozen", "missing"), "its not-frozen entry does not list it"),
            (lambda s: s["role_dispositions"]["zk-ace.identity-digest384"].__setitem__("disposition", "deferred"), "disposition differs from its not-frozen entry"),
            (lambda s: s["not_frozen"][1].__setitem__("missing", []), "`missing` is missing"),
            (lambda s: s["not_frozen"][1].__setitem__("status", "frozen"), "unknown status"),
            (lambda s: s["defect_dispositions"].pop(0), "no disposition for defect BN254-POSEIDON-D1"),
            (lambda s: s["defect_dispositions"][4].__setitem__("disposition", "accepted"), "unknown disposition 'accepted'"),
            (lambda s: s["defect_dispositions"][5].__setitem__("profile", "retained.pq.mldsa-shake"), "is not a frozen profile"),
            (lambda s: s["defect_dispositions"][1].__setitem__("vectors_required", ""), "`vectors_required` is missing"),
            (lambda s: s.__setitem__("task", "H.1"), "the section belongs to H.2"),
        )
        for mutate, expected in cases:
            spec = self.mutated()
            mutate(spec["semantic_profiles"])
            self.assertReported(self.profile_errors(spec), expected)
        spec = self.mutated()
        spec["bn254_poseidon"]["defects"].append({"id": "BN254-POSEIDON-D9"})
        self.assertReported(self.profile_errors(spec), "defect BN254-POSEIDON-D9 of this file has no disposition")

    def test_frozen_parameters_follow_their_records_and_generators(self) -> None:
        def changed(name: str, key: str, value) -> list:
            spec = self.mutated()
            profile = self.profile(spec, name)
            self.parameter(profile, key)["value"] = value
            profile["identity"] = profile_reference.identity_of(profile)
            return self.profile_errors(spec)

        self.assertReported(changed("bn254.poseidon.x5-t3.v1", "partial_rounds", 56), "width or round numbers differ from the frozen correction")
        self.assertReported(changed("bn254.poseidon.x5-t6.v1", "partial_rounds", 57), "width or round numbers differ from the frozen correction")
        self.assertReported(changed("bn254.poseidon.x5-t6.v1", "capacity", 0), "the mode has no single capacity coordinate")
        self.assertReported(changed("bn254.poseidon.x5-t3.v1", "tables_sha3_256", "00" * 32), "table digest differs from the regenerated tables")
        self.assertReported(changed("bn254.poseidon.x5-t3.v1", "vector_hash2_1_2_be", "00" * 32), "corrected hash2 vector differs")
        self.assertReported(changed("bn254.poseidon.x5-t6.v1", "vector_hash6_1_to_6_be", "00" * 32), "corrected hash6 vector differs")
        self.assertReported(changed(self.NATIVE, "frame_version", 2), "frame version differs from the frame")
        self.assertReported(changed(self.NATIVE, "payload_field_count_max", 1), "bound payload_field_count_max differs")
        self.assertReported(changed(self.NATIVE, "output_bytes", 48), "not raw BLAKE3-256")
        self.assertReported(changed("pq.ml-kem.fips203.v1", "ml_kem_768_bytes", [1, 2, 3, 4]), "encoded sizes of ml-kem-768 differ")
        self.assertReported(changed("lantern.trapdoor.falcon512-derived.v1", "labels", "fn-dsa"), "it may be labelled FN-DSA")
        self.assertReported(changed(self.NATIVE, "profile_version", 1) + ["ok"], "ok")
        spec = self.mutated()
        profile = self.profile(spec, self.NATIVE)
        profile["parameters"].append({"key": "source_revision", "type": "text", "value": "abc"})
        profile["identity"] = profile_reference.identity_of(profile)
        self.assertReported(self.profile_errors(spec), "names evidence metadata")
        spec = self.mutated()
        state = copy.deepcopy(self.profile(spec, self.NATIVE))
        state["name"] = "state.tree.blake3"
        state["identity"] = profile_reference.identity_of(state)
        spec["semantic_profiles"]["profiles"].append(state)
        self.assertReported(self.profile_errors(spec), "the State tree and hash are selected by G.3")
        spec = self.mutated()
        self.profile(spec, "bn254.poseidon.x5-t3.v1")["checks"]["permutation_0_1_2_coordinate_0_be"] = "00" * 32
        self.assertReported(self.profile_errors(spec), "the published width-3 reference vector is not reproduced")
        # The corrected width-3 table is the published one: its first constant and reference vector.
        values = profile_reference.parameter_map(self.profile(self.spec, "bn254.poseidon.x5-t3.v1"))
        self.assertEqual(values["first_round_constant_be"], "0ee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e")
        self.assertEqual(values["vector_permutation_0_1_2_be"], "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a")

    def test_the_frozen_transcript_keeps_its_binding_tests_goldens_and_claims(self) -> None:
        cases = (
            (lambda t: t["binding_order"].pop(), "binding order does not answer every requirement"),
            (lambda t: t["binding_order"][3].__setitem__("tests", []), "`bound`, `how` or `tests` is missing"),
            (lambda t: t["binding_order"][1].__setitem__("tests", ["backend::deep_binding::frozen_tests::missing_test"]), "test missing_test is missing"),
            (lambda t: t["binding_order"][1].__setitem__("tests", ["not a path"]), "is not a backend test path"),
            (lambda t: t["security_statement"].__setitem__("qrom", "Established."), "the quantum random-oracle claim must stay open"),
            (lambda t: t["security_statement"].__setitem__("classical_rom", "Proved."), "the classical random-oracle claim must stay conditional"),
            (lambda t: t["security_statement"].__setitem__("status", "Qualified."), "qualification must stay recorded as pending"),
            (lambda t: t["security_statement"].pop("hiding"), "security statement `hiding` is missing"),
            (lambda t: t["grinding"].__setitem__("bits", 20), "grinding bits differ from the profile"),
            (lambda t: t["work_limits"].pop("not_bound"), "the work-limit binding statement is missing"),
            (lambda t: t["engines"].pop(), "differ from the inventory"),
            (lambda t: t["engines"][2].__setitem__("disposition", "kept"), "unknown disposition"),
            (lambda t: t["goldens"]["artifact_profile_ids"].__setitem__("quantity_axt", "00" * 32), "artifact profile id quantity_axt is not pinned"),
            (lambda t: t["goldens"]["proof_pins"].append("fixtures/fastpq/missing.json"), "is missing"),
            (lambda t: t["known_answers"]["inputs"].__setitem__("relation", "another"), "differs from the known answers the reference computes"),
            (lambda t: t.__setitem__("construction", "another"), "construction name differs from the profile"),
            (lambda t: t.__setitem__("profile", "native.commitment.blake3-256.frame-v1"), "names no frozen transcript profile"),
        )
        for mutate, expected in cases:
            spec = self.mutated()
            mutate(spec["semantic_profiles"]["shared_transcript"])
            self.assertReported(self.profile_errors(spec), expected)
        # A changed transcript parameter also leaves the Rust golden and the known answers stale.
        spec = self.mutated()
        profile = self.profile(spec, self.TRANSCRIPT)
        self.parameter(profile, "queries")["value"] = 78
        profile["identity"] = profile_reference.identity_of(profile)
        errors = self.profile_errors(spec)
        self.assertReported(errors, "the Rust golden does not pin the recorded identity")
        self.assertReported(errors, "differs from the known answers the reference computes")
        self.assertEqual(
            (ROOT / self.spec["semantic_profiles"]["shared_transcript"]["known_answers"]["fixture"]).read_text(encoding="utf-8"),
            profile_reference.fixture_text(self.spec),
        )

    def test_identity_excludes_evidence_metadata_and_grants_nothing(self) -> None:
        identity = self.spec["semantic_profiles"]["identity"]
        self.assertIn("None", identity["authority"])
        for mutate, expected in (
            (lambda i: i.__setitem__("excluded_inputs", ["nothing"]), "excluded inputs do not name 'source'"),
            (lambda i: i["frame"].__setitem__("magic_ascii", "other"), "frame magic differs from the reference"),
            (lambda i: i["frame"].__setitem__("kinds", ["transcript"]), "the kinds differ from the reference"),
            (lambda i: i["frame"]["bounds"].__setitem__("parameters", 1), "the frame bounds differ from the reference"),
            (lambda i: i["rust_owner"].__setitem__("symbol", "pub struct Missing {"), "no longer contains"),
        ):
            spec = self.mutated()
            mutate(spec["semantic_profiles"]["identity"])
            self.assertReported(self.profile_errors(spec), expected)
        binding = self.spec["semantic_profiles"]["measurement_binding"]
        self.assertIn("No signature, approval or runtime switch", binding["no_reviewer_token"])
        spec = self.mutated()
        spec["semantic_profiles"]["exploratory_basis"][0]["measurement"] = "missing/measurement"
        self.assertReported(self.profile_errors(spec), "is neither a recorded measurement nor a tracked record")
        spec = self.mutated()
        spec["semantic_profiles"]["exploratory_basis"] = []
        self.assertReported(self.profile_errors(spec), "the exploratory basis of the selections is missing")
        spec = self.mutated()
        spec["semantic_profiles"]["measurement_binding"].pop("no_reviewer_token")
        self.assertReported(self.profile_errors(spec), "`no_reviewer_token` is missing")


class CommandLine(unittest.TestCase):
    def test_a_missing_specification_fails(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()) as printed:
            self.assertEqual(checker.main(["--root", str(ROOT), "--spec", "specs/missing.json"]), 1)
        self.assertIn("specs/missing.json", printed.getvalue())

    def test_the_tracked_file_is_in_canonical_form(self) -> None:
        self.assertEqual(SPEC_PATH.read_text(encoding="utf-8"), checker.dump(load_spec()))
        self.assertEqual(
            checker.dump({"a": [1, 2], "b": [{"c": []}], "d": {}}),
            '{\n "a": [1, 2],\n "b": [\n  {\n   "c": []\n  }\n ],\n "d": {}\n}\n',
        )
        self.assertEqual(checker.spec_path_of({}), checker.DEFAULT_SPEC)
        self.assertEqual(checker.spec_path_of({"artifact": "specs/other.json"}), "specs/other.json")


if __name__ == "__main__":
    unittest.main()
