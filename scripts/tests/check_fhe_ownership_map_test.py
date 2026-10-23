"""Exercise the FHE ownership inventory checker on synthetic trees and on the repository."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import copy
import importlib.util
from io import StringIO
import json
from pathlib import Path
import re
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "check_fhe_ownership_map.py"
SPEC = importlib.util.spec_from_file_location("check_fhe_ownership_map", SCRIPT)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

TAG = "hkdf-sha3-512-prf-v1"
RING = "crates/low/src/ring.rs"
RING_TESTS = "crates/low/src/ring_tests.rs"
BACKEND = "crates/high/src/backend.rs"
KDF = "crates/high/src/kdf.rs"
CLIENT = "sdk/client.kt"
CLIENT_TEST = "sdk/test/ClientTest.kt"
VECTORS = "fixtures/vectors.json"

TREE = {
    "Cargo.toml": '[workspace]\nmembers = ["crates/low", "crates/high"]\n',
    "crates/low/Cargo.toml": '[package]\nname = "low"\n\n[features]\nfixtures = []\n',
    "crates/low/src/lib.rs": "//! Low layer.\npub mod ring;\n#[cfg(test)]\nmod ring_tests;\n",
    RING: (
        "//! Ring arithmetic.\n"
        "/// Forward transform.\n"
        "pub fn ntt_forward(values: &mut [u64]) {\n"
        "    let _ = mul_mod(1, 2, 3);\n"
        "    let _ = values;\n"
        "}\n"
        "fn mul_mod(left: u64, right: u64, modulus: u64) -> u64 {\n"
        "    left * right % modulus\n"
        "}\n"
        "#[cfg(test)]\n"
        "fn ntt_reference(values: &mut [u64]) {\n"
        "    let _ = values;\n"
        "}\n"
        "/// Chain.\n"
        "pub struct RnsChain;\n"
        "impl RnsChain {\n"
        "    /// Product.\n"
        "    pub fn product(&self) -> u64 {\n"
        "        mul_mod(1, 1, 2)\n"
        "    }\n"
        "}\n"
        '#[cfg(any(test, feature = "fixtures"))]\n'
        "pub fn keygen_from_seed() {}\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    #[test]\n"
        "    fn transform_roundtrip() {}\n"
        "}\n"
    ),
    RING_TESTS: "fn check() {\n    super::ring::ntt_forward(&mut []);\n}\n",
    "crates/high/Cargo.toml": (
        '[package]\nname = "high"\n\n[dependencies]\nlow = { path = "../low" }\n\n'
        '[dev-dependencies]\nlow = { path = "../low", features = ["fixtures"] }\n'
    ),
    "crates/high/src/lib.rs": "//! High layer.\npub mod backend;\npub mod kdf;\n",
    BACKEND: (
        "//! Backends.\n"
        "/// Backend.\n"
        "pub enum RamLfeBackend {\n"
        "    /// Plaintext PRF.\n"
        "    HkdfSha3_512PrfV1,\n"
        "    /// Encrypted.\n"
        "    BfvProgrammedV1,\n"
        "}\n"
        "/// Evaluate.\n"
        "pub fn evaluate_hkdf_prf() {\n"
        "    let _ = Hkdf::<Sha3>::new(None, &[]);\n"
        "}\n"
        "/// Derive.\n"
        "pub fn derive_phone_nullifier() {\n"
        "    let _ = Hkdf::<Sha3>::new(None, &[]);\n"
        "}\n"
        "/// Multiply.\n"
        "pub fn bfv_multiply() {\n"
        "    low::ring::ntt_forward(&mut []);\n"
        "}\n"
    ),
    KDF: "//! Session keys.\n/// Derive.\npub fn session_key() {\n    let hkdf_salt = 1;\n    let _ = hkdf_salt;\n}\n",
    CLIENT: f'const val TAG = "{TAG}"\n',
    CLIENT_TEST: f'val expected = "{TAG}"\n',
    VECTORS: '{"bfv_vectors": []}\n',
    "tools/reader.py": 'open("vectors.json")\n',
}


def scan_header() -> dict:
    """Restate the checker's scan contract as the inventory must."""
    return {
        "patterns": list(CHECKER.PATTERN_IDS),
        "excluded_paths": list(CHECKER.EXCLUDED_PATHS),
        "markdown_patterns": list(CHECKER.MARKDOWN_PATTERNS),
        "generated_registry": CHECKER.GENERATED_REGISTRY,
    }


def valid_map() -> dict:
    """Return the inventory that matches TREE exactly, in the form `refresh` produces."""
    return {
        "schema_version": CHECKER.SCHEMA_VERSION,
        "task": "C.1",
        "scan": scan_header(),
        "development_features": [{"crate": "crates/low", "feature": "fixtures"}],
        "crates": [
            {"name": "shared", "path": "crates/shared", "depends_on": [], "planned": True},
            {"name": "low", "path": "crates/low", "depends_on": []},
            {"name": "high", "path": "crates/high", "depends_on": ["low"]},
        ],
        "destination": {
            "crate": "shared", "planned": True,
            "modules": {"shared::ntt": "Transforms.", "shared::modular": "Scalars."},
        },
        "zk_ams_distinct": {
            "preserve_as_test_oracles": ["low.tests"],
            "production_surface": {
                "prefix": "crates/low/src/", "claim": "The low layer executes no protocol.",
                "allowed_primitives": ["ntt.forward", "modular.mul"],
            },
        },
        "current_state": [
            {"id": "bfv_backends_refused", "claim": "The plaintext backend variant exists and the client carries its tag.",
             "evidence": [{"path": BACKEND, "symbol": "RamLfeBackend::HkdfSha3_512PrfV1"}, {"path": CLIENT, "literal": TAG}],
             "absent": [{"prefix": "crates/low/", "literal": "HkdfSha3_512PrfV1"}]},
            {"id": "execution_proof_relation_unavailable", "claim": "No relation is verified.",
             "evidence": [{"path": BACKEND, "symbol": "RamLfeBackend::BfvProgrammedV1"}]},
            {"id": "signed_mode_and_receipt_attestations_exist", "claim": "The evaluator exists.",
             "evidence": [{"path": BACKEND, "symbol": "evaluate_hkdf_prf"}]},
            {"id": "sdk_input_encryption_unavailable", "claim": "The client only carries the tag.",
             "evidence": [{"path": CLIENT, "literal": "const val TAG"}]},
        ],
        "arithmetic_scopes": [{"prefix": "crates/low/src/", "assignment": "every_function", "reason": "Shared arithmetic owner."}],
        "primitives": [
            {
                "id": "ntt.forward", "owner": {"crate": "shared", "module": "shared::ntt"},
                "canonical_source": {"path": RING, "symbols": ["ntt_forward"]},
                "implementations": [
                    {"path": RING, "symbol": "ntt_forward", "role": "canonical", "callers_exhaustive": True,
                     "callers": {BACKEND: ["bfv_multiply"]}},
                    {"path": RING, "symbol": "ntt_reference", "cfg": ["test"], "test_only": True, "role": "test_only_reference"},
                ],
            },
            {
                "id": "modular.mul", "owner": {"crate": "shared", "module": "shared::modular"},
                "canonical_source": {"path": RING, "symbols": ["mul_mod"]},
                "implementations": [
                    {"path": RING, "symbol": "mul_mod", "role": "canonical", "callers_exhaustive": True,
                     "callers": {RING: ["RnsChain::product", "ntt_forward"]}},
                ],
            },
        ],
        "distinct_arithmetic": [],
        "unrelated_kernel_named": [],
        "protocol_logic": [
            {"id": "bfv.evaluation", "scheme": "bfv", "executes": ["evaluation"], "path": BACKEND,
             "symbols": [{"symbol": "bfv_multiply"}]},
            {"id": "low.chain", "scheme": "bfv", "executes": [], "path": RING, "symbols": [{"symbol": "RnsChain::product"}]},
        ],
        "test_only_references": [
            {"id": "low.keygen", "scheme": "bfv", "kind": "key_generation_reference", "path": RING,
             "symbols": [{"symbol": "keygen_from_seed", "cfg": ['any(test, feature = "fixtures")'], "test_only": True}]},
            {"id": "low.tests", "scheme": "bfv", "kind": "oracle", "path": RING_TESTS, "whole_file": True, "symbols": []},
            {"id": "low.reference", "scheme": "bfv", "kind": "protocol_reference", "path": RING,
             "symbols": [{"symbol": "ntt_reference", "cfg": ["test"], "test_only": True}]},
            {"id": "low.unit_tests", "scheme": "bfv", "kind": "unit_tests", "symbols": []},
        ],
        "function_assignment": [
            {"path": RING, "production": {"low.chain": ["RnsChain::product"]},
             "test_gated": {"low.keygen": ["keygen_from_seed"], "low.reference": ["ntt_reference"], "low.unit_tests": ["mod tests"]}},
        ],
        "hkdf": {
            "ram_lfe_backend": {
                "users": [
                    {"path": BACKEND, "kind": "definition",
                     "symbols": [{"symbol": "RamLfeBackend::HkdfSha3_512PrfV1"}, {"symbol": "evaluate_hkdf_prf"}]},
                    {"path": CLIENT, "kind": "wire_tag", "literals": [TAG]},
                    {"path": CLIENT_TEST, "kind": "test", "literals": [TAG], "test_only": True},
                ],
                "consumer_evidence": [{"path": BACKEND, "symbol": "bfv_multiply"}],
            },
            "plaintext_prf": {"entries": [{"path": BACKEND, "symbols": [
                {"symbol": "derive_phone_nullifier", "callers_exhaustive": True, "callers": {}},
            ]}]},
            "unrelated_preserve": {"entries": [{"path": KDF, "purpose": "Session key derivation."}]},
            "other_derivations": [],
        },
        "generated_consumers": [
            {"path": VECTORS, "kind": "fixture", "evidence": {"path": "tools/reader.py", "literal": "vectors.json"}},
        ],
        "file_groups": [
            {"id": "low.ring", "role": "fhe_implementation", "summary": "Arithmetic.",
             "files": [{"path": RING, "patterns": ["ntt", "rns"]}]},
            {"id": "low.tests", "role": "fhe_test_reference", "summary": "Tests.",
             "files": [{"path": RING_TESTS, "patterns": ["ntt"], "cfg": ["test"], "test_only": True}]},
            {"id": "high.backend", "role": "ram_lfe_implementation", "summary": "Backends.",
             "files": [{"path": BACKEND, "patterns": ["bfv", "hkdf", "hkdf_ram_lfe", "ntt", "ram_lfe"]}]},
            {"id": "hkdf.unrelated", "role": "unrelated_hkdf", "summary": "Session keys.",
             "files": [{"path": KDF, "patterns": ["hkdf"]}]},
            {"id": "sdk", "role": "sdk", "summary": "Client.",
             "files": [{"path": CLIENT, "patterns": ["hkdf", "hkdf_ram_lfe"]},
                       {"path": CLIENT_TEST, "patterns": ["hkdf", "hkdf_ram_lfe"], "test_only": True}]},
            {"id": "fixtures", "role": "fixture", "summary": "Vectors.",
             "files": [{"path": VECTORS, "patterns": ["bfv"], "test_only": True}]},
        ],
    }


class TreeCase(unittest.TestCase):
    """Materialize a synthetic repository for each test."""

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name)
        for path, text in TREE.items():
            self.write(path, text)

    def write(self, path: str, text: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def replace(self, path: str, old: str, new: str) -> None:
        text = (self.root / path).read_text(encoding="utf-8")
        self.assertIn(old, text)
        self.write(path, text.replace(old, new))

    def append(self, path: str, text: str) -> None:
        self.write(path, (self.root / path).read_text(encoding="utf-8") + text)

    def errors(self, document: dict) -> list[str]:
        return CHECKER.check(self.root, document)

    def assert_error(self, document: dict, fragment: str) -> None:
        errors = self.errors(document)
        self.assertTrue(any(fragment in error for error in errors), f"{fragment!r} not in {errors}")

    def assert_no_error(self, document: dict, fragment: str) -> None:
        errors = self.errors(document)
        self.assertFalse(any(fragment in error for error in errors), f"{fragment!r} in {errors}")


class FileWalkTest(TreeCase):
    """The non-Git source snapshot sees the same captured source paths."""

    def test_fallback_keeps_nested_capture_build_directories(self) -> None:
        captures = [
            "docs/validation/rehearsal/build/Cargo.lock.template",
            "docs/validation/rehearsal/capture/source/target/reference.py.template",
            "docs/validation/rehearsal/capture/dist/source.rs.template",
        ]
        for path in captures:
            self.write(path, "ntt")
        found = CHECKER.list_repository_files(self.root)
        self.assertTrue(set(captures).issubset(found))
        scanned = CHECKER.scan_tree(CHECKER.Tree(self.root))
        for path in captures:
            self.assertEqual(scanned[path], ["ntt"])

    def test_fallback_still_skips_ordinary_generated_output_directories(self) -> None:
        outputs = ["target/generated.rs", "dist/result.json", "crates/low/target/cache.rs"]
        for path in outputs:
            self.write(path, "ntt")
        found = CHECKER.list_repository_files(self.root)
        self.assertFalse(set(outputs).intersection(found))
        self.assertIn(RING, found)


class ScanTest(unittest.TestCase):
    def test_identifier_words_split_snake_camel_and_digits(self) -> None:
        self.assertEqual(CHECKER.identifier_words("HkdfSha3_512PrfV1"), ("hkdf", "sha", "3", "512", "prf", "v", "1"))
        self.assertEqual(CHECKER.identifier_words("mqpoly_int_to_NTT"), ("mqpoly", "int", "to", "ntt"))
        self.assertEqual(CHECKER.identifier_words("RNSPolynomial"), ("rns", "polynomial"))

    def test_scan_matches_identifiers_in_every_naming_style(self) -> None:
        cases = {
            "fn ntt_in_place() {}": ["ntt"],
            "val inverseNtt = 1": ["ntt"],
            "struct BfvRnsModulusChain;": ["bfv", "rns"],
            "enum Scheme { Bgv }": ["bgv"],
            "ZK_AMS_MKHE_BYTES": ["mkhe"],
            "let negacyclic_product = 1;": ["negacyclic"],
            "fn basis_extend_polynomial() {}": ["basis_conversion"],
            "class RamLfeWireTags": ["ram_lfe"],
            "ram-lfe route": ["ram_lfe"],
            "import hkdf": ["hkdf"],
            "HkdfSha3_512PrfV1": ["hkdf", "hkdf_ram_lfe"],
            f'"{TAG}"': ["hkdf", "hkdf_ram_lfe"],
            "fn evaluate_hkdf_prf() {}": ["hkdf", "hkdf_ram_lfe"],
            "ToriiRamFheProfile": ["fhe"],
        }
        for text, expected in cases.items():
            self.assertEqual(CHECKER.scan_text(text), expected, text)

    def test_scan_ignores_substrings_and_opaque_payloads(self) -> None:
        for text in ("this returns the content", "patterns and concerns", "database_conversion", "attention", "graphed"):
            self.assertEqual(CHECKER.scan_text(text), [], text)
        payload = "QUJD" * 12 + "+Bfv/" + "REVG" * 12
        self.assertGreaterEqual(len(payload), CHECKER.OPAQUE_RUN_LENGTH)
        self.assertEqual(CHECKER.scan_text(f'"{payload}"'), [])
        self.assertEqual(CHECKER.scan_text('"QUJD+Bfv/REVG"'), ["bfv"])

    def test_every_pattern_sequence_has_an_anchor(self) -> None:
        for pattern, sequences in CHECKER.WORD_PATTERNS.items():
            words, _ = CHECKER._ANCHORS[pattern]
            for sequence in sequences:
                self.assertTrue(any(word in sequence for word in words), (pattern, sequence))

    def test_kernel_names_cover_every_owned_family(self) -> None:
        for name in ("ntt_in_place_mod", "mp_iNTT", "zint_rebuild_CRT", "mod_q", "poly_mul_mod", "is_prime_u64",
                     "multiply_rns_polynomial_by_ciphertext_modulus_polynomial_negacyclic_exact",
                     "apply_galois_automorphism_poly", "div_round_nearest_i128",
                     "key_switch_rns_exact", "keyswitch_digits", "relinearize", "relinearization_inner_product",
                     "modulus_switch_rns_polynomial", "mod_switch_down", "rescale_limbs_exact",
                     "basis_convert", "basis_conversion_table", "reduce_u128_to_u64_mod", "lift_centered",
                     "scale_and_round", "poly_mul_fft", "ifft_columns", "goldilocks_mul"):
            self.assertTrue(CHECKER.is_kernel_name(name), name)
        for name in ("validate", "returns", "product", "encrypt", "liftoff", "reducer_state", "shift_left"):
            self.assertFalse(CHECKER.is_kernel_name(name), name)

    def test_kernel_names_keep_kernels_that_carry_a_protocol_word(self) -> None:
        for name in ("bfv_full_bootstrap_goldilocks_mul_v1", "bootstrap_ciphertext_ntt_slots",
                     "multiply_ciphertexts_registered_rns_basis_extension_exact", "apply_galois_automorphism_ciphertext"):
            self.assertTrue(CHECKER.is_kernel_name(name), name)

    def test_only_the_inventory_checker_and_plan_ledger_are_excluded(self) -> None:
        for path in CHECKER.EXCLUDED_PATHS:
            self.assertTrue(CHECKER.is_excluded(path), path)
        self.assertIn(CHECKER.DEFAULT_MAP, CHECKER.EXCLUDED_PATHS)
        for path in ("specs/plan.md", "specs/inventory.tsv", "docs/notes.json", "crates/x/src/lib.rs", "crates/x/README.md"):
            self.assertFalse(CHECKER.is_excluded(path), path)


class RustSourceTest(unittest.TestCase):
    def test_mask_preserves_offsets_and_hides_comments_and_literals(self) -> None:
        source = 'fn a() { let s = "ntt { } ;"; /* fn b() {} */ let c = \'{\'; } // fn c() {}\nfn d<\'a>() {}\n'
        masked = CHECKER.mask_rust(source)
        self.assertEqual(len(masked), len(source))
        self.assertEqual(masked.count("\n"), source.count("\n"))
        self.assertNotIn("ntt", masked)
        self.assertNotIn("fn b", masked)
        self.assertNotIn("fn c", masked)
        self.assertIn("fn d<'a>", masked)
        raw = 'const X: &str = r#"fn hidden() {}"#;\nfn shown() {}\n'
        self.assertNotIn("hidden", CHECKER.mask_rust(raw))
        self.assertIn("shown", CHECKER.mask_rust(raw))

    def test_items_carry_cfg_chains_of_enclosing_blocks(self) -> None:
        source = CHECKER.RustSource(
            "pub struct Chain;\n"
            "impl Chain {\n"
            "    pub fn product(&self) {}\n"
            "    #[cfg(test)]\n"
            "    fn zero() {}\n"
            "}\n"
            '#[cfg(feature = "json")]\n'
            "impl Display for Chain {\n"
            "    fn fmt(&self) {}\n"
            "}\n"
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    fn helper() {}\n"
            "}\n"
            "enum Backend { Hkdf, Bfv }\n"
            "const TABLE: [u64; 2] = [1, 2];\n"
            "mode = Exact;\n"
        )
        chains = {CHECKER.qualified_name(item): item.cfg_chain() for item in source.named_items() if item.kind == "fn"}
        self.assertEqual(chains, {
            "Chain::product": (), "Chain::zero": ("test",), "Chain::fmt": ('feature = "json"',),
            "tests::helper": ("test",),
        })
        self.assertEqual([item.kind for item in source.resolve("Chain")], ["struct"])
        self.assertEqual(len(source.resolve("Chain::product")), 1)
        self.assertEqual(source.resolve("Backend::Hkdf")[0].kind, "member")
        self.assertEqual(source.resolve("Backend::Missing"), [])
        self.assertEqual([item.kind for item in source.resolve("TABLE")], ["const"])
        self.assertEqual(source.resolve("e"), [])

    def test_cfg_predicates_normalize_and_classify(self) -> None:
        self.assertEqual(CHECKER.normalize_cfg('any( test,feature="x" )'), 'any(test, feature = "x")')
        self.assertTrue(CHECKER.is_test_cfg("test", []))
        self.assertTrue(CHECKER.is_test_cfg("doctest", []))
        self.assertTrue(CHECKER.is_test_cfg('all(test, feature = "a")', []))
        self.assertTrue(CHECKER.is_test_cfg('all(doctest, feature = "a")', []))
        self.assertTrue(CHECKER.is_test_cfg('any(test, feature = "fixtures")', ["fixtures"]))
        self.assertFalse(CHECKER.is_test_cfg('any(test, feature = "fixtures")', []))
        self.assertFalse(CHECKER.is_test_cfg('any(test, all(feature = "gpu", target_os = "macos"))', ["gpu"]))
        self.assertFalse(CHECKER.is_test_cfg('feature = "full"', []))
        self.assertFalse(CHECKER.is_test_cfg("not(doctest)", []))

    def test_uses_are_classified_by_syntax(self) -> None:
        cases = {
            "let x = product(a, b);": ("bare", ""),
            "let x = items.map(product);": ("bare", ""),
            "let x = fold(seed, product, 3);": ("bare", ""),
            "let x = chain.product();": ("method", "chain"),
            "let x = self.product()?;": ("method", "self"),
            "let x = values.iter().product();": ("method", "?"),
            "let x = Chain::product(&chain);": ("path", "Chain"),
            "let x = Self::product::<u64>(1);": ("path", "Self"),
            "let x = items.map(ring::product);": ("path", "ring"),
            "let x = <Chain as Mul>::product(&chain);": ("path", "?"),
            "let product = a * b;": None,
            "let mut product = 1;": None,
            "let x = product + 1;": None,
            "let x = state.product;": None,
            "let x = Totals { product: 1 };": None,
            "fn product() {}": None,
        }
        for text, expected in cases.items():
            self.assertEqual(CHECKER.classify_use(text, text.index("product"), "product"), expected, text)

    def test_local_bindings_shadow_a_callee_name(self) -> None:
        cases = {
            "fn f() { let product = 2; reduce(product) }": True,
            "fn f() { let (product, carry) = split(); reduce(product) }": True,
            "fn f(product: u64) -> u64 { reduce(product) }": True,
            "fn f() { for product in values { reduce(product) } }": True,
            "fn f() { values.map(|product| reduce(product)) }": True,
            "fn f() { values.map(|a, product| reduce(product)) }": True,
            "fn f() { let x = a || product(1) != 1 || b; }": False,
            "fn f() { reduce(product) }": False,
            "fn f() { let x = Totals { product: 1 }; reduce(product) }": False,
        }
        for text, expected in cases.items():
            source = CHECKER.RustSource(text)
            function = next(item for item in source.items if item.kind == "fn")
            self.assertEqual(CHECKER.binds_locally(source, function, "product"), expected, text)

    def test_embedded_paths_resolve_relative_to_the_file_or_the_package(self) -> None:
        def resolve(text: str) -> object:
            return CHECKER.embedded_path(text, text.index("(") + 1, "crates/high/src", "crates/high")
        self.assertEqual(resolve('include_str!("../../../fixtures/a.json");'), "fixtures/a.json")
        self.assertEqual(resolve('include_bytes!("data/b.bin")'), "crates/high/src/data/b.bin")
        self.assertEqual(resolve('include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/a.json"))'), "fixtures/a.json")
        self.assertEqual(resolve('include_str!(concat!("data/", "c.txt"))'), "crates/high/src/data/c.txt")
        self.assertIsNone(resolve('include_str!(concat!(env!("OUT_DIR"), "/generated.rs"))'))
        self.assertIsNone(resolve("include_str!(PATH)"))
        self.assertEqual(CHECKER.normalize_path("a/b", "../c", "./d"), "a/c/d")
        self.assertEqual(CHECKER.normalize_path("", "x.rs"), "x.rs")


class ReachTest(TreeCase):
    def test_modules_resolve_cfg_path_include_and_test_targets(self) -> None:
        self.write("crates/low/src/lib.rs", (
            "//! Low layer.\n"
            '#[cfg(feature = "full")]\n'
            "pub mod ring;\n"
            "#[cfg(test)]\n"
            '#[path = "ring_tests.rs"]\n'
            "mod renamed;\n"
            "mod nested;\n"
        ))
        self.write("crates/low/src/nested.rs", "#[cfg(test)]\nmod tests {\n    mod deep;\n}\nmod parts;\n")
        self.write("crates/low/src/nested/tests/deep.rs", "fn deep() {}\n")
        self.write("crates/low/src/nested/parts.rs", 'include!("../shared_body.rs");\n')
        self.write("crates/low/src/shared_body.rs", "fn shared() {}\n")
        self.write("crates/low/src/gated.rs", "#![cfg(test)]\nfn gated() {}\n")
        self.write("crates/low/tests/integration.rs", "mod support;\n")
        self.write("crates/low/tests/support.rs", "fn support() {}\n")
        self.write("crates/low/src/orphan.rs", "fn orphan() {}\n")
        tree = CHECKER.Tree(self.root)
        self.assertEqual(tree.reaches(RING), [("lib", ('feature = "full"',))])
        self.assertEqual(tree.reaches(RING_TESTS), [("lib", ("test",))])
        self.assertEqual(tree.reaches("crates/low/src/nested/tests/deep.rs"), [("lib", ("test",))])
        self.assertEqual(tree.reaches("crates/low/src/shared_body.rs"), [("lib", ())])
        self.assertEqual(tree.reaches("crates/low/tests/support.rs"), [("test", ())])
        self.assertEqual(tree.reaches("crates/low/src/orphan.rs"), [])
        self.assertEqual(CHECKER.file_facts(tree, RING, []), (['feature = "full"'], False))
        self.assertEqual(CHECKER.file_facts(tree, RING_TESTS, []), (["test"], True))
        self.assertEqual(CHECKER.file_facts(tree, "crates/low/tests/support.rs", []), ([], True))
        self.assertEqual(CHECKER.file_facts(tree, CLIENT_TEST, []), ([], True))
        self.assertEqual(CHECKER.file_facts(tree, CLIENT, []), ([], False))

    def test_inner_cfg_applies_to_the_file_itself(self) -> None:
        self.write("crates/low/src/lib.rs", "//! Low layer.\npub mod ring;\nmod gated;\n")
        self.write("crates/low/src/gated.rs", "#![cfg(test)]\nfn gated() {}\n")
        tree = CHECKER.Tree(self.root)
        self.assertEqual(tree.reaches("crates/low/src/gated.rs"), [("lib", ("test",))])

    def test_module_declared_in_an_included_file_is_a_sibling_of_that_file(self) -> None:
        self.write("crates/low/src/lib.rs", "//! Low layer.\npub mod ring;\nmod outer;\n")
        self.write("crates/low/src/outer.rs", 'include!("outer/body.rs");\n')
        self.write("crates/low/src/outer/body.rs", "#[cfg(test)]\nmod body_tests;\nmod body_helper;\n")
        self.write("crates/low/src/outer/body_tests.rs", "fn check() {}\n")
        self.write("crates/low/src/outer/body_helper.rs", "fn help() {}\n")
        tree = CHECKER.Tree(self.root)
        self.assertEqual(tree.reaches("crates/low/src/outer/body_tests.rs"), [("lib", ("test",))])
        self.assertEqual(CHECKER.file_facts(tree, "crates/low/src/outer/body_tests.rs", []), (["test"], True))
        self.assertEqual(CHECKER.file_facts(tree, "crates/low/src/outer/body_helper.rs", []), ([], False))

    def test_module_declared_in_a_path_attribute_file_is_a_sibling_of_that_file(self) -> None:
        self.write("crates/low/src/lib.rs", '//! Low layer.\npub mod ring;\n#[path = "impl/entry.rs"]\nmod entry;\n')
        self.write("crates/low/src/impl/entry.rs", "#[cfg(test)]\nmod helper;\n")
        self.write("crates/low/src/impl/helper.rs", "fn help() {}\n")
        tree = CHECKER.Tree(self.root)
        self.assertEqual(tree.reaches("crates/low/src/impl/helper.rs"), [("lib", ("test",))])

    def test_doctest_only_module_is_test_only(self) -> None:
        self.write("crates/low/src/lib.rs", "//! Low layer.\npub mod ring;\n#[cfg(doctest)]\nmod boundary;\n")
        self.write("crates/low/src/boundary.rs", "//! Compile-fail doctests.\n")
        tree = CHECKER.Tree(self.root)
        self.assertEqual(CHECKER.file_facts(tree, "crates/low/src/boundary.rs", []), (["doctest"], True))

    def test_fixture_embedded_by_a_production_item_is_production(self) -> None:
        fixture = "fixtures/template.json"
        self.write(fixture, "{}\n")
        self.assertEqual(CHECKER.file_facts(CHECKER.Tree(self.root), fixture, []), ([], True))
        self.append(BACKEND, 'const TEMPLATE: &str = include_str!("../../../fixtures/template.json");\n')
        tree = CHECKER.Tree(self.root)
        self.assertEqual(tree.embedding_sites()[fixture][0][0], BACKEND)
        self.assertEqual(CHECKER.file_facts(tree, fixture, []), ([], False))
        self.write(BACKEND, TREE[BACKEND] + '#[cfg(test)]\nconst TEMPLATE: &str = include_str!("../../../fixtures/template.json");\n')
        self.assertEqual(CHECKER.file_facts(CHECKER.Tree(self.root), fixture, []), ([], True))
        self.write(BACKEND, TREE[BACKEND] + '// include_str!("../../../fixtures/template.json")\n')
        self.assertEqual(CHECKER.file_facts(CHECKER.Tree(self.root), fixture, []), ([], True))
        self.write(BACKEND, TREE[BACKEND])
        self.write(RING_TESTS, TREE[RING_TESTS] + 'const T: &[u8] = include_bytes!("../../../fixtures/template.json");\n')
        self.assertEqual(CHECKER.file_facts(CHECKER.Tree(self.root), fixture, []), ([], True))
        self.append(BACKEND, 'const T: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/template.json"));\n')
        self.assertEqual(CHECKER.file_facts(CHECKER.Tree(self.root), fixture, []), ([], False))

    def test_symbols_resolve_with_cfg_and_test_only_status(self) -> None:
        tree = CHECKER.Tree(self.root)
        self.assertEqual(CHECKER.symbol_facts(tree, RING, "ntt_forward", ["fixtures"]), ([], False, ""))
        self.assertEqual(CHECKER.symbol_facts(tree, RING, "ntt_reference", ["fixtures"]), (["test"], True, ""))
        self.assertEqual(
            CHECKER.symbol_facts(tree, RING, "keygen_from_seed", ["fixtures"]),
            (['any(test, feature = "fixtures")'], True, ""),
        )
        self.assertFalse(CHECKER.symbol_facts(tree, RING, "keygen_from_seed", [])[1])
        self.assertEqual(CHECKER.symbol_facts(tree, RING_TESTS, "check", [])[:2], ([], True))
        self.assertIn("does not define", CHECKER.symbol_facts(tree, RING, "missing", [])[2])
        self.assertEqual(CHECKER.symbol_facts(tree, CLIENT, "TAG", []), ([], False, ""))
        self.assertIn("does not contain", CHECKER.symbol_facts(tree, CLIENT, "TA", [])[2])

    def test_callers_are_production_functions_that_call_the_callee(self) -> None:
        tree = CHECKER.Tree(self.root)
        listed = [RING, RING_TESTS, BACKEND, KDF]
        scope = CHECKER.caller_scope(tree, RING, listed, "pub")
        self.assertIn(BACKEND, scope)
        self.assertEqual(CHECKER.find_callers(tree, RING, "ntt_forward", scope, []), ({BACKEND: ["bfv_multiply"]}, True))
        private = CHECKER.caller_scope(tree, RING, listed, "")
        self.assertNotIn(BACKEND, private)
        self.assertEqual(
            CHECKER.find_callers(tree, RING, "mul_mod", private, []),
            ({RING: ["RnsChain::product", "ntt_forward"]}, True),
        )
        self.write(BACKEND, TREE[BACKEND] + "fn mul_mod() {}\nfn own() {\n    mul_mod();\n}\n")
        tree = CHECKER.Tree(self.root)
        self.assertEqual(
            CHECKER.find_callers(tree, RING, "mul_mod", CHECKER.caller_scope(tree, RING, listed, "pub"), []),
            ({RING: ["RnsChain::product", "ntt_forward"]}, True),
        )
        self.assertEqual(
            CHECKER.find_callers(tree, BACKEND, "mul_mod", CHECKER.caller_scope(tree, BACKEND, listed, ""), []),
            ({BACKEND: ["own"]}, True),
        )
        self.append(BACKEND, "#[cfg(not(target_os = \"linux\"))]\nfn mul_mod() {}\n")
        tree = CHECKER.Tree(self.root)
        self.assertFalse(CHECKER.find_callers(tree, BACKEND, "mul_mod", CHECKER.caller_scope(tree, BACKEND, listed, ""), [])[1])

    def test_local_variable_named_like_the_callee_is_not_a_caller(self) -> None:
        self.append(RING, (
            "fn scale() -> u64 {\n    let mul_mod = 3;\n    mul_mod + 1\n}\n"
            "fn widen(mul_mod: u64) -> u64 {\n    mul_mod * 2\n}\n"
            "fn passes_local() -> u64 {\n    let mul_mod = 3;\n    widen(mul_mod)\n}\n"
            "fn apply() -> [u64; 1] {\n    [1u64].map(mul_mod_one)\n}\n"
            "fn mul_mod_one(value: u64) -> u64 {\n    value\n}\n"
            "fn folds() -> u64 {\n    fold(1, mul_mod, 3)\n}\n"
            "#[cfg(test)]\nfn only_in_tests() -> u64 {\n    mul_mod(1, 2, 3)\n}\n"
        ))
        tree = CHECKER.Tree(self.root)
        scope = CHECKER.caller_scope(tree, RING, [RING], "")
        self.assertEqual(
            CHECKER.find_callers(tree, RING, "mul_mod", scope, []),
            ({RING: ["RnsChain::product", "folds", "ntt_forward"]}, True),
        )

    def test_method_callers_need_the_type(self) -> None:
        self.append(RING, (
            "/// Other.\npub struct Other;\n"
            "impl Other {\n    /// Product.\n    pub fn product(&self) -> u64 {\n        1\n    }\n"
            "    fn twice(&self) -> u64 {\n        self.product() * 2\n    }\n}\n"
            "impl RnsChain {\n"
            "    fn twice(&self) -> u64 {\n        self.product() * 2\n    }\n"
            "    fn with(&self, other: &Self) -> u64 {\n        other.product()\n    }\n"
            "    fn qualified(&self) -> u64 {\n        Self::product(self)\n    }\n"
            "}\n"
            "fn uses_chain(chain: &RnsChain) -> u64 {\n    chain.product()\n}\n"
            "fn uses_other(other: &Other) -> u64 {\n    other.product()\n}\n"
            "fn local_only() -> u64 {\n    let product = 2;\n    product\n}\n"
            "fn by_path(chain: &Other) -> u64 {\n    RnsChain::product(&RnsChain) + Other::product(chain)\n}\n"
        ))
        tree = CHECKER.Tree(self.root)
        scope = CHECKER.caller_scope(tree, RING, [RING], "pub")
        expected = {RING: ["RnsChain::qualified", "RnsChain::twice", "RnsChain::with", "by_path", "uses_chain"]}
        self.assertEqual(CHECKER.find_callers(tree, RING, "RnsChain::product", scope, []), (expected, True))
        self.assertEqual(
            CHECKER.find_callers(tree, RING, "Other::product", scope, []),
            ({RING: ["Other::twice", "by_path", "uses_other"]}, True),
        )
        self.append(RING, "fn iterates() -> u64 {\n    [1u64, 2].iter().product()\n}\n")
        tree = CHECKER.Tree(self.root)
        self.assertEqual(CHECKER.find_callers(tree, RING, "RnsChain::product", scope, []), (expected, False))

    def test_type_turbofish_paths_preserve_the_explicit_qualifier(self) -> None:
        for expression, qualifier in (
            ("SecretPolynomialVectorV1::<TBOX_LEXT_V1>::zero()", "SecretPolynomialVectorV1"),
            ("module::RnsChain::<Vec<Vec<u64>>>::zero()", "RnsChain"),
            ("RnsChain::<fn() -> Vec<u8>>::zero()", "RnsChain"),
            ("RnsChain::<T>::zero::<U>()", "RnsChain"),
            ("polynomial::zero::<T>()", "polynomial"),
            ("polynomial::zero()", "polynomial"),
            ("<T as Factory>::zero()", "?"),
            ("RnsChain::<Vec<T>::zero()", "?"),
        ):
            with self.subTest(expression=expression):
                masked = CHECKER.mask_rust(expression)
                self.assertEqual(
                    CHECKER.classify_use(masked, masked.index("zero"), "zero"),
                    ("path", qualifier),
                )

    def test_generic_type_constructor_is_not_a_free_function_caller(self) -> None:
        self.append(RING, "pub fn zero() {}\n")
        self.append(BACKEND, (
            "struct SecretPolynomialVectorV1<const N: usize>;\n"
            "impl<const N: usize> SecretPolynomialVectorV1<N> {\n"
            "    fn zero() -> Self {\n        Self\n    }\n}\n"
            "fn prove_attempt() {\n    SecretPolynomialVectorV1::<TBOX_LEXT_V1>::zero();\n}\n"
            "fn shared_zero() {\n    low::ring::zero();\n}\n"
        ))
        tree = CHECKER.Tree(self.root)
        self.assertEqual(
            CHECKER.find_callers(tree, RING, "zero", [RING, BACKEND], []),
            ({BACKEND: ["shared_zero"]}, True),
        )
        # Another parsed free zero (as in the Pasta macro) must not turn this
        # explicit type-qualified call into an unresolved free-function use.
        other = "crates/low/src/other.rs"
        self.write(other, "pub fn zero() {}\n")
        tree = CHECKER.Tree(self.root)
        self.assertEqual(
            CHECKER.find_callers(tree, RING, "zero", [RING, BACKEND, other], []),
            ({BACKEND: ["shared_zero"]}, True),
        )

    def test_generic_type_method_is_attributed_and_unknown_receiver_stays_open(self) -> None:
        self.append(RING, (
            "fn typed_generic() {\n    RnsChain::<Vec<Vec<u64>>>::product(&RnsChain);\n}\n"
            "fn typed_function() {\n    RnsChain::<fn() -> Vec<u8>>::product(&RnsChain);\n}\n"
        ))
        expected = {RING: ["typed_function", "typed_generic"]}
        tree = CHECKER.Tree(self.root)
        self.assertEqual(CHECKER.find_callers(tree, RING, "RnsChain::product", [RING], []), (expected, True))
        self.append(RING, "fn unresolved() {\n    <T as Factory>::product();\n}\n")
        tree = CHECKER.Tree(self.root)
        self.assertEqual(CHECKER.find_callers(tree, RING, "RnsChain::product", [RING], []), (expected, False))

    def test_free_function_callers_follow_the_defining_module(self) -> None:
        self.write("crates/low/src/lib.rs", "//! Low layer.\npub mod ring;\npub mod other;\npub mod user;\n")
        self.write("crates/low/src/other.rs", "pub fn ntt_forward(values: &mut [u64]) {\n    let _ = values;\n}\nfn own() {\n    ntt_forward(&mut []);\n}\n")
        self.write("crates/low/src/user.rs", (
            "use crate::ring::ntt_forward;\n"
            "fn imported() {\n    ntt_forward(&mut []);\n}\n"
            "fn other_path() {\n    crate::other::ntt_forward(&mut []);\n}\n"
        ))
        self.write("crates/low/src/blind.rs", "fn unknown() {\n    ntt_forward(&mut []);\n}\n")
        tree = CHECKER.Tree(self.root)
        scope = [RING, "crates/low/src/other.rs", "crates/low/src/user.rs"]
        callers, exhaustive = CHECKER.find_callers(tree, RING, "ntt_forward", scope, [])
        self.assertEqual(callers, {"crates/low/src/user.rs": ["imported", "other_path"]})
        self.assertTrue(exhaustive)
        self.write("crates/low/src/lib.rs", "//! Low layer.\npub mod ring;\npub mod other;\npub mod user;\npub mod blind;\n")
        tree = CHECKER.Tree(self.root)
        callers, exhaustive = CHECKER.find_callers(tree, RING, "ntt_forward", scope + ["crates/low/src/blind.rs"], [])
        self.assertNotIn("crates/low/src/blind.rs", callers)
        self.assertFalse(exhaustive)

    def test_function_nested_in_an_inline_module_is_a_free_function(self) -> None:
        self.append(RING, "mod inner {\n    pub fn nested_scale() {}\n}\nfn uses_nested() {\n    inner::nested_scale();\n}\n")
        tree = CHECKER.Tree(self.root)
        self.assertEqual(
            CHECKER.find_callers(tree, RING, "inner::nested_scale", [RING], []),
            ({RING: ["uses_nested"]}, True),
        )

    def test_use_declarations_are_parsed_into_bound_names(self) -> None:
        masked = CHECKER.mask_rust(
            "use a::{b as c, d::{self as e, f}, g::*};\n"
            "use ::x::y;\n"
            "pub(crate) use m::n as o;\n"
            "use p::{self};\n"
            "// use hidden::in_a_comment as never;\n"
            "fn body() {\n    let use_count = 1;\n    let _ = use_count;\n}\n"
        )
        self.assertEqual(CHECKER.use_bindings(masked), [
            (("a", "b"), "c"), (("a", "d"), "e"), (("a", "d", "f"), "f"), (("a", "g", "*"), "*"),
            (("x", "y"), "y"), (("m", "n"), "o"), (("p",), "p"),
        ])
        self.assertEqual(CHECKER.use_bindings("use a::{b as };\nuse c::d;\n"), [(("c", "d"), "d")])
        self.assertEqual(CHECKER.use_bindings("use a::::b;\n"), [])
        source = CHECKER.RustSource("use low::ring::{mul_mod as product, ntt_forward};\nuse low::ring as arithmetic;\n")
        self.assertEqual(CHECKER.renamed_imports(source, "mul_mod", {"ring"}), ({"product": "ring"}, {"arithmetic"}))
        self.assertEqual(CHECKER.renamed_imports(source, "ntt_forward", {"ring"}), ({}, {"arithmetic"}))
        self.assertEqual(CHECKER.renamed_imports(source, "mul_mod", {"other"}), ({"product": "ring"}, set()))

    def test_callers_through_renamed_imports_are_found(self) -> None:
        user = "crates/low/src/user.rs"
        self.write("crates/low/src/lib.rs", "//! Low layer.\npub mod ring;\npub mod user;\n")
        self.write(user, (
            "use crate::ring::{ntt_forward as forward, RnsChain as Chain};\n"
            "use crate::ring as arithmetic;\n"
            "fn through_item_alias() {\n    forward(&mut []);\n}\n"
            "fn through_module_alias() {\n    arithmetic::ntt_forward(&mut []);\n}\n"
            "fn as_value() {\n    apply(forward);\n}\n"
            "fn shadowed() {\n    let forward = 1;\n    let _ = forward;\n}\n"
            "fn through_type_alias(chain: &Chain) -> u64 {\n    chain.product()\n}\n"
            "fn through_type_alias_path() -> u64 {\n    Chain::product(&Chain)\n}\n"
            "#[cfg(test)]\nfn only_in_tests() {\n    forward(&mut []);\n}\n"
        ))
        tree = CHECKER.Tree(self.root)
        scope = [RING, user]
        self.assertEqual(
            CHECKER.find_callers(tree, RING, "ntt_forward", scope, []),
            ({user: ["as_value", "through_item_alias", "through_module_alias"]}, True),
        )
        self.assertEqual(
            CHECKER.find_callers(tree, RING, "RnsChain::product", scope, []),
            ({user: ["through_type_alias", "through_type_alias_path"]}, True),
        )
        # An alias of a function of the same name from another module of the scope is not a caller;
        # one whose module is unknown leaves the list incomplete.
        other = "crates/low/src/other.rs"
        self.write("crates/low/src/lib.rs", "//! Low layer.\npub mod ring;\npub mod user;\npub mod other;\npub mod blind;\n")
        self.write(other, "pub fn ntt_forward(values: &mut [u64]) {\n    let _ = values;\n}\n")
        self.write("crates/low/src/blind.rs", "use crate::other::ntt_forward as forward;\nfn other_alias() {\n    forward(&mut []);\n}\n")
        tree = CHECKER.Tree(self.root)
        scope = [RING, user, other, "crates/low/src/blind.rs"]
        self.assertEqual(
            CHECKER.find_callers(tree, RING, "ntt_forward", scope, []),
            ({user: ["as_value", "through_item_alias", "through_module_alias"]}, True),
        )
        self.write("crates/low/src/blind.rs", "use elsewhere::ntt_forward as forward;\nfn unknown_alias() {\n    forward(&mut []);\n}\n")
        tree = CHECKER.Tree(self.root)
        callers, exhaustive = CHECKER.find_callers(tree, RING, "ntt_forward", scope, [])
        self.assertNotIn("crates/low/src/blind.rs", callers)
        self.assertFalse(exhaustive)

    def test_path_qualified_call_in_a_file_with_a_function_of_the_same_name(self) -> None:
        self.append(BACKEND, (
            "fn ntt_forward(values: &mut [u64]) {\n    low::ring::ntt_forward(values);\n}\n"
            "fn local_only() {\n    ntt_forward(&mut []);\n}\n"
        ))
        tree = CHECKER.Tree(self.root)
        scope = CHECKER.caller_scope(tree, RING, [RING, RING_TESTS, BACKEND, KDF], "pub")
        self.assertEqual(
            CHECKER.find_callers(tree, RING, "ntt_forward", scope, []),
            ({BACKEND: ["bfv_multiply", "ntt_forward"]}, True),
        )
        self.assertEqual(
            CHECKER.find_callers(tree, BACKEND, "ntt_forward", CHECKER.caller_scope(tree, BACKEND, [BACKEND], ""), []),
            ({BACKEND: ["local_only"]}, True),
        )

    def test_name_imported_from_another_defining_module_is_not_a_caller(self) -> None:
        # A consumer wraps the callee in a function of the same name; its submodules import the wrapper.
        wrapper = "crates/high/src/wrapper.rs"
        child = "crates/high/src/wrapper/child.rs"
        nested = "crates/high/src/wrapper/nested/mod.rs"
        self.write("crates/high/src/lib.rs", "//! High layer.\npub mod backend;\npub mod kdf;\npub mod wrapper;\n")
        self.write(wrapper, (
            "mod child;\nmod nested;\n"
            "fn ntt_forward(values: &mut [u64]) {\n    low::ring::ntt_forward(values);\n}\n"
        ))
        self.write(child, "use super::ntt_forward;\nfn through_wrapper() {\n    ntt_forward(&mut []);\n}\n")
        self.write(nested, "use crate::wrapper::ntt_forward;\nfn through_crate_path() {\n    ntt_forward(&mut []);\n}\n")
        tree = CHECKER.Tree(self.root)
        self.assertEqual(CHECKER.import_qualifiers(tree.rust(child), child, "ntt_forward"), {"wrapper"})
        self.assertEqual(CHECKER.import_qualifiers(tree.rust(nested), nested, "ntt_forward"), {"wrapper"})
        self.assertEqual(CHECKER.import_qualifiers(tree.rust(BACKEND), BACKEND, "ntt_forward"), set())
        scope = [RING, BACKEND, wrapper, child, nested]
        self.assertEqual(
            CHECKER.find_callers(tree, RING, "ntt_forward", scope, []),
            ({BACKEND: ["bfv_multiply"], wrapper: ["ntt_forward"]}, True),
        )
        self.assertEqual(
            CHECKER.find_callers(tree, wrapper, "ntt_forward", [wrapper, child, nested], []),
            ({child: ["through_wrapper"], nested: ["through_crate_path"]}, True),
        )
        # Without the import the bare call cannot be attributed and the list is incomplete.
        self.write(child, "fn through_glob() {\n    ntt_forward(&mut []);\n}\n")
        tree = CHECKER.Tree(self.root)
        self.assertFalse(CHECKER.find_callers(tree, RING, "ntt_forward", scope, [])[1])

    def test_method_receiver_can_be_a_typed_constant(self) -> None:
        self.append(RING, (
            "/// Other.\npub struct Other;\n"
            "impl Other {\n    /// Product.\n    pub fn product(&self) -> u64 {\n        1\n    }\n}\n"
            "const CHAIN: RnsChain = RnsChain;\n"
            "static OTHER: Other = Other;\n"
            "const CHAINS: [RnsChain; 1] = [RnsChain];\n"
            "fn through_constant() -> u64 {\n    CHAIN.product()\n}\n"
            "fn through_static() -> u64 {\n    OTHER.product()\n}\n"
        ))
        tree = CHECKER.Tree(self.root)
        self.assertEqual(CHECKER._typed_constant(tree.rust(RING), "CHAIN"), "RnsChain")
        self.assertEqual(CHECKER._typed_constant(tree.rust(RING), "OTHER"), "Other")
        self.assertIsNone(CHECKER._typed_constant(tree.rust(RING), "MISSING"))
        scope = CHECKER.caller_scope(tree, RING, [RING], "pub")
        self.assertEqual(CHECKER.find_callers(tree, RING, "RnsChain::product", scope, []), ({RING: ["through_constant"]}, True))
        self.assertEqual(CHECKER.find_callers(tree, RING, "Other::product", scope, []), ({RING: ["through_static"]}, True))

    def test_manifest_dependencies_and_development_features(self) -> None:
        tree = CHECKER.Tree(self.root)
        self.assertEqual(CHECKER.manifest_dependencies(tree, "crates/high"), {"low"})
        self.assertEqual(CHECKER.development_feature_errors(tree, "crates/low", "fixtures"), [])
        self.assertTrue(CHECKER.development_feature_errors(tree, "crates/low", "absent"))
        self.replace("crates/high/Cargo.toml", 'low = { path = "../low" }\n\n[dev', 'low = { path = "../low", features = ["fixtures"] }\n\n[dev')
        errors = CHECKER.development_feature_errors(CHECKER.Tree(self.root), "crates/low", "fixtures")
        self.assertTrue(any("outside dev-dependencies" in error for error in errors), errors)

    def test_manifest_dependencies_follow_package_renames_and_tables(self) -> None:
        self.write("crates/high/Cargo.toml", (
            '[package]\nname = "high"\n\n[dependencies]\nbase = { package = "low", path = "../low" }\nserde.workspace = true\n\n'
            '[dependencies.extra]\npackage = "extra-impl"\nversion = "1"\n\n'
            "[target.'cfg(unix)'.dependencies]\nnix = \"1\"\n\n[dev-dependencies]\nonly_dev = \"1\"\n\n[build-dependencies]\ncc = \"1\"\n"
        ))
        self.assertEqual(
            CHECKER.manifest_dependencies(CHECKER.Tree(self.root), "crates/high"),
            {"low", "serde", "extra-impl", "nix"},
        )

    def test_specification_trees_are_scanned_and_markdown_only_for_the_backend(self) -> None:
        self.write("specs/routes.tsv", "ram_lfe_execute\n")
        self.write("docs/notes.json", '{"bfv": 1}\n')
        self.write("specs/overview.md", "BFV, RNS and NTT are described here.\n")
        self.write("specs/guide.md", f"The `{TAG}` tag is not encrypted evaluation; see the BFV notes.\n")
        self.write(CHECKER.DEFAULT_MAP, '{"bfv": 1}\n')
        scan = CHECKER.scan_tree(CHECKER.Tree(self.root))
        self.assertEqual(scan["specs/routes.tsv"], ["ram_lfe"])
        self.assertEqual(scan["docs/notes.json"], ["bfv"])
        self.assertNotIn("specs/overview.md", scan)
        self.assertEqual(scan["specs/guide.md"], ["hkdf", "hkdf_ram_lfe"])
        self.assertNotIn(CHECKER.DEFAULT_MAP, scan)

    def test_function_units_count_production_and_test_gated_separately(self) -> None:
        self.append(RING, (
            "#[cfg(test)]\nimpl RnsChain {\n    fn zero() -> Self {\n        RnsChain\n    }\n}\n"
            "#[cfg(test)]\nmod reference {\n    pub fn slow() {}\n    mod inner {\n        fn deeper() {}\n    }\n}\n"
            '#[cfg(feature = "full")]\nfn feature_gated() {}\n'
        ))
        production, gated = CHECKER.function_units(CHECKER.Tree(self.root), RING, ["fixtures"])
        self.assertEqual(dict(production), {"ntt_forward": 1, "mul_mod": 1, "RnsChain::product": 1, "feature_gated": 1})
        self.assertEqual(dict(gated), {
            "ntt_reference": 1, "keygen_from_seed": 1, "mod tests": 1, "RnsChain::zero": 1, "mod reference": 1,
        })
        production, gated = CHECKER.function_units(CHECKER.Tree(self.root), RING, [])
        self.assertEqual(production["keygen_from_seed"], 1)
        self.assertNotIn("keygen_from_seed", gated)

    def test_hkdf_derivation_functions_are_those_that_instantiate_the_primitive(self) -> None:
        self.append(BACKEND, (
            "fn mentions_only() {\n    let hkdf_label = 1;\n    let _ = hkdf_label;\n}\n"
            "#[cfg(test)]\nfn test_derivation() {\n    let _ = Hkdf::<Sha3>::new(None, &[]);\n}\n"
            "// Hkdf::<Sha3>::new in a comment\n"
        ))
        tree = CHECKER.Tree(self.root)
        self.assertEqual(CHECKER.hkdf_derivation_functions(tree, BACKEND, []), ["derive_phone_nullifier", "evaluate_hkdf_prf"])
        self.assertEqual(CHECKER.hkdf_derivation_functions(tree, KDF, []), [])
        self.assertEqual(CHECKER.function_names(tree, BACKEND, "evaluate_hkdf_prf"), ["evaluate_hkdf_prf"])
        self.assertEqual(CHECKER.function_names(tree, BACKEND, "RamLfeBackend::HkdfSha3_512PrfV1"), [])
        self.assertEqual(CHECKER.function_names(tree, CLIENT, "TAG"), [])


class MapTest(TreeCase):
    def test_valid_map_matches_the_tree(self) -> None:
        self.assertEqual(self.errors(valid_map()), [])

    def test_scan_finds_exactly_the_listed_files(self) -> None:
        scan = CHECKER.scan_tree(CHECKER.Tree(self.root))
        listed = {record["path"]: record["patterns"] for group in valid_map()["file_groups"] for record in group["files"]}
        self.assertEqual(scan, listed)

    def test_header_must_restate_the_scan_contract(self) -> None:
        document = valid_map()
        document["scan"]["patterns"].remove("hkdf")
        self.assert_error(document, "scan must restate")
        document = valid_map()
        document["scan"]["excluded_paths"].append("specs/")
        self.assert_error(document, "scan must restate")
        document = valid_map()
        document["task"] = "C.2"
        self.assert_error(document, "task must be C.1")
        document = valid_map()
        document["schema_version"] = 1
        self.assert_error(document, f"schema_version must be {CHECKER.SCHEMA_VERSION}")
        self.assertEqual(CHECKER.check(self.root, [])[0], "map must be a JSON object")

    def test_new_source_file_must_be_listed(self) -> None:
        self.write("crates/high/src/extra.rs", "fn rns_helper() {}\n")
        self.assert_error(valid_map(), "crates/high/src/extra.rs matches ['rns'] but the map does not list it")

    def test_new_specification_file_must_be_listed(self) -> None:
        self.write("specs/sibling_inventory.json", '{"anchor": "RamLfeBackend::HkdfSha3_512PrfV1"}\n')
        self.assert_error(valid_map(), "specs/sibling_inventory.json matches ['hkdf', 'hkdf_ram_lfe', 'ram_lfe'] but the map does not list it")
        self.assert_error(valid_map(), "specs/sibling_inventory.json names the RAM-LFE HKDF backend but hkdf.ram_lfe_backend.users does not list it")
        self.write("specs/guide.md", f"`{TAG}`\n")
        self.assert_error(valid_map(), "specs/guide.md names the RAM-LFE HKDF backend but hkdf.ram_lfe_backend.users does not list it")
        document = valid_map()
        document["file_groups"].append({"id": "specs", "role": "documentation", "summary": "Specifications.", "files": [
            {"path": "specs/guide.md", "patterns": ["hkdf", "hkdf_ram_lfe"]},
            {"path": "specs/sibling_inventory.json", "patterns": ["hkdf", "hkdf_ram_lfe", "ram_lfe"]},
        ]})
        document["hkdf"]["ram_lfe_backend"]["users"].extend([
            {"path": "specs/guide.md", "kind": "documentation", "literals": [TAG]},
            {"path": "specs/sibling_inventory.json", "kind": "source_anchor", "literals": ["HkdfSha3_512PrfV1"]},
        ])
        self.assertEqual(self.errors(document), [])

    def test_missing_stale_and_duplicate_paths_are_rejected(self) -> None:
        document = valid_map()
        document["file_groups"][0]["files"].append({"path": "crates/low/src/gone.rs", "patterns": ["ntt"]})
        self.assert_error(document, "crates/low/src/gone.rs is listed but does not exist")
        document = valid_map()
        document["file_groups"][0]["files"].append({"path": "tools/reader.py", "patterns": ["ntt"]})
        self.assert_error(document, "tools/reader.py is listed but no longer matches")
        document = valid_map()
        document["file_groups"][1]["files"].append(copy.deepcopy(document["file_groups"][0]["files"][0]))
        self.assert_error(document, f"{RING} is listed twice")

    def test_recorded_patterns_must_equal_the_fresh_scan(self) -> None:
        self.replace(KDF, "let hkdf_salt = 1;", "let hkdf_salt = 1;\n    let ntt_size = 2;")
        self.assert_error(valid_map(), f"{KDF} matches ['hkdf', 'ntt']")
        self.assert_error(valid_map(), "is recorded as unrelated HKDF but matches")

    def test_file_test_only_and_cfg_must_match_the_module_tree(self) -> None:
        document = valid_map()
        del document["file_groups"][1]["files"][0]["test_only"]
        self.assert_error(document, f"{RING_TESTS} test_only is True, map records False")
        document = valid_map()
        document["file_groups"][0]["files"][0]["test_only"] = True
        self.assert_error(document, f"{RING} test_only is False, map records True")
        self.replace("crates/low/src/lib.rs", "pub mod ring;", '#[cfg(feature = "full")]\npub mod ring;')
        self.assert_error(valid_map(), f"{RING} is compiled under ['feature = \"full\"']")

    def test_fixture_embedded_in_production_must_be_recorded_as_production(self) -> None:
        self.append(BACKEND, 'const VECTORS: &str = include_str!("../../../fixtures/vectors.json");\n')
        self.assert_error(valid_map(), f"{VECTORS} test_only is False, map records True")
        document = valid_map()
        del document["file_groups"][5]["files"][0]["test_only"]
        self.assertEqual(self.errors(document), [])

    def test_removed_symbol_is_reported(self) -> None:
        self.replace(RING, "fn mul_mod(", "fn multiply_mod(")
        self.assert_error(valid_map(), f"{RING} does not define mul_mod")

    def test_test_only_reference_cannot_be_recorded_as_production(self) -> None:
        document = valid_map()
        reference = document["primitives"][0]["implementations"][1]
        reference.pop("test_only")
        reference["role"] = "duplicate"
        self.assert_error(document, "ntt_reference test_only is True, map records False")
        document = valid_map()
        document["protocol_logic"].append({
            "id": "low.keygen", "scheme": "bfv", "executes": ["key_generation"], "path": RING,
            "symbols": [{"symbol": "keygen_from_seed", "cfg": ['any(test, feature = "fixtures")'], "test_only": True}],
        })
        self.assert_error(document, "keygen_from_seed must be production")

    def test_ungated_reference_no_longer_counts_as_test_only(self) -> None:
        self.replace(RING, "#[cfg(test)]\nfn ntt_reference", "fn ntt_reference")
        self.assert_error(valid_map(), "ntt_reference cfg is [], map records ['test']")
        self.assert_error(valid_map(), "ntt_reference test_only is False, map records True")
        self.assert_error(valid_map(), f"{RING} records ntt_reference as a test-gated unit, but the source has none by that name (ungated or removed)")

    def test_development_feature_must_stay_out_of_normal_dependencies(self) -> None:
        document = valid_map()
        document["development_features"] = []
        self.assert_error(document, "keygen_from_seed test_only is False, map records True")
        self.assert_error(document, f"{RING}::keygen_from_seed is a production function with no owner in the inventory")
        self.replace("crates/high/Cargo.toml", 'low = { path = "../low" }\n\n[dev', 'low = { path = "../low", features = ["fixtures"] }\n\n[dev')
        self.assert_error(valid_map(), "enables development feature fixtures outside dev-dependencies")

    def test_canonical_source_must_be_production_and_consistent(self) -> None:
        document = valid_map()
        primitive = document["primitives"][0]
        primitive["canonical_source"]["symbols"] = ["ntt_reference"]
        primitive["implementations"][0]["role"] = "duplicate"
        primitive["implementations"][1]["role"] = "canonical"
        self.assert_error(document, "role canonical disagrees with test_only True")
        document = valid_map()
        document["primitives"][0]["canonical_source"]["symbols"] = ["ntt_forward", "mul_mod"]
        self.assert_error(document, "canonical_source symbols differ")
        document = valid_map()
        document["primitives"][0]["canonical_source"] = None
        self.assert_error(document, "has canonical implementations but no canonical_source")

    def test_each_primitive_has_exactly_one_owner(self) -> None:
        document = valid_map()
        del document["primitives"][0]["owner"]
        self.assert_error(document, "primitive ntt.forward must have exactly one owner")
        document = valid_map()
        document["primitives"][0]["owner"] = [{"crate": "shared", "module": "shared::ntt"}, {"crate": "low", "module": "ring"}]
        self.assert_error(document, "primitive ntt.forward must have exactly one owner")
        document = valid_map()
        document["primitives"][0]["owners"] = [document["primitives"][0]["owner"]]
        self.assert_error(document, "primitive ntt.forward must have exactly one owner")
        document = valid_map()
        document["primitives"][0]["owner"]["module"] = "shared::elsewhere"
        self.assert_error(document, "is not a destination module")
        document = valid_map()
        document["primitives"].append(copy.deepcopy(document["primitives"][0]))
        self.assert_error(document, "primitive ntt.forward is listed twice")

    def test_implementation_belongs_to_one_primitive(self) -> None:
        document = valid_map()
        document["primitives"][1]["implementations"].append(copy.deepcopy(document["primitives"][0]["implementations"][0]))
        document["primitives"][1]["implementations"][-1]["role"] = "duplicate"
        self.assert_error(document, f"{RING}::ntt_forward is claimed by both primitive ntt.forward and primitive modular.mul")

    def test_owner_must_be_the_lowest_layer(self) -> None:
        document = valid_map()
        document["primitives"][0]["owner"] = {"crate": "high", "module": "high::backend"}
        self.assert_error(document, "owner is a higher layer than implementation")
        document = valid_map()
        document["crates"][2]["depends_on"] = ["low", "missing"]
        self.assert_error(document, "depends on missing, which is not a lower layer")
        document = valid_map()
        document["crates"][1]["depends_on"] = ["shared"]
        self.assert_error(document, "crates/low/Cargo.toml does not depend on shared")

    def test_layer_list_must_declare_every_manifest_dependency(self) -> None:
        document = valid_map()
        document["crates"][2]["depends_on"] = []
        self.assert_error(document, "crate high depends_on omits ['low'], which crates/high/Cargo.toml depends on")
        document = valid_map()
        high = document["crates"].pop(2)
        high["depends_on"] = []
        document["crates"].insert(0, high)
        for primitive in document["primitives"]:
            primitive["owner"] = {"crate": "high", "module": "high::backend"}
        self.assert_error(document, "crate high depends_on omits ['low']")
        document = valid_map()
        high = document["crates"].pop(2)
        document["crates"].insert(0, high)
        self.assert_error(document, "crate high depends on low, which is not a lower layer in crates")

    def test_planned_destination_must_not_already_exist(self) -> None:
        self.write("crates/shared/Cargo.toml", '[package]\nname = "shared"\n')
        self.assert_error(valid_map(), "planned crate shared now exists")

    def test_recorded_callers_must_match_the_source(self) -> None:
        document = valid_map()
        document["primitives"][1]["implementations"][0]["callers"] = {RING: ["ntt_forward"]}
        self.assert_error(document, "mul_mod production callers are")
        document = valid_map()
        document["primitives"][1]["implementations"][0]["callers"][BACKEND] = ["bfv_multiply"]
        self.assert_error(document, "mul_mod production callers are")
        document = valid_map()
        document["primitives"][1]["implementations"][0]["callers_exhaustive"] = False
        self.assert_error(document, "mul_mod callers_exhaustive must be True")
        self.replace(BACKEND, "low::ring::ntt_forward(&mut []);", "let _ = 1;")
        self.assert_error(valid_map(), "ntt_forward production callers are {}")

    def test_local_variable_does_not_become_a_recorded_caller(self) -> None:
        self.append(BACKEND, "fn tally() -> u64 {\n    let ntt_forward = 2;\n    ntt_forward\n}\n")
        self.assertEqual(self.errors(valid_map()), [])
        document = valid_map()
        document["primitives"][0]["implementations"][0]["callers"][BACKEND].append("tally")
        self.assert_error(document, "ntt_forward production callers are")

    def test_caller_hidden_behind_a_renamed_import_must_be_recorded(self) -> None:
        # A renamed import leaves the callee's own identifier only in the `use` declaration.
        self.append(BACKEND, "use low::ring::ntt_forward as forward;\nfn renamed_item() {\n    forward(&mut []);\n}\n")
        self.assert_error(valid_map(), "ntt_forward production callers are")
        document = valid_map()
        document["primitives"][0]["implementations"][0]["callers"][BACKEND] = ["bfv_multiply", "renamed_item"]
        self.assertEqual(self.errors(document), [])
        self.append(BACKEND, "use low::ring as arithmetic;\nfn renamed_module() {\n    arithmetic::ntt_forward(&mut []);\n}\n")
        self.assert_error(document, "ntt_forward production callers are")
        document["primitives"][0]["implementations"][0]["callers"][BACKEND] = ["bfv_multiply", "renamed_item", "renamed_module"]
        self.assertEqual(self.errors(document), [])

    def test_every_production_function_of_an_owner_file_needs_one_owner(self) -> None:
        self.replace(RING, "/// Chain.", "/// Encrypt.\npub fn encrypt_fresh() {}\n/// Chain.")
        self.assert_error(valid_map(), f"{RING}::encrypt_fresh is a production function with no owner in the inventory")
        document = valid_map()
        document["function_assignment"][0]["production"]["low.chain"].append("encrypt_fresh")
        self.assertEqual(self.errors(document), [])
        document["function_assignment"][0]["production"]["low.chain"].append("encrypt_fresh")
        self.assert_error(document, f"{RING}::encrypt_fresh is assigned 2 times but defined 1 times")
        document = valid_map()
        document["function_assignment"][0]["production"]["low.chain"].append("mul_mod")
        self.assert_error(document, f"{RING}::mul_mod is claimed under primitives and also assigned as protocol logic")
        document = valid_map()
        document["function_assignment"][0]["production"]["low.missing"] = ["encrypt_fresh"]
        self.assert_error(document, "assigns functions to low.missing, which is not an entry of protocol_logic")
        document = valid_map()
        document["function_assignment"][0]["production"]["low.chain"].append("vanished")
        self.assert_error(document, f"{RING} records vanished as a production function, but the source has none by that name (test-gated or removed)")

    def test_kernel_named_function_in_an_owner_file_needs_an_owner_too(self) -> None:
        for name in ("rescale_limbs_exact", "modulus_switch_rns_polynomial", "bootstrap_ciphertext_ntt_slots"):
            self.write(RING, TREE[RING].replace("/// Chain.", f"fn {name}() {{}}\n/// Chain."))
            self.assert_error(valid_map(), f"{RING}::{name} is a production function with no owner in the inventory")

    def test_removing_a_primitive_leaves_all_its_functions_without_an_owner(self) -> None:
        document = valid_map()
        document["primitives"].pop(1)
        document["zk_ams_distinct"]["production_surface"]["allowed_primitives"] = ["ntt.forward"]
        self.assert_error(document, f"{RING}::mul_mod is a production function with no owner in the inventory")

    def test_ungating_a_test_only_function_fails(self) -> None:
        self.replace(RING, '#[cfg(any(test, feature = "fixtures"))]\npub fn keygen_from_seed', "pub fn keygen_from_seed")
        self.assert_error(valid_map(), f"{RING}::keygen_from_seed is a production function with no owner in the inventory")
        self.assert_error(valid_map(), f"{RING} records keygen_from_seed as a test-gated unit, but the source has none by that name (ungated or removed)")
        self.assert_error(valid_map(), "keygen_from_seed test_only is False, map records True")

    def test_every_test_gated_unit_of_an_owner_file_needs_one_reference(self) -> None:
        self.replace(RING, "/// Chain.", "#[cfg(test)]\nfn threshold_keygen_reference() {}\n/// Chain.")
        self.assert_error(valid_map(), f"{RING}::threshold_keygen_reference is a test-gated unit with no owner in the inventory")
        document = valid_map()
        document["function_assignment"][0]["test_gated"]["low.keygen"].append("threshold_keygen_reference")
        self.assertEqual(self.errors(document), [])
        document["function_assignment"][0]["test_gated"]["low.reference"].append("threshold_keygen_reference")
        self.assert_error(document, f"{RING}::threshold_keygen_reference is assigned 2 times but defined 1 times")
        self.write(RING, TREE[RING] + "#[cfg(test)]\nmod more_tests {\n    fn case() {}\n}\n")
        self.assert_error(valid_map(), f"{RING}::mod more_tests is a test-gated unit with no owner in the inventory")
        self.assert_no_error(valid_map(), "case")
        document = valid_map()
        document["function_assignment"][0]["test_gated"]["absent.reference"] = ["mod more_tests"]
        self.assert_error(document, "assigns functions to absent.reference, which is not an entry of test_only_references")

    def test_owner_file_needs_an_entry_and_other_files_cannot_have_one(self) -> None:
        document = valid_map()
        document["function_assignment"] = []
        self.assert_error(document, f"{RING} is an owner file with 1 unclaimed production functions and 3 test-gated units but has no function_assignment entry")
        document = valid_map()
        document["function_assignment"].append({"path": BACKEND, "production": {"bfv.evaluation": ["bfv_multiply"]}, "test_gated": {}})
        self.assert_error(document, f"function_assignment lists {BACKEND}, which is not a production-compiled owner file")
        document = valid_map()
        document["function_assignment"].append(copy.deepcopy(document["function_assignment"][0]))
        self.assert_error(document, f"function_assignment lists {RING} twice")
        document = valid_map()
        document["function_assignment"][0]["production_unassigned"] = ["encrypt_fresh"]
        self.assert_error(document, f"{RING} leaves ['encrypt_fresh'] under production_unassigned")
        document = valid_map()
        del document["function_assignment"]
        self.assert_error(document, "function_assignment must be a JSON array")

    def test_file_holding_a_production_primitive_is_an_owner_file_outside_the_scopes(self) -> None:
        document = valid_map()
        document["arithmetic_scopes"][0]["assignment"] = "kernel_names"
        document["zk_ams_distinct"]["production_surface"]["prefix"] = "crates/absent/"
        errors = self.errors(document)
        self.assertEqual(errors, ["zk_ams_distinct.production_surface crates/absent/ is not inside an every_function scope"])
        tree = CHECKER.Tree(self.root)
        self.assertEqual(CHECKER.owner_files(tree, document, ["fixtures"]), [RING])
        document["function_assignment"] = []
        self.assert_error(document, f"{RING} is an owner file with 1 unclaimed production functions")
        document = valid_map()
        document["arithmetic_scopes"][0]["assignment"] = "sometimes"
        self.assert_error(document, "arithmetic scope crates/low/src/ needs assignment")

    def test_entry_symbols_and_function_assignment_must_agree(self) -> None:
        document = valid_map()
        document["protocol_logic"].append({"id": "low.second", "scheme": "bfv", "executes": [], "path": RING, "symbols": []})
        document["function_assignment"][0]["production"] = {"low.second": ["RnsChain::product"]}
        self.assert_error(document, f"protocol_logic low.chain names {RING}::RnsChain::product, but function_assignment does not assign it there")
        document = valid_map()
        document["function_assignment"][0]["test_gated"] = {
            "low.reference": ["keygen_from_seed", "ntt_reference"], "low.unit_tests": ["mod tests"],
        }
        self.assert_error(document, f"test_only_references low.keygen names {RING}::keygen_from_seed, but function_assignment does not assign it there")
        document = valid_map()
        document["protocol_logic"].append({"id": "low.empty", "scheme": "bfv", "executes": [], "symbols": []})
        self.assert_error(document, "protocol_logic low.empty names no symbol and owns no function")
        document = valid_map()
        document["test_only_references"].append({"id": "low.void", "scheme": "bfv", "kind": "fixture", "symbols": []})
        self.assert_error(document, "test_only_references low.void names no symbol and owns no function")

    def test_scheme_names_a_protocol_or_the_shared_owner(self) -> None:
        document = valid_map()
        document["protocol_logic"][0]["scheme"] = "ckks"
        self.assert_error(document, "protocol_logic bfv.evaluation has unknown scheme ckks")
        document = valid_map()
        document["test_only_references"][-1]["scheme"] = "ckks"
        self.assert_error(document, "test_only_references low.unit_tests has unknown scheme ckks")
        # The shared owner's own references belong to no protocol.
        document = valid_map()
        document["test_only_references"][-1]["scheme"] = "shared_arithmetic"
        self.assertEqual(self.errors(document), [])
        self.assertIn("shared_arithmetic", CHECKER.PROTOCOL_SCHEMES)
        # The shared RNS-BGV scheme of the owner crate is a scheme of its own.
        document = valid_map()
        document["protocol_logic"][0]["scheme"] = "rns_bgv"
        self.assertEqual(self.errors(document), [])
        self.assertIn("rns_bgv", CHECKER.PROTOCOL_SCHEMES)

    def test_protocol_logic_declares_what_it_executes(self) -> None:
        document = valid_map()
        del document["protocol_logic"][0]["executes"]
        self.assert_error(document, "protocol_logic bfv.evaluation needs executes")
        document = valid_map()
        document["protocol_logic"][0]["executes"] = ["teleportation"]
        self.assert_error(document, "protocol_logic bfv.evaluation needs executes")

    def test_fail_closed_surface_executes_nothing_and_holds_only_allowed_primitives(self) -> None:
        document = valid_map()
        document["protocol_logic"][1]["executes"] = ["key_generation"]
        self.assert_error(document, f"{RING} assigns production functions to low.chain, which executes ['key_generation'] inside the fail-closed surface crates/low/src/")
        document = valid_map()
        document["zk_ams_distinct"]["production_surface"]["allowed_primitives"] = ["modular.mul"]
        self.assert_error(document, f"primitive ntt.forward: {RING} holds a production implementation inside the fail-closed surface crates/low/src/")
        document = valid_map()
        document["function_assignment"][0]["production"] = {}
        document["protocol_logic"].pop(1)
        document["distinct_arithmetic"] = [{
            "id": "low.hidden", "owner": {"crate": "low"}, "reason": "Relabelled.",
            "symbols": [{"path": RING, "symbol": "RnsChain::product"}],
        }]
        self.assert_error(document, f"distinct arithmetic low.hidden claims {RING}::RnsChain::product inside the fail-closed surface crates/low/src/")
        document = valid_map()
        del document["zk_ams_distinct"]["production_surface"]["claim"]
        self.assert_error(document, "zk_ams_distinct.production_surface needs a prefix, a claim and allowed_primitives")
        document = valid_map()
        del document["zk_ams_distinct"]
        self.assert_error(document, "zk_ams_distinct must be a JSON object")

    def test_preserved_oracles_must_be_recorded_oracles(self) -> None:
        document = valid_map()
        document["zk_ams_distinct"]["preserve_as_test_oracles"] = []
        self.assert_error(document, "zk_ams_distinct.preserve_as_test_oracles must name at least one test-only reference")
        document = valid_map()
        document["zk_ams_distinct"]["preserve_as_test_oracles"] = ["absent.oracle"]
        self.assert_error(document, "preserves unknown test-only reference absent.oracle")
        document = valid_map()
        document["zk_ams_distinct"]["preserve_as_test_oracles"] = ["low.keygen"]
        self.assert_error(document, "zk_ams_distinct preserves low.keygen, which is not recorded as an oracle")

    def test_each_required_reference_kind_must_be_present(self) -> None:
        for kind in CHECKER.REQUIRED_REFERENCE_KINDS:
            document = valid_map()
            document["test_only_references"] = [entry for entry in document["test_only_references"] if entry["kind"] != kind]
            self.assert_error(document, f"test_only_references needs at least one entry of kind {kind}")
        document = valid_map()
        document["test_only_references"] = []
        errors = self.errors(document)
        for kind in CHECKER.REQUIRED_REFERENCE_KINDS:
            self.assertIn(f"test_only_references needs at least one entry of kind {kind}", errors)
        document = valid_map()
        document["test_only_references"][0]["kind"] = "production_stack"
        self.assert_error(document, "test_only_references low.keygen has unknown kind production_stack")

    def test_production_kernel_function_outside_owner_files_must_be_listed(self) -> None:
        for name in ("negacyclic_mul", "key_switch_rows", "relinearize_rows", "bootstrap_ciphertext_ntt_slots"):
            self.write(BACKEND, TREE[BACKEND] + f"fn {name}() {{}}\n")
            self.assert_error(valid_map(), f"{BACKEND}::{name} is a production arithmetic-named function the map does not list")
        self.write(BACKEND, TREE[BACKEND] + "#[cfg(test)]\nfn key_switch_rows() {}\n")
        self.assertEqual(self.errors(valid_map()), [])
        self.write(BACKEND, TREE[BACKEND] + "fn reduce_rows() {}\n")
        document = valid_map()
        document["unrelated_kernel_named"] = [{"path": BACKEND, "symbol": "reduce_rows", "reason": "Row compaction; no arithmetic."}]
        self.assertEqual(self.errors(document), [])
        document["unrelated_kernel_named"][0]["reason"] = ""
        self.assert_error(document, "unrelated_kernel_named entries need a reason")

    def test_arithmetic_scope_finds_kernels_in_files_without_a_pattern(self) -> None:
        self.write("crates/high/src/lib.rs", "//! High layer.\npub mod backend;\npub mod kdf;\nmod helpers;\n")
        self.write("crates/high/src/helpers.rs", "fn add_mod(left: u64, right: u64) -> u64 {\n    left + right\n}\n")
        self.assertEqual(CHECKER.scan_tree(CHECKER.Tree(self.root)).get("crates/high/src/helpers.rs"), None)
        self.assertEqual(self.errors(valid_map()), [])
        document = valid_map()
        document["arithmetic_scopes"].append({"prefix": "crates/high/src/", "assignment": "kernel_names", "reason": "Consumers."})
        self.assert_error(document, "crates/high/src/helpers.rs defines production arithmetic-named functions ['add_mod'] inside an arithmetic scope")
        document["file_groups"][2]["files"].append({"path": "crates/high/src/helpers.rs", "patterns": [], "pinned": "Scalar helper."})
        self.assert_error(document, "crates/high/src/helpers.rs::add_mod is a production arithmetic-named function")
        document["distinct_arithmetic"] = [{
            "id": "high.helpers", "owner": {"crate": "high"}, "reason": "Consumer-local.",
            "symbols": [{"path": "crates/high/src/helpers.rs", "symbol": "add_mod"}],
        }]
        self.assertEqual(self.errors(document), [])
        document["file_groups"][0]["files"][0]["pinned"] = "Not needed."
        self.assert_error(document, f"{RING} matches ['ntt', 'rns'] and must not be pinned")
        document = valid_map()
        document["arithmetic_scopes"] = [{"prefix": "crates/absent/", "assignment": "kernel_names", "reason": "Gone."}]
        self.assert_error(document, "arithmetic scope crates/absent/ matches no file")
        del document["arithmetic_scopes"]
        self.assert_error(document, "arithmetic_scopes must be a JSON array")

    def test_unlisted_owner_file_is_reported(self) -> None:
        self.write("crates/low/src/lib.rs", "//! Low layer.\npub mod ring;\n#[cfg(test)]\nmod ring_tests;\nmod helpers;\n")
        self.write("crates/low/src/helpers.rs", "fn carry(left: u64) -> u64 {\n    left\n}\n")
        self.assert_error(valid_map(), "crates/low/src/helpers.rs is an owner file but file_groups does not list it")
        self.assert_error(valid_map(), "crates/low/src/helpers.rs is an owner file with 1 unclaimed production functions and 0 test-gated units")

    def test_hkdf_backend_users_must_all_be_listed(self) -> None:
        document = valid_map()
        document["hkdf"]["ram_lfe_backend"]["users"].pop(1)
        self.assert_error(document, f"{CLIENT} names the RAM-LFE HKDF backend but hkdf.ram_lfe_backend.users does not list it")
        document = valid_map()
        document["hkdf"]["ram_lfe_backend"]["users"][1]["literals"] = ["hkdf-sha2-256-prf-v9"]
        self.assert_error(document, "does not contain 'hkdf-sha2-256-prf-v9'")
        document = valid_map()
        del document["hkdf"]["ram_lfe_backend"]["users"][2]["test_only"]
        self.assert_error(document, f"hkdf backend user {CLIENT_TEST} test_only flag disagrees with the file")
        document = valid_map()
        document["hkdf"]["ram_lfe_backend"]["users"] = []
        self.assert_error(document, "hkdf.ram_lfe_backend.users must list the backend's users")

    def test_backend_file_cannot_be_recorded_as_unrelated_hkdf(self) -> None:
        document = valid_map()
        document["hkdf"]["ram_lfe_backend"]["users"].pop(1)
        document["hkdf"]["unrelated_preserve"]["entries"].append({"path": CLIENT, "purpose": "Mislabelled."})
        self.assert_error(document, f"{CLIENT} names the RAM-LFE HKDF backend but is recorded as unrelated HKDF")

    def test_every_hkdf_file_needs_a_classification(self) -> None:
        document = valid_map()
        document["hkdf"]["unrelated_preserve"]["entries"] = []
        self.assert_error(document, f"{KDF} uses HKDF but no hkdf section classifies it")
        self.assert_error(document, f"{KDF} has role unrelated_hkdf but hkdf.unrelated_preserve does not list it")

    def test_unrelated_hkdf_beside_ram_lfe_needs_evidence(self) -> None:
        self.replace(KDF, "let hkdf_salt = 1;", "let hkdf_salt = 1;\n    let ram_lfe_route = 2;")
        document = valid_map()
        document["file_groups"][3]["role"] = "consumer"
        document["file_groups"][3]["files"][0]["patterns"] = ["hkdf", "ram_lfe"]
        self.assert_error(document, "also names RAM-LFE and needs evidence")
        document["hkdf"]["unrelated_preserve"]["entries"][0]["evidence"] = "let hkdf_salt = 1;"
        self.assertEqual(self.errors(document), [])

    def test_backend_user_without_backend_identifier_needs_literal_evidence(self) -> None:
        self.replace(KDF, "let hkdf_salt = 1;", "let hkdf_salt = 1;\n    register_hkdf_program_policy();\n    let ram_lfe = 2;")
        document = valid_map()
        document["file_groups"][3]["role"] = "consumer"
        document["file_groups"][3]["files"][0]["patterns"] = ["hkdf", "ram_lfe"]
        document["hkdf"]["unrelated_preserve"]["entries"] = []
        document["hkdf"]["ram_lfe_backend"]["users"].append({"path": KDF, "kind": "test", "symbols": [{"symbol": "session_key"}]})
        self.assert_error(document, "needs literal evidence because no backend identifier pattern matches")
        document["hkdf"]["ram_lfe_backend"]["users"][-1]["literals"] = ["register_hkdf_program_policy"]
        self.assertEqual(self.errors(document), [])

    def test_plaintext_prf_is_separate_from_the_backend(self) -> None:
        document = valid_map()
        document["hkdf"]["plaintext_prf"]["entries"][0]["symbols"] = [{"symbol": "evaluate_hkdf_prf", "callers_exhaustive": True, "callers": {}}]
        self.assert_error(document, "evaluate_hkdf_prf is recorded as both plaintext PRF and RAM-LFE backend")
        self.assert_error(document, f"{BACKEND}::evaluate_hkdf_prf instantiates HKDF and is recorded as the RAM-LFE backend and the plaintext PRF")
        document = valid_map()
        document["hkdf"]["plaintext_prf"]["entries"][0]["symbols"] = [{"symbol": "absent_derivation"}]
        self.assert_error(document, "does not define absent_derivation")
        document = valid_map()
        document["hkdf"]["plaintext_prf"]["entries"] = []
        self.assert_error(document, "hkdf.plaintext_prf.entries must record the plaintext PRF")
        self.replace(BACKEND, "pub fn bfv_multiply() {", "pub fn bfv_multiply() {\n    derive_phone_nullifier();")
        self.assert_error(valid_map(), "derive_phone_nullifier production callers are {'crates/high/src/backend.rs': ['bfv_multiply']}")

    def test_every_hkdf_derivation_in_a_backend_file_is_accounted_for(self) -> None:
        self.append(BACKEND, "/// Derive.\npub fn derive_email_nullifier() {\n    let _ = Hkdf::<Sha3>::new(None, &[]);\n}\n")
        message = f"{BACKEND}::derive_email_nullifier instantiates HKDF but is recorded as neither the RAM-LFE backend, the plaintext PRF nor another derivation"
        self.assert_error(valid_map(), message)
        document = valid_map()
        document["hkdf"]["plaintext_prf"]["entries"][0]["symbols"].append(
            {"symbol": "derive_email_nullifier", "callers_exhaustive": True, "callers": {}})
        self.assertEqual(self.errors(document), [])
        document = valid_map()
        document["hkdf"]["other_derivations"] = [{"path": BACKEND, "symbol": "derive_email_nullifier", "purpose": "Session key."}]
        self.assertEqual(self.errors(document), [])
        document["hkdf"]["other_derivations"][0]["purpose"] = ""
        self.assert_error(document, "hkdf.other_derivations entries need a purpose")
        document = valid_map()
        document["hkdf"]["ram_lfe_backend"]["users"][0]["symbols"].pop(1)
        self.assert_error(document, f"{BACKEND}::evaluate_hkdf_prf instantiates HKDF but is recorded as neither")

    def test_generated_consumers_need_listing_and_evidence(self) -> None:
        document = valid_map()
        document["generated_consumers"] = []
        self.assert_error(document, f"{VECTORS} has role fixture but generated_consumers does not list it")
        document = valid_map()
        document["file_groups"][5]["role"] = "inventory"
        document["generated_consumers"] = []
        self.assert_error(document, f"{VECTORS} has role inventory but generated_consumers does not list it")
        document = valid_map()
        document["generated_consumers"][0]["evidence"]["literal"] = "absent.json"
        self.assert_error(document, "tools/reader.py does not contain 'absent.json'")
        document = valid_map()
        document["generated_consumers"][0]["registered"] = True
        self.assert_error(document, "is not an output in generated-files.toml")
        self.write("generated-files.toml", f'[[generated]]\noutputs = ["{CLIENT}", "{VECTORS}"]\n')
        self.assertEqual(self.errors(document), [f"{CLIENT} is a registered generated output but generated_consumers does not list it"])

    def test_consumer_evidence_generators_and_destination_are_checked(self) -> None:
        document = valid_map()
        document["generated_sdk_code"] = {"runtime_generators": [
            {"generator": BACKEND, "symbols": [{"symbol": "evaluate_hkdf_prf"}], "consumers": [CLIENT_TEST]},
        ]}
        document["destination"]["path"] = "crates/shared"
        self.assertEqual(self.errors(document), [])
        document["hkdf"]["ram_lfe_backend"]["consumer_evidence"][0]["symbol"] = "absent_rejection"
        self.assert_error(document, "hkdf consumer evidence: crates/high/src/backend.rs does not define absent_rejection")
        document["hkdf"]["ram_lfe_backend"]["consumer_evidence"] = []
        self.assert_error(document, "hkdf.ram_lfe_backend.consumer_evidence must anchor the current backend consumers")
        del document["hkdf"]["ram_lfe_backend"]["consumer_evidence"]
        self.assert_error(document, "hkdf.ram_lfe_backend.consumer_evidence must anchor the current backend consumers")
        document["generated_sdk_code"]["runtime_generators"][0]["consumers"] = ["sdk/absent.kt"]
        self.assert_error(document, "runtime generator consumer sdk/absent.kt is not listed")
        document["generated_sdk_code"]["runtime_generators"][0]["symbols"] = [{"symbol": "absent_emitter"}]
        self.assert_error(document, "runtime generator: crates/high/src/backend.rs does not define absent_emitter")
        document["destination"]["path"] = "crates/elsewhere"
        self.assert_error(document, "destination.path must equal")

    def test_consumer_evidence_rejects_retired_no_effect_contract(self) -> None:
        document = valid_map()
        backend = document["hkdf"]["ram_lfe_backend"]
        backend["no_effect_evidence"] = copy.deepcopy(backend["consumer_evidence"])
        self.assert_error(document, "hkdf.ram_lfe_backend.no_effect_evidence is retired; record current consumer_evidence")
        del backend["consumer_evidence"]
        self.assert_error(document, "hkdf.ram_lfe_backend.consumer_evidence must anchor the current backend consumers")

    def test_consumer_evidence_requires_production_symbols(self) -> None:
        document = valid_map()
        document["hkdf"]["ram_lfe_backend"]["consumer_evidence"] = [
            {"path": RING, "symbol": "ntt_reference", "cfg": ["test"], "test_only": True},
        ]
        self.assert_error(document, f"hkdf consumer evidence: {RING}::ntt_reference must be production")

    def test_current_state_claims_need_live_anchors(self) -> None:
        document = valid_map()
        document["current_state"][0]["evidence"][1]["literal"] = "bfv-affine-v9"
        self.assert_error(document, f"current_state bfv_backends_refused: {CLIENT} does not contain 'bfv-affine-v9'")
        document = valid_map()
        document["current_state"][0]["evidence"][0]["symbol"] = "RamLfeBackend::Retired"
        self.assert_error(document, "current_state bfv_backends_refused: crates/high/src/backend.rs does not define RamLfeBackend::Retired")
        document = valid_map()
        document["current_state"][0]["absent"][0]["prefix"] = "crates/high/"
        self.assert_error(document, f"current_state bfv_backends_refused: {BACKEND} now contains 'HkdfSha3_512PrfV1'")
        document = valid_map()
        document["current_state"][0]["evidence"] = []
        self.assert_error(document, "current_state bfv_backends_refused needs evidence")
        document = valid_map()
        del document["current_state"]
        self.assert_error(document, "current_state must be a JSON array")

    def test_every_required_current_state_claim_must_be_present(self) -> None:
        self.assertEqual(len(CHECKER.REQUIRED_CURRENT_STATE), 4)
        for index, identifier in enumerate(CHECKER.REQUIRED_CURRENT_STATE):
            document = valid_map()
            self.assertEqual(document["current_state"][index]["id"], identifier)
            document["current_state"].pop(index)
            self.assert_error(document, f"current_state needs the claim {identifier}")
        document = valid_map()
        document["current_state"] = []
        errors = self.errors(document)
        for identifier in CHECKER.REQUIRED_CURRENT_STATE:
            self.assertIn(f"current_state needs the claim {identifier}", errors)

    def test_incidental_files_need_evidence_text(self) -> None:
        document = valid_map()
        document["file_groups"][5]["role"] = "incidental"
        document["generated_consumers"] = []
        self.assert_error(document, f"{VECTORS} is recorded as incidental without evidence")
        document["file_groups"][5]["files"][0]["evidence"] = "bfv_vectors"
        self.assertEqual(self.errors(document), [])

    def test_whole_file_reference_must_be_a_test_only_file(self) -> None:
        document = valid_map()
        document["test_only_references"][1]["path"] = RING
        self.assert_error(document, f"{RING} is not test-only as a whole file")

    def test_distinct_arithmetic_needs_owner_reason_and_real_symbols(self) -> None:
        document = valid_map()
        document["distinct_arithmetic"] = [{
            "id": "high.session", "owner": {"crate": "high"}, "reason": "Algorithm-specific.",
            "symbols": [{"path": KDF, "symbol": "session_key"}],
        }]
        self.assertEqual(self.errors(document), [])
        document["distinct_arithmetic"][0]["reason"] = ""
        self.assert_error(document, "needs a reason for distinct ownership")
        document["distinct_arithmetic"][0]["owner"] = {"crate": "absent"}
        self.assert_error(document, "must have exactly one owner crate listed in crates")

    def test_distinct_arithmetic_claims_a_function_of_an_owner_file(self) -> None:
        self.replace(RING, "/// Chain.", "fn goldilocks_mul_v1() {}\n/// Chain.")
        self.assert_error(valid_map(), f"{RING}::goldilocks_mul_v1 is a production function with no owner in the inventory")
        document = valid_map()
        document["distinct_arithmetic"] = [{
            "id": "proof.field", "owner": {"crate": "low"}, "reason": "Proof-field arithmetic.",
            "symbols": [{"path": RING, "symbol": "goldilocks_mul_v1"}],
        }]
        self.assertEqual(self.errors(document), [
            f"distinct arithmetic proof.field claims {RING}::goldilocks_mul_v1 inside the fail-closed surface crates/low/src/; "
            "only allowed primitives and protocol logic may own its functions",
        ])
        document["zk_ams_distinct"]["production_surface"]["prefix"] = "crates/low/src/ring_tests.rs"
        self.assertEqual(self.errors(document), [])

    def test_command_line_reports_failures_and_prints_the_scan(self) -> None:
        self.write(CHECKER.DEFAULT_MAP, json.dumps(valid_map()))
        output = StringIO()
        with redirect_stdout(output):
            status = CHECKER.main(["--root", str(self.root)])
        self.assertEqual(status, 0, output.getvalue())
        self.assertIn("7 files and 2 primitives match the tree", output.getvalue())
        self.replace(RING, "fn mul_mod(", "fn multiply_mod(")
        output = StringIO()
        with redirect_stdout(output):
            status = CHECKER.main(["--root", str(self.root), "--map", CHECKER.DEFAULT_MAP])
        self.assertEqual(status, 1)
        self.assertIn(f"error: primitive modular.mul: {RING} does not define mul_mod", output.getvalue())
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(CHECKER.main(["--root", str(self.root), "--print-scan"]), 0)
        self.assertEqual(json.loads(output.getvalue())[CLIENT], ["hkdf", "hkdf_ram_lfe"])
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(CHECKER.main(["--root", str(self.root), "--map", "absent.json"]), 1)


class RefreshTest(TreeCase):
    """`--refresh` recomputes derived facts and never changes a classification."""

    def refreshed(self, document: dict) -> dict:
        return CHECKER.refresh(CHECKER.Tree(self.root), document)

    def test_refresh_keeps_a_matching_inventory_unchanged(self) -> None:
        document = valid_map()
        self.assertEqual(self.refreshed(document), document)
        self.assertEqual(CHECKER.render(self.refreshed(document)), CHECKER.render(document))
        self.assertEqual(document, valid_map())

    def test_refresh_recomputes_flags_patterns_and_callers(self) -> None:
        self.replace("crates/low/src/lib.rs", "pub mod ring;", '#[cfg(feature = "full")]\npub mod ring;')
        self.replace(KDF, "let hkdf_salt = 1;", "let hkdf_salt = 1;\n    let ntt_size = 2;")
        self.append(BACKEND, "/// Second.\npub fn second() {\n    low::ring::ntt_forward(&mut []);\n}\n")
        self.replace(CLIENT_TEST, "val expected", "val wanted")
        self.write("sdk/main/ClientTest.kt", (self.root / CLIENT_TEST).read_text(encoding="utf-8"))
        document = valid_map()
        document["file_groups"][4]["files"][1]["path"] = "sdk/main/ClientTest.kt"
        document["hkdf"]["ram_lfe_backend"]["users"][2]["path"] = "sdk/main/ClientTest.kt"
        (self.root / CLIENT_TEST).unlink()
        refreshed = self.refreshed(document)
        files = {record["path"]: record for group in refreshed["file_groups"] for record in group["files"]}
        self.assertEqual(files[RING], {"path": RING, "patterns": ["ntt", "rns"], "cfg": ['feature = "full"']})
        self.assertEqual(files[KDF]["patterns"], ["hkdf", "ntt"])
        self.assertNotIn("test_only", files["sdk/main/ClientTest.kt"])
        self.assertNotIn("test_only", refreshed["hkdf"]["ram_lfe_backend"]["users"][2])
        forward = refreshed["primitives"][0]["implementations"][0]
        self.assertEqual(forward["callers"], {BACKEND: ["bfv_multiply", "second"]})
        self.assertEqual(list(forward), ["path", "symbol", "role", "callers_exhaustive", "callers"])
        errors = self.errors(refreshed)
        self.assertEqual(errors, [f"{KDF} is recorded as unrelated HKDF but matches ['hkdf', 'ntt']"])

    def test_refresh_follows_gating_changes_without_reclassifying(self) -> None:
        self.replace(RING, "#[cfg(test)]\nfn ntt_reference", "fn ntt_reference")
        refreshed = self.refreshed(valid_map())
        reference = refreshed["primitives"][0]["implementations"][1]
        self.assertEqual(reference, {"path": RING, "symbol": "ntt_reference", "role": "test_only_reference",
                                     "callers_exhaustive": True, "callers": {}})
        self.assertEqual(refreshed["function_assignment"][0]["test_gated"],
                         {"low.keygen": ["keygen_from_seed"], "low.unit_tests": ["mod tests"]})
        self.assert_error(refreshed, "role test_only_reference disagrees with test_only False")

    def test_refresh_leaves_new_functions_and_files_for_a_maintainer(self) -> None:
        self.replace(RING, "/// Chain.", "/// Encrypt.\npub fn encrypt_fresh() {}\n#[cfg(test)]\nfn sampler_reference() {}\n/// Chain.")
        self.write("crates/high/src/extra.rs", "fn rns_helper() {}\n")
        (self.root / VECTORS).unlink()
        refreshed = self.refreshed(valid_map())
        entry = refreshed["function_assignment"][0]
        self.assertEqual(entry["production_unassigned"], ["encrypt_fresh"])
        self.assertEqual(entry["test_gated_unassigned"], ["sampler_reference"])
        self.assertEqual(entry["production"], {"low.chain": ["RnsChain::product"]})
        groups = {group["id"]: group for group in refreshed["file_groups"]}
        self.assertNotIn("fixtures", groups)
        self.assertEqual(groups[CHECKER.UNCLASSIFIED_GROUP]["files"], [{"path": "crates/high/src/extra.rs", "patterns": ["rns"]}])
        errors = self.errors(refreshed)
        for fragment in ("file group unclassified has unknown role unclassified",
                         f"{RING} leaves ['encrypt_fresh'] under production_unassigned",
                         f"{RING} leaves ['sampler_reference'] under test_gated_unassigned"):
            self.assertTrue(any(fragment in error for error in errors), (fragment, errors))
        again = self.refreshed(refreshed)
        self.assertEqual(again, refreshed)

    def test_refresh_assigns_a_new_test_gated_unit_only_when_the_file_has_one_reference(self) -> None:
        self.replace(RING, "/// Chain.", "#[cfg(test)]\nfn sampler_reference() {}\n/// Chain.")
        document = valid_map()
        document["function_assignment"][0]["test_gated"] = {"low.reference": ["keygen_from_seed", "mod tests", "ntt_reference"]}
        refreshed = self.refreshed(document)
        self.assertEqual(refreshed["function_assignment"][0]["test_gated"],
                         {"low.reference": ["keygen_from_seed", "mod tests", "ntt_reference", "sampler_reference"]})
        self.assertNotIn("test_gated_unassigned", refreshed["function_assignment"][0])

    def test_refresh_builds_the_assignment_of_a_new_owner_file(self) -> None:
        self.write("crates/low/src/lib.rs", "//! Low layer.\npub mod ring;\n#[cfg(test)]\nmod ring_tests;\nmod helpers;\nmod empty;\n")
        self.write("crates/low/src/helpers.rs", "fn carry(left: u64) -> u64 {\n    left\n}\n")
        self.write("crates/low/src/empty.rs", "//! Constants only.\nconst LIMIT: u64 = 1;\n")
        refreshed = self.refreshed(valid_map())
        self.assertEqual([entry["path"] for entry in refreshed["function_assignment"]], ["crates/low/src/helpers.rs", RING])
        self.assertEqual(refreshed["function_assignment"][0],
                         {"path": "crates/low/src/helpers.rs", "production": {}, "production_unassigned": ["carry"], "test_gated": {}})

    def test_render_is_deterministic_and_round_trips(self) -> None:
        document = valid_map()
        document["function_assignment"][0]["production"]["low.chain"] = [f"function_number_{index:03d}" for index in range(40)]
        text = CHECKER.render(document)
        self.assertEqual(json.loads(text), document)
        self.assertEqual(text, CHECKER.render(json.loads(text)))
        self.assertRegex(text, r'\n +"function_number_000",\n +"function_number_001",\n')
        self.assertIn('{"name": "low", "path": "crates/low", "depends_on": []}', text)
        self.assertEqual(CHECKER.render({"a": [1, 2], "b": "é"}), '{"a": [1, 2], "b": "é"}')

    def test_command_line_refresh_prints_or_writes(self) -> None:
        document = valid_map()
        document["primitives"][0]["implementations"][0]["callers"] = {}
        document["file_groups"][1]["files"][0].pop("test_only")
        self.write(CHECKER.DEFAULT_MAP, json.dumps(document))
        before = (self.root / CHECKER.DEFAULT_MAP).read_text(encoding="utf-8")
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(CHECKER.main(["--root", str(self.root), "--refresh"]), 0)
        self.assertEqual(output.getvalue(), CHECKER.render(valid_map()) + "\n")
        self.assertEqual((self.root / CHECKER.DEFAULT_MAP).read_text(encoding="utf-8"), before)
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(CHECKER.main(["--root", str(self.root)]), 1)
        with redirect_stdout(StringIO()):
            self.assertEqual(CHECKER.main(["--root", str(self.root), "--refresh", "--write"]), 0)
        self.assertEqual((self.root / CHECKER.DEFAULT_MAP).read_text(encoding="utf-8"), CHECKER.render(valid_map()) + "\n")
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(CHECKER.main(["--root", str(self.root)]), 0, output.getvalue())
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as raised:
            CHECKER.main(["--root", str(self.root), "--write"])
        self.assertEqual(raised.exception.code, 2)
        self.write(CHECKER.DEFAULT_MAP, "[]")
        with redirect_stdout(StringIO()):
            self.assertEqual(CHECKER.main(["--root", str(self.root), "--refresh"]), 1)

    def test_symbol_records_cover_every_section(self) -> None:
        document = valid_map()
        document["distinct_arithmetic"] = [{"id": "d", "symbols": [{"path": KDF, "symbol": "session_key"}]}]
        document["unrelated_kernel_named"] = [{"path": KDF, "symbol": "session_key", "reason": "x"}]
        document["hkdf"]["other_derivations"] = [{"path": KDF, "symbol": "session_key", "purpose": "x"}]
        document["generated_sdk_code"] = {"runtime_generators": [{"generator": BACKEND, "symbols": [{"symbol": "bfv_multiply"}]}]}
        sections = [section for section, _, _, _ in CHECKER.symbol_records(document)]
        for section in ("primitives", "distinct_arithmetic", "unrelated_kernel_named", "protocol_logic",
                        "test_only_references", "current_state", "hkdf", "generated_sdk_code"):
            self.assertIn(section, sections)
        wanted = {(path, record["symbol"]) for _, path, record, wants in CHECKER.symbol_records(document) if wants}
        self.assertEqual(wanted, {(RING, "ntt_forward"), (RING, "ntt_reference"), (RING, "mul_mod"), (BACKEND, "derive_phone_nullifier")})
        self.assertEqual(sorted(CHECKER.listed_files(document)), sorted([RING, RING_TESTS, BACKEND, KDF, CLIENT, CLIENT_TEST, VECTORS]))
        self.assertEqual(CHECKER.declared_development_features(document), ["fixtures"])
        tree = CHECKER.Tree(self.root)
        self.assertEqual(CHECKER.claimed_functions(tree, document, RING, ["fixtures"]),
                         {"ntt_forward": "primitives", "mul_mod": "primitives"})
        self.assertEqual(CHECKER.claimed_functions(tree, document, KDF, ["fixtures"]), {"session_key": "distinct_arithmetic"})


# Shapes that spell out modular coefficient arithmetic instead of calling the shared owner.
INLINE_KERNEL_SHAPES = (
    ("signed Euclidean reduction", re.compile(r"\brem_euclid\s*\(")),
    ("widening product reduced by a remainder",
     re.compile(r"\bu(?:32|64|128)::from\s*\([^()]*\)\s*\*\s*u(?:32|64|128)::from\s*\([^()]*\)\s*%")),
    ("remainder by a modulus",
     re.compile(r"%\s*(?:[ui](?:16|32|64|128)::from\s*\(\s*)?(?:[A-Za-z0-9_]+\s*\.\s*)*(?:[A-Z0-9_]*MODULUS[A-Z0-9_]*|[a-z0-9_]*modulus)\b")),
    ("wrapping, overflowing or remainder-checked product", re.compile(r"\b(?:wrapping_mul|overflowing_mul|checked_rem)\s*\(")),
)


def inline_kernel_shapes(source, development_features) -> dict[str, list[str]]:
    """Return, per production function of a Rust source, the modular-arithmetic shapes its body spells out."""
    found: dict[str, list[str]] = {}
    for item in source.items:
        if item.kind != "fn" or item.body_start is None:
            continue
        if any(CHECKER.is_test_cfg(cfg, development_features) for cfg in item.cfg_chain()):
            continue
        body = source.masked[item.body_start : item.end]
        shapes = [label for label, pattern in INLINE_KERNEL_SHAPES if pattern.search(body)]
        if shapes:
            found[CHECKER.qualified_name(item)] = shapes
    return found


class RepositoryTest(unittest.TestCase):
    """The committed inventory must match the repository it describes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = (CHECKER.ROOT / CHECKER.DEFAULT_MAP).read_text(encoding="utf-8")
        cls.document = json.loads(cls.text)
        cls.tree = CHECKER.Tree(CHECKER.ROOT)
        cls.scan = CHECKER.scan_tree(cls.tree)

    def test_committed_inventory_matches_the_repository(self) -> None:
        self.assertEqual(CHECKER.MapChecker(self.tree, copy.deepcopy(self.document), self.scan).run(), [])

    def test_committed_inventory_is_what_refresh_writes(self) -> None:
        refreshed = CHECKER.refresh(self.tree, self.document, self.scan)
        self.assertEqual(CHECKER.render(refreshed) + "\n", self.text)

    def test_test_only_references_are_never_recorded_as_production(self) -> None:
        references = self.document["test_only_references"]
        assigned = {
            identifier for entry in self.document["function_assignment"]
            for identifier, names in entry["test_gated"].items() if names
        }
        for entry in references:
            self.assertTrue(entry.get("whole_file") or entry["symbols"] or entry["id"] in assigned, entry["id"])
            for symbol in entry["symbols"]:
                self.assertTrue(symbol.get("test_only"), (entry["id"], symbol))
        for primitive in self.document["primitives"]:
            self.assertIsInstance(primitive["owner"], dict, primitive["id"])
            for record in primitive["implementations"]:
                self.assertEqual(record["role"] == "test_only_reference", bool(record.get("test_only")), record)
        for entry in self.document["protocol_logic"]:
            for symbol in entry["symbols"]:
                self.assertFalse(symbol.get("test_only"), (entry["id"], symbol))

    def test_reference_kinds_and_preserved_oracles_are_present(self) -> None:
        references = {entry["id"]: entry for entry in self.document["test_only_references"]}
        kinds = {entry["kind"] for entry in references.values()}
        for kind in ("oracle", "key_generation_reference", "protocol_reference", "fixture", "candidate", "unit_tests"):
            self.assertIn(kind, kinds)
        preserved = self.document["zk_ams_distinct"]["preserve_as_test_oracles"]
        self.assertEqual(preserved, ["mkhe.ring_arithmetic_oracle", "mkhe.streaming_decryption_ntt"])
        for identifier in preserved:
            self.assertEqual(references[identifier]["kind"], "oracle")
        key_generation = {identifier for identifier, entry in references.items() if entry["kind"] == "key_generation_reference"}
        for identifier in ("mkhe.key_generation_reference", "mkhe.collective_public_key_generation",
                           "mkhe.collective_evaluated_key_generation", "mkhe.party_authentication_reference",
                           "bfv.fixture_gated_key_generation"):
            self.assertIn(identifier, key_generation)

    def test_zk_ams_key_generation_is_recorded_as_test_gated(self) -> None:
        prefix = self.document["zk_ams_distinct"]["production_surface"]["prefix"]
        executes = {entry["id"]: entry["executes"] for entry in self.document["protocol_logic"]}
        gated: dict[str, str] = {}
        for entry in self.document["function_assignment"]:
            if not entry["path"].startswith(prefix):
                continue
            for identifier, names in entry["production"].items():
                self.assertEqual(executes[identifier], [], (entry["path"], identifier))
                self.assertTrue(names)
            for identifier, names in entry["test_gated"].items():
                for name in names:
                    gated[f"{entry['path']}::{name}"] = identifier
        for suffix, identifier in (
            ("mkhe/collective.rs::generate_zk_ams_mkhe_collective_party_state_with_prepared_public_a_v1", "mkhe.collective_public_key_generation"),
            ("mkhe/collective.rs::aggregate_zk_ams_mkhe_collective_public_key_v1", "mkhe.collective_public_key_generation"),
            ("mkhe/active.rs::ZkAmsMkheActivePartySecretV1::generate", "mkhe.party_authentication_reference"),
            ("mkhe.rs::independent_keygen", "mkhe.key_generation_reference"),
        ):
            self.assertEqual(gated[f"{prefix}/{suffix}"], identifier)

    def test_callers_name_only_functions_that_call(self) -> None:
        chain = next(primitive for primitive in self.document["primitives"] if primitive["id"] == "rns.modulus_chain")
        product = next(record for record in chain["implementations"] if record["symbol"] == "checked_modulus_product")
        # Callers are attributed across crates, and a local binding named `product` is not a call.
        self.assertEqual(product["callers"], {
            "crates/iroha_crypto/src/fhe_bfv.rs": ["checked_rns_modulus_product"],
            "crates/iroha_fhe/src/rns.rs": ["basis_extend_target_limbs", "validate_ntt_modulus_chain"],
        })
        self.assertTrue(product["callers_exhaustive"])

    def test_shared_owner_is_established_and_holds_every_production_kernel(self) -> None:
        destination = self.document["destination"]
        self.assertEqual((destination["crate"], destination["path"], destination["planned"]), ("iroha_fhe", "crates/iroha_fhe", False))
        self.assertEqual(destination["established_by"], "C.2")
        shared = next(record for record in self.document["crates"] if record["name"] == "iroha_fhe")
        self.assertEqual(shared["depends_on"], [])
        self.assertNotIn("planned", shared)
        for name in ("iroha_crypto", "iroha_zkp_halo2", "iroha_core_privacy"):
            record = next(record for record in self.document["crates"] if record["name"] == name)
            self.assertIn("iroha_fhe", record["depends_on"], name)
        for primitive in self.document["primitives"]:
            self.assertEqual(primitive["owner"]["crate"], "iroha_fhe", primitive["id"])
            self.assertIn(primitive["owner"]["module"], destination["modules"], primitive["id"])
            self.assertTrue(primitive["canonical_source"]["path"].startswith("crates/iroha_fhe/src/"), primitive["id"])
            for record in primitive["implementations"]:
                # One production owner per primitive: nothing outside the shared crate is production.
                self.assertIn(record["role"], ("canonical", "test_only_reference"), (primitive["id"], record))
                self.assertEqual(record["role"] == "canonical", record["path"].startswith("crates/iroha_fhe/src/"), record)

    def test_consumers_keep_adapters_and_no_kernel(self) -> None:
        features = CHECKER.declared_development_features(self.document)
        for path in (
            "crates/iroha_crypto/src/fhe_bfv.rs",
            "crates/iroha_zkp_halo2/src/vega/zk_ams/mkhe.rs",
            "crates/iroha_zkp_halo2/src/vega/zk_ams/mkhe/packing.rs",
            "crates/iroha_core_privacy/src/privacy_engines/jindo/ring.rs",
            "crates/iroha_core_privacy/src/privacy_engines/jindo/security.rs",
            "crates/iroha_core_privacy/src/privacy_engines/bootle_lantern/ring.rs",
            "crates/iroha_core_privacy/src/privacy_engines/bootle_lantern/toolbox.rs",
        ):
            claims = CHECKER.claimed_functions(self.tree, self.document, path, features)
            self.assertEqual({name for name, section in claims.items() if section == "primitives"}, set(), path)
        entry = next(entry for entry in self.document["function_assignment"] if entry["path"] == "crates/iroha_crypto/src/fhe_bfv.rs")
        adapters = entry["production"]["bfv.shared_arithmetic_adapters"]
        for name in ("bfv_rns_error", "poly_add_mod", "poly_mul_mod", "zero_poly", "reduce_u128_to_u64_mod",
                     "validate_bfv_rns_modulus_chain_with_root_candidate_limit", "BfvRnsModulusChain::reconstruct_polynomial"):
            self.assertIn(name, adapters)
        source = self.tree.text("crates/iroha_crypto/src/fhe_bfv.rs")
        for removed in ("fn ntt_in_place_mod(", "fn mul_mod_u64(", "fn is_prime_u64(", "fn garner_reconstruct_u128(",
                        "fn bit_reverse_permute", "fn mul_mod_prime(", "fn center_lift("):
            self.assertNotIn(removed, source, removed)
        surface = self.document["zk_ams_distinct"]["production_surface"]
        self.assertEqual(surface["allowed_primitives"], [])
        references = {entry["id"]: entry for entry in self.document["test_only_references"]}
        self.assertEqual(references["shared.canonical_vector_oracle"]["kind"], "oracle")
        self.assertEqual(references["shared.canonical_vector_oracle"]["path"], "crates/iroha_fhe/tests/canonical_vectors.rs")

    def test_consumer_function_bodies_spell_out_no_modular_kernel(self) -> None:
        # The scan recognizes the bodies this consolidation removed: a u32 schoolbook product,
        # a widening u128 product, a signed reduction and a sum reduced by a remainder.
        retired = CHECKER.RustSource(
            "fn multiply(lhs: u16, rhs: u16) -> u16 {\n"
            "    (u32::from(lhs) * u32::from(rhs) % u32::from(APPLICATION_MODULUS_V1)) as u16\n}\n"
            "fn mul_mod(left: u64, right: u64, modulus: u64) -> u64 {\n"
            "    (u128::from(left) * u128::from(right) % u128::from(modulus)) as u64\n}\n"
            "fn from_centered(value: i64, modulus: i64) -> i64 {\n    value.rem_euclid(modulus)\n}\n"
            "fn add_mod_u16(lhs: u16, rhs: u16, modulus: u16) -> u32 {\n"
            "    (u32::from(lhs) + u32::from(rhs)) % u32::from(modulus)\n}\n"
            "fn from_balanced(coefficient: i128, prime: Prime) -> i128 {\n    coefficient % prime.modulus\n}\n"
            "fn delegates(lhs: u64, rhs: u64, modulus: u64) -> u64 {\n"
            "    let index = (lhs as usize) % 8;\n    iroha_fhe::modular::mul_mod_u64(lhs, rhs, modulus) + index as u64\n}\n"
            "#[cfg(test)]\nfn reference(lhs: u64, modulus: u64) -> u64 {\n    lhs % modulus\n}\n"
        )
        self.assertEqual(
            sorted(inline_kernel_shapes(retired, [])),
            ["add_mod_u16", "from_balanced", "from_centered", "mul_mod", "multiply"],
        )
        features = CHECKER.declared_development_features(self.document)
        # Every remaining remainder is listed here with what it reduces. None is ring arithmetic.
        allowed = {
            "crates/iroha_core_privacy/src/privacy_engines/jindo/ring.rs": {},
            "crates/iroha_core_privacy/src/privacy_engines/jindo/security.rs": {},
            "crates/iroha_core_privacy/src/privacy_engines/bootle_lantern/ring.rs": {},
            "crates/iroha_core_privacy/src/privacy_engines/bootle_lantern/toolbox.rs": {
                "norm_slack_relation_polynomial_v1": "reduces the public norm bound into the proof field",
            },
            "crates/iroha_crypto/src/fhe_bfv.rs": {
                "add_plain_scalar": "reduces a plaintext scalar into the plaintext modulus before encoding",
                "encode_plaintext": "reduces plaintext slot values into the plaintext modulus",
                "validate_plaintext_multiple_residual_bound": "divisibility check of a residual by the plaintext modulus",
                "bfv_full_bootstrap_goldilocks_reduce_u128_v1": "Goldilocks proof-field reduction, recorded as distinct arithmetic",
                "bfv_full_bootstrap_goldilocks_reduce_le_bytes_v1": "Goldilocks proof-field reduction, recorded as distinct arithmetic",
            },
            "crates/iroha_zkp_halo2/src/vega/zk_ams/mkhe.rs": {
                "PlaintextModulus::residue": "reduces the tiny test plaintext modulus; the T256 arm calls the shared kernel",
            },
            "crates/iroha_zkp_halo2/src/vega/zk_ams/mkhe/packing.rs": {},
        }
        for path, exceptions in allowed.items():
            found = inline_kernel_shapes(self.tree.rust(path), features)
            self.assertEqual(sorted(found), sorted(exceptions), f"{path}: {found}")

    def test_consumers_name_shared_kernels_by_their_own_names_and_are_recorded_as_callers(self) -> None:
        modules = set(self.document["destination"]["modules"])
        ring = "crates/iroha_core_privacy/src/privacy_engines/bootle_lantern/ring.rs"
        jindo = "crates/iroha_core_privacy/src/privacy_engines/jindo/ring.rs"
        security = "crates/iroha_core_privacy/src/privacy_engines/jindo/security.rs"
        consumers = (
            "crates/iroha_crypto/src/fhe_bfv.rs",
            "crates/iroha_zkp_halo2/src/vega/zk_ams/mkhe.rs",
            "crates/iroha_zkp_halo2/src/vega/zk_ams/mkhe/packing.rs",
            jindo, security, ring,
            "crates/iroha_core_privacy/src/privacy_engines/bootle_lantern/toolbox.rs",
        )
        # A renamed import of a shared function or type keeps a second name alive. Only a module of
        # the shared crate may be bound under another name; the checker follows that alias.
        for path in consumers:
            for binding, bound in self.tree.rust(path).use_bindings():
                if binding[0] != "iroha_fhe" or bound in (binding[-1], "*"):
                    continue
                self.assertIn("::".join(binding), modules, f"{path} renames {'::'.join(binding)} to {bound}")
        callers = {
            (record["path"].rsplit("/", 1)[-1], record["symbol"]): record
            for primitive in self.document["primitives"] for record in primitive["implementations"]
            if record["path"].startswith("crates/iroha_fhe/src/") and "callers" in record
        }
        expected = {
            ("polynomial.rs", "negacyclic_mul_schoolbook_into_with"): (ring, "ApplicationPolynomialV1::multiply"),
            ("constant_time.rs", "FixedModulus::multiply"): (ring, "ApplicationPolynomialV1::scale_centered"),
            ("constant_time.rs", "FixedModulus::canonicalize_i64"): (ring, "ApplicationPolynomialV1::from_centered_coefficients"),
            ("constant_time.rs", "select_i64"): (ring, "ProofPolynomialV1::centered_coefficient"),
            ("constant_time.rs", "greater_than_bit_u64"): (ring, "ApplicationPolynomialV1::centered_coefficient"),
            ("constant_time.rs", "CenteredCrt3::reconstruct_mod_target"): (ring, "centered_crt_reconstruct_mod_q_v1"),
            ("accel.rs", "add_mod_assign"): (jindo, "JindoRnsPolynomialV1::add_assign"),
            ("accel.rs", "sub_mod_assign"): (jindo, "JindoRnsPolynomialV1::sub_assign"),
            ("accel.rs", "mul_scalar_mod"): (jindo, "JindoRnsPolynomialV1::scale_power_of_two"),
            ("modular.rs", "mod_pow_u64"): (jindo, "JindoRnsPolynomialV1::scale_power_of_two"),
            ("modular.rs", "reduce_i128_to_u64_mod"): (jindo, "JindoRnsPolynomialV1::from_balanced_coefficients"),
            ("modular.rs", "mul_mod_u64"): (security, "check_prime_difference_classes_v1"),
            ("rns.rs", "decompose"): ("crates/iroha_crypto/src/fhe_bfv.rs", "BfvRnsModulusChain::decompose_polynomial"),
            ("rns.rs", "modulus_product_bit_len"): ("crates/iroha_zkp_halo2/src/vega/zk_ams/mkhe.rs", "modulus_product_bit_len"),
        }
        for key, (path, function) in expected.items():
            record = callers[key]
            self.assertTrue(record["callers_exhaustive"], key)
            self.assertIn(function, record["callers"].get(path, []), key)
        references = {entry["id"]: entry for entry in self.document["test_only_references"]}
        self.assertNotIn("bootle_lantern.test_gated_adapters", references)
        self.assertEqual(references["shared.avx2_lane_model"]["path"], "crates/iroha_fhe/src/accel/avx2_model.rs")
        self.assertEqual(references["shared.clearing_probe"]["path"], "crates/iroha_fhe/tests/clearing.rs")

    def test_goldilocks_and_full_assignment_cover_the_bfv_owner_file(self) -> None:
        path = "crates/iroha_crypto/src/fhe_bfv.rs"
        distinct = {(record["path"], record["symbol"]) for entry in self.document["distinct_arithmetic"] for record in entry["symbols"]}
        for name in ("bfv_full_bootstrap_goldilocks_sub_v1", "bfv_full_bootstrap_goldilocks_mul_v1",
                     "bfv_full_bootstrap_goldilocks_reduce_u128_v1", "bfv_full_bootstrap_goldilocks_reduce_le_bytes_v1"):
            self.assertIn((path, name), distinct)
        for file_name in ("cyclotomic.rs", "fft.rs", "goldilocks_transform.rs"):
            self.assertTrue(any(owner == f"crates/fastpq_prover/src/{file_name}" for owner, _ in distinct), file_name)
        production, gated = CHECKER.function_units(self.tree, path, CHECKER.declared_development_features(self.document))
        entry = next(entry for entry in self.document["function_assignment"] if entry["path"] == path)
        claims = CHECKER.claimed_functions(self.tree, self.document, path, CHECKER.declared_development_features(self.document))
        assigned = [name for names in entry["production"].values() for name in names]
        self.assertEqual(sorted(assigned + sorted(claims)), sorted(production.elements()))
        self.assertEqual(sorted(name for names in entry["test_gated"].values() for name in names), sorted(gated.elements()))

    def test_plaintext_prf_and_backend_are_recorded_separately(self) -> None:
        hkdf = self.document["hkdf"]
        backend = {(user["path"], symbol["symbol"]) for user in hkdf["ram_lfe_backend"]["users"] for symbol in user.get("symbols", [])}
        derivations = {(entry["path"], symbol["symbol"]) for entry in hkdf["plaintext_prf"]["entries"] for symbol in entry["symbols"]}
        self.assertTrue(derivations)
        self.assertFalse(backend & derivations)
        self.assertEqual(hkdf["unrelated_preserve"]["disposition"], "preserve")
        self.assertTrue(hkdf["ram_lfe_backend"]["consumer_evidence"])
        self.assertEqual([entry["id"] for entry in self.document["current_state"]], list(CHECKER.REQUIRED_CURRENT_STATE))


if __name__ == "__main__":
    unittest.main()
