use super::*;
use crate::privacy_engines::fcmp_plus_plus::{
    FCMP_MAX_INPUTS_NATIVE_V1, FCMP_MAX_OUTPUTS_NATIVE_V1, FCMP_MAX_PROOF_WIRE_BYTES_V1,
    FCMP_NATIVE_KAT_PUBLIC_SHA256_V1, FCMP_NATIVE_KAT_WIRE_SHA256_V1, FCMP_OUTPUT_TUPLE_BYTES_V1,
    FailingRngV1, build_fcmp_frontier_v1,
    field::{encode_field25519_scalar, encode_helioselene_scalar, hash_helios, hash_selene},
    output_from_multiples, verify_fcmp_plus_plus_v1, verify_fcmp_transaction_v1,
};
use core::cell::Cell;
use p256::elliptic_curve::bigint::{Encoding as _, U256};
use rand_08::{SeedableRng as _, rngs::StdRng};
use sha2::{Digest as _, Sha256};
const TEST_AMOUNT: u64 = 5;
thread_local! {
    static PROVER_COPY_CLEARS: Cell<usize> = const { Cell::new(0) };
}
fn reset_prover_secret_copy_owner_drops() {
    PROVER_SECRET_COPY_OWNER_DROPS_V1.with(|drops| drops.set(0));
}
fn prover_secret_copy_owner_drops() -> usize {
    PROVER_SECRET_COPY_OWNER_DROPS_V1.with(Cell::get)
}
fn reset_rerandomization_scalar_decoder_owner_drops() {
    PROVER_SECRET_EDWARDS_CANONICALITY_OWNER_DROPS_V1.with(|drops| drops.set(0));
    PROVER_SECRET_EDWARDS_WIDE_INPUT_OWNER_DROPS_V1.with(|drops| drops.set(0));
    reset_prover_secret_copy_owner_drops();
}
fn rerandomization_canonicality_owner_drops() -> usize {
    PROVER_SECRET_EDWARDS_CANONICALITY_OWNER_DROPS_V1.with(Cell::get)
}
fn rerandomization_wide_input_owner_drops() -> usize {
    PROVER_SECRET_EDWARDS_WIDE_INPUT_OWNER_DROPS_V1.with(Cell::get)
}
fn reset_fcmp_input_rerandomization_owner_drops() {
    FCMP_INPUT_RERANDOMIZATION_OWNER_DROPS_V1.with(|drops| drops.set(0));
}
fn fcmp_input_rerandomization_owner_drops() -> usize {
    FCMP_INPUT_RERANDOMIZATION_OWNER_DROPS_V1.with(Cell::get)
}
fn reset_fcmp_prover_input_owner_drops() {
    FCMP_PROVER_INPUT_OWNER_DROPS_V1.with(|drops| drops.set(0));
}
fn fcmp_prover_input_owner_drops() -> usize {
    FCMP_PROVER_INPUT_OWNER_DROPS_V1.with(Cell::get)
}
fn reset_prover_secret_scalar_owner_drops() {
    PROVER_SECRET_SCALAR_OWNER_DROPS_V1.with(|drops| drops.set(0));
}
fn prover_secret_scalar_owner_drops() -> usize {
    PROVER_SECRET_SCALAR_OWNER_DROPS_V1.with(Cell::get)
}
fn reset_prover_secret_point_owner_drops() {
    PROVER_SECRET_POINT_OWNER_DROPS_V1.with(|drops| drops.set(0));
}
fn prover_secret_point_owner_drops() -> usize {
    PROVER_SECRET_POINT_OWNER_DROPS_V1.with(Cell::get)
}
fn reset_sal_owner_drop_counters() {
    super::super::sal::reset_sal_secret_copy_owner_drops_v1();
    super::super::sal::reset_fcmp_sal_witness_owner_drops_v1();
}
fn sal_secret_copy_owner_drops() -> usize {
    super::super::sal::sal_secret_copy_owner_drops_v1()
}
fn fcmp_sal_witness_owner_drops() -> usize {
    super::super::sal::fcmp_sal_witness_owner_drops_v1()
}
fn sal_test_encoding_owner(bytes: [u8; 32]) -> FcmpSalSecretScalarEncodingV1 {
    FcmpSalSecretScalarEncodingV1::from_test_bytes_v1(bytes)
}
fn sal_scalar_encoding_owner(scalar: &Scalar) -> FcmpSalSecretScalarEncodingV1 {
    FcmpSalSecretScalarEncodingV1::from_scalar_ref_v1(scalar)
}
fn sal_witness_from_test_encodings(
    encodings: [[u8; 32]; 4],
) -> Result<FcmpSalWitnessV1, FcmpNativeErrorV1> {
    FcmpSalWitnessV1::from_secret_scalar_encoding_owners_v1(
        sal_test_encoding_owner(encodings[0]),
        sal_test_encoding_owner(encodings[1]),
        sal_test_encoding_owner(encodings[2]),
        sal_test_encoding_owner(encodings[3]),
    )
}
fn sal_witness_from_scalar_refs(
    scalars: &[Scalar; 4],
) -> Result<FcmpSalWitnessV1, FcmpNativeErrorV1> {
    FcmpSalWitnessV1::from_secret_scalar_encoding_owners_v1(
        sal_scalar_encoding_owner(&scalars[0]),
        sal_scalar_encoding_owner(&scalars[1]),
        sal_scalar_encoding_owner(&scalars[2]),
        sal_scalar_encoding_owner(&scalars[3]),
    )
}
fn exercise_sal_scalar_encoding_role_owner(role: usize, label: &str) {
    assert!(role < 4);
    let values = [
        Scalar::from(17_u64),
        Scalar::from(23_u64),
        Scalar::from(31_u64),
        Scalar::from(43_u64),
    ];
    reset_sal_owner_drop_counters();
    {
        let witness = sal_witness_from_scalar_refs(&values).expect("owned SAL witness");
        assert_eq!(sal_secret_copy_owner_drops(), 8);
        assert_eq!(fcmp_sal_witness_owner_drops(), 0);
        let _ = core::hint::black_box(&witness);
    }
    assert_eq!(sal_secret_copy_owner_drops(), 8);
    assert_eq!(fcmp_sal_witness_owner_drops(), 1);
    reset_sal_owner_drop_counters();
    let mut encodings = values.map(|value| value.to_bytes());
    encodings[role] = [u8::MAX; 32];
    let result = sal_witness_from_test_encodings(encodings);
    assert!(matches!(result, Err(FcmpNativeErrorV1::ScalarEncoding)));
    assert_eq!(sal_secret_copy_owner_drops(), 4 + role, "{label}");
    assert_eq!(fcmp_sal_witness_owner_drops(), 0);
    reset_sal_owner_drop_counters();
    let unwind = std::panic::catch_unwind(|| {
        let witness = sal_witness_from_scalar_refs(&values).expect("witness before unwind");
        assert_eq!(sal_secret_copy_owner_drops(), 8);
        assert_eq!(fcmp_sal_witness_owner_drops(), 0);
        let _ = core::hint::black_box(&witness);
        panic!("exercise SAL {label} owner unwind");
    });
    assert!(unwind.is_err());
    assert_eq!(sal_secret_copy_owner_drops(), 8);
    assert_eq!(fcmp_sal_witness_owner_drops(), 1);
}
fn source_section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing source boundary {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing source boundary {end}"))
        .0
}
fn assert_source_contains_all(source: &str, expected: &[&str]) {
    for needle in expected {
        assert!(source.contains(needle), "missing {needle}");
    }
}
fn assert_source_excludes_all(source: &str, forbidden: &[&str]) {
    for needle in forbidden {
        assert!(!source.contains(needle), "retained {needle}");
    }
}
fn assert_source_order(source: &str, expected: &[&str]) {
    let positions = expected
        .iter()
        .map(|needle| {
            source
                .find(needle)
                .unwrap_or_else(|| panic!("missing ordered source {needle}"))
        })
        .collect::<Vec<_>>();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
}
fn assert_source_counts(source: &str, expected: &[(&str, usize)]) {
    for (needle, count) in expected {
        assert_eq!(source.matches(needle).count(), *count, "count for {needle}");
    }
}
const SOURCE_CONTRACT_GROUPS_V1: &[u8] = include_bytes!("tests/source_contract_groups_v1.json");
const SOURCE_CONTRACT_GROUPS_V1_LEN: usize = 40_108;
const SOURCE_CONTRACT_GROUPS_V1_SHA256: [u8; 32] = [
    0xab, 0x65, 0xde, 0x4c, 0xc1, 0x54, 0x09, 0xe2, 0x79, 0x2c, 0x43, 0x39, 0xb6, 0x55, 0xf5, 0x8b,
    0xf7, 0xfa, 0x67, 0x45, 0x73, 0xe3, 0x3e, 0xf7, 0x39, 0xc1, 0x98, 0x36, 0xaa, 0x67, 0x87, 0x29,
];
#[derive(Debug, crate::json_macros::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct SourceContractGroupFileV1 {
    schema: String,
    preimage: SourceContractGroupPreimageV1,
    groups: Vec<SourceContractGroupV1>,
}
#[derive(Debug, crate::json_macros::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct SourceContractGroupPreimageV1 {
    tests_rs: String,
    commitment_mask_rs: String,
    runtime_rs: String,
}
#[derive(Debug, crate::json_macros::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct SourceContractGroupV1 {
    id: String,
    kind: String,
    needles: Vec<String>,
    counts: Vec<usize>,
}
fn load_source_contract_groups_v1() -> SourceContractGroupFileV1 {
    assert_eq!(
        SOURCE_CONTRACT_GROUPS_V1.len(),
        SOURCE_CONTRACT_GROUPS_V1_LEN
    );
    let digest: [u8; 32] = Sha256::digest(SOURCE_CONTRACT_GROUPS_V1).into();
    assert_eq!(digest, SOURCE_CONTRACT_GROUPS_V1_SHA256);
    let fixture: SourceContractGroupFileV1 = norito::json::from_slice(SOURCE_CONTRACT_GROUPS_V1)
        .expect("decode strict FCMP source-contract groups");
    assert_eq!(fixture.schema, "iroha_core.fcmp_source_contract_groups.v1");
    assert_eq!(
        fixture.preimage.tests_rs,
        "4b6267d86f7bd45203188e665215c83eaa58b5f7"
    );
    assert_eq!(
        fixture.preimage.commitment_mask_rs,
        "cf118c236e6fc1fb88b70a7dcb6c66189e27c23a"
    );
    assert_eq!(
        fixture.preimage.runtime_rs,
        "e81723d0b934b2295c2ed6fd198aab880867c61c"
    );
    assert_eq!(fixture.groups.len(), 76);
    let mut ids = std::collections::BTreeSet::new();
    for group in &fixture.groups {
        assert!(
            ids.insert(group.id.as_str()),
            "duplicate group {}",
            group.id
        );
        assert!(!group.needles.is_empty(), "empty group {}", group.id);
        assert!(
            group.needles.iter().all(|needle| !needle.is_empty()),
            "empty needle in {}",
            group.id
        );
        match group.kind.as_str() {
            "counts" => assert_eq!(group.counts.len(), group.needles.len(), "{}", group.id),
            "contains" | "excludes" | "order" => {
                assert!(group.counts.is_empty(), "unexpected counts in {}", group.id);
            }
            _ => panic!("unknown source-contract kind in {}", group.id),
        }
    }
    fixture
}
static SOURCE_CONTRACT_GROUPS: std::sync::LazyLock<SourceContractGroupFileV1> =
    std::sync::LazyLock::new(load_source_contract_groups_v1);
fn assert_source_contract_group(id: &str, source: &str) {
    let group = SOURCE_CONTRACT_GROUPS
        .groups
        .iter()
        .find(|group| group.id == id)
        .unwrap_or_else(|| panic!("missing source-contract group {id}"));
    match group.kind.as_str() {
        "contains" => {
            for needle in &group.needles {
                assert!(source.contains(needle), "{id}: missing {needle}");
            }
        }
        "excludes" => {
            for needle in &group.needles {
                assert!(!source.contains(needle), "{id}: retained {needle}");
            }
        }
        "order" => {
            let mut cursor = 0;
            for needle in &group.needles {
                let offset = source[cursor..]
                    .find(needle)
                    .unwrap_or_else(|| panic!("{id}: missing ordered source {needle}"));
                cursor += offset + needle.len();
            }
        }
        "counts" => {
            for (needle, count) in group.needles.iter().zip(&group.counts) {
                assert_eq!(
                    source.matches(needle).count(),
                    *count,
                    "{id}: count for {needle}"
                );
            }
        }
        _ => unreachable!("source-contract kinds are validated at load"),
    }
}
#[derive(Clone, Copy)]
enum SourcePoint<'a> {
    First(&'a str),
    Last(&'a str),
    Nth(&'a str, usize),
}
fn source_point_position(source: &str, point: SourcePoint<'_>) -> usize {
    match point {
        SourcePoint::First(needle) => source
            .find(needle)
            .unwrap_or_else(|| panic!("missing first source point {needle}")),
        SourcePoint::Last(needle) => source
            .rfind(needle)
            .unwrap_or_else(|| panic!("missing last source point {needle}")),
        SourcePoint::Nth(needle, index) => {
            assert!(!needle.is_empty(), "source point needle must not be empty");
            let mut search_start = 0;
            let mut position = None;
            for _ in 0..=index {
                let offset = source[search_start..]
                    .find(needle)
                    .unwrap_or_else(|| panic!("missing source point {needle} at index {index}"));
                let absolute = search_start + offset;
                position = Some(absolute);
                search_start = absolute + needle.len();
            }
            position.expect("source point loop executes at least once")
        }
    }
}
fn assert_source_point_order(source: &str, expected: &[SourcePoint<'_>]) {
    let mut previous = None;
    for point in expected {
        let position = source_point_position(source, *point);
        if let Some(previous) = previous {
            assert!(previous < position, "source points are out of order");
        }
        previous = Some(position);
    }
}
macro_rules! source_part {
    ($source:expr; $start:expr => $end:expr) => {
        source_section($source, $start, $end)
    };
}
macro_rules! source_has {
    ($source:expr; $($needle:expr),* $(,)?) => {
        assert_source_contains_all($source, &[$($needle),*])
    };
}
macro_rules! source_lacks {
    ($source:expr; $($needle:expr),* $(,)?) => {
        assert_source_excludes_all($source, &[$($needle),*])
    };
}
macro_rules! source_order {
    ($source:expr; $($needle:expr),* $(,)?) => {
        assert_source_order($source, &[$($needle),*])
    };
}
macro_rules! source_counts {
    ($source:expr; $($needle:expr => $count:expr),* $(,)?) => {
        assert_source_counts($source, &[$(($needle, $count)),*])
    };
}
#[derive(Clone, Copy)]
struct TrackingCopy(u64);
impl Zeroize for TrackingCopy {
    fn zeroize(&mut self) {
        self.0 = 0;
        PROVER_COPY_CLEARS.with(|calls| calls.set(calls.get() + 1));
    }
}
#[test]
fn prover_copy_owner_clears_transfer_success_and_unwind_slots() {
    PROVER_COPY_CLEARS.with(|calls| calls.set(0));
    let mut source = TrackingCopy(7);
    let owner = ProverSecretCopyValueV1::take(&mut source);
    assert_eq!(source.0, 0);
    assert_eq!(owner.expose_ref().0, 7);
    assert_eq!(PROVER_COPY_CLEARS.with(Cell::get), 1);
    drop(owner);
    assert_eq!(PROVER_COPY_CLEARS.with(Cell::get), 2);
    PROVER_COPY_CLEARS.with(|calls| calls.set(0));
    assert!(
        std::panic::catch_unwind(|| {
            let _owner = ProverSecretCopyValueV1::new(TrackingCopy(11));
            panic!("tracking unwind");
        })
        .is_err()
    );
    assert_eq!(PROVER_COPY_CLEARS.with(Cell::get), 2);
}
#[test]
fn fixture_spendable_output_owns_inputs_and_secret_outputs_on_every_exit() {
    let expected = FcmpOutputTupleV1::new(
        ((ED25519_BASEPOINT_POINT * Scalar::from(17_u64)) + (generator_t() * Scalar::from(23_u64)))
            .compress()
            .to_bytes(),
        (ED25519_BASEPOINT_POINT * Scalar::from(31_u64))
            .compress()
            .to_bytes(),
        (super::super::range::amount_generator().expect("amount generator")
            * Scalar::from(TEST_AMOUNT)
            + ED25519_BASEPOINT_POINT * Scalar::from(37_u64))
        .compress()
        .to_bytes(),
    )
    .expect("legacy fixture equation remains canonical");
    reset_prover_secret_copy_owner_drops();
    let fixture = fcmp_fixture_spendable_output_from_scalars_v1(
        Scalar::from(17_u64),
        Scalar::from(23_u64),
        Scalar::from(31_u64),
        TEST_AMOUNT,
        Scalar::from(37_u64),
    )
    .expect("owned fixture output");
    assert_eq!(fixture.0, expected);
    assert_eq!(fixture.1.expose_ref(), &Scalar::from(17_u64).to_bytes());
    assert_eq!(fixture.2.expose_ref(), &Scalar::from(23_u64).to_bytes());
    assert_eq!(prover_secret_copy_owner_drops(), 6);
    drop(fixture);
    assert_eq!(prover_secret_copy_owner_drops(), 8);
    reset_prover_secret_copy_owner_drops();
    let error = fcmp_fixture_spendable_output_from_scalars_v1(
        Scalar::ZERO,
        Scalar::ZERO,
        Scalar::ZERO,
        0,
        Scalar::ZERO,
    )
    .err()
    .expect("identity fixture output must reject");
    assert_eq!(error, FcmpNativeErrorV1::EdwardsPointIdentity);
    assert_eq!(prover_secret_copy_owner_drops(), 6);
    reset_prover_secret_copy_owner_drops();
    let unwind = std::panic::catch_unwind(|| {
        let _fixture = fcmp_fixture_spendable_output_from_scalars_v1(
            Scalar::from(41_u64),
            Scalar::from(43_u64),
            Scalar::from(47_u64),
            TEST_AMOUNT,
            Scalar::from(53_u64),
        )
        .expect("owned unwind fixture");
        assert_eq!(prover_secret_copy_owner_drops(), 6);
        panic!("exercise secret fixture-output owner unwind");
    });
    assert!(unwind.is_err());
    assert_eq!(prover_secret_copy_owner_drops(), 8);
}
#[test]
fn fixture_spendable_output_source_stays_owned_through_release_transfer() {
    let source = include_str!("../prover.rs");
    source_has!(source; "#[cfg(any(test, feature = \"test-utils\", feature = \"privacy-release-evidence\"))]\ntype FcmpFixtureSpendableOutputV1 = (");
    let fixture = source_part!(source; "fn fcmp_fixture_spendable_output_from_scalars_v1(" => "fn fcmp_fixture_spendable_output_v1(");
    source_has!(fixture; "mut spend_x: Scalar", "mut output_y: Scalar", "mut linking: Scalar", "mut amount: u64", "mut commitment_mask: Scalar", "ProverSecretCopyValueV1::new(spend_x.expose_ref().to_bytes())", "ProverSecretCopyValueV1::new(output_y.expose_ref().to_bytes())", "Ok((output, spend_x_bytes, output_y_bytes))");
    source_counts!(fixture; "ProverSecretCopyValueV1::take(&mut" => 5, "secret_edwards_product_v1(" => 5, "Zeroizing::new(&*" => 2);
    assert!(
        fixture.rfind("ProverSecretCopyValueV1::take(&mut").unwrap()
            < fixture.find("amount_generator()?").unwrap()
    );
    source_lacks!(fixture; "ED25519_BASEPOINT_POINT * spend_x", "generator_t() * output_y", "ED25519_BASEPOINT_POINT * linking", "Scalar::from(amount)", "ED25519_BASEPOINT_POINT * commitment_mask", "Ok((output, spend_x.to_bytes(), output_y.to_bytes()))");
    source_has!(source_part!(source; "fn from_secret_byte_owners_v1(" => "#[cfg(test)]\n    fn duplicate_for_test"); "spend_x_bytes: ProverSecretCopyValueV1<[u8; 32]>", "output_y_bytes: ProverSecretCopyValueV1<[u8; 32]>");
    let release_fixture = source_part!(source; "pub fn fcmp_release_fixture_v1(" => "/// Build a maximum-shape fixture whose first canonical branch");
    source_counts!(release_fixture; "FcmpProverInputV1::from_secret_byte_owners_v1(" => 3);
    source_lacks!(release_fixture; "spend_x.expose_copy()", "output_y.expose_copy()", "FcmpProverInputV1::new(");
    source_has!(source; "#[cfg(any(test, feature = \"test-utils\"))]\n#[doc(hidden)]\npub fn fcmp_test_spendable_output_v1(");
    source_has!(source_part!(source; "pub fn fcmp_test_spendable_output_v1(" => "fn fcmp_fixture_output_opening_v1("); "spend_x.expose_copy()", "output_y.expose_copy()");
}
#[test]
fn fixture_u64_wrapper_owns_slots_on_success_error_and_inner_unwind() {
    let expected = fcmp_fixture_spendable_output_from_scalars_v1(
        Scalar::from(17_u64),
        Scalar::from(23_u64),
        Scalar::from(31_u64),
        TEST_AMOUNT,
        Scalar::from(37_u64),
    )
    .expect("owned scalar fixture");
    let expected_output = expected.0;
    drop(expected);
    reset_prover_secret_copy_owner_drops();
    let fixture =
        fcmp_fixture_spendable_output_v1(17, 23, 31, TEST_AMOUNT, 37).expect("owned u64 fixture");
    assert_eq!(fixture.0, expected_output);
    assert_eq!(fixture.1.expose_ref(), &Scalar::from(17_u64).to_bytes());
    assert_eq!(fixture.2.expose_ref(), &Scalar::from(23_u64).to_bytes());
    assert_eq!(prover_secret_copy_owner_drops(), 11);
    drop(fixture);
    assert_eq!(prover_secret_copy_owner_drops(), 13);
    reset_prover_secret_copy_owner_drops();
    let error = fcmp_fixture_spendable_output_v1(0, 0, 0, 0, 0)
        .err()
        .expect("identity u64 fixture must reject");
    assert_eq!(error, FcmpNativeErrorV1::EdwardsPointIdentity);
    assert_eq!(prover_secret_copy_owner_drops(), 11);
    reset_prover_secret_copy_owner_drops();
    let unwind = std::panic::catch_unwind(|| {
        let _result: Result<FcmpFixtureSpendableOutputV1, FcmpNativeErrorV1> =
            with_fcmp_fixture_u64_secret_owners_v1(
                ProverSecretCopyValueV1::new(41_u64),
                ProverSecretCopyValueV1::new(43_u64),
                ProverSecretCopyValueV1::new(47_u64),
                ProverSecretCopyValueV1::new(TEST_AMOUNT),
                ProverSecretCopyValueV1::new(53_u64),
                |spend_x, output_y, linking, amount, commitment_mask| {
                    assert_eq!(
                        (*spend_x, *output_y, *linking, *amount, *commitment_mask),
                        (41, 43, 47, TEST_AMOUNT, 53)
                    );
                    panic!("exercise fixture u64 inner unwind");
                },
            );
    });
    assert!(unwind.is_err());
    assert_eq!(prover_secret_copy_owner_drops(), 5);
}
#[test]
fn fixture_u64_wrapper_source_takes_every_slot_before_inner_conversion() {
    let source = include_str!("../prover.rs");
    source_has!(source; "#[cfg(any(test, feature = \"test-utils\", feature = \"privacy-release-evidence\"))]\nfn with_fcmp_fixture_u64_secret_owners_v1<T>(", "#[cfg(any(test, feature = \"test-utils\", feature = \"privacy-release-evidence\"))]\nfn fcmp_fixture_spendable_output_v1(");
    let owner_scope = source_part!(source; "fn with_fcmp_fixture_u64_secret_owners_v1<T>(" => "fn fcmp_fixture_spendable_output_v1(");
    source_counts!(owner_scope; "ProverSecretCopyValueV1<u64>" => 5, ".expose_ref()" => 5);
    source_has!(owner_scope; "operation: impl FnOnce(&u64, &u64, &u64, &u64, &u64) -> T");
    let wrapper = source_part!(source; "fn fcmp_fixture_spendable_output_v1(" => "#[cfg(any(test, feature = \"test-utils\"))]\n#[doc(hidden)]\npub fn fcmp_test_spendable_output_v1(");
    source_has!(wrapper; "mut spend_x: u64", "mut output_y: u64", "mut linking: u64", "mut amount: u64", "mut commitment_mask: u64", "*amount,");
    source_counts!(wrapper; "ProverSecretCopyValueV1::take(&mut" => 5, "Scalar::from(*" => 4);
    assert!(
        wrapper.rfind("ProverSecretCopyValueV1::take(&mut").unwrap()
            < wrapper
                .find("with_fcmp_fixture_u64_secret_owners_v1(")
                .unwrap()
    );
    source_order!(wrapper; "with_fcmp_fixture_u64_secret_owners_v1(", "Scalar::from(*spend_x)");
    source_lacks!(wrapper; "let spend_x_scalar", "let output_y_scalar", "?");
}
#[test]
fn fixture_output_opening_owns_success_error_mismatch_and_unwind_slots() {
    let expected_output = FcmpOutputTupleV1::new(
        (ED25519_BASEPOINT_POINT * Scalar::from(43_u64))
            .compress()
            .to_bytes(),
        (ED25519_BASEPOINT_POINT * Scalar::from(47_u64))
            .compress()
            .to_bytes(),
        (super::super::range::amount_generator().expect("amount generator")
            * Scalar::from(TEST_AMOUNT)
            + ED25519_BASEPOINT_POINT * Scalar::from(79_u64))
        .compress()
        .to_bytes(),
    )
    .expect("legacy fixture opening output");
    reset_prover_secret_copy_owner_drops();
    let opening =
        fcmp_fixture_output_opening_v1(43, 47, TEST_AMOUNT, 79).expect("owned fixture opening");
    assert_eq!(opening.output(), expected_output);
    assert_eq!(opening.amount(), &TEST_AMOUNT);
    assert_eq!(
        &*opening.commitment_mask(),
        &Scalar::from(79_u64).to_bytes()
    );
    assert_eq!(prover_secret_copy_owner_drops(), 9);
    drop(opening);
    assert_eq!(prover_secret_copy_owner_drops(), 9);
    reset_prover_secret_copy_owner_drops();
    let error = fcmp_fixture_output_opening_v1(0, 0, 0, 0)
        .err()
        .expect("identity fixture opening must reject");
    assert_eq!(error, FcmpNativeErrorV1::EdwardsPointIdentity);
    assert_eq!(prover_secret_copy_owner_drops(), 8);
    reset_prover_secret_copy_owner_drops();
    let mismatch = with_fcmp_fixture_output_u64_secret_owners_v1(
        ProverSecretCopyValueV1::new(11_u64),
        ProverSecretCopyValueV1::new(13_u64),
        ProverSecretCopyValueV1::new(TEST_AMOUNT),
        ProverSecretCopyValueV1::new(17_u64),
        |output_key, linking, amount, mask| {
            let mask_scalar = ProverSecretCopyValueV1::new(Scalar::from(*mask));
            let mask_bytes = ProverSecretCopyValueV1::new(mask_scalar.expose_ref().to_bytes());
            FcmpOutputCommitmentOpeningV1::new_borrowed(
                output_from_multiples(*output_key, *linking, *mask),
                amount,
                mask_bytes.expose_ref(),
            )
        },
    )
    .err()
    .expect("missing positive amount component must mismatch");
    assert_eq!(mismatch, FcmpNativeErrorV1::RangeCommitmentOpeningMismatch);
    assert_eq!(prover_secret_copy_owner_drops(), 6);
    reset_prover_secret_copy_owner_drops();
    let unwind = std::panic::catch_unwind(|| {
        let _result: Result<FcmpOutputCommitmentOpeningV1, FcmpNativeErrorV1> =
            with_fcmp_fixture_output_u64_secret_owners_v1(
                ProverSecretCopyValueV1::new(19_u64),
                ProverSecretCopyValueV1::new(23_u64),
                ProverSecretCopyValueV1::new(TEST_AMOUNT),
                ProverSecretCopyValueV1::new(29_u64),
                |output_key, linking, amount, mask| {
                    let output_key_scalar = ProverSecretCopyValueV1::new(Scalar::from(*output_key));
                    let linking_scalar = ProverSecretCopyValueV1::new(Scalar::from(*linking));
                    let amount_scalar = ProverSecretCopyValueV1::new(Scalar::from(*amount));
                    let mask_scalar = ProverSecretCopyValueV1::new(Scalar::from(*mask));
                    let output_key_point = secret_edwards_product_v1(
                        &ED25519_BASEPOINT_POINT,
                        output_key_scalar.expose_ref(),
                    );
                    let linking_point = secret_edwards_product_v1(
                        &ED25519_BASEPOINT_POINT,
                        linking_scalar.expose_ref(),
                    );
                    let amount_generator =
                        super::super::range::amount_generator().expect("amount generator");
                    let amount_component =
                        secret_edwards_product_v1(&amount_generator, amount_scalar.expose_ref());
                    let mask_component = secret_edwards_product_v1(
                        &ED25519_BASEPOINT_POINT,
                        mask_scalar.expose_ref(),
                    );
                    let amount_point = Zeroizing::new(&*amount_component + &*mask_component);
                    let _ = core::hint::black_box((
                        &*output_key_point,
                        &*linking_point,
                        &*amount_point,
                    ));
                    panic!("exercise fixture opening inner unwind");
                },
            );
    });
    assert!(unwind.is_err());
    assert_eq!(prover_secret_copy_owner_drops(), 8);
}
#[test]
fn fixture_output_opening_source_stays_owned_until_borrowed_constructor() {
    let source = include_str!("../prover.rs");
    source_has!(source; "#[cfg(any(test, feature = \"privacy-release-evidence\"))]\nfn with_fcmp_fixture_output_u64_secret_owners_v1<T>(", "#[cfg(any(test, feature = \"privacy-release-evidence\"))]\nfn fcmp_fixture_output_opening_v1(");
    let owner_scope = source_part!(source; "fn with_fcmp_fixture_output_u64_secret_owners_v1<T>(" => "fn fcmp_fixture_output_opening_v1(");
    source_counts!(owner_scope; "ProverSecretCopyValueV1<u64>" => 4, ".expose_ref()" => 4);
    source_has!(owner_scope; "operation: impl FnOnce(&u64, &u64, &u64, &u64) -> T");
    let fixture = source_part!(source; "fn fcmp_fixture_output_opening_v1(" => "fn fcmp_fixture_rerandomization_v1(");
    source_has!(fixture; "mut output_key: u64", "mut linking: u64", "mut amount: u64", "mut mask: u64", "FcmpOutputCommitmentOpeningV1::new_borrowed(output, amount, mask_bytes.expose_ref())");
    source_counts!(fixture; "ProverSecretCopyValueV1::take(&mut" => 4, "ProverSecretCopyValueV1::new(Scalar::from(*" => 4, "secret_edwards_product_v1(" => 4, "Zeroizing::new(&*" => 1);
    assert!(
        fixture.rfind("ProverSecretCopyValueV1::take(&mut").unwrap()
            < fixture
                .find("with_fcmp_fixture_output_u64_secret_owners_v1(")
                .unwrap()
    );
    source_order!(fixture; "with_fcmp_fixture_output_u64_secret_owners_v1(", "ProverSecretCopyValueV1::new(Scalar::from(*output_key))", "super::range::amount_generator()?", "let output = FcmpOutputTupleV1::new(", "ProverSecretCopyValueV1::new(mask_scalar.expose_ref().to_bytes())", "FcmpOutputCommitmentOpeningV1::new_borrowed(");
    source_lacks!(fixture; "let mask = Scalar::from(mask)", "ED25519_BASEPOINT_POINT * Scalar::from", "FcmpOutputCommitmentOpeningV1::new(");
}
#[test]
fn fixture_rerandomization_owns_success_error_and_unwind_slots() {
    reset_prover_secret_copy_owner_drops();
    let rerandomization =
        fcmp_fixture_rerandomization_v1(61, 67, 71, 41).expect("owned rerandomization fixture");
    assert_eq!(&rerandomization.output, &Scalar::from(61_u64));
    assert_eq!(&rerandomization.linking, &Scalar::from(67_u64));
    assert_eq!(
        &rerandomization.rerandomization_blind,
        &Scalar::from(71_u64)
    );
    assert_eq!(&rerandomization.commitment, &Scalar::from(41_u64));
    assert_eq!(prover_secret_copy_owner_drops(), 16);
    drop(rerandomization);
    assert_eq!(prover_secret_copy_owner_drops(), 16);
    reset_prover_secret_copy_owner_drops();
    let error = fcmp_fixture_rerandomization_v1(61, 67, 71, 0)
        .err()
        .expect("zero final rerandomization scalar must reject");
    assert_eq!(error, FcmpNativeErrorV1::ScalarEncoding);
    assert_eq!(prover_secret_copy_owner_drops(), 16);
    reset_prover_secret_copy_owner_drops();
    let unwind = std::panic::catch_unwind(|| {
        let _result: Result<FcmpInputRerandomizationV1, FcmpNativeErrorV1> =
            with_fcmp_fixture_rerandomization_u64_secret_owners_v1(
                ProverSecretCopyValueV1::new(73_u64),
                ProverSecretCopyValueV1::new(79_u64),
                ProverSecretCopyValueV1::new(83_u64),
                ProverSecretCopyValueV1::new(89_u64),
                |output, linking, blind, commitment| {
                    let scalars = [
                        ProverSecretCopyValueV1::new(Scalar::from(*output)),
                        ProverSecretCopyValueV1::new(Scalar::from(*linking)),
                        ProverSecretCopyValueV1::new(Scalar::from(*blind)),
                        ProverSecretCopyValueV1::new(Scalar::from(*commitment)),
                    ];
                    let bytes = [
                        ProverSecretCopyValueV1::new(scalars[0].expose_ref().to_bytes()),
                        ProverSecretCopyValueV1::new(scalars[1].expose_ref().to_bytes()),
                        ProverSecretCopyValueV1::new(scalars[2].expose_ref().to_bytes()),
                        ProverSecretCopyValueV1::new(scalars[3].expose_ref().to_bytes()),
                    ];
                    let _ = core::hint::black_box((&scalars, &bytes));
                    panic!("exercise rerandomization fixture inner unwind");
                },
            );
    });
    assert!(unwind.is_err());
    assert_eq!(prover_secret_copy_owner_drops(), 12);
}
#[test]
fn rerandomization_scalar_decoder_owns_comparison_wide_and_result_on_every_exit() {
    assert_eq!(
        PROVER_ED25519_SCALAR_MODULUS_LE_V1,
        U256::from_be_hex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")
            .to_le_bytes()
    );
    let modulus = U256::from_le_bytes(PROVER_ED25519_SCALAR_MODULUS_LE_V1);
    for (label, integer, expected) in [
        ("one", U256::ONE, Scalar::ONE),
        ("l-1", modulus.wrapping_sub(&U256::ONE), -Scalar::ONE),
    ] {
        reset_rerandomization_scalar_decoder_owner_drops();
        let bytes = integer.to_le_bytes();
        let scalar = prover_secret_decode_nonzero_edwards_scalar_v1(&bytes)
            .unwrap_or_else(|error| panic!("{label} rejected: {error:?}"));
        assert_eq!(scalar.expose_ref(), &expected, "{label}");
        assert_eq!(rerandomization_canonicality_owner_drops(), 1, "{label}");
        assert_eq!(rerandomization_wide_input_owner_drops(), 1, "{label}");
        assert_eq!(prover_secret_copy_owner_drops(), 0, "{label}");
        drop(scalar);
        assert_eq!(prover_secret_copy_owner_drops(), 1, "{label}");
    }
    reset_rerandomization_scalar_decoder_owner_drops();
    let zero = U256::ZERO.to_le_bytes();
    let scalar = ProverValidatedSecretEdwardsScalarEncodingV1::validate_v1(&zero)
        .expect("zero is a canonical scalar encoding")
        .into_scalar_owner_v1();
    assert_eq!(scalar.expose_ref(), &Scalar::ZERO);
    assert_eq!(rerandomization_canonicality_owner_drops(), 1);
    assert_eq!(rerandomization_wide_input_owner_drops(), 1);
    assert_eq!(prover_secret_copy_owner_drops(), 0);
    drop(scalar);
    assert_eq!(prover_secret_copy_owner_drops(), 1);
    reset_rerandomization_scalar_decoder_owner_drops();
    assert!(matches!(
        prover_secret_decode_nonzero_edwards_scalar_v1(&zero),
        Err(FcmpNativeErrorV1::ScalarEncoding)
    ));
    assert_eq!(rerandomization_canonicality_owner_drops(), 1);
    assert_eq!(rerandomization_wide_input_owner_drops(), 1);
    assert_eq!(prover_secret_copy_owner_drops(), 1);
    for (label, integer) in [
        ("l", modulus),
        ("l+1", modulus.wrapping_add(&U256::ONE)),
        ("max", U256::MAX),
    ] {
        reset_rerandomization_scalar_decoder_owner_drops();
        let bytes = integer.to_le_bytes();
        assert!(
            matches!(
                prover_secret_decode_nonzero_edwards_scalar_v1(&bytes),
                Err(FcmpNativeErrorV1::ScalarEncoding)
            ),
            "{label} accepted"
        );
        assert_eq!(rerandomization_canonicality_owner_drops(), 1, "{label}");
        assert_eq!(rerandomization_wide_input_owner_drops(), 0, "{label}");
        assert_eq!(prover_secret_copy_owner_drops(), 0, "{label}");
    }
    reset_rerandomization_scalar_decoder_owner_drops();
    let result_unwind = std::panic::catch_unwind(|| {
        let bytes = U256::from(7_u8).to_le_bytes();
        let scalar = prover_secret_decode_nonzero_edwards_scalar_v1(&bytes)
            .expect("owned scalar before unwind");
        assert_eq!(rerandomization_canonicality_owner_drops(), 1);
        assert_eq!(rerandomization_wide_input_owner_drops(), 1);
        assert_eq!(prover_secret_copy_owner_drops(), 0);
        let _ = core::hint::black_box(scalar.expose_ref());
        panic!("exercise rerandomization scalar owner unwind");
    });
    assert!(result_unwind.is_err());
    assert_eq!(rerandomization_canonicality_owner_drops(), 1);
    assert_eq!(rerandomization_wide_input_owner_drops(), 1);
    assert_eq!(prover_secret_copy_owner_drops(), 1);
    reset_rerandomization_scalar_decoder_owner_drops();
    let comparison_unwind = std::panic::catch_unwind(|| {
        let mut canonicality = ProverSecretEdwardsCanonicalityStateV1::new_v1();
        canonicality.observe_byte_v1(&7_u8, &11_u8);
        assert_eq!(rerandomization_canonicality_owner_drops(), 0);
        let _ = core::hint::black_box(&canonicality.less);
        panic!("exercise rerandomization canonicality owner unwind");
    });
    assert!(comparison_unwind.is_err());
    assert_eq!(rerandomization_canonicality_owner_drops(), 1);
    assert_eq!(rerandomization_wide_input_owner_drops(), 0);
    assert_eq!(prover_secret_copy_owner_drops(), 0);
    reset_rerandomization_scalar_decoder_owner_drops();
    let wide_unwind = std::panic::catch_unwind(|| {
        let bytes = U256::from(11_u8).to_le_bytes();
        let wide = ProverSecretEdwardsWideInputV1::from_borrowed_v1(&bytes);
        assert_eq!(rerandomization_wide_input_owner_drops(), 0);
        let _ = core::hint::black_box(&wide.0);
        panic!("exercise rerandomization wide owner unwind");
    });
    assert!(wide_unwind.is_err());
    assert_eq!(rerandomization_canonicality_owner_drops(), 0);
    assert_eq!(rerandomization_wide_input_owner_drops(), 1);
    assert_eq!(prover_secret_copy_owner_drops(), 0);
}
#[test]
fn rerandomization_constructor_direct_handoff_covers_every_exit() {
    let encoded = [
        Scalar::from(61_u64).to_bytes(),
        Scalar::from(67_u64).to_bytes(),
        Scalar::from(71_u64).to_bytes(),
        Scalar::from(41_u64).to_bytes(),
    ];
    reset_prover_secret_copy_owner_drops();
    reset_fcmp_input_rerandomization_owner_drops();
    let mut rerandomization =
        FcmpInputRerandomizationV1::new(encoded[0], encoded[1], encoded[2], encoded[3])
            .expect("direct owner handoff");
    assert_eq!(rerandomization.output, Scalar::from(61_u64));
    assert_eq!(rerandomization.linking, Scalar::from(67_u64));
    assert_eq!(rerandomization.rerandomization_blind, Scalar::from(71_u64));
    assert_eq!(rerandomization.commitment, Scalar::from(41_u64));
    assert_eq!(prover_secret_copy_owner_drops(), 8);
    assert_eq!(fcmp_input_rerandomization_owner_drops(), 0);
    rerandomization.zeroize();
    assert_eq!(rerandomization.output, Scalar::ZERO);
    assert_eq!(rerandomization.linking, Scalar::ZERO);
    assert_eq!(rerandomization.rerandomization_blind, Scalar::ZERO);
    assert_eq!(rerandomization.commitment, Scalar::ZERO);
    drop(rerandomization);
    assert_eq!(prover_secret_copy_owner_drops(), 8);
    assert_eq!(fcmp_input_rerandomization_owner_drops(), 1);
    for invalid_index in 0..4 {
        let mut invalid = encoded;
        invalid[invalid_index] = Scalar::ZERO.to_bytes();
        reset_prover_secret_copy_owner_drops();
        reset_fcmp_input_rerandomization_owner_drops();
        assert!(matches!(
            FcmpInputRerandomizationV1::new(invalid[0], invalid[1], invalid[2], invalid[3]),
            Err(FcmpNativeErrorV1::ScalarEncoding)
        ));
        assert_eq!(
            prover_secret_copy_owner_drops(),
            5 + invalid_index,
            "decoded owners before invalid position {invalid_index}"
        );
        assert_eq!(fcmp_input_rerandomization_owner_drops(), 0);
    }
    for invalid_index in 0..4 {
        let mut invalid = encoded;
        invalid[invalid_index] = [u8::MAX; 32];
        reset_prover_secret_copy_owner_drops();
        reset_fcmp_input_rerandomization_owner_drops();
        assert!(matches!(
            FcmpInputRerandomizationV1::new(invalid[0], invalid[1], invalid[2], invalid[3]),
            Err(FcmpNativeErrorV1::ScalarEncoding)
        ));
        assert_eq!(
            prover_secret_copy_owner_drops(),
            4 + invalid_index,
            "decoded owners before noncanonical position {invalid_index}"
        );
        assert_eq!(fcmp_input_rerandomization_owner_drops(), 0);
    }
    reset_prover_secret_copy_owner_drops();
    reset_fcmp_input_rerandomization_owner_drops();
    let unwind = std::panic::catch_unwind(|| {
        let rerandomization =
            FcmpInputRerandomizationV1::new(encoded[0], encoded[1], encoded[2], encoded[3])
                .expect("direct owner handoff before unwind");
        assert_eq!(prover_secret_copy_owner_drops(), 8);
        let _ = core::hint::black_box(&rerandomization);
        panic!("exercise rerandomization destination-owner unwind");
    });
    assert!(unwind.is_err());
    assert_eq!(prover_secret_copy_owner_drops(), 8);
    assert_eq!(fcmp_input_rerandomization_owner_drops(), 1);
}
#[test]
fn fixture_rerandomization_source_keeps_feature_secret_owners_in_order() {
    let source = include_str!("../prover.rs");
    source_has!(source; "#[cfg(any(test, feature = \"privacy-release-evidence\"))]\nfn with_fcmp_fixture_rerandomization_u64_secret_owners_v1<T>(", "#[cfg(any(test, feature = \"privacy-release-evidence\"))]\nfn fcmp_fixture_rerandomization_v1(");
    let owner_scope = source_part!(source; "fn with_fcmp_fixture_rerandomization_u64_secret_owners_v1<T>(" => "fn fcmp_fixture_rerandomization_v1(");
    source_counts!(owner_scope; "ProverSecretCopyValueV1<u64>" => 4, ".expose_ref()" => 4);
    source_has!(owner_scope; "operation: impl FnOnce(&u64, &u64, &u64, &u64) -> T");
    let fixture = source_part!(source; "fn fcmp_fixture_rerandomization_v1(" => "/// Build the canonical deterministic FCMP++ release fixture.");
    source_has!(fixture; "mut output: u64", "mut linking: u64", "mut blind: u64", "mut commitment: u64");
    source_counts!(fixture; "ProverSecretCopyValueV1::take(&mut" => 4, "ProverSecretCopyValueV1::new(Scalar::from(*" => 4, ".expose_ref().to_bytes())" => 4);
    assert!(
        fixture.rfind("ProverSecretCopyValueV1::take(&mut").unwrap()
            < fixture
                .find("with_fcmp_fixture_rerandomization_u64_secret_owners_v1(")
                .unwrap()
    );
    source_order!(fixture; "with_fcmp_fixture_rerandomization_u64_secret_owners_v1(", "ProverSecretCopyValueV1::new(Scalar::from(*output))", "ProverSecretCopyValueV1::new(output_scalar.expose_ref().to_bytes())", "FcmpInputRerandomizationV1::from_rerandomization_secret_byte_owners_v1(");
    source_lacks!(fixture; "FcmpInputRerandomizationV1::new(", "Scalar::from(output)", "Scalar::from(linking)", "Scalar::from(blind)", "Scalar::from(commitment)");
}
#[test]
fn fixture_leaf_coordinate_scope_owns_success_error_and_unwind() {
    let leaves = [
        output_from_multiples(101, 103, 107),
        output_from_multiples(109, 113, 127),
    ];
    let expected_root = build_fcmp_frontier_v1(&leaves)
        .expect("canonical hidden-leaf frontier")
        .root;
    reset_prover_secret_scalar_owner_drops();
    let hash = with_fcmp_fixture_leaf_coordinate_owners_v1(
        &leaves,
        secret_edwards_to_wei25519_v1,
        prover_secret_hash_selene_v1,
    )
    .expect("owned hidden-leaf coordinates");
    assert_eq!(hash.expose_ref().encode(), expected_root.point());
    assert_eq!(prover_secret_scalar_owner_drops(), 12);
    reset_prover_secret_scalar_owner_drops();
    let conversions = Cell::new(0_usize);
    let conversion_error = with_fcmp_fixture_leaf_coordinate_owners_v1(
        &leaves,
        |point| {
            let index = conversions.get();
            conversions.set(index + 1);
            if index == 2 {
                return Err(FcmpNativeErrorV1::EdwardsPointEncoding);
            }
            secret_edwards_to_wei25519_v1(point)
        },
        hash_selene,
    )
    .err()
    .expect("injected third-point conversion failure");
    assert_eq!(conversion_error, FcmpNativeErrorV1::EdwardsPointEncoding);
    assert_eq!(conversions.get(), 3);
    assert_eq!(prover_secret_scalar_owner_drops(), 4);
    reset_prover_secret_scalar_owner_drops();
    let empty_hash_error = with_fcmp_fixture_leaf_coordinate_owners_v1(
        &[],
        secret_edwards_to_wei25519_v1,
        hash_selene,
    )
    .err()
    .expect("empty canonical Selene hash must reject");
    assert_eq!(empty_hash_error, FcmpNativeErrorV1::BranchWidth);
    assert_eq!(prover_secret_scalar_owner_drops(), 0);
    reset_prover_secret_scalar_owner_drops();
    let hash_error = with_fcmp_fixture_leaf_coordinate_owners_v1(
        &leaves,
        secret_edwards_to_wei25519_v1,
        |_| -> Result<SelenePoint, FcmpNativeErrorV1> {
            Err(FcmpNativeErrorV1::ArithmeticInvariant)
        },
    )
    .err()
    .expect("injected hash failure");
    assert_eq!(hash_error, FcmpNativeErrorV1::ArithmeticInvariant);
    assert_eq!(prover_secret_scalar_owner_drops(), 12);
    reset_prover_secret_scalar_owner_drops();
    let conversion_unwind = std::panic::catch_unwind(|| {
        let mut conversions = 0_usize;
        let _result: Result<SelenePoint, FcmpNativeErrorV1> =
            with_fcmp_fixture_leaf_coordinate_owners_v1(
                &leaves,
                |point| {
                    if conversions == 2 {
                        panic!("exercise hidden-leaf conversion unwind");
                    }
                    conversions += 1;
                    secret_edwards_to_wei25519_v1(point)
                },
                hash_selene,
            );
    });
    assert!(conversion_unwind.is_err());
    assert_eq!(prover_secret_scalar_owner_drops(), 4);
    reset_prover_secret_scalar_owner_drops();
    let hash_unwind = std::panic::catch_unwind(|| {
        let _result: Result<SelenePoint, FcmpNativeErrorV1> =
            with_fcmp_fixture_leaf_coordinate_owners_v1(
                &leaves,
                secret_edwards_to_wei25519_v1,
                |_| panic!("exercise hidden-leaf hash unwind"),
            );
    });
    assert!(hash_unwind.is_err());
    assert_eq!(prover_secret_scalar_owner_drops(), 12);
}
#[test]
fn fixture_secret_selene_hash_matches_equation_and_owns_all_exit_paths() {
    let values = [Field25519::ONE, Field25519::ONE.add_ref(&Field25519::ONE)];
    let expected = hash_selene(&values).expect("public canonical Selene equation");
    reset_prover_secret_point_owner_drops();
    {
        let actual = prover_secret_hash_selene_v1(&values)
            .expect("complete private Selene multiexponentiation");
        assert_eq!(actual.expose_ref().encode(), expected.encode());
        assert_eq!(prover_secret_point_owner_drops(), 0);
    }
    assert_eq!(prover_secret_point_owner_drops(), 1);
    reset_prover_secret_point_owner_drops();
    let downstream_error: Result<(), FcmpNativeErrorV1> = prover_secret_hash_selene_v1(&values)
        .and_then(|owned| {
            assert_eq!(prover_secret_point_owner_drops(), 0);
            let _ = core::hint::black_box(owned.expose_ref());
            Err(FcmpNativeErrorV1::ArithmeticInvariant)
        });
    assert_eq!(
        downstream_error,
        Err(FcmpNativeErrorV1::ArithmeticInvariant)
    );
    assert_eq!(prover_secret_point_owner_drops(), 1);
    assert!(matches!(
        prover_secret_hash_selene_v1(&[]),
        Err(FcmpNativeErrorV1::BranchWidth)
    ));
    let mut incomplete = SecretMultiexpBuilder::<SeleneSuite>::new(values.len() + 2)
        .expect("one deliberately incomplete slot");
    incomplete
        .push(&Field25519::ONE, &selene_hash_initializer())
        .expect("initializer term");
    for (scalar, generator) in values.iter().zip(selene_generators()) {
        incomplete.push(scalar, generator).expect("ordered term");
    }
    let incomplete_result: Result<(), FcmpNativeErrorV1> =
        incomplete.evaluate().map(|_| ()).map_err(Into::into);
    assert_eq!(
        incomplete_result,
        Err(FcmpNativeErrorV1::ArithmeticInvariant)
    );
    let mut full =
        SecretMultiexpBuilder::<SeleneSuite>::new(1).expect("initializer-only exact capacity");
    full.push(&Field25519::ONE, &selene_hash_initializer())
        .expect("initializer fills builder");
    assert_eq!(full.capacity(), 1);
    assert_eq!(full.len(), 1);
    assert_eq!(
        full.push(&values[0], &selene_generators()[0])
            .map_err(FcmpNativeErrorV1::from),
        Err(FcmpNativeErrorV1::TreeFull)
    );
    assert_eq!(
        SecretMultiexpBuilder::<SeleneSuite>::new(usize::MAX)
            .err()
            .map(FcmpNativeErrorV1::from),
        Some(FcmpNativeErrorV1::TreeFull)
    );
    reset_prover_secret_point_owner_drops();
    let unwind = std::panic::catch_unwind(|| {
        let _owned =
            prover_secret_hash_selene_v1(&values).expect("owned Selene point before unwind");
        assert_eq!(prover_secret_point_owner_drops(), 0);
        panic!("exercise private Selene point-owner unwind");
    });
    assert!(unwind.is_err());
    assert_eq!(prover_secret_point_owner_drops(), 1);
}
#[test]
fn fixture_secret_cycle_step_matches_public_equations_and_owns_copies() {
    let helios_values = [
        HelioseleneField::ONE,
        HelioseleneField::ONE.add_ref(&HelioseleneField::ONE),
    ];
    let expected_helios = hash_helios(&helios_values).expect("public Helios equation");
    reset_prover_secret_point_owner_drops();
    reset_prover_secret_copy_owner_drops();
    {
        let actual_helios = prover_secret_hash_helios_v1(&helios_values)
            .expect("private Helios multiexponentiation");
        assert_eq!(
            actual_helios.expose_ref().encode(),
            expected_helios.encode()
        );
        let expected_x = expected_helios.x().expect("nonidentity public Helios hash");
        let child = prover_secret_helios_x_v1(&actual_helios).expect("owned Helios x coordinate");
        assert!(child.expose_ref().eq_ref(&expected_x));
        assert_eq!(prover_secret_point_owner_drops(), 0);
        assert_eq!(prover_secret_copy_owner_drops(), 0);
        let root_encoding = fcmp_fixture_secret_helios_encoding_v1(&actual_helios)
            .expect("owned Helios root encoding");
        assert_eq!(root_encoding.as_ref(), &expected_helios.encode());
        let encoded = encode_secret_field25519_scalar_v1(child.expose_ref());
        assert_eq!(encoded.as_ref(), &encode_field25519_scalar(expected_x));
        let mut branches =
            zeroizing_exact_secret_buffer_v1::<Vec<[u8; 32]>>(1).expect("one branch");
        push_fcmp_fixture_secret_branch_v1(&mut branches, encoded)
            .expect("preallocated branch insertion");
        assert_eq!(
            branches.as_slice(),
            &[vec![encode_field25519_scalar(expected_x)]]
        );
    }
    assert_eq!(prover_secret_point_owner_drops(), 1);
    assert_eq!(prover_secret_copy_owner_drops(), 0);
    reset_prover_secret_point_owner_drops();
    {
        let expected_selene = hash_selene(&[Field25519::ONE]).expect("public Selene equation");
        let actual_selene = prover_secret_hash_selene_v1(&[Field25519::ONE])
            .expect("private Selene multiexponentiation");
        let expected_x = expected_selene.x().expect("nonidentity public Selene hash");
        let child = prover_secret_selene_x_v1(&actual_selene).expect("owned Selene x coordinate");
        assert!(child.expose_ref().eq_ref(&expected_x));
        assert_eq!(
            encode_secret_helioselene_scalar_v1(child.expose_ref()).as_ref(),
            &encode_helioselene_scalar(expected_x)
        );
    }
    assert_eq!(prover_secret_point_owner_drops(), 1);
    reset_prover_secret_point_owner_drops();
    {
        let identity = ProverSecretPointV1(SelenePoint::identity());
        assert!(matches!(
            prover_secret_selene_x_v1(&identity),
            Err(FcmpNativeErrorV1::ArithmeticInvariant)
        ));
        assert_eq!(
            ct_secret_selene_point_eq_v1(
                &identity,
                &hash_selene(&[Field25519::ONE]).expect("public Selene comparison point"),
            ),
            Err(FcmpNativeErrorV1::ArithmeticInvariant)
        );
    }
    assert_eq!(prover_secret_point_owner_drops(), 1);
    reset_prover_secret_point_owner_drops();
    {
        let identity = ProverSecretPointV1(HeliosPoint::identity());
        assert!(matches!(
            prover_secret_helios_x_v1(&identity),
            Err(FcmpNativeErrorV1::ArithmeticInvariant)
        ));
        assert!(matches!(
            fcmp_fixture_secret_helios_encoding_v1(&identity),
            Err(FcmpNativeErrorV1::ArithmeticInvariant)
        ));
    }
    assert_eq!(prover_secret_point_owner_drops(), 1);
    let mut no_capacity: Zeroizing<Vec<Vec<[u8; 32]>>> = Zeroizing::new(Vec::new());
    assert!(matches!(
        push_fcmp_fixture_secret_branch_v1(
            &mut no_capacity,
            encode_secret_field25519_scalar_v1(&Field25519::ONE),
        ),
        Err(FcmpNativeErrorV1::ArithmeticInvariant)
    ));
    assert!(no_capacity.is_empty());
}
#[test]
fn fixture_secret_branch_direct_handoff_covers_capacity_success_and_unwind() {
    let expected_helioselene = encode_helioselene_scalar(HelioseleneField::ONE);
    let expected_field25519 = encode_field25519_scalar(Field25519::ONE);
    let mut branches =
        zeroizing_exact_secret_buffer_v1::<Vec<[u8; 32]>>(2).expect("two final branches");
    let allocation_capacity = branches.capacity();
    let allocation_pointer = branches.as_ptr();
    push_fcmp_fixture_secret_branch_v1(
        &mut branches,
        encode_secret_helioselene_scalar_v1(&HelioseleneField::ONE),
    )
    .expect("direct Helioselene encoded-owner handoff");
    push_fcmp_fixture_secret_branch_v1(
        &mut branches,
        encode_secret_field25519_scalar_v1(&Field25519::ONE),
    )
    .expect("direct Field25519 encoded-owner handoff");
    assert_eq!(
        branches.as_slice(),
        &[vec![expected_helioselene], vec![expected_field25519]]
    );
    assert_eq!(branches.capacity(), allocation_capacity);
    assert_eq!(branches.as_ptr(), allocation_pointer);
    assert!(
        branches
            .iter()
            .all(|branch| branch.len() == 1 && branch.capacity() >= 1)
    );
    branches.zeroize();
    assert!(branches.is_empty());
    let mut no_capacity: Zeroizing<Vec<Vec<[u8; 32]>>> = Zeroizing::new(Vec::new());
    assert_eq!(
        push_fcmp_fixture_secret_branch_v1(
            &mut no_capacity,
            encode_secret_field25519_scalar_v1(&Field25519::ONE),
        ),
        Err(FcmpNativeErrorV1::ArithmeticInvariant)
    );
    assert!(no_capacity.is_empty());
    let mut unwind_branches =
        zeroizing_exact_secret_buffer_v1::<Vec<[u8; 32]>>(1).expect("one unwind branch");
    let unwind_capacity = unwind_branches.capacity();
    let unwind_pointer = unwind_branches.as_ptr();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        push_fcmp_fixture_secret_branch_v1(
            &mut unwind_branches,
            encode_secret_field25519_scalar_v1(&Field25519::ONE),
        )
        .expect("direct owner handoff before unwind");
        assert_eq!(unwind_branches.as_slice(), &[vec![expected_field25519]]);
        assert_eq!(unwind_branches.capacity(), unwind_capacity);
        assert_eq!(unwind_branches.as_ptr(), unwind_pointer);
        panic!("exercise final branch owner unwind");
    }));
    assert!(unwind.is_err());
    assert_eq!(unwind_branches.as_slice(), &[vec![expected_field25519]]);
    unwind_branches.zeroize();
    assert!(unwind_branches.is_empty());
}
#[test]
fn fixture_secret_cycle_source_has_no_raw_coordinate_hash_or_branch_boundary() {
    let source = include_str!("../prover.rs");
    let release_fixture = source_section(
        source,
        "pub fn fcmp_release_fixture_v1(",
        "/// Build a maximum-shape fixture whose first canonical branch",
    );
    assert_source_contract_group(
        "fixture_secret_cycle_source_has_no_raw_coordinate_hash_or_branch_boundary/00",
        release_fixture,
    );
    assert_source_contract_group(
        "fixture_secret_cycle_source_has_no_raw_coordinate_hash_or_branch_boundary/01",
        release_fixture,
    );
    assert_source_counts(release_fixture, &[(".expose_public_copy_v1()", 1)]);
    let x_helpers = source_section(
        source,
        "fn prover_secret_selene_x_v1(",
        "fn push_fcmp_fixture_secret_branch_v1(",
    );
    assert_source_counts(x_helpers, &[(".secret_x_owner_v1()", 2)]);
    assert_source_contract_group(
        "fixture_secret_cycle_source_has_no_raw_coordinate_hash_or_branch_boundary/02",
        x_helpers,
    );
    let branch_insertion = source_section(
        source,
        "fn push_fcmp_fixture_secret_branch_v1(",
        "fn fcmp_fixture_secret_helios_encoding_v1(",
    );
    assert_source_contract_group(
        "fixture_secret_cycle_source_has_no_raw_coordinate_hash_or_branch_boundary/03",
        branch_insertion,
    );
    let transfer = branch_insertion
        .find("core::mem::swap(&mut final_branch[destination], encoded.as_mut())")
        .expect("direct final-owner transfer");
    let final_drop = branch_insertion
        .rfind("drop(encoded);")
        .expect("final source-owner clear");
    assert!(transfer < final_drop);
    assert_source_contract_group(
        "fixture_secret_cycle_source_has_no_raw_coordinate_hash_or_branch_boundary/04",
        branch_insertion,
    );
    assert_source_contract_group(
        "fixture_secret_cycle_source_has_no_raw_coordinate_hash_or_branch_boundary/05",
        branch_insertion,
    );
    assert_source_contract_group(
        "fixture_secret_cycle_source_has_no_raw_coordinate_hash_or_branch_boundary/06",
        release_fixture,
    );
    assert_source_contract_group(
        "fixture_secret_cycle_source_has_no_raw_coordinate_hash_or_branch_boundary/07",
        release_fixture,
    );
    let field = include_str!("../field.rs");
    for helper in [
        "fn encode_secret_field25519_scalar_v1",
        "fn encode_secret_helioselene_scalar_v1",
    ] {
        assert_source_contract_group(
            "fixture_secret_cycle_source_has_no_raw_coordinate_hash_or_branch_boundary/08",
            source_section(field, helper, "}"),
        );
    }
    assert_source_contract_group(
        "fixture_secret_cycle_source_has_no_raw_coordinate_hash_or_branch_boundary/09",
        source_section(
            field,
            "pub(super) fn secret_x_ref_v1(&self)",
            "/// Encode a private projective point",
        ),
    );
    assert!(!field.contains("pub(super) fn secret_x_v1(mut self)"));
    let secret_encoding = source_section(
        field,
        "pub(super) fn secret_encode_v1(mut self)",
        "pub(super) fn secret_encode_ref_v1(&self)",
    );
    assert_source_contract_group(
        "fixture_secret_cycle_source_has_no_raw_coordinate_hash_or_branch_boundary/10",
        secret_encoding,
    );
    assert_source_contract_group(
        "fixture_secret_cycle_source_has_no_raw_coordinate_hash_or_branch_boundary/11",
        secret_encoding,
    );
    assert_source_excludes_all(secret_encoding, &["y.as_ref().is_odd_ref()"]);
}
#[test]
fn invalid_path_fixture_replacement_owns_success_error_and_zeroize_slots() {
    reset_prover_secret_copy_owner_drops();
    let mut helios_values = Vec::with_capacity(1);
    helios_values.push(HelioseleneField::ONE);
    let helios_capacity = helios_values.capacity();
    let helios_pointer = helios_values.as_ptr();
    let mut helios = AdditionalBranch::ToHelios(helios_values);
    replace_first_secret_coordinate_v1(&mut helios).expect("owned Helios replacement");
    let AdditionalBranch::ToHelios(helios_values) = &helios else {
        panic!("Helios branch variant changed");
    };
    assert!(helios_values[0].eq_ref(&HelioseleneField::ONE.add_ref(&HelioseleneField::ONE)));
    assert_eq!(helios_values.len(), 1);
    assert_eq!(helios_values.capacity(), helios_capacity);
    assert_eq!(helios_values.as_ptr(), helios_pointer);
    assert_eq!(prover_secret_copy_owner_drops(), 3);
    replace_first_secret_coordinate_v1(&mut helios).expect("owned non-one Helios replacement");
    let AdditionalBranch::ToHelios(helios_values) = &helios else {
        panic!("Helios branch variant changed");
    };
    assert!(helios_values[0].eq_ref(&HelioseleneField::ONE));
    assert_eq!(helios_values.len(), 1);
    assert_eq!(helios_values.capacity(), helios_capacity);
    assert_eq!(helios_values.as_ptr(), helios_pointer);
    assert_eq!(prover_secret_copy_owner_drops(), 6);
    helios.zeroize();
    let AdditionalBranch::ToHelios(helios_values) = &helios else {
        panic!("Helios branch variant changed during zeroize");
    };
    assert!(helios_values.is_empty());
    reset_prover_secret_copy_owner_drops();
    let mut selene_values = Vec::with_capacity(1);
    selene_values.push(Field25519::ONE);
    let selene_capacity = selene_values.capacity();
    let selene_pointer = selene_values.as_ptr();
    let mut selene = AdditionalBranch::ToSelene(selene_values);
    replace_first_secret_coordinate_v1(&mut selene).expect("owned Selene replacement");
    let AdditionalBranch::ToSelene(selene_values) = &selene else {
        panic!("Selene branch variant changed");
    };
    assert!(selene_values[0].eq_ref(&Field25519::ONE.add_ref(&Field25519::ONE)));
    assert_eq!(selene_values.len(), 1);
    assert_eq!(selene_values.capacity(), selene_capacity);
    assert_eq!(selene_values.as_ptr(), selene_pointer);
    assert_eq!(prover_secret_copy_owner_drops(), 3);
    replace_first_secret_coordinate_v1(&mut selene).expect("owned non-one Selene replacement");
    let AdditionalBranch::ToSelene(selene_values) = &selene else {
        panic!("Selene branch variant changed");
    };
    assert!(selene_values[0].eq_ref(&Field25519::ONE));
    assert_eq!(selene_values.len(), 1);
    assert_eq!(selene_values.capacity(), selene_capacity);
    assert_eq!(selene_values.as_ptr(), selene_pointer);
    assert_eq!(prover_secret_copy_owner_drops(), 6);
    selene.zeroize();
    let AdditionalBranch::ToSelene(selene_values) = &selene else {
        panic!("Selene branch variant changed during zeroize");
    };
    assert!(selene_values.is_empty());
    reset_prover_secret_copy_owner_drops();
    let empty_helios_values = Vec::with_capacity(1);
    let empty_helios_capacity = empty_helios_values.capacity();
    let empty_helios_pointer = empty_helios_values.as_ptr();
    let mut empty_helios = AdditionalBranch::ToHelios(empty_helios_values);
    assert_eq!(
        replace_first_secret_coordinate_v1(&mut empty_helios),
        Err(FcmpNativeErrorV1::ArithmeticInvariant)
    );
    let AdditionalBranch::ToHelios(empty_helios_values) = &empty_helios else {
        panic!("empty Helios branch variant changed");
    };
    assert!(empty_helios_values.is_empty());
    assert_eq!(empty_helios_values.capacity(), empty_helios_capacity);
    assert_eq!(empty_helios_values.as_ptr(), empty_helios_pointer);
    assert_eq!(prover_secret_copy_owner_drops(), 0);
    reset_prover_secret_copy_owner_drops();
    let empty_selene_values = Vec::with_capacity(1);
    let empty_selene_capacity = empty_selene_values.capacity();
    let empty_selene_pointer = empty_selene_values.as_ptr();
    let mut empty_selene = AdditionalBranch::ToSelene(empty_selene_values);
    assert_eq!(
        replace_first_secret_coordinate_v1(&mut empty_selene),
        Err(FcmpNativeErrorV1::ArithmeticInvariant)
    );
    let AdditionalBranch::ToSelene(empty_selene_values) = &empty_selene else {
        panic!("empty Selene branch variant changed");
    };
    assert!(empty_selene_values.is_empty());
    assert_eq!(empty_selene_values.capacity(), empty_selene_capacity);
    assert_eq!(empty_selene_values.as_ptr(), empty_selene_pointer);
    assert_eq!(prover_secret_copy_owner_drops(), 0);
}
#[test]
fn invalid_path_fixture_replacement_final_owner_zeroizes_on_unwind() {
    let (mut inputs, _outputs, _root) = maximum_bound_fixture();
    let mut input = inputs.remove(0);
    drop(inputs);
    reset_prover_secret_copy_owner_drops();
    replace_first_secret_coordinate_v1(
        input
            .additional_branches
            .first_mut()
            .expect("maximum fixture has a private branch"),
    )
    .expect("replace first private coordinate before unwind");
    assert_eq!(prover_secret_copy_owner_drops(), 3);
    reset_fcmp_prover_input_owner_drops();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _ = core::hint::black_box(&input);
        panic!("exercise invalid-path final-owner unwind");
    }));
    assert!(unwind.is_err());
    assert_eq!(prover_secret_copy_owner_drops(), 3);
    assert_eq!(fcmp_prover_input_owner_drops(), 1);
}
#[test]
fn invalid_path_fixture_source_confines_both_replacements_to_direct_owner_swaps() {
    let source = include_str!("../prover.rs");
    let helper = source_section(
        source,
        "fn replace_first_secret_coordinate_v1(",
        "pub(crate) fn fcmp_release_invalid_path_fixture_v1(",
    );
    let (helios_arm, selene_arm) = helper
        .split_once("AdditionalBranch::ToSelene(values) => {")
        .expect("two concrete invalid-coordinate arms");
    assert_source_contract_group(
        "invalid_path_fixture_source_confines_both_replacements_to_direct_owner_swaps/00",
        helios_arm,
    );
    assert_source_contract_group(
        "invalid_path_fixture_source_confines_both_replacements_to_direct_owner_swaps/01",
        selene_arm,
    );
    assert_source_contract_group(
        "invalid_path_fixture_source_confines_both_replacements_to_direct_owner_swaps/02",
        helper,
    );
    assert_source_contract_group(
        "invalid_path_fixture_source_confines_both_replacements_to_direct_owner_swaps/03",
        helper,
    );
    let fixture = source_section(
        source,
        "pub(crate) fn fcmp_release_invalid_path_fixture_v1(",
        "enum RootValues",
    );
    assert_source_contract_group(
        "invalid_path_fixture_source_confines_both_replacements_to_direct_owner_swaps/04",
        fixture,
    );
    assert_source_contract_group(
        "invalid_path_fixture_source_confines_both_replacements_to_direct_owner_swaps/05",
        fixture,
    );
    assert_source_contract_group(
        "invalid_path_fixture_source_confines_both_replacements_to_direct_owner_swaps/06",
        fixture,
    );
}
#[test]
fn root_value_equality_owns_every_coordinate_difference_and_scans_full_shape() {
    let one_c1 = Field25519::ONE;
    let two_c1 = Field25519::ONE.add_ref(&Field25519::ONE);
    let three_c1 = two_c1.add_ref(&Field25519::ONE);
    let left_c1 = RootValues::C1(vec![one_c1, two_c1]);
    let equal_c1 = RootValues::C1(vec![one_c1, two_c1]);
    let unequal_c1 = RootValues::C1(vec![three_c1, two_c1]);
    reset_prover_secret_copy_owner_drops();
    assert!(bool::from(root_values_ct_eq(&left_c1, &equal_c1)));
    assert_eq!(prover_secret_copy_owner_drops(), 2);
    reset_prover_secret_copy_owner_drops();
    assert!(!bool::from(root_values_ct_eq(&left_c1, &unequal_c1)));
    assert_eq!(prover_secret_copy_owner_drops(), 2);
    let one_c2 = HelioseleneField::ONE;
    let two_c2 = HelioseleneField::ONE.add_ref(&HelioseleneField::ONE);
    let left_c2 = RootValues::C2(vec![one_c2, two_c2]);
    let equal_c2 = RootValues::C2(vec![one_c2, two_c2]);
    reset_prover_secret_copy_owner_drops();
    assert!(bool::from(root_values_ct_eq(&left_c2, &equal_c2)));
    assert_eq!(prover_secret_copy_owner_drops(), 2);
    reset_prover_secret_copy_owner_drops();
    assert!(!bool::from(root_values_ct_eq(&left_c1, &left_c2)));
    assert_eq!(prover_secret_copy_owner_drops(), 0);
    let short_c1 = RootValues::C1(vec![one_c1]);
    assert!(!bool::from(root_values_ct_eq(&left_c1, &short_c1)));
    assert_eq!(prover_secret_copy_owner_drops(), 0);
}
#[test]
fn root_value_equality_source_uses_only_borrowed_subtraction_and_owned_differences() {
    let source = include_str!("../prover.rs");
    let equality = source
        .split_once("fn root_values_ct_eq")
        .expect("root-value equality")
        .1
        .split_once("fn all_paths_share_root")
        .expect("root-value equality boundary")
        .0;
    assert_eq!(equality.matches("ct_equal_slices_by(").count(), 2);
    assert_eq!(
        equality
            .matches("ProverSecretCopyValueV1::new(left.sub_ref(right))")
            .count(),
        2
    );
    assert_eq!(
        equality
            .matches("difference.expose_ref().ct_is_zero()")
            .count(),
        2
    );
    for forbidden in ["*left - *right", "*left -", "- *right"] {
        assert!(!equality.contains(forbidden), "retained {forbidden}");
    }
}
#[test]
fn fixture_leaf_coordinate_buffer_zeroizes_on_drop_and_unwind() {
    PROVER_COPY_CLEARS.with(|calls| calls.set(0));
    {
        let mut values =
            zeroizing_exact_secret_buffer_v1::<TrackingCopy>(2).expect("exact secret buffer");
        assert!(values.capacity() >= 2);
        values.push(TrackingCopy(131));
        values.push(TrackingCopy(137));
    }
    assert_eq!(PROVER_COPY_CLEARS.with(Cell::get), 2);
    PROVER_COPY_CLEARS.with(|calls| calls.set(0));
    let unwind = std::panic::catch_unwind(|| {
        let mut values =
            zeroizing_exact_secret_buffer_v1::<TrackingCopy>(2).expect("exact unwind buffer");
        values.push(TrackingCopy(139));
        values.push(TrackingCopy(149));
        panic!("exercise exact secret-buffer unwind");
    });
    assert!(unwind.is_err());
    assert_eq!(PROVER_COPY_CLEARS.with(Cell::get), 2);
    assert!(matches!(
        zeroizing_exact_secret_buffer_v1::<TrackingCopy>(usize::MAX),
        Err(FcmpNativeErrorV1::ArithmeticInvariant)
    ));
}
#[test]
fn fixture_leaf_coordinate_source_keeps_exact_erasing_owners_through_hash() {
    let source = include_str!("../prover.rs");
    assert_source_contract_group(
        "fixture_leaf_coordinate_source_keeps_exact_erasing_owners_through_hash/00",
        source,
    );
    assert_source_contract_group(
        "fixture_leaf_coordinate_source_keeps_exact_erasing_owners_through_hash/01",
        source_section(
            source,
            "fn zeroizing_exact_secret_buffer_v1<T: Zeroize>(",
            "fn push_secret_scalar_v1<F: ProofScalar + Zeroize>(",
        ),
    );
    let coordinate_scope = source_section(
        source,
        "fn prover_secret_leaf_coordinates_v1(",
        "fn with_fcmp_fixture_leaf_coordinate_owners_v1<T>(",
    );
    assert_source_contract_group(
        "fixture_leaf_coordinate_source_keeps_exact_erasing_owners_through_hash/02",
        coordinate_scope,
    );
    assert_source_contract_group(
        "fixture_leaf_coordinate_source_keeps_exact_erasing_owners_through_hash/03",
        coordinate_scope,
    );
    assert_source_counts(coordinate_scope, &[("push_borrowed_secret_scalar_v1(", 2)]);
    assert_source_contract_group(
        "fixture_leaf_coordinate_source_keeps_exact_erasing_owners_through_hash/04",
        coordinate_scope,
    );
    let release_fixture = source_section(
        source,
        "pub fn fcmp_release_fixture_v1(",
        "/// Build a maximum-shape fixture whose first canonical branch",
    );
    assert_source_contract_group(
        "fixture_leaf_coordinate_source_keeps_exact_erasing_owners_through_hash/05",
        release_fixture,
    );
    assert_source_contract_group(
        "fixture_leaf_coordinate_source_keeps_exact_erasing_owners_through_hash/06",
        release_fixture,
    );
}
#[test]
fn hidden_output_identifier_push_is_preallocated_and_owned_on_success_and_error() {
    let output = output_from_multiples(13, 17, 19);
    let expected = output.output_id();
    super::super::FCMP_SECRET_OUTPUT_ID_DROPS_V1.with(|drops| drops.set(0));
    let mut identifiers = Zeroizing::new(Vec::with_capacity(1));
    let allocation_capacity = identifiers.capacity();
    let allocation_pointer = identifiers.as_ptr();
    require_preallocated_push(identifiers.len(), identifiers.capacity())
        .expect("public capacity preflight");
    push_owned_secret_output_id_v1(&mut identifiers, output.secret_output_id_v1())
        .expect("preallocated hidden output identifier");
    assert_eq!(identifiers.as_slice(), &[expected]);
    assert_eq!(identifiers.capacity(), allocation_capacity);
    assert_eq!(identifiers.as_ptr(), allocation_pointer);
    assert_eq!(
        super::super::FCMP_SECRET_OUTPUT_ID_DROPS_V1.with(Cell::get),
        1
    );
    super::super::FCMP_SECRET_OUTPUT_ID_DROPS_V1.with(|drops| drops.set(0));
    let mut no_capacity = Zeroizing::new(Vec::new());
    assert!(matches!(
        push_owned_secret_output_id_v1(&mut no_capacity, output.secret_output_id_v1()),
        Err(FcmpNativeErrorV1::ArithmeticInvariant)
    ));
    assert!(no_capacity.is_empty());
    assert_eq!(
        super::super::FCMP_SECRET_OUTPUT_ID_DROPS_V1.with(Cell::get),
        1
    );
}
#[test]
fn private_output_identifier_callsites_use_only_borrowed_owned_insertion() {
    let source = include_str!("../prover.rs");
    let production = source
        .split_once("#[cfg(test)]\n#[path = \"prover/tests.rs\"]\nmod tests")
        .expect("production prover boundary")
        .0;
    let push = source_section(
        source,
        "fn push_owned_secret_output_id_v1(",
        "fn zeroizing_exact_secret_buffer_v1<T: Zeroize>(",
    );
    assert_source_contract_group(
        "private_output_identifier_callsites_use_only_borrowed_owned_insertion/00",
        push,
    );
    assert_source_excludes_all(push, &["value: [u8; 32]", "value.expose_copy()"]);
    let constructor = source_section(
        source,
        "fn from_secret_byte_owners_v1(",
        "#[cfg(test)]\n    fn duplicate_for_test(&self)",
    );
    assert_source_contract_group(
        "private_output_identifier_callsites_use_only_borrowed_owned_insertion/01",
        constructor,
    );
    assert_source_contract_group(
        "private_output_identifier_callsites_use_only_borrowed_owned_insertion/02",
        constructor,
    );
    let prove_once = source_section(
        source,
        "fn prove_fcmp_plus_plus_once_v1(",
        "fn retry_membership_prover<T>(",
    );
    let preflight = source_section(
        source,
        "fn preflight_fcmp_plus_plus_v1(",
        "/// Prove a complete first-release FCMP++ statement in native Rust.",
    );
    for scope in [prove_once, preflight] {
        assert_source_contract_group(
            "private_output_identifier_callsites_use_only_borrowed_owned_insertion/03",
            scope,
        );
        assert_source_excludes_all(scope, &["spent_outputs.push(", "input.output.output_id()"]);
    }
    assert_source_counts(production, &[("input.output.secret_output_id_v1()", 2)]);
    assert_source_counts(production, &[("input.output.output_id()", 0)]);
    assert_source_counts(production, &[(".secret_output_id_v1()", 4)]);
    assert_source_contract_group(
        "private_output_identifier_callsites_use_only_borrowed_owned_insertion/04",
        production,
    );
}
#[test]
fn duplicate_key_image_precheck_owners_cover_success_decode_error_capacity_and_unwind() {
    let (input, _output, _root) = one_layer_fixture();
    let expected = input
        .public_input()
        .expect("canonical public input")
        .key_image;
    let linking_bytes = input.output.component_refs_v1().1;
    reset_prover_secret_copy_owner_drops();
    let key_image = prover_secret_key_image_id_v1(linking_bytes, &input.spend_x)
        .expect("owned duplicate-precheck key image");
    assert_eq!(key_image.expose_ref(), &expected);
    assert_eq!(prover_secret_copy_owner_drops(), 4);
    let mut identifiers = Zeroizing::new(Vec::with_capacity(1));
    let allocation_capacity = identifiers.capacity();
    let allocation_pointer = identifiers.as_ptr();
    push_owned_prover_secret_digest_v1(&mut identifiers, key_image)
        .expect("preallocated key-image insertion");
    assert_eq!(identifiers.as_slice(), &[expected]);
    assert_eq!(identifiers.capacity(), allocation_capacity);
    assert_eq!(identifiers.as_ptr(), allocation_pointer);
    assert_eq!(prover_secret_copy_owner_drops(), 5);
    reset_prover_secret_copy_owner_drops();
    let key_image = prover_secret_key_image_id_v1(linking_bytes, &input.spend_x)
        .expect("owned capacity-error key image");
    assert_eq!(prover_secret_copy_owner_drops(), 4);
    let mut no_capacity = Zeroizing::new(Vec::new());
    assert!(matches!(
        push_owned_prover_secret_digest_v1(&mut no_capacity, key_image),
        Err(FcmpNativeErrorV1::ArithmeticInvariant)
    ));
    assert!(no_capacity.is_empty());
    assert_eq!(prover_secret_copy_owner_drops(), 5);
    reset_prover_secret_copy_owner_drops();
    let small_order = curve25519_dalek::constants::EIGHT_TORSION[1]
        .compress()
        .to_bytes();
    assert!(matches!(
        prover_secret_key_image_id_v1(&small_order, &input.spend_x),
        Err(FcmpNativeErrorV1::EdwardsPointEncoding)
    ));
    assert_eq!(prover_secret_copy_owner_drops(), 3);
    reset_prover_secret_copy_owner_drops();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let key_image = prover_secret_key_image_id_v1(linking_bytes, &input.spend_x)
            .expect("owned key image before unwind");
        assert_eq!(key_image.expose_ref(), &expected);
        assert_eq!(prover_secret_copy_owner_drops(), 4);
        let _ = core::hint::black_box(&key_image);
        panic!("exercise duplicate-key-image owner unwind");
    }));
    assert!(unwind.is_err());
    assert_eq!(prover_secret_copy_owner_drops(), 5);
    let duplicate = Zeroizing::new(vec![expected, expected]);
    assert!(ct_has_duplicate_digests(&duplicate));
}
#[test]
fn duplicate_key_image_precheck_source_is_borrowed_owned_and_constant_time() {
    let source = include_str!("../prover.rs");
    let production = source
        .split_once("#[cfg(test)]\n#[path = \"prover/tests.rs\"]\nmod tests")
        .expect("production prover boundary")
        .0;
    let owner_push = source_section(
        production,
        "fn push_owned_prover_secret_digest_v1(",
        "fn zeroizing_exact_secret_buffer_v1<T: Zeroize>(",
    );
    assert_source_contract_group(
        "duplicate_key_image_precheck_source_is_borrowed_owned_and_constant_time/00",
        owner_push,
    );
    assert_source_contract_group(
        "duplicate_key_image_precheck_source_is_borrowed_owned_and_constant_time/01",
        owner_push,
    );
    let derivation = source_section(
        production,
        "fn prover_secret_key_image_id_v1(",
        "fn secret_edwards_product_v1(",
    );
    assert_source_contract_group(
        "duplicate_key_image_precheck_source_is_borrowed_owned_and_constant_time/02",
        derivation,
    );
    assert_source_contract_group(
        "duplicate_key_image_precheck_source_is_borrowed_owned_and_constant_time/03",
        derivation,
    );
    let prove_once = source_section(
        production,
        "fn prove_fcmp_plus_plus_once_v1(",
        "fn retry_membership_prover<T>(",
    );
    assert_source_contract_group(
        "duplicate_key_image_precheck_source_is_borrowed_owned_and_constant_time/04",
        prove_once,
    );
    assert_source_contract_group(
        "duplicate_key_image_precheck_source_is_borrowed_owned_and_constant_time/05",
        prove_once,
    );
    assert!(!production.contains(
        "#[cfg(any(test, feature = \"test-utils\", feature = \"privacy-release-evidence\"))]\n\
         fn prover_secret_key_image_id_v1("
    ));
}
#[test]
fn proof_input_coordinate_owners_cover_success_decode_error_downstream_error_and_unwind() {
    let output = output_from_multiples(43, 47, 53);
    let (output_bytes, linking_bytes, commitment_bytes) = output.component_refs_v1();
    let expected_output = edwards_to_wei25519(*output_bytes).expect("public output coordinates");
    let expected_linking = edwards_to_wei25519(*linking_bytes).expect("public linking coordinates");
    let expected_commitment =
        edwards_to_wei25519(*commitment_bytes).expect("public commitment coordinates");
    reset_prover_secret_copy_owner_drops();
    {
        let coordinates = prover_secret_output_coordinate_owners_v1(
            output_bytes,
            linking_bytes,
            commitment_bytes,
        )
        .expect("owned proof-input coordinates");
        assert_eq!(
            coordinates.output.padding.expose_ref().as_slice(),
            &[expected_output.0, expected_output.1]
        );
        assert_eq!(
            coordinates.linking.padding.expose_ref().as_slice(),
            &[expected_linking.0, expected_linking.1]
        );
        assert_eq!(
            coordinates.commitment.padding.expose_ref().as_slice(),
            &[expected_commitment.0, expected_commitment.1]
        );
        assert_eq!(prover_secret_copy_owner_drops(), 0);
    }
    assert_eq!(prover_secret_copy_owner_drops(), 3);

    let torsion = curve25519_dalek::constants::EIGHT_TORSION[1]
        .compress()
        .to_bytes();
    reset_prover_secret_copy_owner_drops();
    assert!(matches!(
        prover_secret_output_coordinate_owners_v1(output_bytes, &torsion, commitment_bytes),
        Err(FcmpNativeErrorV1::EdwardsPointEncoding)
    ));
    assert_eq!(prover_secret_copy_owner_drops(), 1);

    reset_prover_secret_copy_owner_drops();
    let downstream_error = (|| -> Result<(), FcmpNativeErrorV1> {
        let coordinates = prover_secret_output_coordinate_owners_v1(
            output_bytes,
            linking_bytes,
            commitment_bytes,
        )?;
        assert_eq!(prover_secret_copy_owner_drops(), 0);
        let _ = core::hint::black_box(coordinates.output.padding.expose_ref());
        let mut tape = ProverVectorCommitmentTape::<Field25519>::new(128)?;
        tape.append_branch(&[])?;
        Ok(())
    })();
    assert_eq!(
        downstream_error,
        Err(FcmpNativeErrorV1::ArithmeticInvariant)
    );
    assert_eq!(prover_secret_copy_owner_drops(), 3);

    reset_prover_secret_copy_owner_drops();
    let unwind = std::panic::catch_unwind(|| {
        let coordinates = prover_secret_output_coordinate_owners_v1(
            output_bytes,
            linking_bytes,
            commitment_bytes,
        )
        .expect("owned proof-input coordinates before unwind");
        assert_eq!(prover_secret_copy_owner_drops(), 0);
        let _ = core::hint::black_box(&coordinates);
        panic!("exercise proof-input coordinate owner unwind");
    });
    assert!(unwind.is_err());
    assert_eq!(prover_secret_copy_owner_drops(), 3);
}
#[test]
fn input_blind_v_padding_owner_covers_success_downstream_error_and_unwind() {
    let scalar = Scalar::from(59_u64);
    let input_blind_v =
        prepare_ed_blind(generator_v(), &scalar, true).expect("prepared input V blind");
    let input_blind_blind =
        prepare_ed_blind(generator_t(), &scalar, false).expect("prepared input blind blind");
    let (input_blind_v_x, input_blind_v_y) = input_blind_v.coordinates.component_refs();
    let expected = [*input_blind_v_x, *input_blind_v_y];

    reset_prover_secret_copy_owner_drops();
    {
        let padding = ProverSecretCopyValueV1::new([*input_blind_v_x, *input_blind_v_y]);
        assert_eq!(padding.expose_ref(), &expected);
        assert_eq!(prover_secret_copy_owner_drops(), 0);
        let mut tape = ProverVectorCommitmentTape::<Field25519>::new(128)
            .expect("one exact prover commitment tape");
        let (_, variables) = tape
            .append_claimed_point(
                ED25519_DLOG_PARAMETERS,
                &input_blind_blind.decomposition,
                &input_blind_blind.divisor,
                input_blind_blind.coordinates.component_pair_ref(),
                padding.expose_ref().as_slice(),
            )
            .expect("owned input V padding insertion");
        assert_eq!(variables.len(), 2);
        assert_eq!(prover_secret_copy_owner_drops(), 0);
    }
    assert_eq!(prover_secret_copy_owner_drops(), 1);

    reset_prover_secret_copy_owner_drops();
    let downstream_error = (|| -> Result<(), FcmpNativeErrorV1> {
        let padding = ProverSecretCopyValueV1::new([*input_blind_v_x, *input_blind_v_y]);
        assert_eq!(padding.expose_ref(), &expected);
        let mut tape = ProverVectorCommitmentTape::<Field25519>::new(128)?;
        tape.append_claimed_point(
            ED25519_DLOG_PARAMETERS,
            &[],
            &input_blind_blind.divisor,
            input_blind_blind.coordinates.component_pair_ref(),
            padding.expose_ref().as_slice(),
        )?;
        Ok(())
    })();
    assert_eq!(
        downstream_error,
        Err(FcmpNativeErrorV1::ArithmeticInvariant)
    );
    assert_eq!(prover_secret_copy_owner_drops(), 1);

    reset_prover_secret_copy_owner_drops();
    let unwind = std::panic::catch_unwind(|| {
        let padding = ProverSecretCopyValueV1::new([*input_blind_v_x, *input_blind_v_y]);
        assert_eq!(padding.expose_ref(), &expected);
        let _ = core::hint::black_box(padding.expose_ref());
        panic!("exercise input V padding owner unwind");
    });
    assert!(unwind.is_err());
    assert_eq!(prover_secret_copy_owner_drops(), 1);
}
#[test]
fn sal_y_sum_owner_covers_success_constructor_error_and_unwind() {
    let output_y = Scalar::from(29_u64);
    let rerandomization_output = Scalar::from(31_u64);
    let expected = Scalar::from(60_u64);

    reset_prover_secret_scalar_owner_drops();
    reset_prover_secret_copy_owner_drops();
    reset_sal_owner_drop_counters();
    {
        let sal_y = prover_secret_edwards_scalar_sum_v1(&output_y, &rerandomization_output);
        assert_eq!(sal_y.expose_ref(), &expected);
        let witness = FcmpSalWitnessV1::from_secret_scalar_encoding_owners_v1(
            sal_scalar_encoding_owner(&Scalar::from(37_u64)),
            sal_scalar_encoding_owner(sal_y.expose_ref()),
            sal_scalar_encoding_owner(&Scalar::from(41_u64)),
            sal_scalar_encoding_owner(&Scalar::from(43_u64)),
        )
        .expect("owned SAL y sum witness");
        let _ = core::hint::black_box(&witness);
        assert_eq!(prover_secret_scalar_owner_drops(), 0);
        assert_eq!(prover_secret_copy_owner_drops(), 0);
        assert_eq!(sal_secret_copy_owner_drops(), 8);
        assert_eq!(fcmp_sal_witness_owner_drops(), 0);
    }
    assert_eq!(prover_secret_scalar_owner_drops(), 0);
    assert_eq!(prover_secret_copy_owner_drops(), 1);
    assert_eq!(sal_secret_copy_owner_drops(), 8);
    assert_eq!(fcmp_sal_witness_owner_drops(), 1);
    exercise_sal_scalar_encoding_role_owner(1, "y");
}
#[test]
fn sal_linking_bytes_owner_covers_success_constructor_error_and_unwind() {
    exercise_sal_scalar_encoding_role_owner(2, "linking");
}
#[test]
fn sal_scalar_encoding_handoff_covers_decode_zeroize_downstream_and_unwind() {
    let values = [
        Scalar::from(17_u64),
        Scalar::from(23_u64),
        Scalar::from(31_u64),
        Scalar::from(43_u64),
    ];
    let encodings = values.map(|value| value.to_bytes());

    for invalid_position in 0..4 {
        reset_sal_owner_drop_counters();
        let mut invalid_encodings = encodings;
        invalid_encodings[invalid_position] = [u8::MAX; 32];
        let result = sal_witness_from_test_encodings(invalid_encodings);
        assert!(matches!(result, Err(FcmpNativeErrorV1::ScalarEncoding)));
        assert_eq!(
            sal_secret_copy_owner_drops(),
            4 + invalid_position,
            "decode position {invalid_position}"
        );
        assert_eq!(fcmp_sal_witness_owner_drops(), 0);
    }

    reset_sal_owner_drop_counters();
    let mut witness = sal_witness_from_scalar_refs(&values).expect("owned SAL witness");
    assert_eq!(sal_secret_copy_owner_drops(), 8);
    assert_eq!(fcmp_sal_witness_owner_drops(), 0);
    witness.zeroize();
    drop(witness);
    assert_eq!(sal_secret_copy_owner_drops(), 8);
    assert_eq!(fcmp_sal_witness_owner_drops(), 1);

    reset_sal_owner_drop_counters();
    let input_generator = ED25519_BASEPOINT_POINT * Scalar::from(59_u64);
    let public = FcmpProofInputPublicV1::new(
        ((ED25519_BASEPOINT_POINT * (values[0] + Scalar::ONE)) + (generator_t() * values[1]))
            .compress()
            .to_bytes(),
        input_generator.compress().to_bytes(),
        ((generator_v() * values[2]) + (generator_t() * values[3]))
            .compress()
            .to_bytes(),
        (ED25519_BASEPOINT_POINT * Scalar::from(61_u64))
            .compress()
            .to_bytes(),
        ((input_generator * values[0]) - (generator_u() * (values[0] * values[2])))
            .compress()
            .to_bytes(),
    )
    .expect("non-identity mismatched SAL public input");
    let witness = sal_witness_from_scalar_refs(&values).expect("mismatched SAL witness");
    assert_eq!(sal_secret_copy_owner_drops(), 8);
    assert_eq!(fcmp_sal_witness_owner_drops(), 0);
    assert_eq!(
        prove_fcmp_sal_with_checked_rng_v1(&mut FailingRngV1, [0_u8; 32], &public, &witness),
        Err(FcmpNativeErrorV1::SalWitnessMismatch)
    );
    assert_eq!(fcmp_sal_witness_owner_drops(), 0);
    drop(witness);
    assert_eq!(fcmp_sal_witness_owner_drops(), 1);

    reset_sal_owner_drop_counters();
    let unwind = std::panic::catch_unwind(|| {
        let witness = sal_witness_from_scalar_refs(&values).expect("witness before unwind");
        assert_eq!(sal_secret_copy_owner_drops(), 8);
        assert_eq!(fcmp_sal_witness_owner_drops(), 0);
        let _ = core::hint::black_box(&witness);
        panic!("exercise SAL witness downstream unwind");
    });
    assert!(unwind.is_err());
    assert_eq!(sal_secret_copy_owner_drops(), 8);
    assert_eq!(fcmp_sal_witness_owner_drops(), 1);
}
fn assert_sal_scalar_encoding_owner_handoff_source() {
    let source = include_str!("../prover.rs");
    let production = source
        .split_once("#[cfg(test)]\n#[path = \"prover/tests.rs\"]\nmod tests")
        .expect("production prover boundary")
        .0;
    let prove_once = source_section(
        production,
        "fn prove_fcmp_plus_plus_once_v1(",
        "fn retry_membership_prover<T>(",
    );
    assert_source_contract_group(
        "assert_sal_scalar_encoding_owner_handoff_source/00",
        prove_once,
    );
    assert_source_contract_group(
        "assert_sal_scalar_encoding_owner_handoff_source/01",
        prove_once,
    );
    assert_source_contract_group(
        "assert_sal_scalar_encoding_owner_handoff_source/02",
        prove_once,
    );

    let sal_source = include_str!("../sal.rs");
    let constructor = source_section(
        sal_source,
        "impl FcmpSalWitnessV1 {",
        "#[allow(clippy::too_many_arguments)]",
    );
    assert_source_contract_group(
        "assert_sal_scalar_encoding_owner_handoff_source/03",
        constructor,
    );
    assert_source_contract_group(
        "assert_sal_scalar_encoding_owner_handoff_source/04",
        constructor,
    );
    assert_source_contract_group(
        "assert_sal_scalar_encoding_owner_handoff_source/05",
        constructor,
    );
    let encoding_owner = source_section(
        sal_source,
        "pub(super) struct FcmpSalSecretScalarEncodingV1(",
        "// Generated by the pinned Monero",
    );
    assert_source_contract_group(
        "assert_sal_scalar_encoding_owner_handoff_source/06",
        encoding_owner,
    );
    assert_source_contract_group(
        "assert_sal_scalar_encoding_owner_handoff_source/07",
        encoding_owner,
    );
    assert_source_counts(encoding_owner, &[("impl ", 1)]);
    let sal_copy_owner = source_section(
        sal_source,
        "impl<T: Copy + Zeroize> SalSecretCopyValueV1<T> {",
        "impl<T: Copy + Zeroize> Drop for SalSecretCopyValueV1<T>",
    );
    assert!(!sal_copy_owner.contains("fn expose_copy(&self)"));
}
#[test]
fn sal_linking_bytes_source_owns_encoding_through_constructor() {
    assert_sal_scalar_encoding_owner_handoff_source();
}
#[test]
fn sal_spend_x_bytes_owner_covers_success_constructor_error_and_unwind() {
    exercise_sal_scalar_encoding_role_owner(0, "spend x");
}
#[test]
fn sal_spend_x_bytes_source_owns_encoding_through_constructor() {
    assert_sal_scalar_encoding_owner_handoff_source();
}
#[test]
fn sal_rerandomization_blind_bytes_owner_covers_success_constructor_error_and_unwind() {
    exercise_sal_scalar_encoding_role_owner(3, "rerandomization blind");
}
#[test]
fn sal_rerandomization_blind_bytes_source_owns_encoding_through_constructor() {
    assert_sal_scalar_encoding_owner_handoff_source();
}
#[test]
fn sal_y_sum_source_borrows_operands_and_retains_owners_through_constructor() {
    let source = include_str!("../prover.rs");
    let production = source
        .split_once("#[cfg(test)]\n#[path = \"prover/tests.rs\"]\nmod tests")
        .expect("production prover boundary")
        .0;
    let sum = source_section(
        production,
        "fn prover_secret_edwards_scalar_sum_v1(",
        "struct ProverSecretPointV1<P: ProofPoint>",
    );
    assert_source_contract_group(
        "sal_y_sum_source_borrows_operands_and_retains_owners_through_constructor/00",
        sum,
    );
    assert_source_contract_group(
        "sal_y_sum_source_borrows_operands_and_retains_owners_through_constructor/01",
        sum,
    );
    assert_sal_scalar_encoding_owner_handoff_source();
}
#[test]
fn proof_input_coordinate_source_is_borrowed_owned_and_production_visible() {
    let source = include_str!("../prover.rs");
    let production = source
        .split_once("#[cfg(test)]\n#[path = \"prover/tests.rs\"]\nmod tests")
        .expect("production prover boundary")
        .0;
    let owners = source_section(
        production,
        "struct ProverSecretEdwardsCoordinateOwnerV1 {",
        "fn secret_edwards_product_v1(",
    );
    assert_source_contract_group(
        "proof_input_coordinate_source_is_borrowed_owned_and_production_visible/00",
        owners,
    );
    assert_source_contract_group(
        "proof_input_coordinate_source_is_borrowed_owned_and_production_visible/01",
        owners,
    );
    assert_source_contract_group(
        "proof_input_coordinate_source_is_borrowed_owned_and_production_visible/02",
        owners,
    );

    let prove_once = source_section(
        production,
        "fn prove_fcmp_plus_plus_once_v1(",
        "fn retry_membership_prover<T>(",
    );
    assert_source_contract_group(
        "proof_input_coordinate_source_is_borrowed_owned_and_production_visible/03",
        prove_once,
    );
    assert_source_contract_group(
        "proof_input_coordinate_source_is_borrowed_owned_and_production_visible/04",
        prove_once,
    );
    assert_source_counts(production, &[("input.public_input()?", 2)]);
    assert_source_contract_group(
        "proof_input_coordinate_source_is_borrowed_owned_and_production_visible/05",
        prove_once,
    );
    assert_source_contract_group(
        "proof_input_coordinate_source_is_borrowed_owned_and_production_visible/06",
        prove_once,
    );

    let field_source = include_str!("../field.rs");
    let private_conversion = source_section(
        field_source,
        "pub(super) fn secret_edwards_to_wei25519_v1(",
        "pub(super) fn monero_varint(",
    );
    assert_source_contract_group(
        "proof_input_coordinate_source_is_borrowed_owned_and_production_visible/07",
        private_conversion,
    );
    assert!(
        private_conversion
            .contains(") -> Result<SecretCycleCoordinatesV1<Field25519>, FcmpNativeErrorV1>")
    );
    assert_source_contract_group(
        "proof_input_coordinate_source_is_borrowed_owned_and_production_visible/08",
        private_conversion,
    );
    assert!(!production.contains(
        "#[cfg(any(test, feature = \"test-utils\", feature = \"privacy-release-evidence\"))]\n\
         fn prover_secret_output_coordinate_owners_v1("
    ));
}
#[test]
fn fixture_secret_selene_hash_source_uses_borrowed_exact_builder_and_owned_result() {
    let source = include_str!("../prover.rs");
    assert!(source.contains("fn prover_secret_hash_selene_v1("));
    let private_hash = source
        .split_once("fn prover_secret_hash_selene_v1(")
        .expect("private fixture Selene hash")
        .1
        .split_once("/// Build the canonical deterministic FCMP++ release fixture.")
        .expect("private fixture Selene hash boundary")
        .0;
    let width = private_hash
        .find("values.is_empty() || values.len() > SELENE_GENERATOR_COUNT_V1")
        .expect("canonical Selene width guard");
    let exact_capacity = private_hash
        .find(".checked_add(1)")
        .expect("initializer-inclusive exact capacity");
    let builder = private_hash
        .find("SecretMultiexpBuilder::<SeleneSuite>::new(exact_capacity)?")
        .expect("exact-capacity secret builder");
    let initializer = private_hash
        .find("terms.push(&Field25519::ONE, &selene_hash_initializer())?")
        .expect("canonical initializer term");
    let ordered_generators = private_hash
        .find("values.iter().zip(selene_generators())")
        .expect("ordered canonical generator prefix");
    let borrowed_push = private_hash
        .find("terms.push(scalar, generator)?")
        .expect("borrowed secret term insertion");
    let evaluate = private_hash
        .find("let point = terms.evaluate()?")
        .expect("complete secret multiexponentiation");
    let result_owner = private_hash
        .find("Ok(ProverSecretPointV1::from_secret(point))")
        .expect("controlled transfer into the next move-only owner");
    assert!(
        width < exact_capacity
            && exact_capacity < builder
            && builder < initializer
            && initializer < ordered_generators
            && ordered_generators < borrowed_push
            && borrowed_push < evaluate
            && evaluate < result_owner
    );
    for forbidden in [
        ".fold(",
        "generator.mul(*scalar)",
        "hash.add(",
        "terms.push(*scalar",
        "point.expose_copy()",
        "ProverSecretPointV1::take(&mut point)",
        ".transfer(",
    ] {
        assert!(!private_hash.contains(forbidden));
    }
    let release_fixture = source
        .split_once("pub fn fcmp_release_fixture_v1(")
        .expect("release fixture")
        .1
        .split_once("/// Build a maximum-shape fixture whose first canonical branch")
        .expect("release fixture boundary")
        .0;
    let private_call = release_fixture
        .find("prover_secret_hash_selene_v1")
        .expect("private initial hash call");
    let borrowed_x = release_fixture
        .find("prover_secret_selene_x_v1(&current_selene)?")
        .expect("secret-safe owned-point coordinate extraction");
    let next_owner = release_fixture
        .find("current_selene =\n                prover_secret_hash_selene_v1")
        .expect("later private hash returns an owner");
    assert!(private_call < borrowed_x && borrowed_x < next_owner);
    assert!(!release_fixture.contains("let mut next_selene = hash_selene(&[child])?"));
    assert!(!release_fixture.contains("hash_selene,\n    )?"));
    let field_source = include_str!("../field.rs");
    let public_hash = field_source
        .split_once("pub(super) fn hash_selene(")
        .expect("public Selene hash")
        .1
        .split_once("pub(super) fn hash_helios(")
        .expect("public Selene hash boundary")
        .0;
    assert!(public_hash.contains(".fold(selene_hash_initializer()"));
    assert!(public_hash.contains("hash.add(generator.mul(*scalar))"));
}
#[test]
fn rerandomization_constructor_takes_all_bytes_before_decoding() {
    let source = include_str!("../prover.rs");
    let support = source
        .split_once("static PROVER_ED25519_SCALAR_MODULUS_LE_V1: [u8; 32] = [")
        .expect("rerandomization scalar decoder support")
        .1
        .split_once("/// Caller-selected rerandomization witness")
        .expect("rerandomization scalar decoder support boundary")
        .0;
    let modulus = source
        .split_once("static PROVER_ED25519_SCALAR_MODULUS_LE_V1: [u8; 32] = [")
        .expect("little-endian scalar modulus")
        .1
        .split_once("];")
        .expect("scalar modulus boundary")
        .0;
    assert_eq!(
        modulus.split_whitespace().collect::<String>(),
        "0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,"
    );
    for forbidden in [
        "#[derive(",
        "impl Clone",
        "impl Copy",
        "U256",
        "from_le_slice",
        "from_le_bytes",
        "callback",
        "FnOnce",
        "FnMut",
        "Deref",
    ] {
        assert!(!support.contains(forbidden), "retained support {forbidden}");
    }
    let comparison_owner = support
        .split_once("struct ProverSecretEdwardsCanonicalityStateV1 {")
        .expect("rerandomization canonicality owner")
        .1
        .split_once("struct ProverValidatedSecretEdwardsScalarEncodingV1<'a>(")
        .expect("rerandomization canonicality owner boundary")
        .0;
    source_order!(comparison_owner;
        "self.prefix_decided = self.less | self.greater",
        "self.prefix_equal = !self.prefix_decided",
        "self.byte_less = byte.ct_lt(modulus_byte)",
        "self.byte_greater = modulus_byte.ct_lt(byte)",
        "self.less_update = self.prefix_equal & self.byte_less",
        "self.greater_update = self.prefix_equal & self.byte_greater",
        "self.less |= self.less_update",
        "self.greater |= self.greater_update",
    );
    assert_eq!(comparison_owner.matches(".ct_lt(").count(), 2);
    assert!(!comparison_owner.contains("bool::from("));
    for field in [
        "less",
        "greater",
        "byte_less",
        "byte_greater",
        "prefix_decided",
        "prefix_equal",
        "less_update",
        "greater_update",
    ] {
        assert_eq!(
            comparison_owner
                .matches(&format!("\n    {field}: Choice,"))
                .count(),
            1,
            "missing comparison state {field}"
        );
        assert_eq!(
            comparison_owner
                .matches(&format!("self.{field} = Choice::from(0)"))
                .count(),
            1,
            "comparison state {field} is not cleared"
        );
        assert_eq!(
            comparison_owner
                .matches(&format!("black_box(&mut self.{field})"))
                .count(),
            1,
            "comparison state {field} is not pinned after clear"
        );
    }
    assert!(comparison_owner.contains("compiler_fence"));

    let validated_encoding = support
        .split_once("struct ProverValidatedSecretEdwardsScalarEncodingV1<'a>(&'a [u8; 32]);")
        .expect("validated secret scalar encoding")
        .1
        .split_once("struct ProverSecretEdwardsWideInputV1([u8; 64]);")
        .expect("validated secret scalar encoding boundary")
        .0;
    let validation_steps = [
        "fn validate_v1(bytes: &'a [u8; 32])",
        "let mut canonicality = ProverSecretEdwardsCanonicalityStateV1::new_v1()",
        "let mut index = PROVER_ED25519_SCALAR_MODULUS_LE_V1.len()",
        "while index != 0",
        "index -= 1",
        "let byte = &bytes[index]",
        "let modulus_byte = &PROVER_ED25519_SCALAR_MODULUS_LE_V1[index]",
        "canonicality.observe_byte_v1(byte, modulus_byte)",
        "let is_canonical = bool::from(canonicality.less)",
        "drop(canonicality)",
        "if !is_canonical",
        "Ok(Self(bytes))",
        "fn into_scalar_owner_v1(self)",
        "ProverSecretEdwardsWideInputV1::from_borrowed_v1(self.0)",
        "Scalar::from_bytes_mod_order_wide(&wide.0)",
        "drop(wide)",
        "ProverSecretCopyValueV1::take(&mut scalar)",
    ];
    let validation_positions = validation_steps
        .iter()
        .map(|needle| {
            validated_encoding
                .find(needle)
                .unwrap_or_else(|| panic!("missing validation step {needle}"))
        })
        .collect::<Vec<_>>();
    assert!(
        validation_positions
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    for (needle, expected) in [
        ("ProverSecretEdwardsCanonicalityStateV1::new_v1()", 1),
        ("PROVER_ED25519_SCALAR_MODULUS_LE_V1.len()", 1),
        ("canonicality.observe_byte_v1(byte, modulus_byte)", 1),
        ("bool::from(canonicality.less)", 1),
        ("drop(canonicality)", 1),
        (
            "ProverSecretEdwardsWideInputV1::from_borrowed_v1(self.0)",
            1,
        ),
        ("Scalar::from_bytes_mod_order_wide(&wide.0)", 1),
        ("drop(wide)", 1),
        ("ProverSecretCopyValueV1::take(&mut scalar)", 1),
    ] {
        assert_eq!(
            validated_encoding.matches(needle).count(),
            expected,
            "{needle}"
        );
    }
    for forbidden in [
        "#[derive(",
        "impl Clone",
        "impl Copy",
        "Deref",
        "fn expose_",
        "fn get",
        "fn as_",
        "fn with_",
        "callback",
        "FnOnce",
        "FnMut",
        ") -> [u8; 32]",
        ") -> Scalar",
        "Result<Scalar",
        ".expose_copy()",
        ".clone()",
        ".to_owned()",
    ] {
        assert!(
            !validated_encoding.contains(forbidden),
            "retained validated encoding {forbidden}"
        );
    }

    let wide_owner = support
        .split_once("struct ProverSecretEdwardsWideInputV1([u8; 64]);")
        .expect("rerandomization wide-input owner")
        .1
        .split_once("fn prover_secret_decode_nonzero_edwards_scalar_v1(")
        .expect("rerandomization wide-input owner boundary")
        .0;
    assert!(wide_owner.contains("fn from_borrowed_v1(bytes: &[u8; 32]) -> Self"));
    assert!(wide_owner.contains("let mut wide = Self([0_u8; 64])"));
    assert!(wide_owner.contains("wide.0[..32].copy_from_slice(bytes)"));
    assert!(wide_owner.contains("self.0.zeroize()"));
    assert!(wide_owner.contains("compiler_fence"));
    assert!(wide_owner.contains("black_box"));
    for owner in [comparison_owner, wide_owner] {
        for forbidden in [
            "fn expose_",
            "fn get",
            "fn as_",
            "fn with_",
            "callback",
            "FnOnce",
            "FnMut",
            "Deref",
        ] {
            assert!(!owner.contains(forbidden), "retained owner {forbidden}");
        }
    }

    let decoder = source
        .split_once("fn prover_secret_decode_nonzero_edwards_scalar_v1(")
        .expect("rerandomization secret scalar decoder")
        .1
        .split_once("/// Caller-selected rerandomization witness")
        .expect("rerandomization secret scalar decoder boundary")
        .0;
    let decoder_steps = [
        "bytes: &[u8; 32]",
        "ProverValidatedSecretEdwardsScalarEncodingV1::validate_v1(bytes)?",
        ".into_scalar_owner_v1()",
        "let is_zero = bool::from(scalar.expose_ref().ct_eq(&Scalar::ZERO))",
        "if is_zero",
        "Ok(scalar)",
    ];
    let decoder_positions = decoder_steps
        .iter()
        .map(|needle| {
            decoder
                .find(needle)
                .unwrap_or_else(|| panic!("missing decoder step {needle}"))
        })
        .collect::<Vec<_>>();
    assert!(decoder_positions.windows(2).all(|pair| pair[0] < pair[1]));
    for (needle, expected) in [
        (
            "ProverValidatedSecretEdwardsScalarEncodingV1::validate_v1(bytes)?",
            1,
        ),
        (".into_scalar_owner_v1()", 1),
        ("bool::from(", 1),
        ("scalar.expose_ref().ct_eq(&Scalar::ZERO)", 1),
    ] {
        assert_eq!(decoder.matches(needle).count(), expected, "{needle}");
    }
    for forbidden in [
        "bytes: [u8; 32]",
        "validate_edwards_scalar",
        "Scalar::from_canonical_bytes",
        "CtOption",
        "Option::<Scalar>",
        ".filter(",
        "*bytes",
        "U256",
        "from_le_slice",
        "from_le_bytes",
        ".expose_copy()",
        ".clone()",
        ".to_owned()",
        "callback",
        "FnOnce",
        "Deref",
        "Result<Scalar",
    ] {
        assert!(!decoder.contains(forbidden), "retained decoder {forbidden}");
    }

    let constructor = source
        .split_once("impl FcmpInputRerandomizationV1 {")
        .expect("rerandomization impl")
        .1
        .split_once("#[cfg(test)]\n    fn duplicate_for_test")
        .expect("constructor boundary")
        .0;
    assert_eq!(
        constructor
            .matches("ProverSecretCopyValueV1::take(&mut")
            .count(),
        4
    );
    assert_eq!(
        constructor
            .matches(": ProverSecretCopyValueV1<[u8; 32]>")
            .count(),
        4
    );
    assert!(constructor.contains("fn from_rerandomization_secret_byte_owners_v1("));
    let last_take = constructor
        .rfind("ProverSecretCopyValueV1::take(&mut")
        .expect("last input take");
    let first_decode = constructor
        .find("prover_secret_decode_nonzero_edwards_scalar_v1(")
        .expect("first owned decoder call");
    assert!(last_take < first_decode);
    assert_eq!(
        constructor
            .matches("prover_secret_decode_nonzero_edwards_scalar_v1(")
            .count(),
        4
    );
    let last_scalar = constructor
        .rfind("prover_secret_decode_nonzero_edwards_scalar_v1(")
        .expect("last decoded owner");
    let destination = constructor
        .find("let mut rerandomization = Self {")
        .expect("zeroed final destination");
    let output_swap = constructor
        .find("core::mem::swap(&mut rerandomization.output, &mut output_scalar.0)")
        .expect("output owner transfer");
    let output_drop = constructor
        .find("drop(output_scalar)")
        .expect("output source clear");
    let linking_swap = constructor
        .find("core::mem::swap(&mut rerandomization.linking, &mut linking_scalar.0)")
        .expect("linking owner transfer");
    let linking_drop = constructor
        .find("drop(linking_scalar)")
        .expect("linking source clear");
    let blind_swap = constructor
        .find("&mut rerandomization.rerandomization_blind")
        .expect("rerandomization-blind owner transfer");
    let blind_drop = constructor
        .find("drop(rerandomization_blind_scalar)")
        .expect("rerandomization-blind source clear");
    let commitment_swap = constructor
        .find("&mut rerandomization.commitment")
        .expect("commitment owner transfer");
    let commitment_drop = constructor
        .find("drop(commitment_scalar)")
        .expect("commitment source clear");
    let returned = constructor
        .find("Ok(rerandomization)")
        .expect("final owner return");
    assert!(
        first_decode < last_scalar
            && last_scalar < destination
            && destination < output_swap
            && output_swap < output_drop
            && output_drop < linking_swap
            && linking_swap < linking_drop
            && linking_drop < blind_swap
            && blind_swap < blind_drop
            && blind_drop < commitment_swap
            && commitment_swap < commitment_drop
            && commitment_drop < returned
    );
    assert_eq!(constructor.matches("core::mem::swap(").count(), 4);
    assert_eq!(constructor.matches("drop(").count(), 4);
    for zeroed_field in [
        "output: Scalar::ZERO",
        "linking: Scalar::ZERO",
        "rerandomization_blind: Scalar::ZERO",
        "commitment: Scalar::ZERO",
    ] {
        assert!(constructor.contains(zeroed_field));
    }
    assert!(!constructor.contains("output_scalar.expose_copy()"));
    assert!(!constructor.contains("linking_scalar.expose_copy()"));
    assert!(!constructor.contains("rerandomization_blind_scalar.expose_copy()"));
    assert!(!constructor.contains("commitment_scalar.expose_copy()"));
    assert!(!constructor.contains(".expose_copy()"));
    assert!(!constructor.contains("callback"));
    assert!(!constructor.contains("FnOnce"));
    assert!(!constructor.contains("Zeroizing::new(output)"));
    assert!(!constructor.contains("output: decode("));
    for forbidden in [
        "let decode =",
        "validate_edwards_scalar",
        "Scalar::from_canonical_bytes",
        "CtOption",
        "Option::<Scalar>",
        ".filter(",
        "*bytes",
        "ProverSecretCopyValueV1::new(decode(",
    ] {
        assert!(!constructor.contains(forbidden), "retained {forbidden}");
    }
    let lifecycle = source
        .split_once("impl Zeroize for FcmpInputRerandomizationV1")
        .expect("rerandomization zeroize")
        .1
        .split_once("impl core::fmt::Debug for FcmpInputRerandomizationV1")
        .expect("rerandomization lifecycle boundary")
        .0;
    assert_eq!(lifecycle.matches(".zeroize()").count(), 5);
    assert!(lifecycle.contains("impl Drop for FcmpInputRerandomizationV1"));
    assert!(lifecycle.contains("self.zeroize();"));
}
fn spendable_output(
    x: Scalar,
    y: Scalar,
    linking: Scalar,
    commitment: Scalar,
) -> FcmpOutputTupleV1 {
    fcmp_fixture_spendable_output_from_scalars_v1(x, y, linking, TEST_AMOUNT, commitment)
        .expect("valid output")
        .0
}
fn output_opening(
    output_key: u64,
    linking: u64,
    amount: u64,
    mask: u64,
) -> FcmpOutputCommitmentOpeningV1 {
    fcmp_fixture_output_opening_v1(output_key, linking, amount, mask).expect("valid output opening")
}
fn rerandomization(
    output: u64,
    linking: u64,
    blind: u64,
    commitment: u64,
) -> FcmpInputRerandomizationV1 {
    fcmp_fixture_rerandomization_v1(output, linking, blind, commitment)
        .expect("canonical test rerandomization")
}
fn one_layer_fixture() -> (
    FcmpProverInputV1,
    FcmpOutputCommitmentOpeningV1,
    FcmpTreeRootV1,
) {
    let (mut inputs, mut outputs, root) =
        fcmp_release_fixture_v1(false).expect("one-layer release fixture");
    assert_eq!(inputs.len(), 1);
    assert_eq!(outputs.len(), 1);
    (inputs.remove(0), outputs.remove(0), root)
}
fn maximum_bound_fixture() -> (
    Vec<FcmpProverInputV1>,
    Vec<FcmpOutputCommitmentOpeningV1>,
    FcmpTreeRootV1,
) {
    fcmp_release_fixture_v1(true).expect("maximum-bound release fixture")
}
#[path = "tests/commitment_mask.rs"]
mod commitment_mask;
#[path = "tests/runtime.rs"]
mod runtime;
