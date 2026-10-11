//! The step statement encoding (the G1 wallet statement field encoding of
//! split lineage) and the canonical limb encodings of spec S6:
//!
//! - the in-circuit statement digest equals the native
//!   `StatementV1::digest` on both parities and both steps (the relation
//!   identity is two witness cells; the lineage inputs of a Send are cells,
//!   those of a Receive the constant zero);
//! - the native and the in-circuit encodings reproduce the G1 statement
//!   vectors of `fixtures/kagemusha/wallet_v1_vectors.json` (element lists
//!   and digests);
//! - foreign limbs go through the canonical S6 encoding: values at or above
//!   the foreign modulus are unsatisfiable, so `s >= p` cannot pass as
//!   `s mod p`;
//! - a word of the circuit's own field decomposes only into its canonical
//!   limbs (the halves of its canonical encoding);
//! - the tamper suites and the inventory (14 folded blocks; 4 range checks
//!   per canonical value).

mod common;

use common::{
    Chips, GadgetCircuit, Inputs, RANGE_COLUMN, Shape, accepts, assigned, extent, lane_columns,
    report,
};
use ff::{Field as _, PrimeField};
use iroha_pasta::{Fp, Fq, PastaField, poseidon::PoseidonField};
use iroha_plonk::{
    check::{CheckFailure, CheckMode, check_circuit},
    frontend::{Error, Region, configure, synthesize},
};
use iroha_plonk_gadgets::{
    MAX_GATE_DEGREE, UintChip, Word,
    cells::low_u128,
    poseidon::ROWS_PER_PERMUTATION,
    statement::{
        EFFECT_UNION_FIELDS, STATEMENT_DOMAIN, STATEMENT_FIELDS, StatementCells, StatementV1,
        StepRelation, assign_canonical_limbs, assign_foreign_scalar, bytes_to_limbs, digest_fields,
        foreign_limbs, foreign_value_native, limb_fields, statement_digest,
    },
    tamper::{Tamper, assigned_advice_cells, check_tampered},
};

/// Plain statement fields before the lineage inputs and the effect:
/// relation identity (2), scheme (2), asset (2), credential (2), lifecycle,
/// sequence, `next_load`, predecessor, successor, enabled-controls mask.
const PLAIN: usize = 13;
/// `k` of the statement circuits (14 folded blocks, 9-bit limbs).
const K: u32 = 10;
/// The relation identity of the sample statements.
const RELATION_ID: [u8; 32] = *b"gadget-test-relation-identity-01";

/// The lineage inputs (`burned_total`, pending-outgoing root) of `step`.
const fn lineage_fields(step: StepRelation) -> usize {
    match step {
        StepRelation::Send => 2,
        StepRelation::Receive => 0,
    }
}

/// The step of program argument 0 (0 Send, 1 Receive).
fn step_of(inputs: &Inputs<impl Copy>) -> StepRelation {
    if inputs.arg(0) == 0 {
        StepRelation::Send
    } else {
        StepRelation::Receive
    }
}

/// Inputs: the plain fields, the lineage inputs (Send), then the effect
/// (`arg 1` fields).
fn statement_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let step = step_of(inputs);
    let effect = usize::try_from(inputs.arg(1)).map_err(|_| Error::Synthesis)?;
    let lineage = lineage_fields(step);
    let values = (0..PLAIN + lineage + effect)
        .map(|i| inputs.get(i))
        .collect::<Vec<_>>();
    let words = chips.glue.witnesses(region, &values)?;
    let cells = StatementCells {
        relation_id: [&words[0], &words[1]],
        scheme_id: [&words[2], &words[3]],
        asset_digest: [&words[4], &words[5]],
        credential_digest: &words[6],
        lifecycle: &words[7],
        sequence: &words[8],
        next_load: &words[9],
        predecessor: &words[10],
        successor: &words[11],
        enabled_controls: &words[12],
        lineage_burned_total: (lineage > 0).then(|| &words[PLAIN]),
        lineage_pending_outgoing_root: (lineage > 0).then(|| &words[PLAIN + 1]),
        effect: &words[PLAIN + lineage..],
    };
    Ok(vec![statement_digest(
        &mut chips.sponges[0],
        region,
        step,
        &cells,
    )?])
}

/// A statement with distinct field values.
fn sample_statement<F: PoseidonField>(step: StepRelation, effect: usize) -> StatementV1<F> {
    let bytes = |seed: u8| {
        core::array::from_fn(|i| {
            seed.wrapping_mul(31)
                .wrapping_add(u8::try_from(i).unwrap_or(0))
        })
    };
    let send = step == StepRelation::Send;
    StatementV1 {
        relation_id: RELATION_ID,
        step,
        scheme_id: bytes(1),
        asset_digest: bytes(3),
        credential_digest: {
            let mut bytes = bytes(2);
            bytes[31] &= 0x3f;
            bytes
        },
        lifecycle: 1,
        sequence: (1 << 70) + 3,
        next_load: (1 << 90) + 5,
        enabled_controls: 0,
        lineage_burned_total: if send { 40 } else { 0 },
        lineage_pending_outgoing_root: if send { F::from(1_000_003u64) } else { F::ZERO },
        predecessor: F::from(0xdead_beef_u64),
        successor: -F::from(77u64),
        effect: (0..effect).map(|i| F::from(100 + i as u64)).collect(),
    }
}

/// The circuit of `statement` and its public digest.
fn circuit<F: PoseidonField>(statement: &StatementV1<F>) -> (GadgetCircuit<F>, Vec<F>) {
    let mut inputs = Vec::new();
    for bytes in [
        &statement.relation_id,
        &statement.scheme_id,
        &statement.asset_digest,
    ] {
        inputs.extend(digest_fields::<F>(bytes));
    }
    inputs.push(
        iroha_plonk_gadgets::statement::canonical_field::<F>(&statement.credential_digest)
            .expect("canonical digest"),
    );
    inputs.extend([
        F::from(u64::from(statement.lifecycle)),
        F::from_u128(statement.sequence),
        F::from_u128(statement.next_load),
        statement.predecessor,
        statement.successor,
        F::from(u64::from(statement.enabled_controls)),
    ]);
    if statement.step == StepRelation::Send {
        inputs.extend([
            F::from_u128(statement.lineage_burned_total),
            statement.lineage_pending_outgoing_root,
        ]);
    }
    inputs.extend(statement.effect.iter().copied());
    let step = u64::from(statement.step == StepRelation::Receive);
    let effect = u64::try_from(statement.effect.len()).expect("effect length");
    let shape = Shape::new(1, 9, 1)
        .with_args(&[step, effect])
        .folding(&[(STATEMENT_DOMAIN, STATEMENT_FIELDS)]);
    let digest = statement.digest().expect("at most 9 effect fields");
    (
        GadgetCircuit::new(shape, statement_program::<F>, inputs),
        vec![digest],
    )
}

fn digests_match<F: PoseidonField>() {
    for (step, effect) in [(StepRelation::Send, 9), (StepRelation::Receive, 4)] {
        let statement = sample_statement::<F>(step, effect);
        let (honest, public) = circuit::<F>(&statement);
        assert!(
            accepts(&honest, K, &public),
            "{}",
            report(&honest, K, &public)
        );
        let mut wrong = public.clone();
        wrong[0] += F::ONE;
        assert!(!accepts(&honest, K, &wrong));
        // Every statement field is bound by the digest.
        let mut other = statement.clone();
        other.lineage_burned_total += 1;
        if step == StepRelation::Send {
            assert_ne!(other.digest(), statement.digest());
        }
        other = statement.clone();
        other.relation_id[0] ^= 1;
        assert_ne!(other.digest(), statement.digest());
        // The relation identity is a witness: the same circuit proves the
        // statement of another relation identity only under its digest.
        let (relabelled, relabelled_public) = circuit::<F>(&other);
        assert!(accepts(&relabelled, K, &relabelled_public));
        assert!(!accepts(&relabelled, K, &public));
        other = statement.clone();
        other.next_load += 1;
        assert_ne!(other.digest(), statement.digest());
    }
}

#[test]
fn in_circuit_digest_equals_the_native_statement_digest() {
    digests_match::<Fp>();
    digests_match::<Fq>();
}

/// Inputs: the two limbs (`lo`, `hi`) of a value of the foreign field `G`;
/// the outputs are the checked limbs.
fn foreign_program<F: PoseidonField, G: PastaField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let limbs = inputs
        .get(0)
        .zip(inputs.get(1))
        .map(|(lo, hi)| [low_u128(&lo), low_u128(&hi)]);
    let mut uint = UintChip::new(&mut chips.glue, &mut chips.range);
    let scalar = assign_foreign_scalar::<F, G>(&mut uint, region, limbs)?;
    Ok(scalar.words().map(Clone::clone).to_vec())
}

/// The foreign-scalar circuit of `limbs` and its public limbs.
fn foreign_circuit<F: PoseidonField, G: PastaField>(
    limbs: [u128; 2],
) -> (GadgetCircuit<F>, Vec<F>) {
    let public = limb_fields::<F>(limbs).to_vec();
    (
        GadgetCircuit::new(Shape::new(1, 9, 2), foreign_program::<F, G>, public.clone()),
        public,
    )
}

/// Whether the strict check fails, and only through range lookups.
fn only_range_failures<F: PoseidonField>(circuit: &GadgetCircuit<F>, public: &[F]) -> bool {
    let report = check_circuit(circuit, K, &[public.to_vec()], CheckMode::Strict).expect("check");
    !report.is_satisfied()
        && report
            .failures()
            .iter()
            .all(|failure| matches!(failure, CheckFailure::LookupInputMissing { .. }))
}

fn non_canonical_limbs_are_unsatisfiable<F: PoseidonField, G: PastaField>() {
    let [max_lo, max_hi] = foreign_limbs(&-G::ONE);
    // The modulus itself, the modulus + 5 (whose reduction is 5: `s >= p`
    // passed in place of `s mod p`), a high limb above the modulus's, and a
    // high limb of 2^127.
    for limbs in [
        [max_lo + 1, max_hi],
        [max_lo + 6, max_hi],
        [0, max_hi + 1],
        [u128::MAX, max_hi],
        [0, 1 << 127],
    ] {
        assert_eq!(foreign_value_native::<G>(limbs), None);
        let (circuit, public) = foreign_circuit::<F, G>(limbs);
        assert!(only_range_failures(&circuit, &public), "limbs {limbs:x?}");
    }
    // The largest canonical value and a small one are accepted.
    for limbs in [[max_lo, max_hi], foreign_limbs(&G::from(5u64))] {
        let (circuit, public) = foreign_circuit::<F, G>(limbs);
        assert!(
            accepts(&circuit, K, &public),
            "{}",
            report(&circuit, K, &public)
        );
    }
}

#[test]
fn s6_non_canonical_foreign_limbs_are_unsatisfiable() {
    non_canonical_limbs_are_unsatisfiable::<Fp, Fq>();
    non_canonical_limbs_are_unsatisfiable::<Fq, Fp>();
}

/// Input: a value of the circuit's own field; the outputs are its canonical
/// limbs.
fn canonical_program<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let value = chips.glue.witness(region, inputs.get(0))?;
    let mut uint = UintChip::new(&mut chips.glue, &mut chips.range);
    let scalar = assign_canonical_limbs(&mut uint, region, &value)?;
    Ok(scalar.words().map(Clone::clone).to_vec())
}

/// The canonical-limbs circuit of `value` and its public limbs.
fn canonical_circuit<F: PoseidonField>(value: F) -> (GadgetCircuit<F>, Vec<F>) {
    (
        GadgetCircuit::new(Shape::new(1, 9, 2), canonical_program::<F>, vec![value]),
        limb_fields::<F>(foreign_limbs(&value)).to_vec(),
    )
}

fn canonical_limbs_decompose<F: PoseidonField + PrimeField<Repr = [u8; 32]>>() {
    for value in [F::ZERO, F::ONE, -F::ONE, F::from(0xdead_beef_u64).square()] {
        let (circuit, public) = canonical_circuit(value);
        assert!(
            accepts(&circuit, K, &public),
            "{}",
            report(&circuit, K, &public)
        );
        // The limbs are the halves of the canonical 32-byte encoding.
        assert_eq!(
            public,
            limb_fields::<F>(bytes_to_limbs(&value.to_repr())).to_vec()
        );
        // Claimed limbs of another value are rejected.
        let mut wrong = public.clone();
        wrong[1] += F::ONE;
        assert!(!accepts(&circuit, K, &wrong));
    }
}

#[test]
fn own_field_words_decompose_into_their_canonical_limbs() {
    canonical_limbs_decompose::<Fp>();
    canonical_limbs_decompose::<Fq>();
}

#[test]
fn an_effect_longer_than_9_fields_is_an_error() {
    let statement = sample_statement::<Fp>(StepRelation::Send, EFFECT_UNION_FIELDS + 1);
    assert_eq!(statement.digest(), None);
    let short = sample_statement::<Fp>(StepRelation::Send, EFFECT_UNION_FIELDS);
    let (mut circuit, public) = circuit::<Fp>(&short);
    circuit.shape.args[1] = 10;
    circuit.inputs.push(Fp::ONE);
    assert_eq!(
        synthesize(&circuit, K, Some(&[public][..])).map(|_| ()),
        Err(Error::Synthesis)
    );
}

#[test]
fn inventory_14_blocks_and_the_s6_checks() {
    let statement = sample_statement::<Fp>(StepRelation::Receive, 4);
    let (circuit, public) = circuit::<Fp>(&statement);
    let flags = assigned(&circuit, K, &public);
    // The folded statement digest: 14 blocks.
    assert_eq!(
        extent(&flags[lane_columns(0)[0]]),
        14 * ROWS_PER_PERMUTATION
    );
    assert_eq!(extent(&flags[RANGE_COLUMN]), 0);
    // A canonical value: four range checks (lo 128, hi 127, the bound of
    // hi 127, the conditional bound of lo 128) of 16 rows at b = 9.
    let (canonical, limbs) = canonical_circuit(-Fp::ONE);
    let flags = assigned(&canonical, K, &limbs);
    assert_eq!(extent(&flags[RANGE_COLUMN]), 4 * 16);
    // Every gate of the composite circuit keeps the degree policy, and the
    // circuit degree (lookups included) is exactly the policy bound.
    let (cs, _) = configure(&circuit).expect("configure");
    for gate in cs.gates() {
        for poly in gate.polynomials() {
            assert!(poly.degree() <= MAX_GATE_DEGREE, "gate {}", gate.name());
        }
    }
    assert_eq!(cs.degree(), MAX_GATE_DEGREE);
}

/// Tampers `cells`; returns those the checker accepted.
fn undetected<F: PoseidonField>(
    circuit: &GadgetCircuit<F>,
    public: &[F],
    cells: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    cells
        .iter()
        .copied()
        .filter(|(column, row)| {
            let tamper = Tamper {
                column: *column,
                row: *row,
                delta: F::ONE,
            };
            check_tampered(circuit, K, &[public.to_vec()], Some(tamper))
                .expect("check")
                .is_satisfied()
        })
        .collect()
}

#[test]
fn glue_and_boundary_lane_cells_are_pinned() {
    // Every glue cell, and every lane cell of the first and last blocks (the
    // lane suites tamper every block of smaller sponges).
    let statement = sample_statement::<Fq>(StepRelation::Send, 9);
    let (circuit, public) = circuit::<Fq>(&statement);
    let lane = lane_columns(0);
    let cells = assigned_advice_cells(&circuit, K, std::slice::from_ref(&public))
        .expect("cells")
        .into_iter()
        .filter(|(column, row)| {
            !lane.contains(column)
                || *row < ROWS_PER_PERMUTATION
                || *row >= 13 * ROWS_PER_PERMUTATION
        })
        .collect::<Vec<_>>();
    assert_eq!(undetected(&circuit, &public, &cells), Vec::new());
}

#[test]
fn every_canonical_limb_cell_is_pinned() {
    for value in [-Fp::ONE, Fp::from(12_345u64)] {
        let (circuit, public) = canonical_circuit(value);
        let cells =
            assigned_advice_cells(&circuit, K, std::slice::from_ref(&public)).expect("cells");
        assert_eq!(undetected(&circuit, &public, &cells), Vec::new());
    }
}

#[test]
#[ignore = "every cell of the 14-block statement circuit; run in release"]
fn every_statement_cell_is_pinned() {
    let statement = sample_statement::<Fp>(StepRelation::Receive, 4);
    let (circuit, public) = circuit::<Fp>(&statement);
    let cells = assigned_advice_cells(&circuit, K, std::slice::from_ref(&public)).expect("cells");
    assert_eq!(undetected(&circuit, &public, &cells), Vec::new());
}

/// Little-endian unsigned integer of `bytes` (at most 16 bytes).
fn le_u128(bytes: &[u8]) -> u128 {
    bytes
        .iter()
        .rev()
        .fold(0_u128, |value, byte| (value << 8) | u128::from(*byte))
}

/// Bytes of a lowercase hex string.
fn hex_bytes(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "even hex length");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex digit"))
        .collect()
}

/// The canonical field value of a 32-byte little-endian encoding.
fn field_of(bytes: [u8; 32]) -> Fp {
    Option::from(Fp::from_repr(bytes)).expect("canonical field value")
}

/// Decode the current G1 field-only statement vector without a retired byte transcript.
fn statement_of_items(items: &[[u8; 32]]) -> StatementV1<Fp> {
    assert_eq!(items.len(), STATEMENT_FIELDS);
    let integer = |i: usize| le_u128(&items[i][..16]);
    let digest = |i: usize| {
        let mut value = [0; 32];
        value[..16].copy_from_slice(&items[i][..16]);
        value[16..].copy_from_slice(&items[i + 1][..16]);
        value
    };
    let step = match integer(16) {
        3 => StepRelation::Send,
        4 => StepRelation::Receive,
        tag => panic!("step {tag}"),
    };
    let effect_len = if step == StepRelation::Send { 9 } else { 4 };
    StatementV1 {
        relation_id: digest(1),
        step,
        scheme_id: digest(3),
        asset_digest: digest(5),
        credential_digest: items[7],
        lifecycle: u8::try_from(integer(8)).expect("lifecycle"),
        sequence: integer(9),
        next_load: integer(10),
        enabled_controls: u32::try_from(integer(11)).expect("mask"),
        lineage_burned_total: integer(12),
        lineage_pending_outgoing_root: field_of(items[13]),
        predecessor: field_of(items[14]),
        successor: field_of(items[15]),
        effect: items[17..17 + effect_len]
            .iter()
            .copied()
            .map(field_of)
            .collect(),
    }
}

/// Spec section 3.2: native and in-circuit encodings share vectors. The
/// statement element lists and digests that the G1 data model publishes in
/// `fixtures/kagemusha/wallet_v1_vectors.json` are exactly the gadget's
/// native encoding of the same statement transcripts, and the in-circuit
/// digest of those elements.
#[test]
fn the_native_and_in_circuit_encodings_reproduce_the_g1_statement_vectors() {
    use norito::json::Value;

    let path = common::repo_root().join("fixtures/kagemusha/wallet_v1_vectors.json");
    let text = std::fs::read_to_string(&path).expect("read wallet_v1_vectors.json");
    let fixture = norito::json::parse_value(&text).expect("parse wallet_v1_vectors.json");
    let encodings = fixture
        .get("field_encodings")
        .expect("field_encodings section");
    let domain = encodings
        .get("domains")
        .and_then(Value::as_array)
        .expect("domains")
        .iter()
        .find(|row| row.get("use").and_then(Value::as_str) == Some("statement"))
        .and_then(|row| row.get("ascii"))
        .and_then(Value::as_str)
        .expect("statement domain");
    assert_eq!(domain.as_bytes(), STATEMENT_DOMAIN.to_le_bytes());
    for (name, step) in [
        ("send_statement", StepRelation::Send),
        ("receive_statement", StepRelation::Receive),
    ] {
        let vector = encodings.get(name).expect(name);
        let text = |key: &str| vector.get(key).and_then(Value::as_str).expect(key);
        let items = vector
            .get("items")
            .and_then(Value::as_array)
            .expect("items")
            .iter()
            .map(|item| {
                hex_bytes(item.as_str().expect("item hex"))
                    .try_into()
                    .expect("32-byte item")
            })
            .collect::<Vec<[u8; 32]>>();
        assert_eq!(items.len(), STATEMENT_FIELDS, "{name}");
        let statement = statement_of_items(&items);
        assert_eq!(statement.step, step, "{name}");
        let encoded = statement.encode().expect("at most 9 effect fields");
        let encoded = encoded
            .iter()
            .map(PrimeField::to_repr)
            .collect::<Vec<[u8; 32]>>();
        assert_eq!(encoded, items, "{name}");
        let digest = field_of(
            hex_bytes(text("digest_hex"))
                .try_into()
                .expect("32-byte digest"),
        );
        assert_eq!(statement.digest(), Some(digest), "{name}");
        // The in-circuit digest of the same statement is the vector's.
        let (in_circuit, public) = circuit::<Fp>(&statement);
        assert_eq!(public, vec![digest], "{name}");
        assert!(
            accepts(&in_circuit, K, &public),
            "{name}: {}",
            report(&in_circuit, K, &public)
        );
        // The digest binds the relation identity the transcript carries.
        let mut other = statement.clone();
        other.relation_id[0] ^= 1;
        assert_ne!(other.digest(), statement.digest(), "{name}");
    }
}
