//! Whole-entry parity against real canonical model frames and atomic failure cases.

use super::*;
use crate::fastpq::{
    poseidon_preimage_digest,
    quantity_statement::quantity_statement_frame_len_from_finalized_transcripts,
};
use fastpq_prover::gadgets::public_transfer_statement::PublicTransferLimits;
use iroha_data_model::{asset::AssetDefinitionId, fastpq::TransferSmtWitness};
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Numeric;
use iroha_test_samples::{ALICE_ID, BOB_ID};

fn limits() -> FastpqSourceStatementBuildLimits {
    FastpqSourceStatementBuildLimits {
        max_executed_entries: 1,
        max_transcripts: 1024,
        max_deltas: 4096,
        max_input_transcript_bytes: 8_000_000,
        max_statement_bytes: 8_000_000,
        max_total_statement_bytes: 8_000_000,
    }
}

fn hash() -> Hash {
    Hash::new(b"complete entry framing")
}

fn quantity(mantissa: u32, scale: u32) -> Quantity {
    Quantity::try_from_numeric(Numeric::new(mantissa, scale)).unwrap()
}

fn delta(scale: u32, reverse: bool) -> TransferDeltaTranscript {
    let amount = quantity(1, scale);
    let sender = Quantity::from(100_u32);
    let receiver = Quantity::from(2_u32);
    TransferDeltaTranscript {
        from_account: if reverse {
            (*BOB_ID).clone()
        } else {
            (*ALICE_ID).clone()
        },
        to_account: if reverse {
            (*ALICE_ID).clone()
        } else {
            (*BOB_ID).clone()
        },
        asset_definition: AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            if reverse { "lily" } else { "rose" }.parse().unwrap(),
        ),
        from_balance_after: sender.try_sub(&amount).unwrap(),
        to_balance_after: receiver.try_add(&amount).unwrap(),
        amount,
        from_balance_before: sender,
        to_balance_before: receiver,
        from_smt_witness: TransferSmtWitness::default(),
        to_smt_witness: TransferSmtWitness::default(),
    }
}

fn transcript(deltas: Vec<TransferDeltaTranscript>, authority: u8) -> TransferTranscript {
    TransferTranscript {
        batch_hash: hash(),
        authority_digest: Hash::new([authority]),
        // Only digest presence belongs to framing. Most tests deliberately use
        // an unvalidated value to avoid confusing byte parity with proof validity.
        poseidon_preimage_digest: (deltas.len() == 1).then_some(Hash::new([authority, 7])),
        deltas,
    }
}

fn statement(bundle: &[TransferTranscript]) -> FastpqPublicTransferStatementV1 {
    let mut transitions = Vec::new();
    for transcript in bundle {
        for delta in &transcript.deltas {
            for (account, before, after) in [
                (
                    &delta.from_account,
                    &delta.from_balance_before,
                    &delta.from_balance_after,
                ),
                (
                    &delta.to_account,
                    &delta.to_balance_before,
                    &delta.to_balance_after,
                ),
            ] {
                let encode = |value| {
                    encode_quantity_units_v1(
                        &FastpqQuantityUnits::from_quantity(value, MAX_DECIMAL_SCALE).unwrap(),
                    )
                    .unwrap()
                };
                transitions.push(FastpqStateTransition {
                    key: transfer_balance_key(&delta.asset_definition, account).unwrap(),
                    pre_value: encode(before),
                    post_value: encode(after),
                    operation: FastpqOperationKind::Transfer,
                });
            }
        }
    }
    // Canonical full model serialization is the independent oracle. Actual
    // original quantities and identities are encoded; no sizing helpers or
    // fabricated serialized-length inputs are used here.
    FastpqPublicTransferStatementV1 {
        public_inputs: FastpqPublicInputs {
            dsid: [19; 16],
            slot: u64::MAX,
            old_root: [23; 32],
            new_root: [42; 32],
            perm_root: [11; 32],
            tx_set_hash: [71; 32],
        },
        ordering_hash: [37; 32],
        transitions,
        transcripts: bundle
            .iter()
            .map(FastpqPublicTransferTranscriptV1::from)
            .collect(),
    }
}

fn reference(bundle: &[TransferTranscript]) -> FastpqSourceTranscriptUsage {
    let bytes = if bundle.is_empty() {
        0
    } else {
        norito::encode_canonical(&statement(bundle)).unwrap().len()
    };
    FastpqSourceTranscriptUsage {
        transcripts: bundle.len(),
        deltas: bundle
            .iter()
            .map(|transcript| transcript.deltas.len())
            .sum(),
        input_transcript_bytes: bundle
            .iter()
            .map(|transcript| norito::encode_canonical(transcript).unwrap().len())
            .sum(),
        max_statement_bytes: bytes,
        total_statement_bytes: bytes,
    }
}

fn snapshot(sizer: &SourceEntryFrameSizer) -> (FastpqSourceTranscriptUsage, usize, usize) {
    (sizer.usage(), sizer.rows_bytes, sizer.transcripts_bytes)
}

#[test]
fn empty_entry_has_no_synthetic_frame_and_keeps_its_separate_entry_bound() {
    let zero = FastpqSourceStatementBuildLimits {
        max_executed_entries: 1,
        max_transcripts: 0,
        max_deltas: 0,
        max_input_transcript_bytes: 0,
        max_statement_bytes: 0,
        max_total_statement_bytes: 0,
    };
    assert_eq!(
        measure_fastpq_source_entry_frame_usage(hash(), &[], zero).unwrap(),
        reference(&[])
    );
    assert!(
        SourceEntryFrameSizer::new(
            hash(),
            FastpqSourceStatementBuildLimits {
                max_executed_entries: 0,
                ..zero
            }
        )
        .is_err()
    );
    let mut sizer = SourceEntryFrameSizer::new(hash(), zero).unwrap();
    let before = snapshot(&sizer);
    assert!(sizer.append(&transcript(vec![delta(0, false)], 1)).is_err());
    assert_eq!(snapshot(&sizer), before);
}

#[test]
fn one_and_many_occurrences_match_whole_canonical_frames_with_distinct_facts() {
    let mut sizer = SourceEntryFrameSizer::new(hash(), limits()).unwrap();
    let mut bundle = Vec::new();
    for index in 0..40 {
        let deltas = (0..=(index % 3))
            .map(|offset| delta((index + offset) % 29, index % 2 == 1))
            .collect();
        bundle.push(transcript(
            deltas,
            u8::try_from(index).expect("fixture value fits u8"),
        ));
        let measured = sizer.append(bundle.last().unwrap()).unwrap();
        assert_eq!(measured, reference(&bundle), "occurrence {}", index + 1);
        let actual = statement(&bundle);
        assert_eq!(
            sizer.rows_bytes,
            norito::core::encoded_payload_len(&actual.transitions).unwrap()
        );
        assert_eq!(
            sizer.transcripts_bytes,
            norito::core::encoded_payload_len(&actual.transcripts).unwrap()
        );
    }
    assert!(sizer.rows_bytes > 16_384);
    let separately_framed: usize = bundle
        .iter()
        .map(|t| reference(std::slice::from_ref(t)).max_statement_bytes)
        .sum();
    assert_ne!(sizer.usage().max_statement_bytes, separately_framed);
    assert_eq!(
        sizer.usage().max_statement_bytes,
        sizer.usage().total_statement_bytes
    );
}

#[test]
fn same_entry_committed_and_pending_slices_are_measured_without_copying_or_double_framing() {
    let bundle = vec![
        transcript(vec![delta(0, false)], 1),
        transcript(vec![delta(28, true)], 2),
    ];
    let bytes = norito::encode_canonical(&bundle).unwrap();
    for split in 0..=bundle.len() {
        let measured = measure_fastpq_source_entry_frame_usage(
            hash(),
            bundle[..split].iter().chain(&bundle[split..]),
            limits(),
        )
        .unwrap();
        assert_eq!(measured, reference(&bundle));
    }
    assert_eq!(norito::encode_canonical(&bundle).unwrap(), bytes);
}

#[test]
fn actual_private_path_and_outer_field_boundaries_preserve_exact_parity() {
    for count in [1, 2, 127, 128] {
        let bundle: Vec<_> = (0..count)
            .map(|index| {
                transcript(
                    vec![delta(index % 29, false)],
                    u8::try_from(index).expect("fixture value fits u8"),
                )
            })
            .collect();
        assert_eq!(
            measure_fastpq_source_entry_frame_usage(hash(), &bundle, limits()).unwrap(),
            reference(&bundle)
        );
    }
    for path_bytes in [127, 128, 16_383, 16_384] {
        let mut d = delta(28, false);
        d.from_smt_witness.path_bits = vec![5; path_bytes];
        d.to_smt_witness.siblings = vec![[9; 32]; 128];
        let original = transcript(vec![delta(28, false)], 1);
        let changed = transcript(vec![d], 1);
        let a = measure_fastpq_source_entry_frame_usage(hash(), [&original], limits()).unwrap();
        let b = measure_fastpq_source_entry_frame_usage(hash(), [&changed], limits()).unwrap();
        assert!(b.input_transcript_bytes > a.input_transcript_bytes);
        assert_eq!(b.max_statement_bytes, a.max_statement_bytes);
        assert_eq!(b, reference(&[changed]));
    }
}

#[test]
fn exact_caps_accept_and_each_one_less_failure_preserves_the_previous_bundle() {
    let bundle = vec![
        transcript(vec![delta(0, false)], 1),
        transcript(vec![delta(28, true)], 2),
    ];
    let exact = reference(&bundle);
    let caps = FastpqSourceStatementBuildLimits {
        max_executed_entries: 1,
        max_transcripts: exact.transcripts,
        max_deltas: exact.deltas,
        max_input_transcript_bytes: exact.input_transcript_bytes,
        max_statement_bytes: exact.max_statement_bytes,
        max_total_statement_bytes: exact.total_statement_bytes,
    };
    assert_eq!(
        measure_fastpq_source_entry_frame_usage(hash(), &bundle, caps).unwrap(),
        exact
    );
    for dimension in 0..5 {
        let mut sizer = SourceEntryFrameSizer::new(hash(), limits()).unwrap();
        sizer.append(&bundle[0]).unwrap();
        let before = snapshot(&sizer);
        let mut low = caps;
        match dimension {
            0 => low.max_transcripts -= 1,
            1 => low.max_deltas -= 1,
            2 => low.max_input_transcript_bytes -= 1,
            3 => low.max_statement_bytes -= 1,
            _ => low.max_total_statement_bytes -= 1,
        }
        sizer.limits = low;
        assert!(sizer.append(&bundle[1]).is_err(), "dimension {dimension}");
        assert_eq!(snapshot(&sizer), before);
        sizer.limits = caps;
        assert_eq!(sizer.append(&bundle[1]).unwrap(), exact);
    }
}

#[test]
fn identity_empty_and_digest_presence_errors_are_atomic_but_digest_values_are_not_validated() {
    let first = transcript(vec![delta(0, false)], 1);
    let mut sizer = SourceEntryFrameSizer::new(hash(), limits()).unwrap();
    sizer.append(&first).unwrap();
    let before = snapshot(&sizer);
    let mut foreign = first.clone();
    foreign.batch_hash = Hash::new(b"foreign");
    let mut missing = first.clone();
    missing.poseidon_preimage_digest = None;
    let mut extra = transcript(vec![delta(0, false), delta(1, false)], 2);
    extra.poseidon_preimage_digest = Some(Hash::new(b"extra"));
    for bad in [foreign, missing, extra, transcript(Vec::new(), 3)] {
        assert!(sizer.append(&bad).is_err());
        assert_eq!(snapshot(&sizer), before);
    }
    let mut changed = first.clone();
    changed.poseidon_preimage_digest = Some(Hash::new(b"unvalidated digest value"));
    assert_eq!(
        sizer.append(&changed).unwrap(),
        reference(&[first, changed])
    );
}

#[test]
fn transfer_supply_changes_transfer_is_sized_without_weakening_strict_proof_preparation() {
    let first_delta = delta(0, false);
    let mut next_delta = delta(0, false);
    // After the first transfer sender=99 and receiver=3. Mint five sender
    // units and burn one receiver unit before the second unit transfer.
    next_delta.from_balance_before = Quantity::from(104_u32);
    next_delta.from_balance_after = Quantity::from(103_u32);
    next_delta.to_balance_before = Quantity::from(2_u32);
    next_delta.to_balance_after = Quantity::from(3_u32);
    let mut bundle = vec![
        transcript(vec![first_delta], 1),
        transcript(vec![next_delta], 2),
    ];
    for t in &mut bundle {
        t.poseidon_preimage_digest = Some(poseidon_preimage_digest(&t.deltas[0], &t.batch_hash));
    }
    assert_eq!(
        measure_fastpq_source_entry_frame_usage(hash(), &bundle, limits()).unwrap(),
        reference(&bundle)
    );
    assert!(
        quantity_statement_frame_len_from_finalized_transcripts(
            &bundle,
            PublicTransferLimits::default()
        )
        .is_err()
    );
    // A byte meter must not be mistaken for arithmetic validation either.
    bundle[1].deltas[0].from_balance_after = Quantity::from(999_u32);
    assert_eq!(
        measure_fastpq_source_entry_frame_usage(hash(), &bundle, limits()).unwrap(),
        reference(&bundle)
    );
}

#[test]
fn valid_bundle_agrees_with_the_strict_whole_entry_statement_measurement() {
    let mut first = transcript(vec![delta(0, false)], 1);
    first.poseidon_preimage_digest = Some(poseidon_preimage_digest(
        &first.deltas[0],
        &first.batch_hash,
    ));
    let mut next_delta = delta(0, false);
    next_delta.from_balance_before = first.deltas[0].from_balance_after.clone();
    next_delta.from_balance_after = Quantity::from(98_u32);
    next_delta.to_balance_before = first.deltas[0].to_balance_after.clone();
    next_delta.to_balance_after = Quantity::from(4_u32);
    let mut second = transcript(vec![next_delta], 2);
    second.poseidon_preimage_digest = Some(poseidon_preimage_digest(
        &second.deltas[0],
        &second.batch_hash,
    ));
    let bundle = [first, second];
    let measured = measure_fastpq_source_entry_frame_usage(hash(), &bundle, limits()).unwrap();
    assert_eq!(measured, reference(&bundle));
    assert_eq!(
        measured.max_statement_bytes,
        quantity_statement_frame_len_from_finalized_transcripts(
            &bundle,
            PublicTransferLimits::default()
        )
        .unwrap()
    );
}

#[test]
fn overflow_and_row_width_fail_before_replacing_any_counter() {
    let t = transcript(vec![delta(0, false)], 1);
    for dimension in 0..5 {
        let mut sizer = SourceEntryFrameSizer::new(hash(), limits()).unwrap();
        match dimension {
            0 => sizer.usage.transcripts = usize::MAX,
            1 => sizer.usage.deltas = (u32::MAX / 2) as usize,
            2 => sizer.usage.input_transcript_bytes = usize::MAX,
            3 => sizer.rows_bytes = usize::MAX,
            _ => sizer.transcripts_bytes = usize::MAX,
        }
        let before = snapshot(&sizer);
        assert!(sizer.append(&t).is_err(), "dimension {dimension}");
        assert_eq!(snapshot(&sizer), before);
    }
}

#[test]
fn canonical_framing_restores_ambient_layout_and_clone_only_restores_the_meter() {
    let bundle = [
        transcript(vec![delta(0, false)], 1),
        transcript(vec![delta(28, true)], 2),
    ];
    let expected = reference(&bundle);
    for flags in [0, header_flags::COMPACT_LEN] {
        let _ambient = DecodeFlagsGuard::enter(flags);
        let before = norito::core::encoded_payload_len(&vec![1_u32, 2]).unwrap();
        let mut sizer = SourceEntryFrameSizer::new(hash(), limits()).unwrap();
        sizer.append(&bundle[0]).unwrap();
        let checkpoint = sizer.clone();
        assert_eq!(sizer.append(&bundle[1]).unwrap(), expected);
        sizer = checkpoint;
        assert_eq!(sizer.usage(), reference(&bundle[..1]));
        assert_eq!(sizer.append(&bundle[1]).unwrap(), expected);
        assert_eq!(
            norito::core::encoded_payload_len(&vec![1_u32, 2]).unwrap(),
            before
        );
    }
}

// Exact captured corpus sizes from the real canonical encoder and the unchanged
// whole-entry meter (September 26). This is framing evidence, not release policy,
// transfer validity, authorization, retained-obligation admission or host capacity.
fn candidate_controller(members: usize, marker: u8) -> iroha_data_model::account::AccountId {
    use iroha_crypto::{Algorithm, PublicKey};
    use iroha_data_model::account::{
        AccountId,
        controller::{MultisigMember, MultisigPolicy},
    };
    let keys: Vec<_> = (0..members)
        .map(|index| {
            // This shape fixture needs no private key or PQC generation backend.
            // Use accepted fixed-length, nonzero ML-DSA public material.
            let mut material = vec![marker; 1_952];
            material[..8].copy_from_slice(&(index as u64).to_le_bytes());
            PublicKey::from_bytes(Algorithm::MlDsa, &material).unwrap()
        })
        .collect();
    if members == 1 {
        AccountId::new(keys[0].clone())
    } else {
        AccountId::new_multisig(
            MultisigPolicy::new(
                1,
                keys.into_iter()
                    .map(|key| MultisigMember::new(key, 1).unwrap())
                    .collect(),
            )
            .unwrap(),
        )
    }
}

#[test]
fn measured_candidate_source_frames_keep_exact_intrinsic_and_obligation_bounds() {
    use iroha_primitives::bigint::BigInt;
    let mut maximum = [0xff; 64];
    maximum[63] = 0x7f;
    for (members, count, account_bytes, input_bytes, statement_bytes) in [
        (1, 16, 3_960, 670_864, 272_175),
        (16, 1, 62_799, 159_609, 252_617),
    ] {
        let from = candidate_controller(members, 17);
        let to = candidate_controller(members, 23);
        assert_eq!(
            norito::encode_canonical(&from).unwrap().len(),
            account_bytes
        );
        for scale in [0, MAX_DECIMAL_SCALE] {
            let maximum = Quantity::from_canonical_numeric(
                Numeric::try_new(BigInt::from_twos_bytes(&maximum).unwrap(), scale).unwrap(),
            )
            .unwrap();
            let mut delta = delta(scale, false);
            delta.from_account = from.clone();
            delta.to_account = to.clone();
            delta.amount = maximum.clone();
            delta.from_balance_before = maximum.clone();
            delta.from_balance_after = maximum.clone();
            delta.to_balance_before = maximum.clone();
            delta.to_balance_after = maximum;
            delta.from_smt_witness = TransferSmtWitness::new(
                [0x31; 32],
                [0x37; 32],
                vec![0xff; 32],
                vec![[0x42; 32]; 256],
            );
            delta.to_smt_witness = delta.from_smt_witness.clone();
            let bundle: Vec<_> = (0..count)
                .map(|index| {
                    transcript(
                        vec![delta.clone()],
                        u8::try_from(index).expect("fixture value fits u8"),
                    )
                })
                .collect();
            let expected = FastpqSourceTranscriptUsage {
                transcripts: count,
                deltas: count,
                input_transcript_bytes: input_bytes,
                max_statement_bytes: statement_bytes,
                total_statement_bytes: statement_bytes,
            };
            assert_eq!(reference(&bundle), expected);
            let exact = FastpqSourceStatementBuildLimits {
                max_executed_entries: 1,
                max_transcripts: count,
                max_deltas: count,
                max_input_transcript_bytes: input_bytes,
                max_statement_bytes: statement_bytes,
                max_total_statement_bytes: statement_bytes,
            };
            assert_eq!(
                measure_fastpq_source_entry_frame_usage(hash(), &bundle, exact).unwrap(),
                expected
            );
            for dimension in 0..6 {
                let mut too_small = exact;
                match dimension {
                    0 => too_small.max_executed_entries -= 1,
                    1 => too_small.max_transcripts -= 1,
                    2 => too_small.max_deltas -= 1,
                    3 => too_small.max_input_transcript_bytes -= 1,
                    4 => too_small.max_statement_bytes -= 1,
                    _ => too_small.max_total_statement_bytes -= 1,
                }
                assert!(
                    measure_fastpq_source_entry_frame_usage(hash(), &bundle, too_small).is_err(),
                    "dimension {dimension}"
                );
            }
        }
    }
}
