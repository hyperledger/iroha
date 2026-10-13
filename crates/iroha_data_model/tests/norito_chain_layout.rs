//! Regression coverage for Norito chain wire layout candidates.
use iroha_crypto::{PrivateKey, PublicKey};
use iroha_data_model::{
    Level,
    account::AccountId,
    block::{SignedBlock, decode_framed_signed_block},
    isi::{InstructionBox, Log},
    transaction::signed::{SignedTransaction, TransactionBuilder, TransactionEntrypoint},
};
use iroha_version::codec::{DecodeVersioned, EncodeVersioned};
use norito::core::{DecodeFlagsGuard, Header, frame_bare_with_header_flags, header_flags};
use std::fmt::Debug;
#[derive(Clone, Copy)]
struct LayoutCandidate {
    name: &'static str,
    requested_flags: u8,
}
const LAYOUT_CANDIDATES: &[LayoutCandidate] = &[
    LayoutCandidate {
        name: "canonical",
        requested_flags: 0,
    },
    LayoutCandidate {
        name: "compact_len",
        requested_flags: header_flags::COMPACT_LEN,
    },
];
const MIXED_BLOCK_INSTRUCTION_COUNTS: &[usize] = &[0, 1, 4, 8, 16, 32];
fn fixed_public_key() -> PublicKey {
    "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
        .parse()
        .expect("fixed public key")
}
fn fixed_private_key() -> PrivateKey {
    "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
        .parse()
        .expect("fixed private key")
}
fn sample_transaction(instruction_count: usize) -> SignedTransaction {
    let private_key = fixed_private_key();
    let authority = AccountId::new(fixed_public_key());
    let instructions = (0..instruction_count)
        .map(|index| {
            InstructionBox::from(Log::new(Level::INFO, format!("layout instruction {index}")))
        })
        .collect::<Vec<_>>();
    TransactionBuilder::new_genesis(
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions)
    .sign(&private_key)
}
fn sample_block(transaction_count: usize, instruction_count: usize) -> SignedBlock {
    let private_key = fixed_private_key();
    let transactions = (0..transaction_count)
        .map(|_| sample_transaction(instruction_count))
        .collect::<Vec<_>>();
    SignedBlock::genesis(transactions, &private_key, None, None)
}
fn sample_mixed_block() -> SignedBlock {
    let private_key = fixed_private_key();
    let transactions = MIXED_BLOCK_INSTRUCTION_COUNTS
        .iter()
        .map(|&instruction_count| sample_transaction(instruction_count))
        .collect::<Vec<_>>();
    SignedBlock::genesis(transactions, &private_key, None, None)
}
fn candidate_by_name(name: &str) -> LayoutCandidate {
    LAYOUT_CANDIDATES
        .iter()
        .copied()
        .find(|candidate| candidate.name == name)
        .expect("known layout candidate")
}
fn layout_payload_with_flags<T>(value: &T, candidate: LayoutCandidate) -> (Vec<u8>, u8)
where
    T: norito::NoritoSerialize,
{
    let _guard = DecodeFlagsGuard::enter(candidate.requested_flags);
    let (payload, flags) = norito::codec::encode_with_header_flags(value);
    let expected = candidate.requested_flags;
    assert_eq!(
        flags & expected,
        expected,
        "{} did not advertise requested layout flags",
        candidate.name
    );
    (payload, flags)
}
fn framed_with_layout<T>(value: &T, candidate: LayoutCandidate) -> Vec<u8>
where
    T: norito::NoritoSerialize,
{
    let (payload, flags) = layout_payload_with_flags(value, candidate);
    frame_bare_with_header_flags::<T>(&payload, flags).expect("frame layout payload")
}
fn versioned_payload_with_layout<T>(value: &T, version: u8, candidate: LayoutCandidate) -> Vec<u8>
where
    T: norito::NoritoSerialize,
{
    let (payload, _) = layout_payload_with_flags(value, candidate);
    let mut versioned = Vec::with_capacity(1 + payload.len());
    versioned.push(version);
    versioned.extend_from_slice(&payload);
    versioned
}
fn versioned_framed_block_with_layout(block: &SignedBlock, candidate: LayoutCandidate) -> Vec<u8> {
    let (payload, flags) = layout_payload_with_flags(block, candidate);
    let mut framed = Vec::with_capacity(1 + Header::SIZE + payload.len());
    framed.push(SignedBlock::WIRE_VERSION);
    framed.extend_from_slice(
        &frame_bare_with_header_flags::<SignedBlock>(&payload, flags)
            .expect("frame signed block payload"),
    );
    framed
}
fn header_flags_from(bytes: &[u8]) -> u8 {
    bytes[Header::SIZE - 1]
}
fn versioned_header_flags_from(bytes: &[u8]) -> u8 {
    bytes[1 + Header::SIZE - 1]
}
fn assert_default_frame_matches_compact<T>(label: &str, value: &T)
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de> + PartialEq + Debug,
{
    let compact = framed_with_layout(value, candidate_by_name("compact_len"));
    let default = norito::core::to_bytes(value).expect("encode default framed payload");
    assert_eq!(default, compact, "{label} default frame must be compact");
    let flags = header_flags_from(&default);
    assert_eq!(
        flags,
        header_flags::COMPACT_LEN,
        "{label} default frame must advertise exactly compact lengths"
    );
    let decoded: T = norito::decode_from_bytes(&default).expect("decode default framed payload");
    assert_eq!(decoded, *value, "{label} default frame roundtrip");
}
fn assert_compact_payload_is_smaller<T>(label: &str, value: &T)
where
    T: norito::NoritoSerialize,
{
    let (canonical, _) = layout_payload_with_flags(value, candidate_by_name("canonical"));
    let (compact, _) = layout_payload_with_flags(value, candidate_by_name("compact_len"));
    assert!(
        compact.len() < canonical.len(),
        "{label} compact payload should be smaller than canonical: compact={} canonical={}",
        compact.len(),
        canonical.len()
    );
}
fn assert_compact_ratio_at_most<T>(label: &str, value: &T, numerator: usize, denominator: usize)
where
    T: norito::NoritoSerialize,
{
    let canonical = framed_with_layout(value, candidate_by_name("canonical"));
    let compact = framed_with_layout(value, candidate_by_name("compact_len"));
    assert!(
        compact.len() * denominator <= canonical.len() * numerator,
        "{label} compact payload ratio exceeded {numerator}/{denominator}: compact={} canonical={}",
        compact.len(),
        canonical.len()
    );
}
fn assert_versioned_default_matches_compact<T>(label: &str, value: &T, versioned: &[u8])
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de> + PartialEq + Debug,
    T: DecodeVersioned,
{
    let version = versioned[0];
    let compact = versioned_payload_with_layout(value, version, candidate_by_name("compact_len"));
    let canonical = versioned_payload_with_layout(value, version, candidate_by_name("canonical"));
    assert_eq!(
        versioned,
        compact.as_slice(),
        "{label} versioned encoding must use compact lengths by default"
    );
    assert!(
        versioned.len() < canonical.len(),
        "{label} compact versioned payload should be smaller than canonical: compact={} canonical={}",
        versioned.len(),
        canonical.len()
    );
    let decoded = T::decode_all_versioned(versioned).expect("decode compact versioned payload");
    assert_eq!(decoded, *value, "{label} compact versioned roundtrip");
    assert!(
        T::decode_all_versioned(&canonical).is_err(),
        "{label} headerless canonical payload decoded despite compact version mapping"
    );
}
fn assert_truncated_layout_candidates_reject<T>(label: &str, value: &T)
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
{
    for &candidate in LAYOUT_CANDIDATES {
        let mut framed = framed_with_layout(value, candidate);
        framed.pop().expect("non-empty framed payload");
        assert!(
            norito::decode_from_bytes::<T>(&framed).is_err(),
            "{label}/{} truncated frame decoded successfully",
            candidate.name
        );
    }
}
#[test]
fn signed_transaction_layout_candidates_decode_from_framed_bytes() {
    let tx = sample_transaction(8);
    for &candidate in LAYOUT_CANDIDATES {
        let framed = framed_with_layout(&tx, candidate);
        let decoded: SignedTransaction = norito::decode_from_bytes(&framed).unwrap_or_else(|err| {
            panic!(
                "{} signed transaction decode failed: {err:?}",
                candidate.name
            )
        });
        assert_eq!(
            decoded, tx,
            "{} signed transaction roundtrip",
            candidate.name
        );
    }
}
#[test]
fn transaction_entrypoint_layout_candidates_decode_from_framed_bytes() {
    let entrypoint = TransactionEntrypoint::from(sample_transaction(8));
    for &candidate in LAYOUT_CANDIDATES {
        let framed = framed_with_layout(&entrypoint, candidate);
        let decoded: TransactionEntrypoint =
            norito::decode_from_bytes(&framed).unwrap_or_else(|err| {
                panic!(
                    "{} transaction entrypoint decode failed: {err:?}",
                    candidate.name
                )
            });
        assert_eq!(
            decoded, entrypoint,
            "{} transaction entrypoint roundtrip",
            candidate.name
        );
    }
}
#[test]
fn signed_block_layout_candidates_decode_from_framed_bytes() {
    let block = sample_block(4, 4);
    for &candidate in LAYOUT_CANDIDATES {
        let framed = framed_with_layout(&block, candidate);
        let decoded: SignedBlock = norito::decode_from_bytes(&framed)
            .unwrap_or_else(|err| panic!("{} signed block decode failed: {err:?}", candidate.name));
        assert_eq!(decoded, block, "{} signed block roundtrip", candidate.name);
    }
}
#[test]
fn signed_block_wire_accepts_default_and_rejects_non_default_layout_flags() {
    let block = sample_block(4, 4);
    for &candidate in LAYOUT_CANDIDATES {
        let wire = versioned_framed_block_with_layout(&block, candidate);
        if candidate.requested_flags == header_flags::COMPACT_LEN {
            let decoded = decode_framed_signed_block(&wire).unwrap_or_else(|err| {
                panic!(
                    "{} signed block wire decode failed: {err:?}",
                    candidate.name
                )
            });
            assert_eq!(
                decoded, block,
                "{} signed block wire roundtrip",
                candidate.name
            );
        } else {
            assert!(
                decode_framed_signed_block(&wire).is_err(),
                "{} signed block wire decoded despite non-default layout flags",
                candidate.name
            );
        }
    }
}
#[test]
fn default_framed_chain_payloads_advertise_compact_lengths() {
    assert_default_frame_matches_compact("signed_transaction", &sample_transaction(8));
    assert_default_frame_matches_compact(
        "transaction_entrypoint",
        &TransactionEntrypoint::from(sample_transaction(8)),
    );
    assert_default_frame_matches_compact("signed_block", &sample_block(4, 4));
}
#[test]
fn versioned_transaction_payloads_use_compact_default() {
    let tx = sample_transaction(8);
    assert_versioned_default_matches_compact("signed_transaction", &tx, &tx.encode_versioned());
    let entrypoint = TransactionEntrypoint::from(sample_transaction(8));
    assert_versioned_default_matches_compact(
        "transaction_entrypoint",
        &entrypoint,
        &entrypoint.encode_versioned(),
    );
}
#[test]
fn canonical_signed_block_wire_uses_compact_default() {
    let block = sample_block(4, 4);
    let compact = versioned_framed_block_with_layout(&block, candidate_by_name("compact_len"));
    let canonical = versioned_framed_block_with_layout(&block, candidate_by_name("canonical"));
    let wire = block.canonical_wire().expect("canonical signed block wire");
    assert_eq!(wire.as_framed(), compact.as_slice());
    assert_eq!(
        block.encode_wire().expect("encode signed block wire"),
        compact
    );
    assert_eq!(
        versioned_header_flags_from(wire.as_framed()),
        header_flags::COMPACT_LEN,
        "signed block wire must advertise compact lengths by default"
    );
    assert!(
        wire.as_framed().len() < canonical.len(),
        "compact signed block wire should be smaller than canonical: compact={} canonical={}",
        wire.as_framed().len(),
        canonical.len()
    );
}
#[test]
fn compact_chain_payload_sizes_stay_within_budget() {
    let tx = sample_transaction(8);
    let entrypoint = TransactionEntrypoint::from(sample_transaction(8));
    let block = sample_block(4, 4);
    assert!(
        tx.encode_versioned().len() <= 1050,
        "signed transaction compact versioned payload grew beyond budget"
    );
    assert!(
        entrypoint.encode_versioned().len() <= 1060,
        "transaction entrypoint compact versioned payload grew beyond budget"
    );
    assert!(
        block.encode_wire().expect("encode signed block wire").len() <= 8800,
        "signed block compact wire payload grew beyond budget"
    );
}
#[test]
fn compact_lengths_reduce_chain_payload_sizes() {
    assert_compact_payload_is_smaller("signed_transaction", &sample_transaction(8));
    assert_compact_payload_is_smaller(
        "transaction_entrypoint",
        &TransactionEntrypoint::from(sample_transaction(8)),
    );
    assert_compact_payload_is_smaller("signed_block", &sample_block(4, 4));
}
#[test]
fn truncated_chain_layout_frames_reject() {
    assert_truncated_layout_candidates_reject("signed_transaction", &sample_transaction(8));
    assert_truncated_layout_candidates_reject(
        "transaction_entrypoint",
        &TransactionEntrypoint::from(sample_transaction(8)),
    );
    assert_truncated_layout_candidates_reject("signed_block", &sample_block(4, 4));
}
#[test]
fn mixed_chain_corpus_keeps_compact_default_and_size_advantage() {
    for instruction_count in [0, 1, 4, 8, 16, 32] {
        let tx = sample_transaction(instruction_count);
        assert_default_frame_matches_compact(
            &format!("signed_transaction_{instruction_count}"),
            &tx,
        );
        assert_compact_payload_is_smaller(&format!("signed_transaction_{instruction_count}"), &tx);
    }
    let entrypoint = TransactionEntrypoint::from(sample_transaction(32));
    assert_default_frame_matches_compact("transaction_entrypoint_32", &entrypoint);
    assert_compact_payload_is_smaller("transaction_entrypoint_32", &entrypoint);
    let mixed_block = sample_mixed_block();
    assert_default_frame_matches_compact("signed_block_mixed", &mixed_block);
    assert_compact_payload_is_smaller("signed_block_mixed", &mixed_block);
    assert_compact_ratio_at_most("signed_block_mixed", &mixed_block, 2, 3);
}
#[test]
fn signed_block_wire_rejects_header_tampering() {
    let block = sample_mixed_block();
    let wire = block.canonical_wire().expect("canonical signed block wire");
    let framed = wire.as_framed();
    let flags_index = 1 + Header::SIZE - 1;
    let length_index = 1 + 23;
    let checksum_index = 1 + 31;
    let mut wrong_flags = framed.to_vec();
    wrong_flags[flags_index] = 0;
    assert!(
        decode_framed_signed_block(&wrong_flags).is_err(),
        "signed block wire decoded after layout flags were cleared"
    );
    let mut wrong_length = framed.to_vec();
    wrong_length[length_index] ^= 0x01;
    assert!(
        decode_framed_signed_block(&wrong_length).is_err(),
        "signed block wire decoded after header length was changed"
    );
    let mut wrong_checksum = framed.to_vec();
    wrong_checksum[checksum_index] ^= 0x01;
    assert!(
        decode_framed_signed_block(&wrong_checksum).is_err(),
        "signed block wire decoded after checksum was changed"
    );
}
