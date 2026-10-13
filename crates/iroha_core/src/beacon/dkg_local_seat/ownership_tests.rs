//! Actual pre-RNG output allocation, original-pool refusal and canonical borrowed-frame controls.

use super::*;
use crate::{
    beacon::{
        AdaptiveGlobalThresholdBeaconDkgCryptoV1, GlobalThresholdBeaconDkgStateV1,
        GlobalThresholdBeaconSessionBindingV1, validate_global_threshold_beacon_session_v1,
    },
    test_allocations::{allocations_during, refuse_one_layout_during},
};
use iroha_allocation::ChargedBufferError;
use std::task::{Context, Waker};

pub(super) fn authenticated_source(
    seats: u16,
    time: u64,
) -> (
    crate::sumeragi::test_chain::PreparedTestChainConfig,
    AuthenticatedGlobalBeaconDkgAttemptV1,
    crate::sumeragi::native_journal::NativeJournalCursor,
    Vec<PeerId>,
    AllocationBudget,
) {
    use crate::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_data_model::{
        NetworkId,
        parameter::{
            Parameter,
            system::{SumeragiConsensusMode, SumeragiNposParameters},
        },
    };
    let (_, keys, _) = super::tests::signed_session(seats);
    let mut config = TestChainConfig::new(World::new(), time);
    config.validator_keys = Some(keys);
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config.genesis_parameters.push(Parameter::Custom(
        SumeragiNposParameters::default().into_custom_parameter(),
    ));
    let root_scope = config.root_scope;
    let chain_id = config.chain_id.clone();
    let source = CertifiedTestChain::prepare(config).unwrap();
    let network = NetworkId::from_genesis_hash(source.genesis.block().hash());
    let authority = AuthenticatedGlobalBeaconDkgAttemptV1::signed_genesis(
        source.genesis.block(),
        network,
        &chain_id,
    )
    .unwrap();
    let budget = crate::beacon::fixtures::fixture_budget();
    let clock = crate::sumeragi::native_journal::NativeJournalCursor::new(
        chain_id,
        network,
        root_scope,
        iroha_data_model::sumeragi::finality::NativeFinalityLimits {
            block_bytes: 1024 * 1024,
            journal_bytes: 4 * 1024 * 1024,
            block_count: 4,
            allocated_bytes: 64 * 1024 * 1024,
        },
        &budget,
    )
    .unwrap();
    let roster = source
        .validator_keys
        .iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect();
    (source, authority, clock, roster, budget)
}

// These canonical bytes are a component-only intent commitment. Actual daemon
// write-ahead/file+directory durability and durable replay are separate controls.
fn component_intent(session: &GlobalThresholdBeaconDkgSessionV1, seat: u16) -> [u8; 32] {
    Hash::new(&norito::encode_canonical(&(session.attempt_id, seat, session.start_height)).unwrap())
        .into()
}

fn checked_context(
    authority: &AuthenticatedGlobalBeaconDkgAttemptV1,
    clock: &crate::sumeragi::native_journal::NativeJournalCursor,
    seat: u16,
    signer: &KeyPair,
    publication: &[u8],
    revision: u64,
) -> VerifiedGlobalBeaconDkgCheckpointContextV1 {
    authority
        .checkpoint_context(
            clock,
            1,
            seat,
            signer,
            "software-provider",
            revision,
            Hash::new(publication).into(),
            [0; 32],
            [0; 32],
            component_intent(&authority.session(), seat),
        )
        .unwrap()
}

fn assert_canonical_bytes(actual: &[u8], expected: &[u8]) {
    assert!(
        actual == expected,
        "canonical frame mismatch: actual length {}, expected length {}, first differing offset {:?}",
        actual.len(),
        expected.len(),
        actual
            .iter()
            .zip(expected)
            .position(|(left, right)| left != right)
            .or_else(
                || (actual.len() != expected.len()).then_some(actual.len().min(expected.len()))
            )
    );
}

#[test]
fn prepared_local_outputs_are_complete_before_randomness_at_four_and_thirty_one() {
    for n in [4, 31] {
        // Source authentication precedes every measured constructor/producer scope.
        let (source, authority, clock, roster, budget) = authenticated_source(n, 1000);
        let session = authority.session();
        let keys = &source.validator_keys;
        let mut prepared = None;
        let allocations = allocations_during(|| {
            prepared = Some(
                PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
                    session, &roster, 1, &keys[0], &budget,
                )
                .unwrap(),
            )
        });
        assert_eq!(
            allocations,
            37 + 6 * usize::from(n),
            "exact existing outputs plus three six-allocation phase banks and the five-allocation aggregate-only bank"
        );
        let prepared = prepared.unwrap();
        let original_frame = prepared.public_frame.backing();
        let retained = budget.reserved_bytes();
        let blocker = budget
            .try_reserve_bytes(budget.limit_bytes() - retained)
            .unwrap();
        let mut local = None;
        assert_eq!(
            allocations_during(|| local = Some(prepared.generate(&keys[0]).unwrap())),
            0,
            "a claimed attempt cannot require another allocation after RNG begins"
        );
        let mut local = local.unwrap();
        assert_eq!(local.public_frame.backing(), original_frame);
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        let mut frame_len = 0;
        assert_eq!(
            allocations_during(|| frame_len = local.publication_frame().unwrap().len()),
            0
        );
        assert!(frame_len < original_frame.1);
        let binding = checked_context(
            &authority,
            &clock,
            1,
            &keys[0],
            local.encoded_public_frame(),
            7,
        );
        let mut private_pointer = std::ptr::null();
        assert_eq!(
            allocations_during(|| {
                private_pointer = local
                    .seal_private_checkpoint(&binding, &keys[0])
                    .unwrap()
                    .as_ptr();
            }),
            0
        );
        let mut retry_pointer = std::ptr::null();
        assert_eq!(
            allocations_during(|| {
                retry_pointer = local
                    .seal_private_checkpoint(&binding, &keys[0])
                    .unwrap()
                    .as_ptr();
            }),
            0
        );
        assert_eq!(private_pointer, retry_pointer);
        let changed = checked_context(
            &authority,
            &clock,
            1,
            &keys[0],
            local.encoded_public_frame(),
            8,
        );
        assert_eq!(
            allocations_during(|| {
                assert!(local.seal_private_checkpoint(&changed, &keys[0]).is_err());
            }),
            0
        );
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        let raw: GlobalThresholdBeaconDkgSnapshotV1 =
            norito::decode_canonical(local.publication_frame().unwrap()).unwrap();
        let (key, commitment) = local.publication();
        let parameters = adaptive_beacon_parameters(&session).unwrap();
        let expected = GlobalThresholdBeaconDkgSnapshotV1 {
            session,
            generator_h: *parameters.h_bytes(),
            generator_v: *parameters.v_bytes(),
            recipient_keys: vec![key.clone()],
            dealer_commitments: vec![commitment.clone()],
            encrypted_shares: vec![],
            share_acceptances: vec![],
            last_updated_height: session.start_height,
        };
        assert_eq!(raw, expected);
        assert_canonical_bytes(
            local.publication_frame().unwrap(),
            &norito::encode_canonical(&expected).unwrap(),
        );
        drop(local);
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes() - retained);
        drop(blocker);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

fn original_checkpoint(
    authority: &AuthenticatedGlobalBeaconDkgAttemptV1,
    clock: &crate::sumeragi::native_journal::NativeJournalCursor,
    roster: &[PeerId],
    seat: u16,
    signer: &KeyPair,
    budget: &AllocationBudget,
) -> (
    ChargedBuffer<u8>,
    ChargedBuffer<u8>,
    VerifiedGlobalBeaconDkgCheckpointContextV1,
) {
    let mut original = PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
        authority.session(),
        roster,
        seat,
        signer,
        budget,
    )
    .unwrap()
    .generate(signer)
    .unwrap();
    let bytes = original.publication_frame().unwrap();
    let context = checked_context(authority, clock, seat, signer, bytes, 7);
    let mut public = ChargedBuffer::new(bytes.len(), budget).unwrap();
    public.append(bytes).unwrap();
    let bytes = original.seal_private_checkpoint(&context, signer).unwrap();
    let mut encrypted = ChargedBuffer::new(bytes.len(), budget).unwrap();
    encrypted.append(bytes).unwrap();
    drop(original);
    (public, encrypted, context)
}

#[test]
fn original_phase_one_restore_keeps_prepaid_signatures_ciphertext_and_publication_at_four_and_thirty_one()
 {
    use crate::beacon::PreparedGlobalThresholdBeaconDkgPublicationV1;
    for n in [4, 31] {
        let (source, authority, clock, roster, budget) = authenticated_source(n, 1000);
        let seat = n;
        let signer = &source.validator_keys[usize::from(seat - 1)];
        let (public, encrypted, context) =
            original_checkpoint(&authority, &clock, &roster, seat, signer, &budget);
        let floor = budget.reserved_bytes();
        let public_source = (public.as_slice().as_ptr(), Hash::new(public.as_slice()));
        let encrypted_source = (
            encrypted.as_slice().as_ptr(),
            Hash::new(encrypted.as_slice()),
        );
        let prepared = PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
            authority.session(),
            &roster,
            seat,
            signer,
            &budget,
        )
        .unwrap();
        let recipient_backing = prepared.recipient.restoration_backing();
        let dealer_backing = prepared.dealer.restoration_backing();
        let frame_backing = prepared.public_frame.backing();
        let mut bank = PreparedGlobalThresholdBeaconDkgPublicationV1::new(
            authority.session(),
            &roster,
            seat,
            &budget,
        )
        .unwrap();
        assert!(bank.belongs_to(&budget));
        assert!(!bank.belongs_to(&crate::beacon::fixtures::fixture_budget()));
        let blocker = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        let mut result = None;
        let retirement_bytes = bank.decode_retirement_bytes().unwrap();
        let mut after_public_decode = None;
        assert_eq!(
            allocations_during(|| {
                bank.decode(
                    public.as_slice(),
                    norito::canonical_decode_limits(public.as_slice().len()),
                )
                .unwrap();
                // Extraction drops only the prepared destination objects and
                // their span plans; canonical fields keep their original charge.
                after_public_decode = Some(budget.reserved_bytes());
                result = Some(prepared.restore_generated(
                    &context,
                    bank.publication().unwrap(),
                    public.as_slice(),
                    encrypted.as_slice(),
                    signer,
                    norito::canonical_decode_limits(encrypted.as_slice().len()),
                ));
            }),
            0,
            "actual original field walk and restored opaque owners need no allocation or secret producer"
        );
        let mut restored = result
            .unwrap()
            .unwrap_or_else(|(_, error)| panic!("original phase-one restore: {error}"));
        let (recipient, dealer) = restored.publication();
        assert_eq!(recipient, &bank.publication().unwrap().recipient_keys[0]);
        assert_eq!(dealer, &bank.publication().unwrap().dealer_commitments[0]);
        assert_eq!(recipient.signature.payload().as_ptr(), recipient_backing.0);
        assert_eq!(dealer.signature.payload().as_ptr(), dealer_backing.0);
        assert_eq!(recipient_backing.1, recipient.signature.payload().len());
        assert_eq!(dealer_backing.1, dealer.signature.payload().len());
        assert!(
            restored.recipient_key.belongs_to(&budget)
                && restored.dealer_commitment.belongs_to(&budget)
        );
        assert_eq!(restored.public_frame.backing(), frame_backing);
        assert_canonical_bytes(restored.encoded_public_frame(), public.as_slice());
        let checkpoint_pointer = restored.checkpoints[0].encrypted_record().unwrap().as_ptr();
        assert_canonical_bytes(
            restored.checkpoints[0].encrypted_record().unwrap(),
            encrypted.as_slice(),
        );
        assert_eq!(
            allocations_during(|| {
                assert_eq!(
                    restored
                        .seal_private_checkpoint(&context, signer)
                        .unwrap()
                        .as_ptr(),
                    checkpoint_pointer
                );
            }),
            0
        );
        assert_eq!(
            restored.encryption.public().x25519_bytes(),
            bank.publication().unwrap().recipient_keys[0].x25519_public_key
        );
        assert!(restored.dealer_secret.is_some());
        assert!(
            !restored.delivered && !restored.accepted && !restored.extracted && !restored.aborted
        );
        assert_eq!(
            after_public_decode.unwrap(),
            budget.limit_bytes() - retirement_bytes
        );
        assert_eq!(budget.reserved_bytes(), after_public_decode.unwrap());
        assert!(bank.decode_retirement_bytes().is_none());
        assert_eq!(
            (public.as_slice().as_ptr(), Hash::new(public.as_slice())),
            public_source
        );
        assert_eq!(
            (
                encrypted.as_slice().as_ptr(),
                Hash::new(encrypted.as_slice())
            ),
            encrypted_source
        );
        drop(restored);
        drop(bank);
        drop(blocker);
        assert_eq!(budget.reserved_bytes(), floor);
        drop(public);
        drop(encrypted);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn original_publication_and_private_decode_refusals_keep_same_banks_and_sources_before_retry() {
    use crate::beacon::{
        GlobalThresholdBeaconInputErrorV1, PreparedGlobalThresholdBeaconDkgPublicationV1,
    };
    use norito::core::{DecodeAttemptErrorKind, PreparedDecodeError, with_decode_limits_scope};
    let (source, authority, clock, roster, budget) = authenticated_source(4, 1000);
    let signer = &source.validator_keys[0];
    let (public, encrypted, context) =
        original_checkpoint(&authority, &clock, &roster, 1, signer, &budget);
    let mut bank = PreparedGlobalThresholdBeaconDkgPublicationV1::new(
        authority.session(),
        &roster,
        1,
        &budget,
    )
    .unwrap();
    let prepared = PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
        authority.session(),
        &roster,
        1,
        signer,
        &budget,
    )
    .unwrap();
    let recipient_backing = prepared.recipient.restoration_backing();
    let dealer_backing = prepared.dealer.restoration_backing();
    let floor = budget.reserved_bytes();
    let retirement_bytes = bank.decode_retirement_bytes().unwrap();
    let public_hash = Hash::new(public.as_slice());
    let encrypted_hash = Hash::new(encrypted.as_slice());
    let narrow = norito::DecodeLimits::new(0, 0, 0, 0, 0);
    let public_limits = norito::canonical_decode_limits(public.as_slice().len());
    let private_limits = norito::canonical_decode_limits(encrypted.as_slice().len());
    let public_refusal =
        with_decode_limits_scope(narrow, || bank.decode(public.as_slice(), public_limits))
            .unwrap_err();
    assert!(
        matches!(&public_refusal, GlobalThresholdBeaconInputErrorV1::Decode(PreparedDecodeError::Codec(cause)) if cause.kind() == DecodeAttemptErrorKind::EnclosingLimit)
    );
    assert!(bank.publication().is_none());
    let foreign = public.as_slice().to_vec();
    assert!(matches!(
        bank.decode(&foreign, public_limits),
        Err(GlobalThresholdBeaconInputErrorV1::SourceChanged)
    ));
    assert_eq!(budget.reserved_bytes(), floor);
    bank.decode(public.as_slice(), public_limits).unwrap();
    // The successful first extraction releases its prepared destination/span
    // backing. All following refusal and retry checks use this same live prefix.
    let after_public_decode = budget.reserved_bytes();
    assert_eq!(after_public_decode, floor - retirement_bytes);
    assert!(bank.decode_retirement_bytes().is_none());
    let floor = after_public_decode;
    let original_publication_pointer = bank.publication().unwrap().recipient_keys.as_ptr();
    let (prepared, private_refusal) = with_decode_limits_scope(narrow, || {
        prepared.restore_generated(
            &context,
            bank.publication().unwrap(),
            public.as_slice(),
            encrypted.as_slice(),
            signer,
            private_limits,
        )
    })
    .err()
    .unwrap();
    assert!(
        matches!(&private_refusal, LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(DkgCheckpointErrorV1::Decode(PreparedDecodeError::Codec(cause))) if cause.kind() == DecodeAttemptErrorKind::EnclosingLimit)
    );
    assert_eq!(prepared.recipient.restoration_backing(), recipient_backing);
    assert_eq!(prepared.dealer.restoration_backing(), dealer_backing);
    let mut corrupted = encrypted.as_slice().to_vec();
    corrupted[0] ^= 1;
    let (prepared, changed_source_refusal) = prepared
        .restore_generated(
            &context,
            bank.publication().unwrap(),
            public.as_slice(),
            &corrupted,
            signer,
            private_limits,
        )
        .err()
        .unwrap();
    assert!(matches!(
        &changed_source_refusal,
        LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(DkgCheckpointErrorV1::Binding)
    ));
    assert_eq!(prepared.recipient.restoration_backing(), recipient_backing);
    assert_eq!(prepared.dealer.restoration_backing(), dealer_backing);
    assert_eq!(budget.reserved_bytes(), floor);
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - floor)
        .unwrap();
    let mut restored = None;
    assert_eq!(
        allocations_during(|| {
            bank.decode(public.as_slice(), public_limits).unwrap();
            restored = Some(prepared.restore_generated(
                &context,
                bank.publication().unwrap(),
                public.as_slice(),
                encrypted.as_slice(),
                signer,
                private_limits,
            ));
        }),
        0
    );
    let restored = restored
        .unwrap()
        .unwrap_or_else(|(_, error)| panic!("unchanged original retry: {error}"));
    assert_eq!(
        bank.publication().unwrap().recipient_keys.as_ptr(),
        original_publication_pointer
    );
    assert_eq!(
        restored.publication().0.signature.payload().as_ptr(),
        recipient_backing.0
    );
    assert_eq!(Hash::new(public.as_slice()), public_hash);
    assert_eq!(Hash::new(encrypted.as_slice()), encrypted_hash);
    drop(restored);
    drop(bank);
    drop(blocker);
    drop(public);
    drop(encrypted);
    // Each original enclosing-limit error still owns its prepared derived
    // counter after the corresponding decoder and source backing retire.
    // Its exact physical layout, rather than a fixed numeric refund, remains
    // charged through the last error reader and every unchanged-source retry.
    let counter_bytes = norito::core::PreparedDecodeWorkspace::allocation_layouts()[0].size();
    assert!(
        matches!(&public_refusal, GlobalThresholdBeaconInputErrorV1::Decode(PreparedDecodeError::Codec(cause)) if cause.kind() == DecodeAttemptErrorKind::EnclosingLimit)
    );
    assert!(
        matches!(&private_refusal, LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(DkgCheckpointErrorV1::Decode(PreparedDecodeError::Codec(cause))) if cause.kind() == DecodeAttemptErrorKind::EnclosingLimit)
    );
    assert!(matches!(
        &changed_source_refusal,
        LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(DkgCheckpointErrorV1::Binding)
    ));
    assert_eq!(budget.reserved_bytes(), counter_bytes * 2);
    drop(public_refusal);
    assert_eq!(budget.reserved_bytes(), counter_bytes);
    drop(private_refusal);
    assert_eq!(budget.reserved_bytes(), 0);
    drop(changed_source_refusal);
}

#[test]
fn phase_one_restore_authenticates_original_signatures_proof_canonical_bytes_and_signed_source_before_copy()
 {
    use iroha_crypto::Signature;
    let (source, authority, clock, roster, budget) = authenticated_source(4, 1000);
    let signer = &source.validator_keys[0];
    let (public, encrypted, context) =
        original_checkpoint(&authority, &clock, &roster, 1, signer, &budget);
    let original: GlobalThresholdBeaconDkgSnapshotV1 =
        norito::decode_canonical(public.as_slice()).unwrap();
    let floor = budget.reserved_bytes();
    for failure in 0..3 {
        let mut candidate = original.clone();
        if failure == 0 {
            let mut invalid = candidate.recipient_keys[0].signature.payload().to_vec();
            invalid[0] ^= 1;
            candidate.recipient_keys[0].signature = Signature::from_bytes(&invalid);
        } else if failure == 1 {
            let dealer = &mut candidate.dealer_commitments[0];
            dealer.constant_term_proof.response[0] ^= 1;
            // Real BLS ownership signs this changed proof, so a mere signature
            // check cannot substitute for the original Schnorr proof obligation.
            dealer.signature = Signature::new(
                signer.private_key(),
                &super::super::global_threshold_beacon_dkg_dealer_commitment_preimage_v1(
                    &authority.session(),
                    dealer,
                ),
            );
        }
        let mut bytes = norito::encode_canonical(&candidate).unwrap();
        if failure == 2 {
            bytes.push(0);
        }
        let changed = checked_context(&authority, &clock, 1, signer, &bytes, 7);
        let prepared = PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
            authority.session(),
            &roster,
            1,
            signer,
            &budget,
        )
        .unwrap();
        let backing = (
            prepared.recipient.restoration_backing(),
            prepared.dealer.restoration_backing(),
        );
        let reserved = budget.reserved_bytes();
        let mut result = None;
        assert_eq!(
            allocations_during(|| result = Some(prepared.restore_generated(
                &changed,
                &candidate,
                &bytes,
                encrypted.as_slice(),
                signer,
                norito::canonical_decode_limits(encrypted.as_slice().len())
            ))),
            0
        );
        let (prepared, error) = result.unwrap().err().unwrap();
        match failure {
            0 => assert!(matches!(
                error,
                LocalGlobalThresholdBeaconDkgErrorV1::Session(
                    GlobalThresholdBeaconSessionError::Invalid(
                        GlobalThresholdBeaconError::InvalidDkgRecipientKey
                    )
                )
            )),
            1 => assert!(matches!(
                error,
                LocalGlobalThresholdBeaconDkgErrorV1::Threshold(_)
            )),
            _ => assert!(matches!(
                error,
                LocalGlobalThresholdBeaconDkgErrorV1::Session(
                    GlobalThresholdBeaconSessionError::Encoding(
                        norito::Error::NonCanonicalEncoding
                    )
                )
            )),
        }
        assert_eq!(
            (
                prepared.recipient.restoration_backing(),
                prepared.dealer.restoration_backing()
            ),
            backing
        );
        assert!(prepared.checkpoints[0].encrypted_record().is_none());
        assert_eq!(budget.reserved_bytes(), reserved);
        drop(prepared);
        assert_eq!(budget.reserved_bytes(), floor);
    }
    let (foreign_source, foreign_authority, foreign_clock, _, _) = authenticated_source(4, 2000);
    assert!(
        AuthenticatedGlobalBeaconDkgAttemptV1::signed_genesis(
            foreign_source.genesis.block(),
            clock.network_id(),
            clock.chain_id()
        )
        .is_err()
    );
    assert!(
        authority
            .checkpoint_context(
                &foreign_clock,
                1,
                1,
                signer,
                "software-provider",
                7,
                context.binding().public_output_hash,
                [0; 32],
                [0; 32],
                component_intent(&authority.session(), 1)
            )
            .is_err()
    );
    let foreign_context = checked_context(
        &foreign_authority,
        &foreign_clock,
        1,
        &foreign_source.validator_keys[0],
        public.as_slice(),
        7,
    );
    let prepared = PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
        authority.session(),
        &roster,
        1,
        signer,
        &budget,
    )
    .unwrap();
    let (prepared, error) = prepared
        .restore_generated(
            &foreign_context,
            &original,
            public.as_slice(),
            encrypted.as_slice(),
            signer,
            norito::canonical_decode_limits(encrypted.as_slice().len()),
        )
        .err()
        .unwrap();
    assert!(matches!(
        error,
        LocalGlobalThresholdBeaconDkgErrorV1::Invalid(
            GlobalThresholdBeaconError::InvalidDkgSession
        )
    ));
    assert_eq!(prepared.recipient.restoration_backing().2, 0);
    assert_eq!(prepared.dealer.restoration_backing().2, 0);
    drop(prepared);
    assert_eq!(budget.reserved_bytes(), floor);
}

#[test]
fn restored_original_row_and_checkpoint_owners_retire_before_their_pool_refunds_on_unwind() {
    use crate::beacon::PreparedGlobalThresholdBeaconDkgPublicationV1;
    let (source, authority, clock, roster, budget) = authenticated_source(4, 1000);
    let signer = &source.validator_keys[0];
    let (public, encrypted, context) =
        original_checkpoint(&authority, &clock, &roster, 1, signer, &budget);
    let floor = budget.reserved_bytes();
    let public_source = (public.as_slice().as_ptr(), Hash::new(public.as_slice()));
    let encrypted_source = (
        encrypted.as_slice().as_ptr(),
        Hash::new(encrypted.as_slice()),
    );
    let prepared = PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
        authority.session(),
        &roster,
        1,
        signer,
        &budget,
    )
    .unwrap();
    let mut bank = PreparedGlobalThresholdBeaconDkgPublicationV1::new(
        authority.session(),
        &roster,
        1,
        &budget,
    )
    .unwrap();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        bank.decode(
            public.as_slice(),
            norito::canonical_decode_limits(public.as_slice().len()),
        )
        .unwrap();
        let restored = prepared
            .restore_generated(
                &context,
                bank.publication().unwrap(),
                public.as_slice(),
                encrypted.as_slice(),
                signer,
                norito::canonical_decode_limits(encrypted.as_slice().len()),
            )
            .unwrap_or_else(|(_, error)| panic!("restore before unwind: {error}"));
        assert!(
            restored.recipient_key.belongs_to(&budget)
                && restored.dealer_commitment.belongs_to(&budget)
        );
        assert_canonical_bytes(
            restored.checkpoints[0].encrypted_record().unwrap(),
            encrypted.as_slice(),
        );
        // Move the actual nested canonical owner and bank into an unwinding
        // consumer; this exercises their real destruction, not a cost estimate.
        let _original = (restored, bank);
        panic!("consumer unwinds after original checkpoint restoration");
    }));
    assert!(unwind.is_err());
    assert_eq!(budget.reserved_bytes(), floor);
    assert_eq!(
        (public.as_slice().as_ptr(), Hash::new(public.as_slice())),
        public_source
    );
    assert_eq!(
        (
            encrypted.as_slice().as_ptr(),
            Hash::new(encrypted.as_slice())
        ),
        encrypted_source
    );
    drop(public);
    drop(encrypted);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn singleton_publication_preparation_refuses_real_capacity_and_allocator_before_claim() {
    use crate::beacon::PreparedGlobalThresholdBeaconDkgPublicationV1;
    let (session, keys, roster) = super::tests::signed_session(4);
    let budget = crate::beacon::fixtures::fixture_budget();
    let blocker = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
    assert!(
        PreparedGlobalThresholdBeaconDkgPublicationV1::new(session, &roster, 4, &budget).is_err()
    );
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    drop(blocker);
    let (result, refused) = refuse_one_layout_during(Layout::array::<u8>(96).unwrap(), || {
        PreparedGlobalThresholdBeaconDkgPublicationV1::new(session, &roster, 4, &budget)
    });
    assert!(
        refused && result.is_err(),
        "actual original BLS destination allocation refused"
    );
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        PreparedGlobalThresholdBeaconDkgPublicationV1::new(session, &roster, 0, &budget).is_err()
    );
    assert_eq!(budget.reserved_bytes(), 0);
    let _ready =
        PreparedGlobalThresholdBeaconDkgPublicationV1::new(session, &roster, 4, &budget).unwrap();
    assert_eq!(keys.len(), 4);
}

#[test]
fn prepared_local_capacity_and_physical_refusals_preserve_original_attempt_and_refund() {
    let (session, keys, roster) = super::tests::signed_session(4);
    let budget = crate::beacon::fixtures::fixture_budget();
    let mut slot = crate::unit_test_support::release_registration(&budget);
    let floor = budget.reserved_bytes();
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - floor)
        .unwrap();
    let error =
        PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(session, &roster, 1, &keys[0], &budget)
            .err()
            .unwrap();
    let LocalGlobalThresholdBeaconDkgErrorV1::Session(
        GlobalThresholdBeaconSessionError::Admission(AllocationRefusal::Capacity {
            release, ..
        }),
    ) = error
    else {
        panic!("retain original admission source")
    };
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(slot.poll_wait(&release, &mut cx).is_pending());
    let foreign = AllocationBudget::new(128);
    drop(foreign.try_reserve_bytes(128).unwrap());
    assert!(slot.poll_wait(&release, &mut cx).is_pending());
    drop(blocker);
    assert!(slot.poll_wait(&release, &mut cx).is_ready());
    slot.cancel();
    let ready =
        PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(session, &roster, 1, &keys[0], &budget)
            .unwrap();
    drop(ready);
    assert_eq!(budget.reserved_bytes(), floor);
    for layout in [
        Layout::array::<u8>(1184).unwrap(),
        Layout::array::<u8>(1088).unwrap(),
        Layout::array::<u8>(124).unwrap(),
        Layout::array::<u8>(96).unwrap(),
        Layout::array::<[u8; 96]>(2).unwrap(),
        Layout::array::<DasRenPrivateShare<BeaconPurpose>>(4).unwrap(),
    ] {
        let (result, refused) = refuse_one_layout_during(layout, || {
            PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(session, &roster, 1, &keys[0], &budget)
        });
        assert!(refused, "actual selected layout {layout:?}");
        assert!(matches!(
            result,
            Err(LocalGlobalThresholdBeaconDkgErrorV1::Session(
                GlobalThresholdBeaconSessionError::Buffer(
                    iroha_allocation::PrepaidBufferError::Allocation(
                        ChargedBufferError::Allocator { .. }
                    )
                )
            ))
        ));
        assert_eq!(
            budget.reserved_bytes(),
            floor,
            "every initialized field is dropped before its original refund"
        );
        drop(
            PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
                session, &roster, 1, &keys[0], &budget,
            )
            .unwrap(),
        );
        assert_eq!(budget.reserved_bytes(), floor);
    }
    drop(slot);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn prepared_public_frame_maximum_matches_canonical_full_transcripts_at_four_and_thirty_one() {
    for n in [4, 31] {
        let (session, keys, roster) = super::tests::signed_session(n);
        let budget = crate::beacon::fixtures::fixture_budget();
        let fixture = crate::beacon::fixtures::adaptive_beacon_fixture_for_session_and_keys(
            session, &keys, &budget,
        );
        let prepared = PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
            session, &roster, 1, &keys[0], &budget,
        )
        .unwrap();
        let dkg = &fixture.session.record().adaptive_dkg;
        let complete = GlobalThresholdBeaconDkgSnapshotV1 {
            session,
            generator_h: dkg.generator_h,
            generator_v: dkg.generator_v,
            recipient_keys: dkg.recipient_keys.clone(),
            dealer_commitments: dkg.dealer_commitments.clone(),
            encrypted_shares: dkg.encrypted_shares.clone(),
            share_acceptances: dkg.share_acceptances.clone(),
            last_updated_height: session.acceptances_end_height,
        };
        let count = usize::from(n);
        assert_eq!(complete.encrypted_shares.len(), count * count);
        assert_eq!(complete.share_acceptances.len(), count * count);
        let mut local = complete.clone();
        local
            .share_acceptances
            .retain(|row| row.recipient_index == 1);
        assert_eq!(local.share_acceptances.len(), count);
        let local_wire = norito::encode_canonical(&local).unwrap();
        assert_eq!(
            prepared.public_frame.backing().1,
            local_wire.len(),
            "canonical max{n} local geometry, including every original actual signature"
        );
        assert!(norito::encode_canonical(&complete).unwrap().len() > local_wire.len());
        let mut commitments = complete.clone();
        commitments.encrypted_shares.clear();
        commitments.share_acceptances.clear();
        commitments.last_updated_height = session.start_height;
        let mut deliveries = complete.clone();
        deliveries.share_acceptances.clear();
        deliveries.last_updated_height = session.commitments_end_height;
        assert_eq!(
            prepared.input_frame_bounds()[0],
            norito::canonical_frame_len(&commitments).unwrap()
        );
        assert_eq!(
            prepared.input_frame_bounds()[1],
            norito::canonical_frame_len(&deliveries).unwrap()
        );
        assert_eq!(
            prepared.input_frame_bounds()[2],
            norito::canonical_frame_len(fixture.session.record()).unwrap(),
            "complete signed aggregate keeps every n² input acknowledgment"
        );
    }
}

#[test]
fn local_phase_frames_preserve_exact_input_and_prepaid_pointer_without_late_growth() {
    let (session, keys, roster) = super::tests::signed_session(4);
    let budget = crate::beacon::fixtures::fixture_budget();
    let mut local = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
                session,
                &roster,
                u16::try_from(index + 1).unwrap(),
                key,
                &budget,
            )
            .unwrap()
            .generate(key)
            .unwrap()
        })
        .collect::<Vec<_>>();
    let crypto = AdaptiveGlobalThresholdBeaconDkgCryptoV1;
    let mut public = GlobalThresholdBeaconDkgStateV1::new(session, &crypto, &budget).unwrap();
    for seat in &local {
        let (key, dealer) = seat.publication();
        public.record_recipient_key(1, key).unwrap();
        public.record_dealer_commitment(1, dealer, &crypto).unwrap();
    }
    let all_public = public.public_snapshot().unwrap();
    for (seat, key) in local.iter_mut().zip(&keys) {
        let backing = seat.public_frame.backing();
        let original_bytes = budget.reserved_bytes();
        let blocker = budget
            .try_reserve_bytes(budget.limit_bytes() - original_bytes)
            .unwrap();
        assert_eq!(
            allocations_during(|| {
                let _ = seat
                    .deliver(
                        &all_public.recipient_keys,
                        &all_public.dealer_commitments,
                        2,
                        key,
                    )
                    .unwrap();
            }),
            0
        );
        assert_eq!(
            allocations_during(|| {
                let _ = seat.delivery_frame(&all_public).unwrap();
            }),
            0
        );
        assert_eq!(seat.public_frame.backing(), backing);
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(blocker);
        let mut expected = all_public.record().clone();
        expected.encrypted_shares = seat
            .outputs
            .outgoing
            .as_slice()
            .iter()
            .map(|row| row.get().clone())
            .collect();
        expected.last_updated_height = 2;
        assert_canonical_bytes(
            seat.delivery_frame(&all_public).unwrap(),
            &norito::encode_canonical(&expected).unwrap(),
        );
        for edge in &expected.encrypted_shares {
            public.record_encrypted_share(2, edge).unwrap();
        }
        let mut foreign = all_public.record().clone();
        foreign.last_updated_height = 2;
        assert!(matches!(
            seat.delivery_frame(&foreign),
            Err(LocalGlobalThresholdBeaconDkgErrorV1::Invalid(
                GlobalThresholdBeaconError::InvalidDkgSession
            ))
        ));
    }
    let all_edges = public.public_snapshot().unwrap();
    for (seat, key) in local.iter_mut().zip(&keys) {
        assert_eq!(
            allocations_during(|| {
                assert!(matches!(
                    seat.accept(&all_edges, 3, key),
                    Err(LocalGlobalThresholdBeaconDkgErrorV1::Invalid(
                        GlobalThresholdBeaconError::DkgTerminal
                    ))
                ));
            }),
            0,
            "acceptance cannot overtake durable original delivery publication"
        );
    }
    for seat in &mut local {
        assert!(seat.dealer_secret.is_some());
        assert_eq!(
            allocations_during(|| seat.retire_durably_published_dealer().unwrap()),
            0
        );
        assert!(seat.dealer_secret.is_none());
    }
    for (seat, key) in local.iter_mut().zip(&keys) {
        let backing = seat.public_frame.backing();
        let before = budget.reserved_bytes();
        let blocker = budget
            .try_reserve_bytes(budget.limit_bytes() - before)
            .unwrap();
        assert_eq!(
            allocations_during(|| {
                let _ = seat.accept(&all_edges, 3, key).unwrap();
            }),
            0
        );
        assert_eq!(
            allocations_during(|| {
                let _ = seat.acceptance_frame(&all_edges).unwrap();
            }),
            0
        );
        assert_eq!(seat.public_frame.backing(), backing);
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(blocker);
        let mut expected = all_edges.record().clone();
        expected.share_acceptances = seat
            .outputs
            .acceptances
            .as_slice()
            .iter()
            .map(|row| row.get().clone())
            .collect();
        expected.last_updated_height = 3;
        assert_canonical_bytes(
            seat.acceptance_frame(&all_edges).unwrap(),
            &norito::encode_canonical(&expected).unwrap(),
        );
        for row in &expected.share_acceptances {
            public.record_share_acceptance(3, row).unwrap();
        }
        let mut changed = all_edges.record().clone();
        changed.encrypted_shares[0].encrypted_share[0] ^= 1;
        assert!(matches!(
            seat.acceptance_frame(&changed),
            Err(LocalGlobalThresholdBeaconDkgErrorV1::Invalid(
                GlobalThresholdBeaconError::InvalidDkgSession
            ))
        ));
    }
    let record = public.finalize(4, &crypto).unwrap();
    let binding = GlobalThresholdBeaconSessionBindingV1 {
        network_id: record.network_id,
        session_id: record.session_id,
        roster_hash: record.roster_hash,
        transcript_hash: record.transcript_hash,
    };
    let foreign_budget = crate::beacon::fixtures::fixture_budget();
    let foreign =
        validate_global_threshold_beacon_session_v1(record, &binding, &foreign_budget).unwrap();
    for seat in &mut local {
        assert!(matches!(
            seat.aggregate_private_share(&foreign),
            Err(LocalGlobalThresholdBeaconDkgErrorV1::Session(
                GlobalThresholdBeaconSessionError::ForeignReservation
            ))
        ));
        assert!(
            !seat.extracted,
            "foreign owner cannot consume the original private shares"
        );
    }
    drop(foreign);
    assert_eq!(foreign_budget.reserved_bytes(), 0);
    let sealed = validate_global_threshold_beacon_session_v1(record, &binding, &budget).unwrap();
    for seat in &mut local {
        assert_eq!(
            allocations_during(|| {
                let _ = seat.aggregate_private_share(&sealed).unwrap();
            }),
            0
        );
    }
}

#[test]
fn cancelling_or_unwinding_prepared_attempt_refunds_all_original_output_backing() {
    let (session, keys, roster) = super::tests::signed_session(4);
    let budget = crate::beacon::fixtures::fixture_budget();
    let prepared =
        PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(session, &roster, 1, &keys[0], &budget)
            .unwrap();
    assert!(budget.reserved_bytes() > 0);
    drop(prepared);
    assert_eq!(budget.reserved_bytes(), 0);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _prepared = PreparedLocalGlobalThresholdBeaconDkgSeatV1::new(
            session, &roster, 1, &keys[0], &budget,
        )
        .unwrap();
        assert!(budget.reserved_bytes() > 0);
        panic!("test-only caller unwind before its durable attempt claim");
    }));
    assert!(result.is_err());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_dealer_entropy_failures_remain_local_threshold_causes() {
    struct Entropy {
        unavailable: bool,
        calls: usize,
    }
    impl rand::TryRngCore for Entropy {
        type Error = std::io::Error;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut bytes = [0; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut bytes = [0; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }
        fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
            self.calls += 1;
            if self.unavailable {
                return Err(std::io::ErrorKind::Other.into());
            }
            bytes.fill(0);
            Ok(())
        }
    }
    impl rand::TryCryptoRng for Entropy {}
    let (session, _, _) = super::tests::signed_session(4);
    let parameters = adaptive_beacon_parameters(&session).unwrap();
    for unavailable in [true, false] {
        let mut entropy = Entropy {
            unavailable,
            calls: 0,
        };
        let original = DasRenDealerSecret::generate_with_rng(&parameters, 1, &mut entropy)
            .err()
            .expect("real threshold producer rejects unavailable or inert entropy");
        let expected = if unavailable {
            iroha_crypto::threshold_bls::ThresholdBlsError::RandomnessUnavailable
        } else {
            iroha_crypto::threshold_bls::ThresholdBlsError::InertRandomness
        };
        assert_eq!(original, expected);
        let LocalGlobalThresholdBeaconDkgErrorV1::Threshold(retained) =
            LocalGlobalThresholdBeaconDkgErrorV1::from(original)
        else {
            panic!("a local entropy failure must never authenticate an invalid-input verdict")
        };
        assert_eq!(retained, expected);
        if unavailable {
            assert_eq!(entropy.calls, 1);
        } else {
            assert!(entropy.calls > 1);
        }
    }
}
