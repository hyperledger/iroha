//! Original checkpoint corruption is terminal; original resource and entropy causes stay local.

use super::tests::{prepare_restartable, prepare_with_sources, root, through_publication_encoding};
use super::*;
use iroha_crypto::threshold_bls::checkpoint::DkgCheckpointErrorV1;

const HANDLE: &str = "software://iroha/consensus-threshold/retained-attempt";

#[test]
fn corrupted_original_checkpoint_closes_the_receiver_without_rewriting_or_rerolling() {
    let (_temporary, root) = root();
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let (mut original, _writers, inherited) = prepare_restartable(&root, &budget).unwrap();
    through_publication_encoding(&mut original);
    original.step().unwrap();
    let directory = original.claim.directory().unwrap().path.clone();
    let private_path = directory.join("private-checkpoint-1.norito");
    let head_path = directory.join("phase-head-1.norito");
    let mut corrupted = fs::read(&private_path).unwrap();
    *corrupted.last_mut().unwrap() ^= 1;
    fs::write(&private_path, &corrupted).unwrap();
    // Update only the untrusted outer checksum so the actual AEAD verifier,
    // rather than an earlier byte-hash mismatch, rejects this complete source.
    let mut head: durable::Head = norito::decode_canonical(&fs::read(&head_path).unwrap()).unwrap();
    head.checkpoint_hash = Hash::new(&corrupted).into();
    let head_bytes = norito::encode_canonical(&head).unwrap();
    fs::write(&head_path, &head_bytes).unwrap();
    let public = fs::read(directory.join("publication.norito")).unwrap();
    let intent = fs::read(directory.join("producer-1-intent.norito")).unwrap();
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);

    let restored = prepare_with_sources(&root, &budget, inherited, HANDLE, 7).unwrap();
    let receiver = std::ptr::from_ref(&*restored);
    let private_pointer = restored.durable.private_source().as_ptr();
    let public_pointer = restored.durable.public_source().as_ptr();
    let admitted = budget.reserved_bytes();
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - admitted)
        .unwrap();
    let pending = restored.resume().unwrap_err();
    assert!(matches!(
        pending.cause,
        AttemptError::Local(LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(
            DkgCheckpointErrorV1::Encryption(iroha_crypto::encryption::Error::Decryption(_))
        ))
    ));
    assert_eq!(pending.owner.phase, Phase::Terminal);
    assert_eq!(std::ptr::from_ref(&*pending.owner), receiver);
    assert_eq!(
        pending.owner.durable.private_source().as_ptr(),
        private_pointer
    );
    assert_eq!(
        pending.owner.durable.public_source().as_ptr(),
        public_pointer
    );
    assert_eq!(pending.owner.durable.private_source(), corrupted);
    assert_eq!(pending.owner.durable.public_source(), public);
    assert!(pending.owner.prepared.is_some());
    assert!(pending.owner.local.is_none());
    // The canonical public graph is decoded before private AEAD verification;
    // its original prepared row containers have retired even on this later error.
    let terminal_reserved = budget.reserved_bytes();
    assert!(terminal_reserved < budget.limit_bytes());
    let pending = pending.owner.resume().unwrap_err();
    assert!(matches!(pending.cause, AttemptError::Phase));
    assert_eq!(budget.reserved_bytes(), terminal_reserved);
    assert_eq!(pending.owner.phase, Phase::Terminal);
    assert_eq!(std::ptr::from_ref(&*pending.owner), receiver);
    assert_eq!(
        pending.owner.durable.private_source().as_ptr(),
        private_pointer
    );
    assert_eq!(fs::read(&private_path).unwrap(), corrupted);
    assert_eq!(fs::read(&head_path).unwrap(), head_bytes);
    assert_eq!(
        fs::read(directory.join("publication.norito")).unwrap(),
        public
    );
    assert_eq!(
        fs::read(directory.join("producer-1-intent.norito")).unwrap(),
        intent
    );
    drop(pending);
    assert_eq!(budget.reserved_bytes(), blocker.remaining_bytes());
    drop(blocker);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_checkpoint_enclosing_refusal_keeps_the_prepared_owner_and_same_source_for_retry() {
    use norito::core::{DecodeAttemptErrorKind, PreparedDecodeError, with_decode_limits_scope};
    let (_temporary, root) = root();
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let (mut original, _writers, inherited) = prepare_restartable(&root, &budget).unwrap();
    through_publication_encoding(&mut original);
    original.step().unwrap();
    drop(original);
    let mut owner = prepare_with_sources(&root, &budget, inherited, HANDLE, 7).unwrap();
    let restored = &mut *owner;
    restored.claim.open_existing().unwrap();
    restored.phase = Phase::RestoringGeneration;
    assert!(
        restored.original_publications[0]
            .as_ref()
            .unwrap()
            .belongs_to(&budget)
    );
    assert!(
        restored.original_publications[1..]
            .iter()
            .all(Option::is_none)
    );
    let (_, head) = restored
        .durable
        .load_generation(restored.claim.read_directory().unwrap())
        .unwrap();
    let context = restored
        .authority
        .checkpoint_context(
            restored.finality.clock(),
            1,
            restored.signer_index,
            &restored.signer,
            HANDLE,
            7,
            head.context.public_output_hash,
            [0; 32],
            [0; 32],
            head.context.producer_intent_hash,
        )
        .unwrap();
    let public_limits = norito::canonical_decode_limits(restored.durable.public_source().len());
    restored.original_publications[0]
        .as_mut()
        .unwrap()
        .decode(restored.durable.public_source(), public_limits)
        .unwrap();
    let receiver = std::ptr::from_ref(&*restored);
    let private_pointer = restored.durable.private_source().as_ptr();
    let public_pointer = restored.durable.public_source().as_ptr();
    let original_rows = restored.original_publications[0]
        .as_ref()
        .unwrap()
        .publication()
        .unwrap()
        .recipient_keys
        .as_ptr();
    let source_hash = Hash::new(restored.durable.private_source());
    let mut noncanonical = restored.durable.public_source().to_vec();
    noncanonical.push(0);
    let canonical_error = norito::verify_exact_canonical_frame(
        restored.original_publications[0]
            .as_ref()
            .unwrap()
            .publication()
            .unwrap(),
        &noncanonical,
    )
    .unwrap_err();
    assert!(matches!(
        canonical_error,
        norito::Error::NonCanonicalEncoding
    ));
    let canonical_error = AttemptError::Local(LocalGlobalThresholdBeaconDkgErrorV1::Session(
        GlobalThresholdBeaconSessionError::Encoding(canonical_error),
    ));
    assert!(canonical_error.terminal(Phase::RestoringGeneration));
    let admitted = budget.reserved_bytes();
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - admitted)
        .unwrap();
    let capacity = budget.try_reserve_bytes(1).unwrap_err();
    let capacity = AttemptError::Local(LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(
        DkgCheckpointErrorV1::Admission(capacity),
    ));
    assert!(matches!(
        capacity,
        AttemptError::Local(LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(
            DkgCheckpointErrorV1::Admission(AllocationRefusal::Capacity { .. })
        ))
    ));
    assert!(!capacity.terminal(Phase::RestoringGeneration));
    let prepared = restored.prepared.take().unwrap();
    let private_limits = norito::canonical_decode_limits(restored.durable.private_source().len());
    let (prepared, error) =
        with_decode_limits_scope(norito::DecodeLimits::new(0, 0, 0, 0, 0), || {
            prepared.restore_generated(
                &context,
                restored.original_publications[0]
                    .as_ref()
                    .unwrap()
                    .publication()
                    .unwrap(),
                restored.durable.public_source(),
                restored.durable.private_source(),
                &restored.signer,
                private_limits,
            )
        })
        .err()
        .unwrap();
    assert!(matches!(
        error,
        LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(DkgCheckpointErrorV1::Decode(
            PreparedDecodeError::Codec(ref original)
        )) if original.kind() == DecodeAttemptErrorKind::EnclosingLimit
    ));
    let error = AttemptError::Local(error);
    assert!(!error.terminal(restored.phase));
    restored.prepared = Some(prepared);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    assert_eq!(restored.durable.private_source().as_ptr(), private_pointer);
    assert_eq!(Hash::new(restored.durable.private_source()), source_hash);
    assert_eq!(
        restored.original_publications[0]
            .as_ref()
            .unwrap()
            .publication()
            .unwrap()
            .recipient_keys
            .as_ptr(),
        original_rows
    );
    drop(error);
    drop(capacity);
    restored.step().unwrap();
    assert_eq!(restored.phase, Phase::PublicationDurable);
    assert_eq!(std::ptr::from_ref(&*restored), receiver);
    assert_eq!(restored.durable.public_source().as_ptr(), public_pointer);
    assert_eq!(restored.durable.private_source().as_ptr(), private_pointer);
    assert_eq!(Hash::new(restored.durable.private_source()), source_hash);
    assert!(restored.local.is_some());
    assert!(restored.prepared.is_none());
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    drop(owner);
    assert_eq!(budget.reserved_bytes(), blocker.remaining_bytes());
    drop(blocker);
    assert_eq!(budget.reserved_bytes(), 0);
}

struct RefusingRng {
    calls: usize,
}
impl rand::TryRngCore for RefusingRng {
    type Error = std::io::Error;
    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        self.calls += 1;
        Err(std::io::ErrorKind::WouldBlock.into())
    }
    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        self.calls += 1;
        Err(std::io::ErrorKind::WouldBlock.into())
    }
    fn try_fill_bytes(&mut self, _output: &mut [u8]) -> std::result::Result<(), Self::Error> {
        self.calls += 1;
        Err(std::io::ErrorKind::WouldBlock.into())
    }
}
impl rand::TryCryptoRng for RefusingRng {}

#[test]
fn checked_secret_failures_close_restore_but_actual_crypto_rng_refusals_remain_local() {
    let custody = ClaimError::Directory(seat_export::ExportError::Custody);
    assert!(AttemptError::Claim(custody).terminal(Phase::RestoringGeneration));
    use iroha_crypto::hybrid::{HybridError, HybridKeyPair, HybridSecretKey};
    use iroha_crypto::threshold_bls::{
        AdaptiveThresholdBlsParameters, BeaconPurpose, DasRenDealerSecret,
        DasRenSecretCoefficientsV1, MAX_DEALER_COEFFICIENTS_V1, ThresholdBlsError,
        ThresholdBlsSession,
    };
    // These controls exercise checked primitive causes, not disk/native authority.
    let error = HybridSecretKey::from_bytes([0; 32], [0; 2400])
        .err()
        .unwrap();
    assert_eq!(error, HybridError::InvalidX25519SecretKey);
    assert!(
        AttemptError::Local(LocalGlobalThresholdBeaconDkgErrorV1::Hybrid(error.clone()))
            .terminal(Phase::RestoringGeneration)
    );
    assert!(
        AttemptError::Local(LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(
            DkgCheckpointErrorV1::Hybrid(error)
        ))
        .terminal(Phase::RestoringGeneration)
    );
    let session =
        ThresholdBlsSession::<BeaconPurpose>::new([1; 32], [2; 32], [3; 32], 4, 2).unwrap();
    let parameters = AdaptiveThresholdBlsParameters::derive(&session).unwrap();
    let mut values = Zeroizing::new([[[0; 32]; 3]; MAX_DEALER_COEFFICIENTS_V1]);
    values[0][0] = [0xff; 32];
    let coefficients = DasRenSecretCoefficientsV1::new(values, 2).unwrap();
    let mut rng = RefusingRng { calls: 0 };
    let error =
        DasRenDealerSecret::from_coefficients_with_rng(&parameters, 1, coefficients, &mut rng)
            .err()
            .unwrap();
    assert_eq!(error, ThresholdBlsError::InvalidScalar);
    assert_eq!(rng.calls, 0);
    assert!(
        AttemptError::Local(LocalGlobalThresholdBeaconDkgErrorV1::Threshold(error))
            .terminal(Phase::RestoringGeneration)
    );
    assert!(
        AttemptError::Local(LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(
            DkgCheckpointErrorV1::Threshold(error)
        ))
        .terminal(Phase::RestoringGeneration)
    );
    let hybrid = HybridKeyPair::try_generate(&mut rng).err().unwrap();
    assert!(matches!(hybrid, HybridError::RandomBytes { .. }));
    assert_eq!(rng.calls, 1);
    assert!(
        !AttemptError::Local(LocalGlobalThresholdBeaconDkgErrorV1::Hybrid(hybrid.clone()))
            .terminal(Phase::RestoringGeneration)
    );
    assert!(
        !AttemptError::Local(LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(
            DkgCheckpointErrorV1::Hybrid(hybrid)
        ))
        .terminal(Phase::RestoringGeneration)
    );
    let threshold = DasRenDealerSecret::generate_with_rng(&parameters, 1, &mut rng)
        .err()
        .unwrap();
    assert_eq!(threshold, ThresholdBlsError::RandomnessUnavailable);
    assert_eq!(rng.calls, 2);
    assert!(
        !AttemptError::Local(LocalGlobalThresholdBeaconDkgErrorV1::Threshold(threshold))
            .terminal(Phase::RestoringGeneration)
    );
    assert!(
        !AttemptError::Local(LocalGlobalThresholdBeaconDkgErrorV1::Checkpoint(
            DkgCheckpointErrorV1::Threshold(threshold)
        ))
        .terminal(Phase::RestoringGeneration)
    );
}
