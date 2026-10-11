//! Drop/restart of genuine original private owners, exact equations and funded refusal controls.

use super::*;
use crate::{
    Algorithm,
    test_allocations::{allocations_during, with_allocation_failure, without_allocations},
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

fn parameters<P: ThresholdBlsPurpose>(n: u16) -> AdaptiveThresholdBlsParameters<P> {
    AdaptiveThresholdBlsParameters::derive(
        &ThresholdBlsSession::new([1; 32], [2; 32], [3; 32], n, (n - 1) / 3 + 1).unwrap(),
    )
    .unwrap()
}
fn signer() -> KeyPair {
    KeyPair::try_from_seed(vec![0x57; 32], Algorithm::BlsNormal).unwrap()
}
fn binding<P: ThresholdBlsPurpose>(
    parameters: &AdaptiveThresholdBlsParameters<P>,
    seat: u16,
    signer: &KeyPair,
    phase: u16,
) -> DkgCheckpointBindingV1 {
    // Primitive AEAD/context controls only: these synthetic context values are
    // not native execution evidence or a genesis provisioning authorization.
    DkgCheckpointBindingV1 {
        network_id: *parameters.session().network_id(),
        attempt_id: [4; 32],
        authority_generation: 7,
        session_id: *parameters.session().session_id(),
        roster_hash: *parameters.session().roster_hash(),
        seat_index: seat,
        lifecycle_key_hash: DkgCheckpointBindingV1::lifecycle_key_digest(signer.public_key())
            .unwrap(),
        provider_handle_hash: [11; 32],
        provider_revision: 19,
        start_height: 2,
        commitments_end_height: 3,
        deliveries_end_height: 4,
        acceptances_end_height: 5,
        source: DkgCheckpointSourceV1::ExecutedNativeTip {
            height: u64::from(phase) + 1,
            block_hash: [5; 32],
            core_hash: [7; 32],
            result_hash: [6; 32],
        },
        cutoff_height: 8,
        phase,
        public_output_hash: [8; 32],
        phase_input_hash: if phase == 1 { [0; 32] } else { [9; 32] },
        producer_intent_hash: [12; 32],
        previous_checkpoint_hash: if phase == 1 { [0; 32] } else { [10; 32] },
    }
}
fn warm_nonce() {
    let cipher = SymmetricEncryptor::<ChaCha20Poly1305>::new_with_key([0x35; 32]).unwrap();
    cipher
        .encrypt_easy_in_place(b"warm OS entropy only", &mut [0; 28])
        .unwrap();
}
fn private_is_erased<P: ThresholdBlsPurpose>(owner: &PreparedDkgSecretsCheckpointV1<P>) {
    assert!(is_zero(owner.work.0.as_slice()));
    let record = &owner.destination.record.as_slice()[0];
    assert_eq!(record.version, 0);
    assert_eq!(record.coefficient_count, 0);
    assert!(is_zero(&record.x25519_secret));
    assert!(is_zero(&record.mlkem768_secret));
    assert!(is_zero(&record.coefficients));
    assert!(is_zero(&record.contributions));
}

#[test]
fn genuine_owner_drop_and_private_file_restart_restores_exact_hybrid_and_dealer_at_both_bounds() {
    for n in [4, THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1] {
        let parameters = parameters::<BeaconPurpose>(n);
        let budget = AllocationBudget::new(512 * 1024);
        // The genuine prepared storage exists before either producer runs.
        let mut checkpoint = PreparedDkgSecretsCheckpointV1::new(&parameters, n, &budget).unwrap();
        let signer = signer();
        let binding = binding(&parameters, n, &signer, 1);
        let mut rng = ChaCha20Rng::from_seed([0x68; 32]);
        let recipient = HybridKeyPair::try_generate(&mut rng).unwrap();
        let original_public = recipient.public().clone();
        let (dealer, original_proof) =
            DasRenDealerSecret::generate_with_rng(&parameters, n, &mut rng).unwrap();
        let expected = dealer
            .private_share(&parameters, &original_proof, 1)
            .unwrap()
            .components_for_authenticated_encryption();
        let retained = budget.reserved_bytes();
        let blocker = budget
            .try_reserve_bytes(budget.limit_bytes() - retained)
            .unwrap();
        warm_nonce();
        without_allocations(|| {
            checkpoint
                .seal(&binding, &signer, &recipient, Some(&dealer), &[])
                .unwrap()
        });
        private_is_erased(&checkpoint);
        let original_cipher = checkpoint.encrypted_record().unwrap();
        assert_eq!(
            without_allocations(|| checkpoint.encrypted_record_for(&binding, &signer).unwrap()),
            original_cipher
        );
        let directory = tempfile::Builder::new()
            .prefix(".dkg-private-restart-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        // Unix mode controls apply only on Unix; this file/restart test runs on
        // every host and makes no claim about Windows ACL confinement.
        #[cfg(unix)]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("private-checkpoint.aead");
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        (&file).write_all(original_cipher).unwrap();
        file.sync_all().unwrap();
        drop(file);
        // Drop every original private producer and its allocation owner. The file
        // and original proof/public output are the only recovery inputs left.
        drop(dealer);
        drop(recipient);
        drop(checkpoint);
        drop(blocker);
        assert_eq!(budget.reserved_bytes(), 0);
        let encrypted = fs::read(path).unwrap();
        let secret_payload = Zeroizing::new(signer.private_key().try_payload().unwrap());
        let restored_key = PrivateKey::from_bytes(Algorithm::BlsNormal, &secret_payload).unwrap();
        let restored_signer = KeyPair::from_private_key(restored_key).unwrap();
        assert_eq!(signer.public_key(), restored_signer.public_key());
        drop(signer);
        let mut recovery = PreparedDkgSecretsCheckpointV1::new(&parameters, n, &budget).unwrap();
        let original_address = recovery.work.0.as_slice().as_ptr();
        let retained = budget.reserved_bytes();
        let blocker = budget
            .try_reserve_bytes(budget.limit_bytes() - retained)
            .unwrap();
        without_allocations(|| {
            recovery
                .restore(
                    &encrypted,
                    &binding,
                    &restored_signer,
                    &original_public,
                    std::slice::from_ref(&original_proof),
                    norito::canonical_decode_limits(encrypted.len()),
                )
                .unwrap()
        });
        assert_eq!(original_address, recovery.work.0.as_slice().as_ptr());
        private_is_erased(&recovery);
        let restored = recovery.finish().ok().unwrap();
        let (recipient, dealer, contributions) = restored.into_owners();
        assert!(contributions.as_slice().is_empty());
        assert!(contributions.belongs_to(&budget));
        assert_eq!(
            recipient.public().x25519_bytes(),
            original_public.x25519_bytes()
        );
        assert_eq!(
            recipient.public().kyber_bytes(),
            original_public.kyber_bytes()
        );
        let actual = without_allocations(|| {
            dealer
                .as_ref()
                .unwrap()
                .private_share(&parameters, &original_proof, 1)
                .unwrap()
        });
        assert_eq!(*actual.components_for_authenticated_encryption(), *expected);
        assert_eq!(
            dealer.as_ref().unwrap().coefficients.len(),
            usize::from(parameters.session().threshold())
        );
        drop(actual);
        drop(dealer);
        drop(recipient);
        drop(contributions);
        drop(blocker);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn accepted_contributions_restart_preserves_every_original_private_equation_without_allocation() {
    let parameters = parameters::<BeaconPurpose>(4);
    let signer = signer();
    let budget = AllocationBudget::new(512 * 1024);
    let mut checkpoint = PreparedDkgSecretsCheckpointV1::new(&parameters, 3, &budget).unwrap();
    let mut rng = ChaCha20Rng::from_seed([0x69; 32]);
    let recipient = HybridKeyPair::try_generate(&mut rng).unwrap();
    let public = recipient.public().clone();
    let dealers = (1..=4)
        .map(|i| DasRenDealerSecret::generate_with_rng(&parameters, i, &mut rng).unwrap())
        .collect::<Vec<_>>();
    let shares = dealers
        .iter()
        .map(|(secret, proof)| secret.private_share(&parameters, proof, 3).unwrap())
        .collect::<Vec<_>>();
    let expected = shares
        .iter()
        .map(DasRenPrivateShare::components_for_authenticated_encryption)
        .collect::<Vec<_>>();
    let proofs = dealers
        .iter()
        .map(|(_, proof)| proof.clone())
        .collect::<Vec<_>>();
    let binding = binding(&parameters, 3, &signer, 3);
    warm_nonce();
    without_allocations(|| {
        checkpoint
            .seal(&binding, &signer, &recipient, None, &shares)
            .unwrap()
    });
    let encrypted = checkpoint.encrypted_record().unwrap().to_vec();
    drop(shares);
    drop(dealers);
    drop(recipient);
    drop(checkpoint);
    assert_eq!(budget.reserved_bytes(), 0);
    let mut recovery = PreparedDkgSecretsCheckpointV1::new(&parameters, 3, &budget).unwrap();
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    without_allocations(|| {
        recovery
            .restore(
                &encrypted,
                &binding,
                &signer,
                &public,
                &proofs,
                norito::canonical_decode_limits(encrypted.len()),
            )
            .unwrap()
    });
    private_is_erased(&recovery);
    let (recipient, dealer, shares) = recovery.finish().ok().unwrap().into_owners();
    assert!(dealer.is_none());
    assert_eq!(recipient.public().x25519_bytes(), public.x25519_bytes());
    assert_eq!(recipient.public().kyber_bytes(), public.kyber_bytes());
    assert!(shares.belongs_to(&budget));
    assert_eq!(shares.as_slice().len(), 4);
    for (i, (share, expected)) in shares.as_slice().iter().zip(&expected).enumerate() {
        assert_eq!(share.dealer_index(), u16::try_from(i + 1).unwrap());
        assert_eq!(share.recipient_index(), 3);
        assert_eq!(*share.components_for_authenticated_encryption(), **expected);
    }
    drop(shares);
    drop(recipient);
    drop(blocker);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_cipher_and_counter_custody_survive_canonical_refusal_and_retry_without_reroll() {
    let parameters = parameters::<BeaconPurpose>(4);
    let signer = signer();
    let budget = AllocationBudget::new(512 * 1024);
    let mut checkpoint = PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &budget).unwrap();
    let mut rng = ChaCha20Rng::from_seed([0x6a; 32]);
    let recipient = HybridKeyPair::try_generate(&mut rng).unwrap();
    let (dealer, proof) = DasRenDealerSecret::generate_with_rng(&parameters, 1, &mut rng).unwrap();
    let binding = binding(&parameters, 1, &signer, 1);
    warm_nonce();
    checkpoint
        .seal(&binding, &signer, &recipient, Some(&dealer), &[])
        .unwrap();
    let encrypted = checkpoint.encrypted_record().unwrap().to_vec();
    let mut recovery = PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &budget).unwrap();
    let addresses = (
        recovery.source.0.as_slice().as_ptr(),
        recovery.work.0.as_slice().as_ptr(),
        recovery.destination.record.as_slice().as_ptr(),
        recovery.shares.as_ref().unwrap().as_slice().as_ptr(),
    );
    let retained = budget.reserved_bytes();
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - retained)
        .unwrap();
    let original_limits = norito::canonical_decode_limits(encrypted.len());
    let limits = norito::DecodeLimits::new(
        original_limits.max_sequence_elements(),
        1,
        original_limits.max_total_elements(),
        original_limits.max_total_allocated_bytes(),
        original_limits.max_nesting_depth(),
    );
    assert!(matches!(
        without_allocations(|| recovery.restore(
            &encrypted,
            &binding,
            &signer,
            recipient.public(),
            std::slice::from_ref(&proof),
            limits
        )),
        Err(DkgCheckpointErrorV1::Decode(_))
    ));
    private_is_erased(&recovery);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    let mut substituted = encrypted.clone();
    substituted[17] ^= 1;
    assert!(matches!(
        without_allocations(|| recovery.restore(
            &substituted,
            &binding,
            &signer,
            recipient.public(),
            std::slice::from_ref(&proof),
            norito::canonical_decode_limits(substituted.len())
        )),
        Err(DkgCheckpointErrorV1::Binding)
    ));
    without_allocations(|| {
        recovery
            .restore(
                &encrypted,
                &binding,
                &signer,
                recipient.public(),
                std::slice::from_ref(&proof),
                norito::canonical_decode_limits(encrypted.len()),
            )
            .unwrap()
    });
    assert_eq!(
        addresses,
        (
            recovery.source.0.as_slice().as_ptr(),
            recovery.work.0.as_slice().as_ptr(),
            recovery.destination.record.as_slice().as_ptr(),
            recovery.shares.as_ref().unwrap().as_slice().as_ptr()
        )
    );
    let owners = recovery.finish().ok().unwrap();
    drop(owners);
    drop(checkpoint);
    drop(dealer);
    drop(recipient);
    drop(blocker);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn complete_context_replay_corruption_wrong_original_proof_and_duplicate_production_are_refused() {
    let parameters = parameters::<BeaconPurpose>(4);
    let signer = signer();
    let budget = AllocationBudget::new(512 * 1024);
    let mut checkpoint = PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &budget).unwrap();
    let mut rng = ChaCha20Rng::from_seed([0x6b; 32]);
    let recipient = HybridKeyPair::try_generate(&mut rng).unwrap();
    let (dealer, proof) = DasRenDealerSecret::generate_with_rng(&parameters, 1, &mut rng).unwrap();
    let binding = binding(&parameters, 1, &signer, 1);
    warm_nonce();
    checkpoint
        .seal(&binding, &signer, &recipient, Some(&dealer), &[])
        .unwrap();
    let encrypted = checkpoint.encrypted_record().unwrap().to_vec();
    let original_address = checkpoint.encrypted_record().unwrap().as_ptr();
    assert!(matches!(
        without_allocations(|| checkpoint.seal(&binding, &signer, &recipient, Some(&dealer), &[])),
        Err(DkgCheckpointErrorV1::Terminal)
    ));
    assert_eq!(checkpoint.encrypted_record().unwrap(), &encrypted);
    assert_eq!(
        checkpoint.encrypted_record().unwrap().as_ptr(),
        original_address
    );
    assert_eq!(
        without_allocations(|| checkpoint.encrypted_record_for(&binding, &signer).unwrap()),
        encrypted.as_slice(),
        "the unchanged original context must retain its exact ciphertext"
    );
    let mut contexts = Vec::new();
    macro_rules! changed {
        ($field:ident, $value:expr) => {
            let mut changed = binding;
            changed.$field = $value;
            assert_ne!(
                changed,
                binding,
                "each replay fixture must change its original {} binding",
                stringify!($field)
            );
            contexts.push(changed);
        };
    }
    changed!(network_id, [0x11; 32]);
    changed!(attempt_id, [0x12; 32]);
    changed!(authority_generation, 8);
    changed!(session_id, [0x13; 32]);
    changed!(roster_hash, [0x14; 32]);
    changed!(seat_index, 2);
    changed!(lifecycle_key_hash, [0x15; 32]);
    changed!(provider_handle_hash, [0x24; 32]);
    changed!(provider_revision, 20);
    changed!(start_height, 0);
    changed!(commitments_end_height, 5);
    changed!(deliveries_end_height, 5);
    changed!(acceptances_end_height, 6);
    for source in [
        DkgCheckpointSourceV1::ExecutedNativeTip {
            height: 0,
            block_hash: [5; 32],
            core_hash: [7; 32],
            result_hash: [6; 32],
        },
        DkgCheckpointSourceV1::ExecutedNativeTip {
            height: 2,
            block_hash: [0x16; 32],
            core_hash: [7; 32],
            result_hash: [6; 32],
        },
        DkgCheckpointSourceV1::ExecutedNativeTip {
            height: 2,
            block_hash: [5; 32],
            core_hash: [7; 32],
            result_hash: [0x17; 32],
        },
        DkgCheckpointSourceV1::ExecutedNativeTip {
            height: 2,
            block_hash: [5; 32],
            core_hash: [0x18; 32],
            result_hash: [6; 32],
        },
        DkgCheckpointSourceV1::SignedGenesisAuthorization {
            genesis_hash: [1; 32],
        },
    ] {
        changed!(source, source);
    }
    changed!(cutoff_height, 5);
    changed!(phase, 2);
    changed!(public_output_hash, [0x19; 32]);
    changed!(phase_input_hash, [0x20; 32]);
    changed!(producer_intent_hash, [0x23; 32]);
    changed!(previous_checkpoint_hash, [0x21; 32]);
    for changed in contexts {
        assert!(
            without_allocations(|| checkpoint.encrypted_record_for(&changed, &signer)).is_err()
        );
        let mut recovery = PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &budget).unwrap();
        assert!(
            without_allocations(|| recovery.restore(
                &encrypted,
                &changed,
                &signer,
                recipient.public(),
                std::slice::from_ref(&proof),
                norito::canonical_decode_limits(encrypted.len())
            ))
            .is_err()
        );
        private_is_erased(&recovery);
        assert!(recovery.finish().is_err());
    }
    let mut corrupt = encrypted.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    let mut recovery = PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &budget).unwrap();
    assert!(matches!(
        without_allocations(|| recovery.restore(
            &corrupt,
            &binding,
            &signer,
            recipient.public(),
            std::slice::from_ref(&proof),
            norito::canonical_decode_limits(corrupt.len())
        )),
        Err(DkgCheckpointErrorV1::Encryption(_))
    ));
    private_is_erased(&recovery);
    drop(recovery);
    let (_, foreign_proof) =
        DasRenDealerSecret::generate_with_rng(&parameters, 1, &mut rng).unwrap();
    let mut recovery = PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &budget).unwrap();
    assert!(matches!(
        without_allocations(|| recovery.restore(
            &encrypted,
            &binding,
            &signer,
            recipient.public(),
            std::slice::from_ref(&foreign_proof),
            norito::canonical_decode_limits(encrypted.len())
        )),
        Err(DkgCheckpointErrorV1::Threshold(
            ThresholdBlsError::InvalidCoefficientCommitment
        ))
    ));
    private_is_erased(&recovery);
    drop(recovery);
    let foreign_recipient = HybridKeyPair::try_generate(&mut rng).unwrap();
    let mut recovery = PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &budget).unwrap();
    assert!(matches!(
        without_allocations(|| recovery.restore(
            &encrypted,
            &binding,
            &signer,
            foreign_recipient.public(),
            std::slice::from_ref(&proof),
            norito::canonical_decode_limits(encrypted.len())
        )),
        Err(DkgCheckpointErrorV1::Binding)
    ));
    private_is_erased(&recovery);
    drop(recovery);
    // Admit independently valid public keys with only one foreign component.
    // Both exact components must match the restored original private owner.
    let mixed_recipients = [
        HybridPublicKey::from_bytes(
            foreign_recipient.public().x25519_bytes(),
            recipient.public().kyber_bytes(),
        )
        .unwrap(),
        HybridPublicKey::from_bytes(
            recipient.public().x25519_bytes(),
            foreign_recipient.public().kyber_bytes(),
        )
        .unwrap(),
    ];
    for mixed_recipient in mixed_recipients {
        let mut recovery = PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &budget).unwrap();
        assert!(matches!(
            without_allocations(|| recovery.restore(
                &encrypted,
                &binding,
                &signer,
                &mixed_recipient,
                std::slice::from_ref(&proof),
                norito::canonical_decode_limits(encrypted.len())
            )),
            Err(DkgCheckpointErrorV1::Binding)
        ));
        private_is_erased(&recovery);
        assert!(recovery.finish().is_err());
    }
    drop(foreign_recipient);
    drop(checkpoint);
    drop(dealer);
    drop(recipient);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn exact_physical_prepare_refusal_covers_every_backing_and_control_without_secret_production() {
    let parameters = parameters::<BeaconPurpose>(4);
    let budget = AllocationBudget::new(512 * 1024);
    let (prepared, allocations) = allocations_during(|| {
        PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &budget).unwrap()
    });
    assert_eq!(allocations, 6);
    assert!(prepared.belongs_to(&budget));
    assert!(!prepared.belongs_to(&AllocationBudget::new(512 * 1024)));
    let envelope_len = prepared.source.0.capacity();
    let exact = budget.reserved_bytes();
    drop(prepared);
    assert_eq!(budget.reserved_bytes(), 0);
    let too_small = AllocationBudget::new(exact - 1);
    assert!(matches!(
        PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &too_small),
        Err(DkgCheckpointErrorV1::Admission(_))
    ));
    assert_eq!(too_small.reserved_bytes(), 0);
    for size in [
        envelope_len,
        std::mem::size_of::<PrivateRecord>(),
        std::mem::size_of::<DasRenPrivateShare<BeaconPurpose>>() * 4,
        PreparedDecodeWorkspace::allocation_layouts()[0].size(),
    ] {
        let result = with_allocation_failure(size, || {
            PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &budget)
        });
        assert!(result.is_err(), "refuse each actual allocation layout");
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let prepared = PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &budget).unwrap();
    assert!(prepared.finish().is_err());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn both_purposes_refuse_changed_original_coefficient_without_a_new_schnorr_proof() {
    fn check<P: ThresholdBlsPurpose>() {
        let parameters = parameters::<P>(4);
        let mut rng = ChaCha20Rng::from_seed([0x6c; 32]);
        let (original, proof) =
            DasRenDealerSecret::generate_with_rng(&parameters, 1, &mut rng).unwrap();
        let unchanged = original.coefficients.values.clone();
        let restored = without_allocations(|| {
            restore_original_dealer(
                &parameters,
                &proof,
                DasRenSecretCoefficientsV1::new(unchanged, 2).unwrap(),
            )
            .unwrap()
        });
        assert_eq!(
            restored.coefficients.as_slice(),
            original.coefficients.as_slice()
        );
        let mut changed = original.coefficients.values.clone();
        changed[1][0] = Scalar::from(42_u64).to_bytes_be();
        assert!(matches!(
            without_allocations(|| restore_original_dealer(
                &parameters,
                &proof,
                DasRenSecretCoefficientsV1::new(changed, 2).unwrap()
            )),
            Err(ThresholdBlsError::InvalidCoefficientCommitment)
        ));
    }
    check::<BeaconPurpose>();
    check::<TleReleasePurpose>();
}

#[test]
fn signed_genesis_context_preserves_wider_cutoff_without_accepting_fake_h1_execution() {
    // Primitive context geometry only. Core separately authenticates the signed
    // body; these raw values never grant protocol authority or certify a result.
    let parameters = parameters::<BeaconPurpose>(4);
    let signer = signer();
    let budget = AllocationBudget::new(512 * 1024);
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let recipient = HybridKeyPair::try_generate(&mut rng).unwrap();
    let (dealer, proof) = DasRenDealerSecret::generate_with_rng(&parameters, 1, &mut rng).unwrap();
    let mut context = binding(&parameters, 1, &signer, 1);
    context.authority_generation = 0;
    context.start_height = 1;
    context.commitments_end_height = 2;
    context.deliveries_end_height = 3;
    context.acceptances_end_height = 4;
    context.source = DkgCheckpointSourceV1::SignedGenesisAuthorization {
        genesis_hash: context.network_id,
    };
    let mut checkpoint = PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &budget).unwrap();
    warm_nonce();
    without_allocations(|| {
        checkpoint
            .seal(&context, &signer, &recipient, Some(&dealer), &[])
            .unwrap()
    });
    let ciphertext = checkpoint.encrypted_record().unwrap().to_vec();
    for mutation in 0..6 {
        let mut wrong = context;
        match mutation {
            0 => {
                wrong.source = DkgCheckpointSourceV1::SignedGenesisAuthorization {
                    genesis_hash: [0x72; 32],
                }
            }
            1 => {
                wrong.source = DkgCheckpointSourceV1::ExecutedNativeTip {
                    height: 1,
                    block_hash: [0x73; 32],
                    core_hash: [0x74; 32],
                    result_hash: [0x75; 32],
                }
            }
            2 => wrong.cutoff_height = wrong.acceptances_end_height,
            3 => wrong.authority_generation = 1,
            4 => wrong.producer_intent_hash = [0; 32],
            _ => wrong.provider_handle_hash = [0; 32],
        }
        let mut recovery = PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &budget).unwrap();
        assert!(
            without_allocations(|| recovery.restore(
                &ciphertext,
                &wrong,
                &signer,
                recipient.public(),
                std::slice::from_ref(&proof),
                norito::canonical_decode_limits(ciphertext.len())
            ))
            .is_err()
        );
        private_is_erased(&recovery);
        assert!(recovery.take_restored_generation_owners().is_err());
    }
    let mut recovery = PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &budget).unwrap();
    without_allocations(|| {
        recovery
            .restore(
                &ciphertext,
                &context,
                &signer,
                recipient.public(),
                std::slice::from_ref(&proof),
                norito::canonical_decode_limits(ciphertext.len()),
            )
            .unwrap()
    });
    assert_eq!(
        recovery.encrypted_record_for(&context, &signer).unwrap(),
        ciphertext
    );
    private_is_erased(&recovery);
}

#[test]
fn generation_owner_take_keeps_original_chained_ciphertext_and_moves_secrets_once_at_both_bounds() {
    for n in [4, THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1] {
        let parameters = parameters::<BeaconPurpose>(n);
        let signer = signer();
        let budget = AllocationBudget::new(512 * 1024);
        let mut rng = ChaCha20Rng::from_seed([0x76; 32]);
        let recipient = HybridKeyPair::try_generate(&mut rng).unwrap();
        let (dealer, proof) =
            DasRenDealerSecret::generate_with_rng(&parameters, n, &mut rng).unwrap();
        let expected = dealer
            .private_share(&parameters, &proof, 1)
            .unwrap()
            .components_for_authenticated_encryption();
        let context = binding(&parameters, n, &signer, 1);
        let mut original = PreparedDkgSecretsCheckpointV1::new(&parameters, n, &budget).unwrap();
        warm_nonce();
        original
            .seal(&context, &signer, &recipient, Some(&dealer), &[])
            .unwrap();
        let bytes = original.encrypted_record().unwrap().to_vec();
        drop(original);
        drop(dealer);
        let mut recovery = PreparedDkgSecretsCheckpointV1::new(&parameters, n, &budget).unwrap();
        let retained = budget.reserved_bytes();
        let blocker = budget
            .try_reserve_bytes(budget.limit_bytes() - retained)
            .unwrap();
        without_allocations(|| {
            recovery
                .restore(
                    &bytes,
                    &context,
                    &signer,
                    recipient.public(),
                    std::slice::from_ref(&proof),
                    norito::canonical_decode_limits(bytes.len()),
                )
                .unwrap()
        });
        let address = recovery.encrypted_record().unwrap().as_ptr();
        let (restored_recipient, restored_dealer) =
            without_allocations(|| recovery.take_restored_generation_owners().unwrap());
        assert_eq!(
            restored_recipient.public().x25519_bytes(),
            recipient.public().x25519_bytes()
        );
        assert_eq!(
            restored_recipient.public().kyber_bytes(),
            recipient.public().kyber_bytes()
        );
        let actual = without_allocations(|| {
            restored_dealer
                .private_share(&parameters, &proof, 1)
                .unwrap()
                .components_for_authenticated_encryption()
        });
        assert_eq!(*actual, *expected);
        assert_eq!(
            recovery.encrypted_record_for(&context, &signer).unwrap(),
            bytes
        );
        assert_eq!(recovery.encrypted_record().unwrap().as_ptr(), address);
        assert!(matches!(
            without_allocations(|| recovery.take_restored_generation_owners()),
            Err(DkgCheckpointErrorV1::Terminal)
        ));
        private_is_erased(&recovery);
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(restored_recipient);
        drop(restored_dealer);
        drop(recovery);
        drop(recipient);
        drop(blocker);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn checkpoint_source_stays_bounded_inline_and_roundtrips_distinct_authorization_kinds() {
    // A real native source has three independent hashes; signed H1 has only its
    // body hash. Keeping that distinction needs neither heap custody nor fake R.
    assert!(std::mem::size_of::<DkgCheckpointSourceV1>() <= 112);
    assert!(std::mem::align_of::<DkgCheckpointSourceV1>() <= 8);
    let genesis = DkgCheckpointSourceV1::SignedGenesisAuthorization {
        genesis_hash: [0x35; 32],
    };
    let native = DkgCheckpointSourceV1::ExecutedNativeTip {
        height: 9,
        block_hash: [0x35; 32],
        core_hash: [0x36; 32],
        result_hash: [0x37; 32],
    };
    let genesis_bytes = norito::encode_canonical(&genesis).unwrap();
    let native_bytes = norito::encode_canonical(&native).unwrap();
    assert_ne!(genesis_bytes, native_bytes);
    for (source, bytes, height) in [(genesis, genesis_bytes, 1), (native, native_bytes, 9)] {
        let decoded: DkgCheckpointSourceV1 = norito::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, source);
        assert_eq!(decoded.height(), height);
        norito::verify_exact_canonical_frame(&decoded, &bytes).unwrap();
    }
}

#[test]
fn original_delivered_owner_take_keeps_polynomial_and_ciphertext_once_at_four_and_thirty_one() {
    for n in [4, THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1] {
        let parameters = parameters::<BeaconPurpose>(n);
        let signer = signer();
        let mut rng = ChaCha20Rng::from_seed([0x79; 32]);
        let recipient = HybridKeyPair::try_generate(&mut rng).unwrap();
        let originals = (1..=n)
            .map(|seat| DasRenDealerSecret::generate_with_rng(&parameters, seat, &mut rng).unwrap())
            .collect::<Vec<_>>();
        let proofs = originals
            .iter()
            .map(|(_, proof)| proof.clone())
            .collect::<Vec<_>>();
        let expected = originals[usize::from(n - 1)]
            .0
            .private_share(&parameters, &proofs[usize::from(n - 1)], 1)
            .unwrap()
            .components_for_authenticated_encryption();
        let budget = AllocationBudget::new(512 * 1024);
        let mut context = binding(&parameters, n, &signer, 2);
        let mut producer = PreparedDkgSecretsCheckpointV1::new(&parameters, n, &budget).unwrap();
        assert!(matches!(
            producer.seal(&context, &signer, &recipient, None, &[]),
            Err(DkgCheckpointErrorV1::Binding)
        ));
        assert!(
            producer.binding.is_none(),
            "phase-two polynomial cannot be retired before its private head"
        );
        warm_nonce();
        producer
            .seal(
                &context,
                &signer,
                &recipient,
                Some(&originals[usize::from(n - 1)].0),
                &[],
            )
            .unwrap();
        let encrypted = producer.encrypted_record().unwrap().to_vec();
        drop(producer);
        drop(originals);
        let mut restored = PreparedDkgSecretsCheckpointV1::new(&parameters, n, &budget).unwrap();
        let blocker = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        without_allocations(|| {
            restored
                .restore(
                    &encrypted,
                    &context,
                    &signer,
                    recipient.public(),
                    &proofs,
                    norito::canonical_decode_limits(encrypted.len()),
                )
                .unwrap()
        });
        let address = restored.encrypted_record().unwrap().as_ptr();
        assert!(matches!(
            without_allocations(|| restored.take_restored_generation_owners()),
            Err(DkgCheckpointErrorV1::Terminal)
        ));
        let (key, dealer) =
            without_allocations(|| restored.take_restored_delivery_owners().unwrap());
        let actual = without_allocations(|| {
            dealer
                .private_share(&parameters, &proofs[usize::from(n - 1)], 1)
                .unwrap()
                .components_for_authenticated_encryption()
        });
        assert_eq!(*actual, *expected);
        assert_eq!(key.public().kyber_bytes(), recipient.public().kyber_bytes());
        assert_eq!(
            restored.encrypted_record_for(&context, &signer).unwrap(),
            encrypted
        );
        assert_eq!(restored.encrypted_record().unwrap().as_ptr(), address);
        assert!(matches!(
            without_allocations(|| restored.take_restored_delivery_owners()),
            Err(DkgCheckpointErrorV1::Terminal)
        ));
        context.previous_checkpoint_hash[0] ^= 1;
        assert!(restored.encrypted_record_for(&context, &signer).is_err());
        private_is_erased(&restored);
        drop(dealer);
        drop(key);
        drop(restored);
        drop(recipient);
        drop(blocker);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn original_accepted_bank_exchanges_exact_same_pool_backing_after_every_capsule_component_check() {
    for n in [4, THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1] {
        let parameters = parameters::<BeaconPurpose>(n);
        let signer = signer();
        let mut rng = ChaCha20Rng::from_seed([0x7a; 32]);
        let recipient = HybridKeyPair::try_generate(&mut rng).unwrap();
        let originals = (1..=n)
            .map(|seat| DasRenDealerSecret::generate_with_rng(&parameters, seat, &mut rng).unwrap())
            .collect::<Vec<_>>();
        let proofs = originals
            .iter()
            .map(|(_, proof)| proof.clone())
            .collect::<Vec<_>>();
        let shares = originals
            .iter()
            .map(|(dealer, proof)| dealer.private_share(&parameters, proof, n).unwrap())
            .collect::<Vec<_>>();
        let budget = AllocationBudget::new(512 * 1024);
        let context = binding(&parameters, n, &signer, 3);
        let mut producer = PreparedDkgSecretsCheckpointV1::new(&parameters, n, &budget).unwrap();
        warm_nonce();
        producer
            .seal(&context, &signer, &recipient, None, &shares)
            .unwrap();
        let encrypted = producer.encrypted_record().unwrap().to_vec();
        drop(producer);
        let mut restored = PreparedDkgSecretsCheckpointV1::new(&parameters, n, &budget).unwrap();
        let mut empty = ChargedBuffer::new(usize::from(n), &budget).unwrap();
        let mut occupied = ChargedBuffer::new(usize::from(n), &budget).unwrap();
        occupied.push_reserved(
            originals[0]
                .0
                .private_share(&parameters, &proofs[0], n)
                .unwrap(),
        );
        let foreign_budget = AllocationBudget::new(512 * 1024);
        let mut foreign = ChargedBuffer::new(usize::from(n), &foreign_budget).unwrap();
        let blocker = budget
            .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .unwrap();
        without_allocations(|| {
            restored
                .restore(
                    &encrypted,
                    &context,
                    &signer,
                    recipient.public(),
                    &proofs,
                    norito::canonical_decode_limits(encrypted.len()),
                )
                .unwrap()
        });
        let filled_pointer = restored.shares.as_ref().unwrap().as_slice().as_ptr();
        let empty_pointer = empty.as_slice().as_ptr();
        let ciphertext_pointer = restored.encrypted_record().unwrap().as_ptr();
        for (index, share) in shares.iter().enumerate() {
            without_allocations(|| {
                restored
                    .verify_restored_accepted_contribution(index, share)
                    .unwrap()
            });
        }
        assert!(
            restored
                .verify_restored_accepted_contribution(0, &shares[1])
                .is_err()
        );
        assert!(
            restored
                .verify_restored_accepted_contribution(usize::from(n), &shares[0])
                .is_err()
        );
        assert!(matches!(
            without_allocations(|| restored.take_restored_accepted_owners(&mut occupied, &budget)),
            Err(DkgCheckpointErrorV1::Binding)
        ));
        assert!(matches!(
            without_allocations(|| restored.take_restored_accepted_owners(&mut foreign, &budget)),
            Err(DkgCheckpointErrorV1::Binding)
        ));
        assert_eq!(
            restored.shares.as_ref().unwrap().as_slice().as_ptr(),
            filled_pointer
        );
        assert_eq!(empty.as_slice().as_ptr(), empty_pointer);
        assert_eq!(
            restored.encrypted_record().unwrap().as_ptr(),
            ciphertext_pointer
        );
        let key = without_allocations(|| {
            restored
                .take_restored_accepted_owners(&mut empty, &budget)
                .unwrap()
        });
        assert_eq!(empty.as_slice().as_ptr(), filled_pointer);
        assert_eq!(
            restored.shares.as_ref().unwrap().as_slice().as_ptr(),
            empty_pointer
        );
        assert!(restored.shares.as_ref().unwrap().as_slice().is_empty());
        for (actual, original) in empty.as_slice().iter().zip(&shares) {
            assert_eq!(
                *actual.components_for_authenticated_encryption(),
                *original.components_for_authenticated_encryption()
            );
        }
        assert_eq!(
            restored.encrypted_record_for(&context, &signer).unwrap(),
            encrypted
        );
        assert_eq!(
            restored.encrypted_record().unwrap().as_ptr(),
            ciphertext_pointer
        );
        assert!(matches!(
            without_allocations(|| restored.take_restored_accepted_owners(&mut empty, &budget)),
            Err(DkgCheckpointErrorV1::Terminal)
        ));
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        private_is_erased(&restored);
        drop(empty);
        drop(occupied);
        drop(restored);
        drop(key);
        drop(recipient);
        drop(blocker);
        assert_eq!(budget.reserved_bytes(), 0);
        drop(foreign);
        assert_eq!(foreign_budget.reserved_bytes(), 0);
    }
}

// Fixed stack leaves retain the ordinary field/depth admissions, but no aligned
// archived copy is needed. The refusal remains the destination's nominal cause.
#[derive(Default)]
struct FixedSourceFields {
    refuse: Option<usize>,
    visited: [usize; 5],
    count: usize,
}
impl FieldDestination for FixedSourceFields {
    type Error = usize;
}
macro_rules! fixed_source_field {
    ($index:literal, [u8; $len:literal]) => {
        fixed_source_field!(@impl $index, [u8; $len], field => {
            field.decode_owned().map_err(DecodeIntoError::Codec)
        });
    };
    ($index:literal, $ty:ty) => {
        fixed_source_field!(@impl $index, $ty, field => {
            field.with_payload(|bytes| {
                let (value, used) = <$ty as DecodeFromSlice>::decode_from_slice(bytes)?;
                if used != bytes.len() {
                    return Err(norito::Error::LengthMismatch.into());
                }
                Ok(value)
            })
        });
    };
    (@impl $index:literal, $ty:ty, $field:ident => $decode:expr) => {
        impl DecodeField<$index, $ty> for FixedSourceFields {
            type Value = $ty;
            fn decode_field(
                &mut self,
                $field: CanonicalField<'_, $ty>,
            ) -> Result<$ty, DecodeIntoError<usize>> {
                self.visited[self.count] = $index;
                self.count += 1;
                if self.refuse == Some($index) {
                    return Err(DecodeIntoError::Destination($index));
                }
                $decode
            }
        }
    };
}
fixed_source_field!(0, [u8; 32]);
fixed_source_field!(1, u64);
fixed_source_field!(2, [u8; 32]);
fixed_source_field!(3, [u8; 32]);
fixed_source_field!(4, [u8; 32]);

fn fixed_source_rows() -> [(DkgCheckpointSourceV1, Vec<u8>, &'static [usize]); 2] {
    let genesis = DkgCheckpointSourceV1::SignedGenesisAuthorization {
        genesis_hash: [0x35; 32],
    };
    let native = DkgCheckpointSourceV1::ExecutedNativeTip {
        height: 9,
        block_hash: [0x35; 32],
        core_hash: [0x36; 32],
        result_hash: [0x37; 32],
    };
    // Independently spell the unchanged default V1 enum payloads: little-endian
    // u32 tags, compact field lengths and raw fixed byte-array variant fields.
    let mut genesis_payload = vec![0, 0, 0, 0, 32];
    genesis_payload.extend_from_slice(&[0x35; 32]);
    let mut native_payload = vec![1, 0, 0, 0, 8];
    native_payload.extend_from_slice(&9_u64.to_le_bytes());
    for byte in [0x35, 0x36, 0x37] {
        native_payload.push(32);
        native_payload.extend_from_slice(&[byte; 32]);
    }
    assert_eq!(genesis_payload.len(), 37);
    assert_eq!(native_payload.len(), 112);
    [
        (genesis, genesis_payload, &[0]),
        (native, native_payload, &[1, 2, 3, 4]),
    ]
}

#[test]
fn checkpoint_source_shared_walk_preserves_literal_v1_bytes_and_allocation_free_prepared_leaves() {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    for (source, literal, indices) in fixed_source_rows() {
        let mut actual = Vec::new();
        norito::core::serialize_to_writer(&source, &mut actual).unwrap();
        assert_eq!(actual, literal);
        let mut destination = FixedSourceFields::default();
        let (decoded, used) = without_allocations(|| {
            DkgCheckpointSourceV1::decode_fields(&literal, &mut destination).unwrap()
        });
        assert_eq!(decoded, source);
        assert_eq!(used, literal.len());
        assert_eq!(&destination.visited[..destination.count], indices);
        let (ordinary, ordinary_used) =
            DkgCheckpointSourceV1::decode_fields(&literal, &mut norito::core::OwnedFields).unwrap();
        assert_eq!(ordinary, decoded);
        assert_eq!(ordinary_used, used);
        // Exercise the ordinary infallible bridge with its existing prepared
        // archived footprint. This setup is deliberately outside the allocation
        // observation; it is not the prepaid destination entry above.
        let prepared = norito::core::prepare_decode_from_slice(
            &literal,
            norito::core::archived_payload_size::<DkgCheckpointSourceV1>(),
            norito::core::archived_payload_align::<DkgCheckpointSourceV1>(),
        )
        .unwrap();
        {
            let _payload = norito::core::PayloadCtxGuard::enter_with_len(
                prepared.bytes(),
                prepared.logical_len(),
            );
            assert_eq!(
                <DkgCheckpointSourceV1 as norito::core::DeserializePayload>::deserialize(
                    prepared.archived::<DkgCheckpointSourceV1>(),
                ),
                source,
            );
        }
        let frame = norito::encode_canonical(&source).unwrap();
        assert_eq!(
            norito::decode_canonical::<DkgCheckpointSourceV1>(&frame).unwrap(),
            source
        );
        norito::verify_exact_canonical_frame(&decoded, &frame).unwrap();
    }
}

#[test]
fn checkpoint_source_shared_walk_rejects_every_truncation_trailing_byte_and_invalid_tag() {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    for (_, payload, _) in fixed_source_rows() {
        for end in 0..payload.len() {
            let mut destination = FixedSourceFields::default();
            assert!(
                without_allocations(|| {
                    DkgCheckpointSourceV1::decode_fields(&payload[..end], &mut destination)
                })
                .is_err()
            );
        }
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(matches!(
            without_allocations(|| {
                DkgCheckpointSourceV1::decode_fields(&trailing, &mut FixedSourceFields::default())
            }),
            Err(DecodeIntoError::Codec(norito::Error::LengthMismatch))
        ));
        let mut invalid = payload;
        invalid[..4].copy_from_slice(&2_u32.to_le_bytes());
        let mut destination = FixedSourceFields::default();
        assert!(matches!(
            DkgCheckpointSourceV1::decode_fields(&invalid, &mut destination),
            Err(DecodeIntoError::Codec(norito::Error::Message(message)))
                if message == "invalid enum discriminant"
        ));
        assert_eq!(destination.count, 0);
    }
}

#[test]
fn checkpoint_source_shared_walk_preserves_each_original_destination_refusal_without_later_fields()
{
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    for (_, payload, indices) in fixed_source_rows() {
        for (position, &index) in indices.iter().enumerate() {
            let mut destination = FixedSourceFields {
                refuse: Some(index),
                ..FixedSourceFields::default()
            };
            assert!(matches!(without_allocations(|| {
                DkgCheckpointSourceV1::decode_fields(&payload, &mut destination)
            }), Err(DecodeIntoError::Destination(cause)) if cause == index));
            assert_eq!(
                &destination.visited[..destination.count],
                &indices[..=position]
            );
            destination = FixedSourceFields::default();
            assert!(
                without_allocations(|| {
                    DkgCheckpointSourceV1::decode_fields(&payload, &mut destination)
                })
                .is_ok()
            );
            assert_eq!(&destination.visited[..destination.count], indices);
        }
    }
}

#[test]
fn checkpoint_source_raw_hash_fields_reject_wrong_widths_and_generic_array_framing() {
    for flags in [0, norito::core::header_flags::COMPACT_LEN] {
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        for (source, _, indices) in fixed_source_rows() {
            let mut payload = Vec::new();
            norito::core::serialize_to_writer(&source, &mut payload).unwrap();
            let mut offset = 4;
            for (position, &index) in indices.iter().enumerate() {
                let frame_start = offset;
                let (length, prefix) =
                    norito::core::inspect_len_from_slice(&payload[offset..]).unwrap();
                let body_start = offset + prefix;
                let end = body_start + length;
                offset = end;
                if index == 1 {
                    continue;
                }
                let hash: [u8; 32] = payload[body_start..end].try_into().unwrap();
                let mut oversized = hash.to_vec();
                oversized.push(0xaa);
                let mut generic_array = Vec::new();
                norito::core::serialize_to_writer(&hash, &mut generic_array).unwrap();
                assert_ne!(generic_array.len(), hash.len());
                for body in [hash[..31].to_vec(), oversized, generic_array] {
                    let mut malformed = payload[..frame_start].to_vec();
                    norito::core::write_len_header_to_vec(&mut malformed, body.len() as u64);
                    malformed.extend_from_slice(&body);
                    malformed.extend_from_slice(&payload[end..]);
                    let mut destination = FixedSourceFields::default();
                    assert!(matches!(
                        without_allocations(|| {
                            DkgCheckpointSourceV1::decode_fields(&malformed, &mut destination)
                        }),
                        Err(DecodeIntoError::Codec(norito::Error::LengthMismatch))
                    ));
                    assert_eq!(
                        &destination.visited[..destination.count],
                        &indices[..position],
                        "invalid raw field reached its destination or a later field"
                    );
                    assert!(matches!(
                        DkgCheckpointSourceV1::decode_fields(
                            &malformed,
                            &mut norito::core::OwnedFields,
                        ),
                        Err(DecodeIntoError::Codec(norito::Error::LengthMismatch))
                    ));
                }
            }
        }
    }
}

#[test]
fn phase_checkpoint_bound_matches_original_physical_source_without_preparing_private_graph() {
    for n in [4, THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1] {
        let parameters = parameters::<BeaconPurpose>(n);
        let bound = without_allocations(|| {
            PreparedDkgSecretsCheckpointV1::<BeaconPurpose>::encrypted_record_bound().unwrap()
        });
        let pool = AllocationBudget::new(512 * 1024);
        let checkpoint = PreparedDkgSecretsCheckpointV1::new(&parameters, n, &pool).unwrap();
        assert_eq!(bound, checkpoint.encrypted_record_capacity());
        drop(checkpoint);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn unfinished_finish_returns_the_same_prepaid_owner_without_allocating_or_refunding() {
    let parameters = parameters::<BeaconPurpose>(4);
    let budget = AllocationBudget::new(512 * 1024);
    let prepared = PreparedDkgSecretsCheckpointV1::new(&parameters, 1, &budget).unwrap();
    let source = prepared.source.0.as_slice().as_ptr();
    let work = prepared.work.0.as_slice().as_ptr();
    let destination = prepared.destination.record.as_slice().as_ptr();
    let shares = prepared.shares.as_ref().unwrap().as_slice().as_ptr();
    let reserved = budget.reserved_bytes();

    let returned = without_allocations(|| prepared.finish().err().unwrap());
    assert!(returned.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(returned.source.0.as_slice().as_ptr(), source);
    assert_eq!(returned.work.0.as_slice().as_ptr(), work);
    assert_eq!(returned.destination.record.as_slice().as_ptr(), destination);
    assert_eq!(
        returned.shares.as_ref().unwrap().as_slice().as_ptr(),
        shares
    );
    private_is_erased(&returned);

    let returned = without_allocations(|| returned.finish().err().unwrap());
    assert!(returned.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(returned.source.0.as_slice().as_ptr(), source);
    assert_eq!(returned.work.0.as_slice().as_ptr(), work);
    assert_eq!(returned.destination.record.as_slice().as_ptr(), destination);
    assert_eq!(
        returned.shares.as_ref().unwrap().as_slice().as_ptr(),
        shares
    );
    private_is_erased(&returned);
    drop(returned);
    assert_eq!(budget.reserved_bytes(), 0);
}
