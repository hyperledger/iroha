//! Genuine aggregate production, immutable file restart and exact original physical refusals.

use super::*;
use crate::{
    Algorithm,
    test_allocations::{allocations_during, with_allocation_failure, without_allocations},
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

struct Fixture {
    parameters: AdaptiveThresholdBlsParameters<BeaconPurpose>,
    transcript: AdaptiveThresholdBlsPublicTranscript<BeaconPurpose>,
    shares: Vec<DasRenPrivateShare<BeaconPurpose>>,
    signer: KeyPair,
    binding: DkgAggregateCheckpointBindingV1,
}
fn fixture(n: u16) -> Fixture {
    let parameters = AdaptiveThresholdBlsParameters::derive(
        &ThresholdBlsSession::new([1; 32], [2; 32], [3; 32], n, (n - 1) / 3 + 1).unwrap(),
    )
    .unwrap();
    let mut rng = ChaCha20Rng::from_seed([0x41; 32]);
    let producers = (1..=n)
        .map(|index| DasRenDealerSecret::generate_with_rng(&parameters, index, &mut rng).unwrap())
        .collect::<Vec<_>>();
    let dealers = producers
        .iter()
        .map(|(_, proof)| proof.clone())
        .collect::<Vec<_>>();
    let transcript = AdaptiveThresholdBlsPublicTranscript::from_qualified_dealers(
        &parameters,
        &dealers,
        &(1..=n).collect::<Vec<_>>(),
        [8; 32],
    )
    .unwrap();
    let shares = producers
        .iter()
        .map(|(secret, proof)| secret.private_share(&parameters, proof, n).unwrap())
        .collect::<Vec<_>>();
    let signer = KeyPair::try_from_seed(vec![0x57; 32], Algorithm::BlsNormal).unwrap();
    // Primitive cryptographic context only. Core separately derives its private
    // checked context from actual native H4; these bytes grant no protocol authority.
    let binding = DkgAggregateCheckpointBindingV1 {
        network_id: [1; 32],
        attempt_id: [4; 32],
        authority_generation: 7,
        session_id: [2; 32],
        roster_hash: [3; 32],
        seat_index: n,
        lifecycle_key_hash: DkgCheckpointBindingV1::lifecycle_key_digest(signer.public_key())
            .unwrap(),
        provider_handle_hash: [11; 32],
        provider_revision: 19,
        start_height: 1,
        commitments_end_height: 2,
        deliveries_end_height: 3,
        acceptances_end_height: 4,
        finalized_at_height: 4,
        source: DkgCheckpointSourceV1::ExecutedNativeTip {
            height: 4,
            block_hash: [5; 32],
            core_hash: [6; 32],
            result_hash: [7; 32],
        },
        cutoff_height: 9,
        public_session_hash: [12; 32],
        transcript_hash: *transcript.transcript_hash(),
        accepted_checkpoint_hash: [13; 32],
        accepted_head_hash: [14; 32],
        extraction_intent_hash: [15; 32],
    };
    Fixture {
        parameters,
        transcript,
        shares,
        signer,
        binding,
    }
}
fn warm_nonce() {
    let cipher = SymmetricEncryptor::<ChaCha20Poly1305>::new_with_key([0x35; 32]).unwrap();
    cipher
        .encrypt_easy_in_place(b"warm OS entropy only", &mut [0; 28])
        .unwrap();
}
fn erased(bank: &PreparedDkgAggregateCheckpointV1<BeaconPurpose>) {
    assert!(is_zero(bank.work.0.as_slice()));
    if let Some(parts) = &bank.destination.components {
        assert!(parts.as_slice()[0].iter().all(|part| is_zero(part)));
    }
}

#[test]
fn original_aggregate_file_restart_preserves_exact_scalar_and_cipher_at_four_and_thirty_one() {
    for n in [4, 31] {
        let fixture = fixture(n);
        let pool = AllocationBudget::new(64 * 1024 * 1024);
        let (mut bank, allocations) = allocations_during(|| {
            PreparedDkgAggregateCheckpointV1::new(&fixture.parameters, n, &pool).unwrap()
        });
        assert_eq!(allocations, 5);
        let layouts =
            PreparedDkgAggregateCheckpointV1::<BeaconPurpose>::allocation_layouts().unwrap();
        assert_eq!(
            pool.reserved_bytes(),
            layouts.iter().map(Layout::size).sum::<usize>()
        );
        assert_eq!(bank.original_backing_bytes(), pool.reserved_bytes());
        let original_scalar = bank
            .destination
            .components
            .as_ref()
            .unwrap()
            .as_slice()
            .as_ptr();
        let contributions = fixture
            .shares
            .iter()
            .map(DasRenPrivateShare::components_for_authenticated_encryption)
            .collect::<Vec<_>>();
        let blocker = pool
            .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
            .unwrap();
        warm_nonce();
        without_allocations(|| {
            bank.produce_original(
                &fixture.binding,
                &fixture.signer,
                &fixture.transcript,
                || {
                    AdaptiveThresholdBlsSecretShare::from_dealer_shares(
                        &fixture.transcript,
                        &fixture.shares,
                    )
                },
            )
            .unwrap()
        });
        assert_eq!(
            fixture
                .shares
                .iter()
                .map(DasRenPrivateShare::components_for_authenticated_encryption)
                .collect::<Vec<_>>(),
            contributions
        );
        let original_cipher = bank.encrypted_record().unwrap();
        let original_cipher_pointer = original_cipher.as_ptr();
        let independent_wire =
            Zeroizing::new(norito::encode_canonical(&bank.destination.record()).unwrap());
        assert_eq!(independent_wire.len() + 28, original_cipher.len());
        let digest = bank
            .context(&fixture.binding, &fixture.signer, &fixture.transcript)
            .unwrap();
        let mut original_plain = Zeroizing::new(original_cipher.to_vec());
        let plain = PreparedDkgAggregateCheckpointV1::<BeaconPurpose>::cipher(
            fixture.signer.private_key(),
            &digest,
        )
        .unwrap()
        .decrypt_easy_in_place(digest, &mut original_plain)
        .unwrap();
        assert_eq!(
            plain,
            independent_wire.as_slice(),
            "independently materialized complete canonical private wire"
        );
        drop(original_plain);
        drop(independent_wire);
        without_allocations(|| {
            bank.produce_original(
                &fixture.binding,
                &fixture.signer,
                &fixture.transcript,
                || panic!("sealed retry must not invoke original producer"),
            )
            .unwrap()
        });
        assert_eq!(
            bank.encrypted_record().unwrap().as_ptr(),
            original_cipher_pointer
        );
        let leaf = without_allocations(|| bank.take_original_aggregate().unwrap());
        assert_eq!(leaf.components.as_slice().as_ptr(), original_scalar);
        let expected = Zeroizing::new(*leaf.components_for_runtime_custody());
        let directory = tempfile::Builder::new()
            .prefix(".aggregate-private-restart-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let path = directory.path().join("aggregate.aead");
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        (&file).write_all(bank.encrypted_record().unwrap()).unwrap();
        file.sync_all().unwrap();
        drop(file);
        #[cfg(unix)]
        {
            let directory_file = std::fs::File::open(directory.path()).unwrap();
            directory_file.sync_all().unwrap();
            drop(directory_file);
        }
        drop(leaf);
        drop(bank);
        drop(blocker);
        assert_eq!(pool.reserved_bytes(), 0);
        // The once-produced contributions are retired before reload. Restoration
        // has only original ciphertext, lifecycle key and validated public equations.
        let Fixture {
            parameters,
            transcript,
            signer,
            binding,
            shares,
        } = fixture;
        drop(shares);
        let encrypted = std::fs::read(path).unwrap();
        let mut bank = PreparedDkgAggregateCheckpointV1::new(&parameters, n, &pool).unwrap();
        let source = bank.source.0.as_slice().as_ptr();
        let scalar = bank
            .destination
            .components
            .as_ref()
            .unwrap()
            .as_slice()
            .as_ptr();
        let blocker = pool
            .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
            .unwrap();
        without_allocations(|| {
            bank.restore(
                &encrypted,
                &binding,
                &signer,
                &transcript,
                norito::canonical_decode_limits(encrypted.len()),
            )
            .unwrap()
        });
        assert_eq!(bank.source.0.as_slice().as_ptr(), source);
        assert_eq!(bank.encrypted_record().unwrap(), encrypted);
        assert!(is_zero(bank.work.0.as_slice()));
        let leaf = without_allocations(|| bank.take_original_aggregate().unwrap());
        assert_eq!(leaf.components.as_slice().as_ptr(), scalar);
        assert_eq!(leaf.components_for_runtime_custody(), &*expected);
        assert!(leaf.belongs_to(&pool));
        assert!(bank.belongs_to(&pool));
        assert!(matches!(
            bank.take_original_aggregate(),
            Err(DkgCheckpointErrorV1::Terminal)
        ));
        let before = pool.reserved_bytes();
        let bank_bytes = bank.original_backing_bytes();
        drop(bank);
        assert_eq!(pool.reserved_bytes(), before - bank_bytes);
        let before = pool.reserved_bytes();
        assert_eq!(leaf.original_backing_bytes(), 96);
        drop(leaf);
        assert_eq!(pool.reserved_bytes(), before - 96);
        drop(blocker);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn aggregate_prepare_refuses_each_real_layout_and_occupied_original_pool_before_production() {
    let fixture = fixture(4);
    let layouts = PreparedDkgAggregateCheckpointV1::<BeaconPurpose>::allocation_layouts().unwrap();
    let exact = layouts.iter().map(Layout::size).sum::<usize>();
    let pool = AllocationBudget::new(exact);
    let occupied = pool.try_reserve_bytes(1).unwrap();
    assert!(matches!(
        PreparedDkgAggregateCheckpointV1::new(&fixture.parameters, 4, &pool),
        Err(DkgCheckpointErrorV1::Admission(AllocationRefusal::Capacity {
            requested_bytes: requested,
            reserved_bytes: reserved,
            limit_bytes: limit,
            ..
        })) if requested == exact && reserved == 1 && limit == exact
    ));
    assert_eq!(pool.reserved_bytes(), 1);
    drop(occupied);
    let insufficient = AllocationBudget::new(exact - 1);
    assert!(matches!(
        PreparedDkgAggregateCheckpointV1::new(&fixture.parameters, 4, &insufficient),
        Err(DkgCheckpointErrorV1::Admission(_))
    ));
    assert_eq!(insufficient.reserved_bytes(), 0);
    for layout in layouts {
        let result = with_allocation_failure(layout.size(), || {
            PreparedDkgAggregateCheckpointV1::new(&fixture.parameters, 4, &pool)
        });
        assert!(
            result.is_err(),
            "actual scalar/source/work/control allocator refusal"
        );
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let bank = PreparedDkgAggregateCheckpointV1::new(&fixture.parameters, 4, &pool).unwrap();
    assert_eq!(bank.original_backing_bytes(), exact);
    drop(bank);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn aggregate_restore_preserves_opaque_scope_refusal_and_original_source_for_exact_retry() {
    let fixture = fixture(4);
    let pool = AllocationBudget::new(1024 * 1024);
    let mut original =
        PreparedDkgAggregateCheckpointV1::new(&fixture.parameters, 4, &pool).unwrap();
    warm_nonce();
    original
        .produce_original(
            &fixture.binding,
            &fixture.signer,
            &fixture.transcript,
            || {
                AdaptiveThresholdBlsSecretShare::from_dealer_shares(
                    &fixture.transcript,
                    &fixture.shares,
                )
            },
        )
        .unwrap();
    let encrypted = original.encrypted_record().unwrap().to_vec();
    drop(original);
    let mut bank = PreparedDkgAggregateCheckpointV1::new(&fixture.parameters, 4, &pool).unwrap();
    let before = pool.reserved_bytes();
    let pointer = bank.source.0.as_slice().as_ptr();
    let scalar = bank
        .destination
        .components
        .as_ref()
        .unwrap()
        .as_slice()
        .as_ptr();
    let enclosing = norito::DecodeLimits::new(0, 0, 0, 0, 0);
    let error = norito::core::with_decode_limits_scope(enclosing, || {
        bank.restore(
            &encrypted,
            &fixture.binding,
            &fixture.signer,
            &fixture.transcript,
            norito::canonical_decode_limits(encrypted.len()),
        )
    })
    .unwrap_err();
    let DkgCheckpointErrorV1::Decode(norito::core::PreparedDecodeError::Codec(original)) = error
    else {
        panic!("preserve exact original codec refusal")
    };
    assert_eq!(
        original.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    erased(&bank);
    assert_eq!(pool.reserved_bytes(), before);
    assert_eq!(bank.source.0.as_slice().as_ptr(), pointer);
    assert_eq!(
        bank.destination
            .components
            .as_ref()
            .unwrap()
            .as_slice()
            .as_ptr(),
        scalar
    );
    let mut changed = encrypted.clone();
    changed[13] ^= 1;
    assert!(matches!(
        bank.restore(
            &changed,
            &fixture.binding,
            &fixture.signer,
            &fixture.transcript,
            norito::canonical_decode_limits(changed.len())
        ),
        Err(DkgCheckpointErrorV1::Binding)
    ));
    erased(&bank);
    assert_eq!(bank.source.0.as_slice(), encrypted);
    let blocker = pool.try_reserve_bytes(pool.limit_bytes() - before).unwrap();
    without_allocations(|| {
        bank.restore(
            &encrypted,
            &fixture.binding,
            &fixture.signer,
            &fixture.transcript,
            norito::canonical_decode_limits(encrypted.len()),
        )
        .unwrap()
    });
    let leaf = bank.take_original_aggregate().unwrap();
    assert_eq!(leaf.components.as_slice().as_ptr(), scalar);
    // The classified error owns its original counter controls through retry.
    // Release that real reader before checking complete bank retirement.
    drop(original);
    drop(leaf);
    drop(bank);
    drop(blocker);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn aggregate_replay_and_every_original_component_require_exact_authenticated_public_equations() {
    let fixture = fixture(4);
    let pool = AllocationBudget::new(1024 * 1024);
    let mut original =
        PreparedDkgAggregateCheckpointV1::new(&fixture.parameters, 4, &pool).unwrap();
    warm_nonce();
    original
        .produce_original(
            &fixture.binding,
            &fixture.signer,
            &fixture.transcript,
            || {
                AdaptiveThresholdBlsSecretShare::from_dealer_shares(
                    &fixture.transcript,
                    &fixture.shares,
                )
            },
        )
        .unwrap();
    let encrypted = original.encrypted_record().unwrap().to_vec();
    for field in 0..10 {
        let mut changed = fixture.binding;
        match field {
            0 => changed.network_id[0] ^= 1,
            1 => changed.attempt_id[0] ^= 1,
            2 => changed.accepted_checkpoint_hash[0] ^= 1,
            3 => changed.accepted_head_hash[0] ^= 1,
            4 => changed.extraction_intent_hash[0] ^= 1,
            5 => changed.cutoff_height += 1,
            6 => changed.public_session_hash[0] ^= 1,
            7 => changed.provider_revision += 1,
            8 => {
                changed.source = DkgCheckpointSourceV1::SignedGenesisAuthorization {
                    genesis_hash: [1; 32],
                }
            }
            _ => changed.transcript_hash[0] ^= 1,
        }
        let mut recovery =
            PreparedDkgAggregateCheckpointV1::new(&fixture.parameters, 4, &pool).unwrap();
        assert!(
            recovery
                .restore(
                    &encrypted,
                    &changed,
                    &fixture.signer,
                    &fixture.transcript,
                    norito::canonical_decode_limits(encrypted.len())
                )
                .is_err()
        );
        erased(&recovery);
    }
    let parts = *original.destination.components.as_ref().unwrap().as_slice()[0];
    for (component, part) in parts.iter().enumerate() {
        for malformed in [true, false] {
            let mut record = original.destination.record();
            let range = component * 32..(component + 1) * 32;
            let bytes = if malformed {
                [0xff; 32]
            } else {
                let mut changed = [0; 32];
                if *part == changed {
                    changed[31] = 1;
                }
                changed
            };
            record.components[range].copy_from_slice(&bytes);
            let mut changed = vec![0; encrypted.len()];
            let length = changed.len();
            let mut output = &mut changed[12..length - 16];
            norito::core::write_canonical_to_writer(&record, &mut output).unwrap();
            assert!(output.is_empty());
            let digest = original
                .context(&fixture.binding, &fixture.signer, &fixture.transcript)
                .unwrap();
            PreparedDkgAggregateCheckpointV1::<BeaconPurpose>::cipher(
                fixture.signer.private_key(),
                &digest,
            )
            .unwrap()
            .encrypt_easy_in_place(digest, &mut changed)
            .unwrap();
            let mut recovery =
                PreparedDkgAggregateCheckpointV1::new(&fixture.parameters, 4, &pool).unwrap();
            let error = without_allocations(|| {
                recovery.restore(
                    &changed,
                    &fixture.binding,
                    &fixture.signer,
                    &fixture.transcript,
                    norito::canonical_decode_limits(changed.len()),
                )
            })
            .unwrap_err();
            assert!(
                matches!(
                    error,
                    DkgCheckpointErrorV1::Threshold(ThresholdBlsError::InvalidScalar)
                ) && malformed
                    || matches!(
                        error,
                        DkgCheckpointErrorV1::Threshold(ThresholdBlsError::SecretShareMismatch)
                    ) && !malformed
            );
            erased(&recovery);
            assert!(recovery.take_original_aggregate().is_err());
        }
    }
    drop(original);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn aggregate_consumes_original_producer_once_even_on_completed_intrinsic_failure() {
    let fixture = fixture(4);
    let pool = AllocationBudget::new(1024 * 1024);
    let mut bank = PreparedDkgAggregateCheckpointV1::new(&fixture.parameters, 4, &pool).unwrap();
    let calls = std::cell::Cell::new(0);
    let first = bank.produce_original(
        &fixture.binding,
        &fixture.signer,
        &fixture.transcript,
        || {
            calls.set(calls.get() + 1);
            AdaptiveThresholdBlsSecretShare::from_dealer_shares(
                &fixture.transcript,
                &fixture.shares[1..],
            )
        },
    );
    assert!(matches!(
        first,
        Err(DkgCheckpointErrorV1::Threshold(
            ThresholdBlsError::NonCanonicalQualifiedSet
        ))
    ));
    let second = bank.produce_original(
        &fixture.binding,
        &fixture.signer,
        &fixture.transcript,
        || {
            calls.set(calls.get() + 1);
            panic!("one original producer already consumed")
        },
    );
    assert!(matches!(second, Err(DkgCheckpointErrorV1::Terminal)));
    assert_eq!(calls.get(), 1);
    erased(&bank);
    assert!(bank.encrypted_record().is_none());
    drop(bank);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn actual_aggregate_unwind_retires_scalar_and_all_original_cipher_controls() {
    let fixture = fixture(4);
    let pool = AllocationBudget::new(1024 * 1024);
    let mut bank = PreparedDkgAggregateCheckpointV1::new(&fixture.parameters, 4, &pool).unwrap();
    warm_nonce();
    bank.produce_original(
        &fixture.binding,
        &fixture.signer,
        &fixture.transcript,
        || {
            AdaptiveThresholdBlsSecretShare::from_dealer_shares(
                &fixture.transcript,
                &fixture.shares,
            )
        },
    )
    .unwrap();
    let leaf = bank.take_original_aggregate().unwrap();
    assert!(
        leaf.components_for_runtime_custody()
            .iter()
            .any(|part| !is_zero(part))
    );
    let physical = leaf.original_backing_bytes() + bank.original_backing_bytes();
    assert_eq!(pool.reserved_bytes(), physical);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        std::hint::black_box(&leaf);
        std::hint::black_box(&bank);
        panic!("genuine failure while both original private owners are live");
    }));
    assert!(unwind.is_err());
    assert_eq!(pool.reserved_bytes(), 0);
    let retry = PreparedDkgAggregateCheckpointV1::new(&fixture.parameters, 4, &pool).unwrap();
    assert_eq!(retry.original_backing_bytes(), physical);
    drop(retry);
    assert_eq!(pool.reserved_bytes(), 0);
}
