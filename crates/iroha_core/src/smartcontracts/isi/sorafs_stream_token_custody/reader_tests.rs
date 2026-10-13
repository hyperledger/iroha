//! Exact historical selection, bounded canonical decoding and no-write read regressions.
use super::*;
use iroha_crypto::Hash;
use std::sync::Arc;

/// The custody fixture's accounts and policy on a certified test chain (height 1 is genesis).
fn certified_fixture() -> (
    crate::sumeragi::test_chain::CertifiedTestChain,
    SignerCustodyPolicyV1,
    ProviderId,
) {
    let f = fixture();
    let chain = crate::query::signer_check::fixture::chain(fixture_world(
        &f.authority,
        &f.other,
        f.provider,
    ));
    let mut policy = f.policy;
    policy.binding.chain_id = chain.state().view().chain_id().to_string();
    policy.binding.network_id = *chain.state().network_id_ref().as_bytes();
    (chain, policy, f.provider)
}

#[test]
fn current_stream_token_custody_requires_same_state_finality_and_grants_no_operation() {
    use crate::query::signer_check::fixture::{commit, commit_uncertified, sign};
    let (mut chain, policy, provider) = certified_fixture();
    let state = Arc::clone(chain.state());
    let read = |binding: &SignerCustodyBindingV1, height| {
        crate::query::stream_token_custody::read_current_stream_token_custody_block_finality_v1(
            &state.view(),
            binding,
            height,
        )
    };
    let configure = MutateSorafsStreamTokenCustody {
        provider_id: provider,
        expected_revision: 0,
        expected_digest: [0; 32],
        action: Action::Configure(encode(&policy).expect("policy")),
    };
    // The configuration is applied and durable, but its block's local CommitQC does not verify.
    assert_eq!(
        commit(
            &mut chain,
            1_000,
            vec![sign(&state, configure.into(), 1, 1_000)]
        ),
        [true]
    );
    let original = chain.committed(2);
    let original_qc = original
        .block()
        .commit_certificate()
        .expect("genuine native exact-quorum certificate")
        .commit_qc()
        .to_vec();
    chain.corrupt_local_quorum_for_test(2, crate::sumeragi::test_chain::Signers::BelowQuorum);
    assert_eq!(
        read(&policy.binding, 2),
        Err(Error::FinalityUnavailable),
        "a retained row and durable block do not replace CommitQC"
    );
    let mut foreign = policy.binding.clone();
    foreign.purpose = SignerPurposeBindingV1::StreamToken {
        provider_id: [0xB6; 32],
    };
    assert_eq!(
        read(&foreign, 2),
        Err(Error::FinalityUnavailable),
        "absence of a provider row cannot bypass finality"
    );
    assert_eq!(read(&policy.binding, 0), Err(Error::StaleHeight));
    // Restore only the exact original QC before advancing. A later valid block
    // cannot replace a missing historical certificate in the required prefix.
    state
        .kura()
        .corrupt_commit_certificate_for_testing(
            std::num::NonZeroUsize::new(2).unwrap(),
            Some(original_qc.clone()),
        )
        .unwrap();
    assert_eq!(
        chain
            .committed(2)
            .block()
            .executed_block_wire_identity()
            .unwrap(),
        original.block().executed_block_wire_identity().unwrap()
    );
    // A certified successor: the retained row is current at a certified block.
    assert!(commit(&mut chain, 1_500, Vec::new()).is_empty());
    // Re-corrupt the historical certificate after the actual successor is sealed.
    // Its otherwise valid newer QC cannot repair the required authority prefix.
    chain.corrupt_local_quorum_for_test(2, crate::sumeragi::test_chain::Signers::BelowQuorum);
    assert_eq!(read(&policy.binding, 3), Err(Error::FinalityUnavailable));
    // Restore only the actual original stored QC, without inventing an execution result.
    chain
        .kura()
        .corrupt_commit_certificate_for_testing(
            std::num::NonZeroUsize::new(2).unwrap(),
            Some(original_qc),
        )
        .expect("restore original native certificate");
    // The retained row is now current on the independently certified complete prefix.
    let current = read(&policy.binding, 3)
        .expect("same-State finality")
        .expect("raw custody");
    assert_eq!(current.custody().state.policy.binding, policy.binding);
    assert_eq!(current.block_finality().height(), 3);
    assert_eq!(
        current.block_finality().block_hash(),
        current.custody().anchor.block_hash
    );
    assert_eq!(
        current.block_finality().context_id(),
        chain.committed(3).id()
    );
    assert_eq!(
        crate::query::stream_token_authority::read_head(state.view().world(), provider)
            .expect("no role-11 operation")
            .revision,
        0,
        "block finality cannot create an operation or completed Check"
    );
    let mut foreign = policy.binding.clone();
    foreign.network_id = [0xA5; 32];
    assert_eq!(read(&foreign, 3), Err(Error::BindingMismatch));
    foreign = policy.binding.clone();
    foreign.purpose = SignerPurposeBindingV1::StreamToken {
        provider_id: [0xB6; 32],
    };
    assert!(read(&foreign, 3).unwrap().is_none());
    assert!(commit_uncertified(&mut chain, 2_000, Vec::new()).is_empty());
    assert_eq!(read(&policy.binding, 3), Err(Error::StaleHeight));
    assert_eq!(
        read(&policy.binding, 4),
        Err(Error::FinalityUnavailable),
        "a later block cannot borrow an earlier QC"
    );
}
#[test]
fn orphan_first_use_key_indexes_reject_fresh_custody_configuration() {
    for keep_signer in [false, true] {
        let mut f = fixture();
        configure(&mut f);
        let mut next = f.policy.clone();
        next.binding.public_key = key(8).public_key().clone();
        next.attester_public_key = key(9).public_key().clone();
        transact(&mut f.state, 2_000, |tx| {
            let old = read_active(tx.world(), f.provider).unwrap().unwrap();
            for key in [
                head_key(f.provider),
                record_key(f.provider, 1),
                height_key(f.provider, old.index.height, old.index.ordinal),
                key_path(
                    f.provider,
                    !keep_signer,
                    if keep_signer {
                        &f.policy.attester_public_key
                    } else {
                        &f.policy.binding.public_key
                    },
                )
                .unwrap(),
            ] {
                tx.world.smart_contract_state.remove(key);
            }
            assert!(read_active(tx.world(), f.provider).is_err());
            let before = tx
                .world()
                .smart_contract_state()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>();
            let fresh = MutateSorafsStreamTokenCustody {
                provider_id: f.provider,
                expected_revision: 0,
                expected_digest: [0; 32],
                action: Action::Configure(encode(&next).unwrap()),
            };
            assert!(fresh.execute(&f.authority, tx).is_err());
            assert_eq!(
                tx.world()
                    .smart_contract_state()
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Vec<_>>(),
                before
            );
        });
    }
}
#[test]
fn reader_rejects_wrong_scope_missing_height_and_does_not_mutate_on_repeated_admission() {
    let mut f = fixture();
    configure(&mut f);
    let before = f
        .state
        .world_view()
        .smart_contract_state()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<Vec<_>>();
    for _ in 0..1_000 {
        let result = read_stream_token_custody_control_at_v1(&f.state.view(), &f.policy.binding, 1)
            .expect("indexed admission")
            .expect("configured");
        assert!(result.state.active_head.is_none());
        assert_eq!(result.anchor.height, 1);
    }
    assert_eq!(
        f.state
            .world_view()
            .smart_contract_state()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>(),
        before
    );
    assert_eq!(
        read_stream_token_custody_control_at_v1(&f.state.view(), &f.policy.binding, 0),
        Err(Error::HeightUnavailable)
    );
    assert_eq!(
        read_stream_token_custody_control_at_v1(&f.state.view(), &f.policy.binding, 2),
        Err(Error::HeightUnavailable)
    );
    let mut wrong = f.policy.binding.clone();
    wrong.role = SignerRoleV1::FinalPromotionProvenance;
    assert_eq!(
        read_stream_token_custody_control_at_v1(&f.state.view(), &wrong, 1),
        Err(Error::BindingMismatch)
    );
    wrong.purpose = SignerPurposeBindingV1::FinalPromotionProvenance {
        deployment_id: "production-primary".into(),
    };
    assert_eq!(
        read_stream_token_custody_control_at_v1(&f.state.view(), &wrong, 1),
        Err(Error::BindingMismatch)
    );
    let mut wrong = f.policy.binding.clone();
    wrong.purpose = SignerPurposeBindingV1::StreamToken {
        provider_id: [88; 32],
    };
    assert_eq!(
        read_stream_token_custody_control_at_v1(&f.state.view(), &wrong, 1),
        Ok(None),
        "an unconfigured provider must not resolve another provider's custody"
    );
    let mut wrong = f.policy.binding.clone();
    wrong.network_id = [88; 32];
    assert_eq!(
        read_stream_token_custody_control_at_v1(&f.state.view(), &wrong, 1),
        Err(Error::BindingMismatch)
    );
    let mut wrong = f.policy.binding.clone();
    wrong.chain_id = "wrong-chain".into();
    assert_eq!(
        read_stream_token_custody_control_at_v1(&f.state.view(), &wrong, 1),
        Err(Error::BindingMismatch)
    );
    let mut wrong = f.policy.binding.clone();
    wrong.policy_digest = [88; 32];
    assert_eq!(
        read_stream_token_custody_control_at_v1(&f.state.view(), &wrong, 1),
        Err(Error::BindingMismatch)
    );
}
#[test]
fn reader_rejects_missing_height_key_replaced_active_pointer_and_missing_key_tombstone() {
    let mut f = fixture();
    configure(&mut f);
    transact(&mut f.state, 1_500, |tx| {
        let original = read_active(tx.world(), f.provider)
            .expect("head")
            .expect("head")
            .index;
        instruction(
            tx,
            f.provider,
            Action::Revoke(SorafsStreamTokenCustodyRevocationV1 {
                signer: true,
                attester: false,
            }),
        )
        .execute(&f.authority, tx)
        .expect("revoke");
        let current = read_active(tx.world(), f.provider)
            .expect("head")
            .expect("head")
            .index;
        tx.world.smart_contract_state.insert(
            head_key(f.provider),
            encode(&original).expect("old pointer"),
        );
        assert!(read_active(tx.world(), f.provider).is_err());
        tx.world.smart_contract_state.insert(
            head_key(f.provider),
            encode(&current).expect("current pointer"),
        );
        let index_path = height_key(f.provider, current.height, current.ordinal);
        let bytes = tx
            .world
            .smart_contract_state
            .get(&index_path)
            .expect("height index")
            .clone();
        tx.world.smart_contract_state.remove(index_path.clone());
        assert!(read_active(tx.world(), f.provider).is_err());
        tx.world.smart_contract_state.insert(index_path, bytes);
        let key =
            key_path(f.provider, true, &f.policy.binding.public_key).expect("key tombstone path");
        let bytes = tx
            .world
            .smart_contract_state
            .get(&key)
            .expect("first-use index")
            .clone();
        tx.world.smart_contract_state.remove(key.clone());
        assert!(read_active(tx.world(), f.provider).is_err());
        tx.world.smart_contract_state.insert(key, bytes);
        assert_eq!(
            read_active(tx.world(), f.provider)
                .expect("restored")
                .expect("head")
                .index,
            current
        );
    });
}
#[test]
fn native_record_digest_binds_authority_request_and_execution_but_not_later_blocks() {
    let mut f = fixture();
    configure(&mut f);
    let first = read_stream_token_custody_control_at_v1(&f.state.view(), &f.policy.binding, 1)
        .expect("snapshot")
        .expect("head");
    let record = read_active(&f.state.world_view(), f.provider)
        .expect("record")
        .expect("head")
        .record;
    let frame = encode(&record).expect("native canonical frame");
    assert_eq!(
        decode::<StreamTokenCustodyControlRecordV1>(&frame).expect("bounded native replay"),
        record
    );
    let digest = record_digest(&record).expect("digest");
    for changed in [
        StreamTokenCustodyControlRecordV1 {
            authority: f.other.clone(),
            ..record.clone()
        },
        StreamTokenCustodyControlRecordV1 {
            request_digest: [33; 32],
            ..record.clone()
        },
        StreamTokenCustodyControlRecordV1 {
            execution_height: 2,
            ..record.clone()
        },
        StreamTokenCustodyControlRecordV1 {
            ordinal: 1,
            ..record.clone()
        },
    ] {
        assert_ne!(record_digest(&changed).expect("mutated digest"), digest);
    }
    let mut suffix = frame.clone();
    suffix.push(0);
    assert!(decode::<StreamTokenCustodyControlRecordV1>(&suffix).is_err());
    assert!(decode::<StreamTokenCustodyControlRecordV1>(&frame[..frame.len() - 1]).is_err());
    assert!(decode::<StreamTokenCustodyControlRecordV1>(&vec![0; 16 * 1024 + 1]).is_err());
    transact(&mut f.state, 1_500, |_| {});
    let later = read_stream_token_custody_control_at_v1(&f.state.view(), &f.policy.binding, 2)
        .expect("later state")
        .expect("head");
    assert_eq!(later.anchor.state_digest, first.anchor.state_digest);
    assert_ne!(later.anchor.block_hash, first.anchor.block_hash);
}
#[test]
fn unknown_provider_and_bad_time_or_oversized_action_cannot_create_state() {
    let mut f = fixture();
    transact(&mut f.state, 0, |tx| {
        assert!(
            instruction(
                tx,
                f.provider,
                Action::Configure(encode(&f.policy).expect("policy"))
            )
            .execute(&f.authority, tx)
            .is_err()
        );
        assert!(
            read_active(tx.world(), f.provider)
                .expect("absent")
                .is_none()
        );
    });
    transact(&mut f.state, 1_000, |tx| {
        assert!(
            instruction(tx, f.provider, Action::Configure(vec![0; 32 * 1024 + 1]))
                .execute(&f.authority, tx)
                .is_err()
        );
        tx.world.provider_owners.remove(f.provider);
        assert!(
            instruction(
                tx,
                f.provider,
                Action::Configure(encode(&f.policy).expect("policy"))
            )
            .execute(&f.authority, tx)
            .is_err()
        );
        assert!(
            read_active(tx.world(), f.provider)
                .expect("absent")
                .is_none()
        );
    });
}

#[test]
fn canonical_control_frames_and_native_digest_ignore_both_v1_ambient_layouts() {
    use norito::core::header_flags::COMPACT_LEN as C;
    let mut f = fixture();
    configure(&mut f);
    let record = read_active(&f.state.world_view(), f.provider)
        .expect("native control")
        .expect("configured")
        .record;
    let frame = encode(&record).expect("canonical native record");
    let digest = record_digest(&record).expect("native digest");
    let mut preimage =
        iroha_data_model::sorafs::stream_token_custody::STREAM_TOKEN_CUSTODY_RECORD_DOMAIN_V1
            .to_vec();
    preimage.extend_from_slice(&frame);
    assert_eq!(digest, *Hash::new(preimage).as_ref());
    for flags in [0, C] {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(encode(&record).expect("ambient canonical encoding"), frame);
        assert_eq!(
            decode::<StreamTokenCustodyControlRecordV1>(&frame)
                .expect("actual bounded reader under ambient flags"),
            record
        );
        assert_eq!(record_digest(&record).expect("ambient digest"), digest);
    }
}

#[test]
fn provider_removal_preserves_historical_reads_but_rejects_mutation_and_exact_retry() {
    let mut f = fixture();
    configure(&mut f);
    let original = MutateSorafsStreamTokenCustody {
        provider_id: f.provider,
        expected_revision: 0,
        expected_digest: [0; 32],
        action: Action::Configure(encode(&f.policy).expect("original policy")),
    };
    let approval = read_stream_token_custody_control_at_v1(&f.state.view(), &f.policy.binding, 1)
        .expect("historical read")
        .expect("configured");
    transact(&mut f.state, 1_500, |tx| {
        tx.world.provider_owners.remove(f.provider);
        let before = tx
            .world
            .smart_contract_state
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>();
        assert!(
            original.execute(&f.authority, tx).is_err(),
            "removed provider cannot acknowledge retries"
        );
        assert!(
            instruction(
                tx,
                f.provider,
                Action::Revoke(SorafsStreamTokenCustodyRevocationV1 {
                    signer: true,
                    attester: true
                })
            )
            .execute(&f.authority, tx)
            .is_err()
        );
        assert_eq!(
            tx.world
                .smart_contract_state
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>(),
            before
        );
    });
    assert_eq!(
        read_stream_token_custody_control_at_v1(&f.state.view(), &f.policy.binding, 1)
            .expect("retained historical record"),
        Some(approval.clone())
    );
    let later = read_stream_token_custody_control_at_v1(&f.state.view(), &f.policy.binding, 2)
        .expect("retained control at later height")
        .expect("retained head");
    assert_eq!(later.state, approval.state);
    assert_eq!(later.anchor.state_digest, approval.anchor.state_digest);
}

#[test]
fn independent_custody_projection_proves_absence_then_exact_native_configuration() {
    use crate::query::signer_check::fixture::{commit, sign};
    use iroha_allocation::AllocationBudget;
    use iroha_data_model::{
        sorafs::stream_token_custody::proof::{
            StreamTokenCustodyProofRefV1, StreamTokenCustodyProofV1,
        },
        sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier},
    };
    let (mut chain, policy, provider) = certified_fixture();
    let state = Arc::clone(chain.state());
    let owner = AccountId::new(key(1).public_key().clone());
    let validators = chain
        .validators()
        .iter()
        .map(|(peer, pop)| FinalityValidator {
            public_key: peer.public_key().clone(),
            proof_of_possession: pop.clone(),
        })
        .collect();
    let mut verifier =
        SumeragiFinalityVerifier::new(chain.genesis(), &policy.binding.chain_id, validators)
            .unwrap();
    verifier
        .verify(&crate::sumeragi::finality::build_proof(&state.view(), 1).unwrap())
        .unwrap();
    assert!(commit(&mut chain, 500, Vec::new()).is_empty());
    let absent_tip = chain.committed(2);
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    let publish = |tip: &crate::sumeragi::certified_chain::CommittedBlock,
                   provider,
                   budget: &AllocationBudget| {
        state.with_native_stream_token_custody_snapshot_v1(
            tip,
            provider,
            budget,
            |world, owner, current| {
                norito::encode_canonical(&StreamTokenCustodyProofRefV1::new(world, owner, current))
                    .map_err(|e| e.to_string())
            },
        )
    };
    let absent =
        StreamTokenCustodyProofV1::decode_frame(&publish(&absent_tip, provider, &budget).unwrap())
            .unwrap();
    let authenticated = verifier
        .verify(&crate::sumeragi::finality::build_proof(&state.view(), 2).unwrap())
        .unwrap();
    assert!(
        absent
            .verify(
                *state.network_id_ref(),
                provider,
                &owner,
                &policy.binding,
                State::native_world_schema_hash_v1().unwrap(),
                &authenticated
            )
            .unwrap()
            .current()
            .is_none()
    );
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(publish(&absent_tip, provider, &AllocationBudget::new(0)).is_err());
    assert!(publish(&absent_tip, ProviderId::new([0xfe; 32]), &budget).is_err());
    let configure = MutateSorafsStreamTokenCustody {
        provider_id: provider,
        expected_revision: 0,
        expected_digest: [0; 32],
        action: Action::Configure(encode(&policy).unwrap()),
    };
    assert_eq!(
        commit(
            &mut chain,
            1_000,
            vec![sign(&state, configure.into(), 1, 1_000)]
        ),
        [true]
    );
    assert!(publish(&absent_tip, provider, &budget).is_err());
    let current_tip = chain.committed(3);
    let current =
        StreamTokenCustodyProofV1::decode_frame(&publish(&current_tip, provider, &budget).unwrap())
            .unwrap();
    let authenticated = verifier
        .verify(&crate::sumeragi::finality::build_proof(&state.view(), 3).unwrap())
        .unwrap();
    let current = current
        .verify(
            *state.network_id_ref(),
            provider,
            &owner,
            &policy.binding,
            State::native_world_schema_hash_v1().unwrap(),
            &authenticated,
        )
        .unwrap();
    let current = current.current().unwrap();
    assert_eq!(current.record().revision, 1);
    assert_eq!(current.record().execution_height, 3);
    assert_eq!(current.record().authority, owner);
    assert_eq!(current.control().policy, policy);
    assert!(current.control().active_head.is_none());
    assert_eq!(
        current.anchor().state_digest,
        current.record().canonical_digest().unwrap()
    );
    assert_eq!(budget.reserved_bytes(), 0);
    // No provider council, admission, advertisement or token operation was installed.
    assert!(
        crate::query::provider_admission::read_head(state.view().world(), None)
            .unwrap()
            .is_none()
    );
    assert!(
        crate::query::provider_admission::read_head(state.view().world(), Some(provider))
            .unwrap()
            .is_none()
    );
}
