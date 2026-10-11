//! Issuer freshness regressions without finalized-source or spend admission.

use super::*;
use crate::{
    kura::Kura,
    nexus::space_directory::{
        SpaceDirectoryManifestRecord, SpaceDirectoryManifestSet, UaidDataspaceBindings,
    },
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{DEFAULT_TEST_NETWORK_ID, State, World},
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    IntoKeyValue, Registrable,
    account::{Account, AccountId},
    asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId},
    block::BlockHeader,
    isi::space_directory::{PublishSpaceDirectoryManifest, RevokeSpaceDirectoryManifest},
    nexus::{
        AssetHandleDraft, AssetPermissionManifest, AxtAnchoredSpendDraftV1, AxtAssetIncarnationV1,
        AxtFastpqBinding, AxtFinalizedSpendAnchorV1, AxtHandleCounterRecord, AxtHandleReplayKey,
        AxtPolicyEntry, AxtProofEnvelope, AxtSourceSuccessReceiptV1, AxtSourceTransferOccurrenceV1,
        AxtSpendNonceV1, GroupBinding, HandleBudget, HandleSubject, ManifestVersion, ProofBlob,
        RemoteSpendIntent, SpendOp, UniversalAccountId, compute_remote_spend_intent_commitment_v1,
    },
    permission::{Permission, Permissions},
};
use iroha_executor_data_model::permission::nexus::CanPublishSpaceDirectoryManifestForUaid;
use iroha_model_base::topology::{DataSpaceId, LaneId};
use iroha_primitives::numeric::Quantity;
use std::{num::NonZeroU64, sync::Arc};

struct Fixture {
    state: State,
    invocation: PreparedContract,
    spend: AxtAnchoredSpendV1,
    issuer: KeyPair,
    issuer_account: AccountId,
}

fn fixture() -> Fixture {
    let issuer = KeyPair::from_seed(vec![0x33; 32], Algorithm::Ed25519);
    let issuer_account = AccountId::new(issuer.public_key().clone());
    let issuer_uaid = UniversalAccountId::from_hash(Hash::new(b"axt-current-issuer"));
    let dsid = DataSpaceId::UNIVERSAL;
    let lane = LaneId::new(0);
    let network_id = *DEFAULT_TEST_NETWORK_ID;
    let binding = AxtBinding::new([0xA5; 32]);
    let program = kotodama_lang::compiler::Compiler::new()
        .compile_source(
            "seiyaku IssuerFixture { permission issuer_fixture_run;  kotoage fn main() authorize(issuer_fixture_run) {} }",
        )
        .expect("compile current ABI V1 artifact");
    let invocation =
        ivm::prepare_contract(Arc::<[u8]>::from(program)).expect("admit current ABI V1 artifact");
    let asset =
        AssetDefinitionId::from_uuid_bytes([0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
            .expect("canonical asset id");
    let incarnation = AxtAssetIncarnationV1::derive(
        &network_id,
        &asset,
        &HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"asset registration")),
        &Hash::new(b"asset execution"),
        0,
    );
    let account = Account::new(issuer_account.clone())
        .with_uaid(Some(issuer_uaid))
        .build(&issuer_account);
    let definition = AssetDefinition::numeric(
        asset.clone(),
        "issuer-freshness",
        AssetBalancePolicy::Global,
        None,
    )
    .build(&issuer_account);
    let mut world = World::with([], [account], [definition]);
    let mut manifest = SpaceDirectoryManifestRecord::new(AssetPermissionManifest {
        version: ManifestVersion::default(),
        uaid: issuer_uaid,
        dataspace: dsid,
        issued_ms: 1,
        activation_epoch: 1,
        expiry_epoch: None,
        entries: Vec::new(),
    });
    manifest.lifecycle.mark_activated(1);
    let manifest_root = manifest.manifest_hash.into();
    let mut manifests = SpaceDirectoryManifestSet::default();
    manifests.upsert(manifest);
    world
        .space_directory_manifests
        .insert(issuer_uaid, manifests);
    let mut bindings = UaidDataspaceBindings::default();
    bindings.bind_account(dsid, issuer_account.clone());
    world.uaid_dataspaces.insert(issuer_uaid, bindings);
    world
        .axt_asset_incarnations
        .insert(asset.clone(), incarnation);
    world
        .axt_handle_counters
        .insert(dsid, AxtHandleCounterRecord::initial(1));
    world.axt_policies.insert(
        dsid,
        AxtPolicyEntry {
            manifest_root,
            target_lane: lane,
            // These are projections, not authority; the permanent ratchet wins.
            active_handle_era: 77,
            next_handle_counter: 88,
            current_slot: u64::MAX,
        },
    );
    let context = AxtHandleIssuerContextV1 {
        network_id,
        asset_dsid: dsid,
        asset_definition_incarnation: incarnation,
        issuer: issuer_uaid,
        issuer_manifest_root: manifest_root,
        code_root: invocation.code_hash().into(),
        abi_version: 1,
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
    };
    let handle = AssetHandleDraft {
        asset_definition_id: asset.clone(),
        scope: vec!["transfer".into()],
        subject: HandleSubject {
            account: issuer_account.to_string(),
            origin_dsid: Some(dsid),
        },
        budget: HandleBudget {
            remaining: Quantity::from(10_u64),
            per_use: Some(Quantity::from(5_u64)),
        },
        handle_era: 1,
        sub_nonce: 1,
        group_binding: GroupBinding {
            composability_group_id: b"settlement".to_vec(),
            epoch_id: 1,
        },
        target_lane: lane,
        axt_binding: binding,
        manifest_view_root: manifest_root,
        expiry_slot: 100,
        max_clock_skew_ms: Some(25),
    }
    .sign_by_issuer_v1(context, issuer.private_key())
    .expect("sign handle");
    let intent = RemoteSpendIntent {
        asset_dsid: dsid,
        op: SpendOp {
            asset_definition_id: asset,
            kind: "transfer".into(),
            from: handle.subject.account.clone(),
            to: "sorauﾛ1NfｷgﾉﾓﾉBｦKﾌﾘﾒoﾇﾂﾛrG81ﾋjWﾎﾕVncwﾌSｱ3pﾘﾋﾉhUS9Q76".into(),
            amount: Some(Quantity::from(5_u64)),
        },
    };
    let claim = compute_remote_spend_intent_commitment_v1(
        AxtHandleReplayKey::from_handle(dsid, &handle),
        &intent.op.asset_definition_id,
        &intent.op.kind,
        &intent.op.from,
        &intent.op.to,
        intent.op.amount.as_ref().expect("clear amount"),
    );
    let anchor = AxtFinalizedSpendAnchorV1 {
        network_id,
        genesis_hash: *network_id.as_bytes(),
        dataspace_id: dsid,
        lane_id: lane,
        lane_incarnation: Hash::new(b"lane incarnation"),
        finalized_height: 2,
        block_header_hash: HashOf::from_untyped_unchecked(Hash::new(b"source block")),
        quorum_certificate_digest: Hash::new(b"source QC"),
        committee_digest: Hash::new(b"source committee"),
        pre_state_root: Hash::new(b"source prestate"),
        post_state_root: Hash::new(b"source poststate"),
        transaction_set_digest: Hash::new(b"source transaction set"),
        da_manifest_digest: Hash::new(b"source DA"),
    };
    let receipt = AxtSourceSuccessReceiptV1 {
        finalized_anchor_digest: anchor.digest_v1(),
        source_tx_commitment: [0xAA; 32],
        source_tx_index: 0,
        post_transaction_state_root: [0xBB; 32],
        effect_set_digest: [0xCC; 32],
    };
    let occurrence = AxtSourceTransferOccurrenceV1 {
        source_tx_commitment: receipt.source_tx_commitment,
        source_success_receipt_digest: receipt.digest_v1(),
        source_tx_index: receipt.source_tx_index,
        transcript_index: 0,
        delta_index: 0,
        pair_ordinal: 0,
        transfer_digest: [0xDD; 32],
        remote_spend_claim_commitment: claim,
    };
    let proof = AxtProofEnvelope {
        dsid,
        manifest_root,
        da_commitment: Some(anchor.da_manifest_digest.into()),
        // Issuer verification authenticates these bytes, never their proof validity.
        proof: vec![0xA5, 0x5A],
        fastpq_binding: Some(AxtFastpqBinding {
            parameter: "fastpq-state-transition-stark-v1".into(),
            source_dsid: dsid.as_u64(),
            source_dataspace: "source".into(),
            source_receipt_id: "receipt".into(),
            source_tx_commitment: hex::encode(receipt.source_tx_commitment),
            claim_type: "tx_predicate".into(),
            claim_digest: "bb".repeat(32),
            witness_commitment: "cc".repeat(32),
            policy_commitment: "dd".repeat(32),
            verified_effect_type: "transfer".into(),
            corridor: "test".into(),
            verifier_id: "fastpq".into(),
            verifier_version: "v1".into(),
            target_dsids: vec![dsid.as_u64()],
            effect_binding: None,
            remote_spend_intent_commitments: vec![claim],
        }),
        committed_amount: Some(5),
        amount_commitment: None,
    };
    let spend = AxtAnchoredSpendDraftV1 {
        handle,
        intent,
        proof: Some(ProofBlob {
            payload: norito::to_bytes(&proof).expect("proof envelope"),
            expiry_slot: Some(100),
        }),
        amount: Some(Quantity::from(5_u64)),
        amount_commitment: None,
        source_receipt: receipt,
        source_occurrence: occurrence,
    }
    .sign_by_issuer_v1(
        anchor,
        100,
        AxtSpendNonceV1::try_new([0x77; 32]).expect("nonce"),
        issuer.private_key(),
    )
    .expect("sign spend");
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    {
        let mut nexus = state.nexus.write();
        nexus.axt.slot_length_ms = NonZeroU64::new(10).expect("positive slot length");
        nexus.axt.max_clock_skew_ms = 5;
    }
    Fixture {
        state,
        invocation,
        spend,
        issuer,
        issuer_account,
    }
}

fn header(slot: u64) -> BlockHeader {
    BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, slot * 10, 0)
}

fn verify(
    transaction: &StateTransaction<'_, '_>,
    fixture: &Fixture,
) -> Result<(), AxtCurrentIssuerErrorV1> {
    transaction.verify_current_axt_spend_issuer_claims_v1(
        &fixture.spend,
        &fixture.invocation,
        fixture.spend.draft.handle.axt_binding,
    )
}

#[test]
fn current_issuer_checks_both_signatures_without_reserving_state() {
    let fixture = fixture();
    let mut block = fixture.state.block(header(100));
    let mut transaction = block.transaction();
    let dsid = fixture.spend.draft.intent.asset_dsid;
    let cached_policy = transaction.world.axt_policies.get_mut(&dsid).unwrap();
    cached_policy.active_handle_era = 77;
    cached_policy.next_handle_counter = 88;
    cached_policy.current_slot = u64::MAX;
    assert_eq!(verify(&transaction, &fixture), Ok(()));
    assert_eq!(verify(&transaction, &fixture), Ok(()));
    assert_eq!(
        transaction
            .world
            .axt_handle_counters
            .get(&dsid)
            .unwrap()
            .next(),
        1
    );
    assert!(
        transaction
            .world
            .axt_spend_nonce_ledger
            .get(&fixture.spend.replay_key_v1())
            .is_none()
    );
    assert!(
        transaction
            .world
            .axt_source_transfer_replay_ledger
            .iter()
            .next()
            .is_none()
    );
    assert!(
        transaction
            .world
            .axt_handle_budget_ledger
            .iter()
            .next()
            .is_none()
    );
    let mut tampered = fixture.spend.clone();
    tampered.authorization.nonce = AxtSpendNonceV1::try_new([0x78; 32]).unwrap();
    assert_eq!(
        transaction.verify_current_axt_spend_issuer_claims_v1(
            &tampered,
            &fixture.invocation,
            tampered.draft.handle.axt_binding,
        ),
        Err(AxtCurrentIssuerErrorV1::Authentication(
            AxtAnchoredSpendValidationErrorV1::SpendSignature
        )),
    );
    tampered = fixture.spend.clone();
    tampered.draft.handle.budget.remaining = Quantity::from(11_u64);
    assert_eq!(
        transaction.verify_current_axt_spend_issuer_claims_v1(
            &tampered,
            &fixture.invocation,
            tampered.draft.handle.axt_binding,
        ),
        Err(AxtCurrentIssuerErrorV1::Authentication(
            AxtAnchoredSpendValidationErrorV1::HandleSignature
        )),
    );
}

#[test]
fn current_issuer_expiry_uses_consensus_slot_and_capped_signed_skew() {
    let mut fixture = fixture();
    for (slot, expected) in [
        (0, Err(AxtCurrentIssuerErrorV1::ZeroLedgerSlot)),
        (100, Ok(())),
        (101, Ok(())),
        (102, Err(AxtCurrentIssuerErrorV1::Expired)),
    ] {
        let mut block = fixture.state.block(header(slot));
        assert_eq!(verify(&block.transaction(), &fixture), expected);
    }
    let mut handle = fixture.spend.draft.handle.draft();
    handle.max_clock_skew_ms = Some(0);
    let mut draft = fixture.spend.draft.clone();
    draft.handle = handle
        .sign_by_issuer_v1(
            fixture.spend.draft.handle.issuer_context,
            fixture.issuer.private_key(),
        )
        .unwrap();
    fixture.spend = draft
        .sign_by_issuer_v1(
            fixture.spend.authorization.anchor,
            fixture.spend.authorization.expiry_slot,
            fixture.spend.authorization.nonce,
            fixture.issuer.private_key(),
        )
        .unwrap();
    let mut block = fixture.state.block(header(101));
    assert_eq!(
        verify(&block.transaction(), &fixture),
        Err(AxtCurrentIssuerErrorV1::Expired)
    );
}

#[test]
fn current_issuer_rejects_revocation_in_the_same_transaction_view() {
    let fixture = fixture();
    let mut block = fixture.state.block(header(100));
    let mut transaction = block.transaction();
    assert_eq!(verify(&transaction, &fixture), Ok(()));
    transaction
        .world
        .uaid_dataspaces
        .remove(fixture.spend.draft.handle.issuer_context.issuer);
    assert_eq!(
        verify(&transaction, &fixture),
        Err(AxtCurrentIssuerErrorV1::Issuer(
            AxtIssuerResolutionError::MissingDataspaceBinding
        ))
    );
    let uaid = fixture.spend.draft.handle.issuer_context.issuer;
    let dsid = fixture.spend.draft.intent.asset_dsid;
    let mut bindings = UaidDataspaceBindings::default();
    bindings.bind_account(dsid, fixture.issuer_account.clone());
    transaction.world.uaid_dataspaces.insert(uaid, bindings);
    let mut manifests = transaction
        .world
        .space_directory_manifests
        .get(&uaid)
        .unwrap()
        .clone();
    let mut manifest = manifests.get(&dsid).unwrap().clone();
    manifest.lifecycle.mark_expired(2);
    manifests.upsert(manifest);
    transaction
        .world
        .space_directory_manifests
        .insert(uaid, manifests);
    assert_eq!(
        verify(&transaction, &fixture),
        Err(AxtCurrentIssuerErrorV1::Issuer(
            AxtIssuerResolutionError::MissingManifest
        ))
    );
}

/// Drive the real instruction owners; never synthesize a transition marker.
fn revoke_and_republish_identical_authority(
    transaction: &mut StateTransaction<'_, '_>,
    fixture: &Fixture,
) {
    let uaid = fixture.spend.draft.handle.issuer_context.issuer;
    let dataspace = fixture.spend.draft.intent.asset_dsid;
    let manifest = transaction
        .world
        .space_directory_manifests
        .get(&uaid)
        .unwrap()
        .get(&dataspace)
        .unwrap()
        .manifest
        .clone();
    let mut permissions = Permissions::new();
    permissions.insert(Permission::from(CanPublishSpaceDirectoryManifestForUaid {
        dataspace,
        uaid,
    }));
    transaction
        .world
        .account_permissions
        .insert(fixture.issuer_account.clone(), permissions);
    RevokeSpaceDirectoryManifest {
        uaid,
        dataspace,
        revoked_epoch: 2,
        reason: Some("issuer freshness control".to_owned()),
    }
    .execute(&fixture.issuer_account, transaction)
    .expect("revoke current manifest");
    PublishSpaceDirectoryManifest { manifest }
        .execute(&fixture.issuer_account, transaction)
        .expect("republish identical manifest and issuer");
    assert_eq!(
        transaction
            .world
            .axt_policies
            .get(&dataspace)
            .unwrap()
            .manifest_root,
        fixture.spend.draft.handle.manifest_view_root
    );
    assert_eq!(
        transaction
            .world
            .axt_handle_counters
            .get(&dataspace)
            .copied(),
        Some(AxtHandleCounterRecord::initial(1)),
        "the permanent generation advances at block finalization"
    );
    assert!(
        transaction
            .world
            .axt_authorization_transitioned
            .contains(&dataspace)
    );
}

#[test]
fn current_issuer_rejects_reactivated_authority_before_local_generation_finalization() {
    let fixture = fixture();
    let mut block = fixture.state.block(header(100));
    let mut transaction = block.transaction();
    assert_eq!(verify(&transaction, &fixture), Ok(()));
    revoke_and_republish_identical_authority(&mut transaction, &fixture);
    assert_eq!(
        verify(&transaction, &fixture),
        Err(AxtCurrentIssuerErrorV1::PendingAuthorizationTransition)
    );
}

#[test]
fn current_issuer_rejects_reactivation_from_an_earlier_accepted_transaction() {
    let fixture = fixture();
    let mut block = fixture.state.block(header(100));
    let mut previous = block.transaction();
    revoke_and_republish_identical_authority(&mut previous, &fixture);
    previous.apply();
    let current = block.transaction();
    let dataspace = fixture.spend.draft.intent.asset_dsid;
    assert!(
        !current
            .world
            .axt_authorization_transitioned
            .contains(&dataspace),
        "this transaction has not changed authority"
    );
    assert!(
        current
            .block_axt_authorization_transitioned
            .contains(&dataspace)
    );
    assert_eq!(
        verify(&current, &fixture),
        Err(AxtCurrentIssuerErrorV1::PendingAuthorizationTransition)
    );
}

#[test]
fn current_issuer_rolled_back_reactivation_does_not_revoke_unchanged_authority() {
    let fixture = fixture();
    let mut block = fixture.state.block(header(100));
    {
        let mut abandoned = block.transaction();
        revoke_and_republish_identical_authority(&mut abandoned, &fixture);
        assert_eq!(
            verify(&abandoned, &fixture),
            Err(AxtCurrentIssuerErrorV1::PendingAuthorizationTransition)
        );
    }
    let current = block.transaction();
    assert!(current.world.axt_authorization_transitioned.is_empty());
    assert!(current.block_axt_authorization_transitioned.is_empty());
    assert_eq!(verify(&current, &fixture), Ok(()));
}

#[test]
fn current_issuer_rejects_stale_counter_generation_and_consumed_nonce() {
    let fixture = fixture();
    let mut block = fixture.state.block(header(100));
    let mut transaction = block.transaction();
    let dsid = fixture.spend.draft.intent.asset_dsid;
    for counter in [
        AxtHandleCounterRecord::try_from_parts(2, 1).unwrap(),
        AxtHandleCounterRecord::try_from_parts(1, 2).unwrap(),
    ] {
        transaction.world.axt_handle_counters.insert(dsid, counter);
        assert_eq!(
            verify(&transaction, &fixture),
            Err(AxtCurrentIssuerErrorV1::HandleCounter)
        );
    }
    transaction.world.axt_handle_counters.remove(dsid);
    assert_eq!(
        verify(&transaction, &fixture),
        Err(AxtCurrentIssuerErrorV1::HandleCounter)
    );
    transaction
        .world
        .axt_handle_counters
        .insert(dsid, AxtHandleCounterRecord::initial(1));
    transaction
        .world
        .axt_spend_nonce_ledger
        .insert(fixture.spend.replay_key_v1(), 99);
    assert_eq!(
        verify(&transaction, &fixture),
        Err(AxtCurrentIssuerErrorV1::NonceConsumed)
    );
}

#[test]
fn current_issuer_rejects_removed_asset_and_changed_registration_incarnation() {
    let fixture = fixture();
    let mut block = fixture.state.block(header(100));
    let mut transaction = block.transaction();
    let asset = fixture.spend.draft.handle.asset_definition_id.clone();
    transaction.world.axt_asset_incarnations.insert(
        asset.clone(),
        AxtAssetIncarnationV1::derive(
            fixture.state.network_id_ref(),
            &asset,
            &HashOf::from_untyped_unchecked(Hash::new(b"new registration")),
            &Hash::new(b"new execution"),
            0,
        ),
    );
    assert_eq!(
        verify(&transaction, &fixture),
        Err(AxtCurrentIssuerErrorV1::Authentication(
            AxtAnchoredSpendValidationErrorV1::HandleSignature
        ))
    );
    transaction.world.asset_definitions.remove(asset);
    assert_eq!(
        verify(&transaction, &fixture),
        Err(AxtCurrentIssuerErrorV1::AssetIncarnation)
    );
}

#[test]
fn current_issuer_rejects_changed_policy_envelope_code_and_key() {
    let fixture = fixture();
    let mut block = fixture.state.block(header(100));
    let mut transaction = block.transaction();
    let dsid = fixture.spend.draft.intent.asset_dsid;
    let original = *transaction.world.axt_policies.get(&dsid).unwrap();
    for changed in [
        AxtPolicyEntry {
            manifest_root: [0x88; 32],
            ..original
        },
        AxtPolicyEntry {
            target_lane: LaneId::new(1),
            ..original
        },
    ] {
        transaction.world.axt_policies.insert(dsid, changed);
        assert_eq!(
            verify(&transaction, &fixture),
            Err(AxtCurrentIssuerErrorV1::PolicyMismatch)
        );
    }
    transaction.world.axt_policies.remove(dsid);
    assert_eq!(
        verify(&transaction, &fixture),
        Err(AxtCurrentIssuerErrorV1::MissingPolicy)
    );
    transaction.world.axt_policies.insert(dsid, original);
    assert_eq!(
        transaction.verify_current_axt_spend_issuer_claims_v1(
            &fixture.spend,
            &fixture.invocation,
            AxtBinding::new([0x99; 32]),
        ),
        Err(AxtCurrentIssuerErrorV1::InvocationBinding)
    );
    let other_program = kotodama_lang::compiler::Compiler::new().compile_source(
        "seiyaku OtherIssuerFixture { permission other_issuer_fixture_run;  kotoage fn other() authorize(other_issuer_fixture_run) {} }",
    ).unwrap();
    let other = ivm::prepare_contract(Arc::<[u8]>::from(other_program)).unwrap();
    assert_eq!(
        transaction.verify_current_axt_spend_issuer_claims_v1(
            &fixture.spend,
            &other,
            fixture.spend.draft.handle.axt_binding,
        ),
        Err(AxtCurrentIssuerErrorV1::Authentication(
            AxtAnchoredSpendValidationErrorV1::HandleSignature
        ))
    );
    let changed_key = KeyPair::from_seed(vec![0x34; 32], Algorithm::Ed25519);
    let changed_account_id = AccountId::new(changed_key.public_key().clone());
    let uaid = fixture.spend.draft.handle.issuer_context.issuer;
    transaction
        .world
        .accounts
        .remove(fixture.issuer_account.clone());
    let (changed_account_id, changed_account) = Account::new(changed_account_id.clone())
        .with_uaid(Some(uaid))
        .build(&changed_account_id)
        .into_key_value();
    transaction
        .world
        .accounts
        .insert(changed_account_id.clone(), changed_account);
    transaction
        .world
        .uaid_accounts
        .insert(uaid, changed_account_id.clone());
    let mut bindings = UaidDataspaceBindings::default();
    bindings.bind_account(dsid, changed_account_id);
    transaction.world.uaid_dataspaces.insert(uaid, bindings);
    assert_ne!(fixture.issuer.public_key(), changed_key.public_key());
    assert_eq!(
        verify(&transaction, &fixture),
        Err(AxtCurrentIssuerErrorV1::Authentication(
            AxtAnchoredSpendValidationErrorV1::HandleSignature
        ))
    );
}
