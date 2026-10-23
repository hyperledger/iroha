//! Genuine executor + BLS-certified block fixture. These sources are not a test
//! result until Native applies the staged models/registrations and runs them.
use super::*;
use iroha_core::{
    state::{StateReadOnly, StorageReadOnly, World, WorldReadOnly},
    sumeragi::{
        finality::{build_checkpoint, build_proof},
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_crypto::sha256;
use iroha_crypto::{Algorithm, HashOf, KeyPair};
use iroha_data_model::{
    account::Account,
    asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId, fi_link::AssetFiV1},
    block::execution_output::ExecutionOutputV1,
    isi::{InstructionBox, Log, Register},
    query::{
        CommittedTransaction, QueryOutput, QueryOutputBatchBox, QueryOutputBatchBoxTuple,
        QueryResponse,
    },
    sumeragi_finality::{SumeragiFinalityCheckpoint, SumeragiFinalityVerifier},
};
use iroha_primitives::numeric::NumericSpec;

pub(crate) struct Fixture {
    pub(crate) checkpoint: SumeragiFinalityCheckpoint,
    pub(crate) checkpoint_bytes: Vec<u8>,
    pub(crate) checkpoint_context: [u8; 32],
    pub(crate) original_request: Vec<u8>,
    pub(crate) request: NormalizedAssetFiContextRequestV1,
    pub(crate) owner: AccountId,
    pub(crate) incarnation: AxtAssetIncarnationV1,
    pub(crate) capsule: AssetFiContextAssertionCapsuleV1,
    pub(crate) later_checkpoint: SumeragiFinalityCheckpoint,
}

pub(crate) fn ffi_fixture(
    false_observation: bool,
    extra_instruction: bool,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let f = Fixture::new(false_observation, extra_instruction);
    let raw: norito::json::Value = norito::json::from_slice(&f.original_request).unwrap();
    let target = raw.as_object().unwrap().get("target").unwrap().clone();
    let AssetFiContextTargetV1::LinkApproval(link) = &f.request.target else {
        unreachable!()
    };
    let trust = norito::json::to_vec(&norito::json!({
        "schema":"iroha.fi-context-verification-trust.v1",
        "networkId":(f.request.network_id.to_string()),"chainId":(f.request.chain_id),
        "checkpointSha256":(hex::encode(sha256(&f.checkpoint_bytes))),
        "checkpointHeight":"2","checkpointContextId":(hex::encode(f.checkpoint_context)),
        "assetOwner":(f.owner.to_string()),"assetIncarnation":(hex::encode(f.incarnation.as_bytes())),
        "assetDefinitionId":(f.request.asset_id.to_string()),"walletAccountId":(f.request.wallet.to_string()),
        "uid":(hex::encode(f.request.uid)),"fiAccountId":(link.link.fi_account_id.to_string()),
        "fiParticipant":(f.request.fi_participant),"uidController":null,
        "runtimeManifestSha256":(hex::encode(f.request.runtime_manifest_sha256)),
        "ownerKeyIdentity":(f.request.owner_key_identity),
        "walletScopeCanonical":(String::from_utf8(f.request.wallet_scope_canonical.clone()).unwrap()),
        "requestSha256":(hex::encode(f.request.original_sha256)),"target":target,
    })).unwrap();
    (
        f.capsule.encode_canonical().unwrap(),
        f.original_request,
        f.checkpoint_bytes,
        trust,
    )
}

impl Fixture {
    pub(crate) fn new(false_observation: bool, extra_instruction: bool) -> Self {
        Self::with_delay(false_observation, extra_instruction, 0)
    }
    pub(crate) fn with_delay(false_observation: bool, extra_instruction: bool, delay: u64) -> Self {
        let wallet = AccountId::new(
            KeyPair::from_seed(vec![0x71; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let fi = AccountId::new(
            KeyPair::from_seed(vec![0x72; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let asset: AssetDefinitionId = "7ZepsJTHCVLKsrFFNZGSRGZgvBhv".parse().unwrap();
        let mut config = TestChainConfig::new(World::new(), 1_000);
        let owner_key = config.genesis_key.clone();
        let owner = AccountId::new(owner_key.public_key().clone());
        config.genesis_instructions = vec![
            Register::account(Account::new(wallet.clone())).into(),
            Register::account(Account::new(fi.clone())).into(),
            Register::asset_definition(AssetDefinition::new(
                asset.clone(),
                "FI fixture",
                NumericSpec::fractional(2),
                AssetBalancePolicy::Global,
                None,
            ))
            .into(),
        ];
        let mut chain = CertifiedTestChain::start(config).unwrap();
        chain.commit(Vec::new());
        let checkpoint = build_checkpoint(&chain.state().view(), 2).unwrap();
        let checkpoint_bytes = checkpoint.encode_canonical().unwrap();
        let (_, tip) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
            &checkpoint,
            &chain.network_id(),
            checkpoint.chain_id(),
        )
        .unwrap();
        let checkpoint_context = *tip.context_id().as_ref();
        let incarnation = *chain
            .state()
            .view()
            .world()
            .axt_asset_incarnations()
            .get(&asset)
            .unwrap();
        let fees = norito::json!({"payer":"sponsor", "value":{
            "program_id":{"sponsor":(wallet.to_string()),"name":"demo"},
            "program_revision":1_u64,"charge_limits":[],"gas_limit":null}});
        let scope = norito::json!({"accountId":(wallet.to_string()),"bank":"demo-bank",
            "participantScope":"demo.universal","coreBaseUrl":"https://core.invalid/demo",
            "chainId":(checkpoint.chain_id()),"networkId":(chain.network_id().to_string()),
            "assetDefinitionId":(asset.to_string()),
            "feeSponsorProgramId":(format!("{wallet}/demo")),"fees":fees});
        let target = norito::json!({"assetDefinitionId":(asset.to_string()),"accountId":(wallet.to_string()),
            "fiAccountId":(fi.to_string()),"referenceDigest":(hex::encode([9_u8;32])),
            "fiRevision":1_u64,"attestationRevision":1_u64,"revision":1_u64,
            "expectedPolicyRevision":1_u64,"enabled":false,"controller":null,
            "waterfall":false,"reverseWaterfall":false});
        let original_request = norito::json::to_vec(&norito::json!({
            "schema":"boi.wallet-fi-context-evidence.ios.v1",
            "binding":{"schema":"boi.wallet-fi-context.v1","walletScope":scope,
                "runtimeManifestDigest":(hex::encode([8_u8;32])),"uid":(hex::encode([7_u8;32])),
                "fiParticipant":"demo-fi","fiAccountId":(fi.to_string()),"uidController":null},
            "ownerKeyIdentity":"retained-device-key","minimumCertifiedHeight":2_u64,
            "challengeHex":(hex::encode([6_u8;32])),"target":target}))
        .unwrap();
        let request = normalize_asset_fi_context_request_v1(&original_request).unwrap();
        let snapshot = AssetFiContextSnapshotV1 {
            asset_definition_id: asset.clone(),
            asset_incarnation: incarnation,
            account_id: wallet,
            uid: request.uid,
            fi_account_id: fi.clone(),
            reference_digest: [9; 32],
            binding: None,
            policy: None,
            fi: false_observation.then_some(AssetFiV1 {
                asset_definition_id: asset,
                fi_account_id: fi,
                revision: 1,
                enabled: true,
            }),
            attestation: None,
            link: None,
            controller: None,
        };
        let assertion = AssertAssetFiContextV1 {
            target: request.target.clone(),
            expected_incarnation: incarnation,
            expected_uid: request.uid,
            expected_context_hash: asset_fi_context_snapshot_hash_v1(&snapshot).unwrap(),
            request_sha256: request.original_sha256,
            challenge: request.challenge,
            minimum_height: 2,
            minimum_block_hash: *checkpoint.block_hash().as_ref(),
        };
        let mut instructions: Vec<InstructionBox> = vec![assertion.into()];
        if extra_instruction {
            instructions.push(Log::new(iroha_data_model::Level::INFO, "extra".into()).into());
        }
        for _ in 0..delay {
            chain.commit(Vec::new());
        }
        let carrier_height = 3 + delay;
        let signed = chain.sign(&owner_key, instructions, 1_002);
        let original = signed.encode_wire_v1().unwrap();
        assert_eq!(chain.commit(vec![signed]), vec![!false_observation]);
        let block = chain.committed(carrier_height).block().clone();
        let output = ExecutionOutputV1::Network(block.network_output_at(0).unwrap().1.clone());
        let row = CommittedTransaction {
            block_hash: block.hash(),
            entrypoint_hash: block.network_entrypoint_at(0).unwrap().hash(),
            entrypoint_proof: block.network_input_proof(0).unwrap(),
            entrypoint: block.network_entrypoint_at(0).unwrap().clone(),
            output_hash: HashOf::new(&output),
            output_proof: block.output_proof(0).unwrap(),
            output,
        };
        let response = norito::to_bytes(&QueryResponse::Iterable(QueryOutput {
            batch: QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::CommittedTransaction(
                vec![row],
            )),
            remaining_items: Some(0),
            has_more: false,
            continue_cursor: None,
        }))
        .unwrap();
        let view = chain.state().view();
        let capsule = AssetFiContextAssertionCapsuleV1 {
            version: 1,
            snapshot,
            assertion_signed_transaction: original,
            committed_transaction_response: response,
            finality_proof_chain: (2..=carrier_height)
                .map(|height| build_proof(&view, height).unwrap())
                .collect(),
        };
        drop(view);
        chain.commit(Vec::new());
        let later_checkpoint = build_checkpoint(&chain.state().view(), carrier_height + 1).unwrap();
        Self {
            checkpoint,
            checkpoint_bytes,
            checkpoint_context,
            original_request,
            request,
            owner,
            incarnation,
            capsule,
            later_checkpoint,
        }
    }
    pub(crate) fn expected(&self) -> FiContextAssertionExpectation<'_> {
        FiContextAssertionExpectation {
            network_id: self.checkpoint.network_id(),
            chain_id: self.checkpoint.chain_id(),
            checkpoint_sha256: sha256(&self.checkpoint_bytes).into(),
            checkpoint_height: 2,
            checkpoint_context_id: self.checkpoint_context,
            asset_owner: &self.owner,
            asset_incarnation: self.incarnation,
            uid: self.request.uid,
            target: &self.request.target,
            runtime_manifest_sha256: self.request.runtime_manifest_sha256,
            owner_key_identity: &self.request.owner_key_identity,
            fi_participant: &self.request.fi_participant,
            wallet_scope_canonical: &self.request.wallet_scope_canonical,
        }
    }
    fn verify(&self) -> Result<VerifiedFiContextAssertionV1, String> {
        verify_fi_context_assertion_v1(
            &self.capsule.encode_canonical()?,
            &self.original_request,
            &self.checkpoint_bytes,
            &self.expected(),
        )
    }
}

#[test]
fn fi_capsule_authenticates_actual_assertion_execution_and_preserves_absence() {
    let fixture = Fixture::new(false, false);
    let bytes = fixture.capsule.encode_canonical().unwrap();
    assert!(
        bytes.len() <= 512 * 1024,
        "positive original must fit the operational carrier bound"
    );
    let verified = fixture.verify().unwrap();
    assert_eq!(verified.block_height, 3);
    assert!(verified.block_creation_time_ms >= 1_002);
    assert_eq!(verified.request_sha256, fixture.request.original_sha256);
    assert!(
        verified.snapshot.binding.is_none()
            && verified.snapshot.policy.is_none()
            && verified.snapshot.fi.is_none()
            && verified.snapshot.attestation.is_none()
            && verified.snapshot.link.is_none()
            && verified.snapshot.controller.is_none()
    );
    // Authenticated absence never means the wallet has membership or an FI role.
}

#[test]
fn fi_capsule_rejects_certified_failed_assertion_and_extra_successful_instruction() {
    assert!(Fixture::new(true, false).verify().is_err());
    assert!(Fixture::new(false, true).verify().is_err());
}

#[test]
fn fi_capsule_rejects_altered_observations_originals_pins_and_finality_page() {
    let mut fixture = Fixture::new(false, false);
    fixture.verify().unwrap();
    let original = fixture.capsule.snapshot.clone();
    fixture.capsule.snapshot.uid = [4; 32];
    assert!(fixture.verify().is_err());
    fixture.capsule.snapshot = original;
    let mut raw: norito::json::Value = norito::json::from_slice(&fixture.original_request).unwrap();
    raw.as_object_mut()
        .unwrap()
        .insert("challengeHex".into(), hex::encode([5_u8; 32]).into());
    assert!(
        verify_fi_context_assertion_v1(
            &fixture.capsule.encode_canonical().unwrap(),
            &norito::json::to_vec(&raw).unwrap(),
            &fixture.checkpoint_bytes,
            &fixture.expected()
        )
        .is_err()
    );
    let mut expected = fixture.expected();
    expected.runtime_manifest_sha256 = [3; 32];
    assert!(
        verify_fi_context_assertion_v1(
            &fixture.capsule.encode_canonical().unwrap(),
            &fixture.original_request,
            &fixture.checkpoint_bytes,
            &expected
        )
        .is_err()
    );
    let mut expected = fixture.expected();
    expected.asset_owner = &fixture.request.wallet;
    assert!(
        verify_fi_context_assertion_v1(
            &fixture.capsule.encode_canonical().unwrap(),
            &fixture.original_request,
            &fixture.checkpoint_bytes,
            &expected
        )
        .is_err()
    );
    fixture.capsule.finality_proof_chain.reverse();
    assert!(fixture.verify().is_err());
}

#[test]
fn fi_capsule_codec_rejects_oversized_versioned_trailing_and_truncated_originals() {
    let mut fixture = Fixture::new(false, false);
    let bytes = fixture.capsule.encode_canonical().unwrap();
    assert_eq!(
        AssetFiContextAssertionCapsuleV1::decode_canonical(&bytes)
            .unwrap()
            .encode_canonical()
            .unwrap(),
        bytes
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(AssetFiContextAssertionCapsuleV1::decode_canonical(&trailing).is_err());
    assert!(AssetFiContextAssertionCapsuleV1::decode_canonical(&bytes[..bytes.len() - 1]).is_err());
    assert!(AssetFiContextAssertionCapsuleV1::decode_canonical(&vec![0; 512 * 1024 + 1]).is_err());
    fixture.capsule.version = 2;
    assert!(fixture.capsule.encode_canonical().is_err());
    fixture.capsule.version = 1;
    fixture.capsule.assertion_signed_transaction = vec![0; 512 * 1024];
    assert!(fixture.capsule.encode_canonical().is_err());
}
