// for `collect`
use super::*;
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode},
};
use futures::executor;
use iroha_config::parameters::actual;
use iroha_core::{query::store::LiveQueryStore, state::State as IrohaState};
use iroha_crypto::{
    Algorithm, Hash, KeyPair, RamLfeBackend, RamLfeVerificationMode, Signature as IrohaSignature,
    SignatureOf, ram_lfe_output_hash,
};
use iroha_data_model::{
    Identifiable, Registrable, ValidationFail,
    account::{Account, AccountId, rekey::AccountAlias},
    block::BlockHeader,
    domain::Domain,
    identifier::{IdentifierNormalization, IdentifierPolicy, IdentifierPolicyId},
    isi::{
        identifier::{ActivateIdentifierPolicy, RegisterIdentifierPolicy},
        ram_lfe::{ActivateRamLfeProgramPolicy, RegisterRamLfeProgramPolicy},
    },
    nexus::{AxtPolicySnapshot, AxtRejectContext, AxtRejectReason, UniversalAccountId},
    permission::Permission,
    prelude::{Parameter, Quantity},
    proof::{ProofId, ProofRecord, ProofStatus},
    ram_lfe::{
        RamLfeOutputOpening, RamLfeOutputOpeningPayload, RamLfeProgramId, RamLfeProgramPolicy,
    },
    role::{Role, RoleId},
    transaction::signed::TransactionBuilder,
};
use iroha_executor_data_model::permission::account::{
    AccountAliasPermissionScope, CanManageAccountAlias, CanResolveAccountAlias,
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_test_samples::ALICE_ID;
use nonzero_ext::nonzero;
use std::{
    collections::HashSet,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};
const PREBUILT_QUARANTINE_PROVIDER_HANDLE: &str = "kms://moderation/quarantine/primary";
const PREBUILT_QUARANTINE_PROVIDER_QUALIFICATION:
    sorafs_node::ModerationQuarantineKeyProviderQualificationV1 =
    sorafs_node::ModerationQuarantineKeyProviderQualificationV1::new(1, [0x51; 32]);
async fn assert_default_body_limit_boundary(limit: usize) {
    use tower::ServiceExt as _;
    let router = axum::Router::new().route(
        "/probe",
        axum::routing::post(move |body: Bytes| async move {
            assert_eq!(body.len(), limit);
            StatusCode::NO_CONTENT
        })
        .layer(DefaultBodyLimit::max(limit)),
    );
    let boundary = Request::builder()
        .method(Method::POST)
        .uri("/probe")
        .body(Body::from(vec![0_u8; limit]))
        .expect("boundary request");
    assert_eq!(
        router
            .clone()
            .oneshot(boundary)
            .await
            .expect("boundary response")
            .status(),
        StatusCode::NO_CONTENT
    );
    let one_over = Request::builder()
        .method(Method::POST)
        .uri("/probe")
        .body(Body::from(vec![0_u8; limit.saturating_add(1)]))
        .expect("one-over request");
    assert_eq!(
        router
            .oneshot(one_over)
            .await
            .expect("one-over response")
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}
#[cfg(feature = "app_api")]
#[tokio::test]
async fn sorafs_protocol_body_limits_admit_boundary_and_reject_one_over() {
    for limit in [
        0,
        sorafs_manifest::provider_advert::PROVIDER_ADVERT_MAX_CANONICAL_BYTES_V1,
        crate::routing::POR_PROOF_SUBMISSION_MAX_HTTP_BODY_BYTES_V1,
        crate::routing::POR_VERDICT_SUBMISSION_MAX_HTTP_BODY_BYTES_V1,
        sorafs_manifest::por::PROVIDER_VRF_SUBMISSION_MAX_CANONICAL_BYTES_V1,
        sorafs_node::orderbook_transaction_forwarder::ORDERBOOK_TRANSACTION_MAX_CANONICAL_BYTES_V1,
    ] {
        assert_default_body_limit_boundary(limit).await;
    }
}
#[cfg(feature = "app_api")]
#[test]
fn bodyless_por_and_orderbook_get_mounts_have_zero_body_limits() {
    let compact_source: String = include_str!("../../lib.rs")
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    for (route, handler) in [
        ("SORAFS_POR_STATUS_GET", "handler_get_sorafs_por_status"),
        ("SORAFS_POR_EXPORT_GET", "handler_get_sorafs_por_export"),
        (
            "SORAFS_POR_INGESTION_BY_MANIFEST_DIGEST_HEX_GET",
            "sorafs::api::handle_get_sorafs_por_ingestion",
        ),
        (
            "SORAFS_POR_REPORT_BY_ISO_WEEK_GET",
            "handler_get_sorafs_por_report",
        ),
        (
            "SORAFS_ORDERBOOK_RECEIPTS_GET",
            "sorafs::api::handle_get_sorafs_orderbook_receipts",
        ),
        (
            "SORAFS_ORDERBOOK_BOOK_GET",
            "sorafs::api::handle_get_sorafs_orderbook_book",
        ),
        (
            "SORAFS_ORDERBOOK_TRADES_GET",
            "sorafs::api::handle_get_sorafs_orderbook_trades",
        ),
        (
            "SORAFS_ORDERBOOK_CHANNELS_GET",
            "sorafs::api::handle_get_sorafs_orderbook_channels",
        ),
        (
            "SORAFS_ORDERBOOK_EVENTS_GET",
            "sorafs::api::handle_get_sorafs_orderbook_events",
        ),
        (
            "SORAFS_ORDERBOOK_EVENTS_STREAM_GET",
            "sorafs::api::handle_get_sorafs_orderbook_events_stream",
        ),
        (
            "SORAFS_ORDERBOOK_EVENTS_WS_GET",
            "sorafs::api::handle_get_sorafs_orderbook_events_ws",
        ),
    ] {
        let expected = if route.ends_with("_STREAM_GET") || route.ends_with("_WS_GET") {
            format!("{route}=>limited_canonical_account_get({handler},app_state,0,0);")
        } else {
            format!("{route}=>limited_public_get({handler},0);")
        };
        assert!(
            compact_source.contains(&expected),
            "{route} must reject every non-empty request body"
        );
    }
}
#[derive(Debug)]
struct PrebuiltQuarantineKeyWrapper;
impl sorafs_node::ModerationQuarantineKeyWrapper for PrebuiltQuarantineKeyWrapper {
    fn provider_handle(&self) -> &str {
        PREBUILT_QUARANTINE_PROVIDER_HANDLE
    }
    fn qualification(
        &self,
    ) -> Result<
        sorafs_node::ModerationQuarantineKeyProviderQualificationV1,
        sorafs_node::ModerationQuarantineKeyProviderReadinessErrorV1,
    > {
        Ok(PREBUILT_QUARANTINE_PROVIDER_QUALIFICATION)
    }
    fn active_key_id(&self) -> &str {
        "software://moderation/quarantine/key-v1"
    }
    fn wrap_dek(
        &self,
        context_digest: [u8; 32],
        dek: &[u8; 32],
    ) -> Result<Vec<u8>, sorafs_node::ModerationQuarantineKeyOperationErrorV1> {
        use iroha_crypto::encryption::{ChaCha20Poly1305, SymmetricEncryptor};
        // Deterministic fixture key and nonce; this wrapper exists only in tests.
        SymmetricEncryptor::<ChaCha20Poly1305>::new_with_key([0xA6; 32])
            .expect("test wrapping key has the required size")
            .encrypt(&context_digest[..12], &context_digest, dek)
            .map_err(|_| sorafs_node::ModerationQuarantineKeyOperationErrorV1::Rejected)
    }
    fn unwrap_dek(
        &self,
        key_id: &str,
        context_digest: [u8; 32],
        wrapped_dek: &[u8],
    ) -> Result<[u8; 32], sorafs_node::ModerationQuarantineKeyOperationErrorV1> {
        use iroha_crypto::encryption::{ChaCha20Poly1305, SymmetricEncryptor};
        if key_id != self.active_key_id() {
            return Err(sorafs_node::ModerationQuarantineKeyOperationErrorV1::StaleOrRevoked);
        }
        SymmetricEncryptor::<ChaCha20Poly1305>::new_with_key([0xA6; 32])
            .expect("test wrapping key has the required size")
            .decrypt(&context_digest[..12], &context_digest, wrapped_dek)
            .map_err(|_| sorafs_node::ModerationQuarantineKeyOperationErrorV1::Rejected)?
            .try_into()
            .map_err(|_| sorafs_node::ModerationQuarantineKeyOperationErrorV1::Rejected)
    }
}
#[test]
fn prebuilt_quarantine_key_wrapper_binds_key_context_and_ciphertext() {
    use sorafs_node::ModerationQuarantineKeyWrapper as _;
    let wrapper = PrebuiltQuarantineKeyWrapper;
    let context = [0x51; 32];
    let dek = [0x63; 32];
    let wrapped = wrapper.wrap_dek(context, &dek).expect("wrap fixture DEK");
    assert_eq!(
        wrapper
            .unwrap_dek(wrapper.active_key_id(), context, &wrapped)
            .expect("unwrap fixture DEK"),
        dek,
    );
    assert!(wrapper.unwrap_dek("wrong-key", context, &wrapped).is_err());
    assert!(
        wrapper
            .unwrap_dek(wrapper.active_key_id(), [0x52; 32], &wrapped)
            .is_err()
    );
    let mut tampered = wrapped;
    tampered[0] ^= 1;
    assert!(
        wrapper
            .unwrap_dek(wrapper.active_key_id(), context, &tampered)
            .is_err()
    );
}
fn prebuilt_quarantine_provider_config(
    qualification: sorafs_node::ModerationQuarantineKeyProviderQualificationV1,
) -> actual::SorafsModerationQuarantineKeyProviderBinding {
    actual::SorafsModerationQuarantineKeyProviderBinding {
        handle: PREBUILT_QUARANTINE_PROVIDER_HANDLE.to_owned(),
        revision: qualification.revision(),
        policy_digest: qualification.policy_digest(),
    }
}
#[test]
fn prebuilt_sorafs_node_rejects_mismatched_quarantine_key_provider_binding() {
    let temp_dir = tempfile::tempdir().expect("create prebuilt SoraFS node temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical prebuilt SoraFS node temp dir");
    let retained_config = sorafs_node::config::StorageConfig::builder()
        .enabled(true)
        .data_dir(root.join("storage"))
        .moderation_quarantine_key_provider(Some(prebuilt_quarantine_provider_config(
            PREBUILT_QUARANTINE_PROVIDER_QUALIFICATION,
        )))
        .build();
    let key_wrapper: Arc<dyn sorafs_node::ModerationQuarantineKeyWrapper> =
        Arc::new(PrebuiltQuarantineKeyWrapper);
    let node = sorafs_node::NodeHandle::try_new_with_quarantine_key_wrapper(
        retained_config,
        Arc::clone(&key_wrapper),
    )
    .expect("start prebuilt SoraFS node with exact provider binding");
    assert!(node.uses_moderation_quarantine_key_wrapper(&key_wrapper));
    let substituted_config = sorafs_node::config::StorageConfig::builder()
        .enabled(true)
        .data_dir(root.join("storage"))
        .moderation_quarantine_key_provider(Some(prebuilt_quarantine_provider_config(
            sorafs_node::ModerationQuarantineKeyProviderQualificationV1::new(2, [0x52; 32]),
        )))
        .build();
    assert_eq!(
        validate_prebuilt_sorafs_quarantine_key_provider_binding(&node, &substituted_config),
        Err("injected SoraFS node quarantine-key provider binding does not match configuration"),
    );
}
const PREBUILT_PRIVACY_PRF_HANDLE: &str = "threshold-prf:transparency:primary";
const PREBUILT_PRIVACY_ANCHOR_HANDLE: &str = "governance-dag:transparency:primary";
const PREBUILT_TRANSPARENCY_LEADER_LEASE_HANDLE: &str = "sealed-cas:transparency:leader-primary";
const PREBUILT_FENCED_PRIVACY_HANDLE: &str = "governance-cas:transparency:privacy-primary";
const PREBUILT_FENCED_PRIVACY_POLICY_DIGEST: [u8; 32] = [0xF7; 32];
const PREBUILT_GOVERNANCE_SIGNER_HANDLE: &str = "software://sorafs/governance-dag/primary";
const PREBUILT_GOVERNANCE_SIGNER_PEER_ID: &[u8] = b"governance-torii-primary";
const PREBUILT_GOVERNANCE_SIGNER_POLICY_DIGEST: [u8; 32] = [0x97; 32];
const PREBUILT_GOVERNANCE_CHECKPOINT_STORE_HANDLE: &str =
    "sealed:governance:producer-checkpoint-primary";
const PREBUILT_GOVERNANCE_CHECKPOINT_STORE_POLICY_DIGEST: [u8; 32] = [0x96; 32];
#[derive(Debug)]
struct PrebuiltGovernanceDagSigner {
    key_pair: KeyPair,
    last_purpose: Mutex<Option<sorafs_node::GovernanceDagSigningPurposeV1>>,
}
impl PrebuiltGovernanceDagSigner {
    fn new() -> Self {
        Self::from_seed(0x97)
    }
    fn from_seed(seed: u8) -> Self {
        Self {
            key_pair: KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                .expect("derive prebuilt Governance DAG signer key"),
            last_purpose: Mutex::new(None),
        }
    }
    fn public_key_bytes(&self) -> [u8; 32] {
        let (algorithm, bytes) = self
            .key_pair
            .public_key()
            .try_to_bytes()
            .expect("serialize prebuilt Governance DAG public key");
        assert_eq!(algorithm, Algorithm::Ed25519);
        bytes.try_into().expect("Ed25519 public key width")
    }
    fn observed_purpose(&self) -> Option<sorafs_node::GovernanceDagSigningPurposeV1> {
        *self.last_purpose.lock().expect("signing purpose lock")
    }
}
impl sorafs_node::GovernanceDagRuntimeSigner for PrebuiltGovernanceDagSigner {
    fn handle(&self) -> &str {
        PREBUILT_GOVERNANCE_SIGNER_HANDLE
    }
    fn qualification(
        &self,
    ) -> Result<sorafs_node::GovernanceDagRuntimeProviderQualificationV1, String> {
        Ok(
            sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(
                1,
                PREBUILT_GOVERNANCE_SIGNER_POLICY_DIGEST,
            ),
        )
    }
    fn publisher_peer_id(&self) -> &[u8] {
        PREBUILT_GOVERNANCE_SIGNER_PEER_ID
    }
    fn public_key(&self) -> [u8; 32] {
        self.public_key_bytes()
    }
    fn sign(
        &self,
        purpose: sorafs_node::GovernanceDagSigningPurposeV1,
        payload: &[u8],
    ) -> Result<[u8; 64], String> {
        *self.last_purpose.lock().expect("signing purpose lock") = Some(purpose);
        IrohaSignature::try_new(self.key_pair.private_key(), payload)
            .map_err(|_| "prebuilt Governance DAG signer refused request".to_owned())?
            .payload()
            .try_into()
            .map_err(|_| "prebuilt Governance DAG signature width changed".to_owned())
    }
}
#[test]
fn prebuilt_governance_signer_receives_the_exact_purpose() {
    let signer = PrebuiltGovernanceDagSigner::new();
    sorafs_node::GovernanceDagRuntimeSigner::sign(
        &signer,
        sorafs_node::GovernanceDagSigningPurposeV1::DagHead,
        b"canonical governance DAG head fixture",
    )
    .expect("fixture signer accepts the explicit purpose");
    assert_eq!(
        signer.observed_purpose(),
        Some(sorafs_node::GovernanceDagSigningPurposeV1::DagHead)
    );
}
#[derive(Debug)]
struct PrebuiltGovernanceDagCheckpointStoreState {
    records: [Option<sorafs_node::GovernanceDagSealedStateRecord>; 6],
    generation_floors: [u64; 6],
}
impl Default for PrebuiltGovernanceDagCheckpointStoreState {
    fn default() -> Self {
        Self {
            records: std::array::from_fn(|_| None),
            generation_floors: [0; 6],
        }
    }
}
#[derive(Debug)]
struct PrebuiltGovernanceDagCheckpointStore {
    handle: &'static str,
    qualification: sorafs_node::GovernanceDagRuntimeProviderQualificationV1,
    state: Mutex<PrebuiltGovernanceDagCheckpointStoreState>,
    qualification_refuse: AtomicBool,
}
impl PrebuiltGovernanceDagCheckpointStore {
    fn exact() -> Self {
        Self::with_binding(
            PREBUILT_GOVERNANCE_CHECKPOINT_STORE_HANDLE,
            sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(
                1,
                PREBUILT_GOVERNANCE_CHECKPOINT_STORE_POLICY_DIGEST,
            ),
        )
    }
    fn with_binding(
        handle: &'static str,
        qualification: sorafs_node::GovernanceDagRuntimeProviderQualificationV1,
    ) -> Self {
        Self {
            handle,
            qualification,
            state: Mutex::new(PrebuiltGovernanceDagCheckpointStoreState::default()),
            qualification_refuse: AtomicBool::new(false),
        }
    }
    const fn slot_index(slot: sorafs_node::GovernanceDagSealedStateSlot) -> usize {
        match slot {
            sorafs_node::GovernanceDagSealedStateSlot::Checkpoint => 0,
            sorafs_node::GovernanceDagSealedStateSlot::PublishIntent => 1,
            sorafs_node::GovernanceDagSealedStateSlot::ProducerCheckpoint => 2,
            sorafs_node::GovernanceDagSealedStateSlot::ProducerPublishIntent => 3,
            sorafs_node::GovernanceDagSealedStateSlot::IpfsRequestReplay => 4,
            sorafs_node::GovernanceDagSealedStateSlot::SignedHeadRequestReplay => 5,
        }
    }
    fn refuse_qualification(&self) {
        self.qualification_refuse
            .store(true, AtomicOrdering::SeqCst);
    }
}
impl sorafs_node::GovernanceDagSealedCheckpointStore for PrebuiltGovernanceDagCheckpointStore {
    fn handle(&self) -> &str {
        self.handle
    }
    fn qualification(
        &self,
    ) -> Result<sorafs_node::GovernanceDagRuntimeProviderQualificationV1, String> {
        if self.qualification_refuse.load(AtomicOrdering::SeqCst) {
            return Err("checkpoint credential must remain redacted".to_owned());
        }
        Ok(self.qualification)
    }
    fn load(
        &self,
        slot: sorafs_node::GovernanceDagSealedStateSlot,
    ) -> Result<Option<sorafs_node::GovernanceDagSealedStateRecord>, String> {
        let state = self.state.lock().map_err(|_| "poisoned".to_owned())?;
        Ok(state.records[Self::slot_index(slot)].clone())
    }
    fn compare_and_swap(
        &self,
        slot: sorafs_node::GovernanceDagSealedStateSlot,
        expected_revision: Option<[u8; 32]>,
        next: sorafs_node::GovernanceDagSealedStateRecord,
    ) -> Result<(), String> {
        let index = Self::slot_index(slot);
        let mut state = self.state.lock().map_err(|_| "poisoned".to_owned())?;
        if state.records[index].as_ref().map(|record| record.revision) != expected_revision {
            return Err("compare-and-swap conflict".to_owned());
        }
        if next.generation <= state.generation_floors[index]
            || next.payload.is_empty()
            || !next.has_valid_revision(slot)
        {
            return Err("invalid or non-monotonic record".to_owned());
        }
        state.generation_floors[index] = next.generation;
        state.records[index] = Some(next);
        Ok(())
    }
    fn delete(
        &self,
        slot: sorafs_node::GovernanceDagSealedStateSlot,
        expected_revision: [u8; 32],
    ) -> Result<(), String> {
        let index = Self::slot_index(slot);
        let mut state = self.state.lock().map_err(|_| "poisoned".to_owned())?;
        if state.records[index].as_ref().map(|record| record.revision) != Some(expected_revision) {
            return Err("delete conflict".to_owned());
        }
        state.records[index] = None;
        Ok(())
    }
}
struct PrebuiltPrivacyPrfProvider;
impl sorafs_node::PrivacyCyclePrfProviderV1 for PrebuiltPrivacyPrfProvider {
    fn derive_cycle_output(
        &self,
        _request: &sorafs_node::PrivacyCyclePrfRequestV1,
    ) -> Result<sorafs_node::PrivacyCyclePrfOutputV1, sorafs_node::PrivacyCyclePrfProviderErrorV1>
    {
        sorafs_node::PrivacyCyclePrfOutputV1::new([0xA5; 32])
            .map_err(|_| sorafs_node::PrivacyCyclePrfProviderErrorV1::Internal)
    }
}
impl sorafs_node::ProductionTransparencyRuntimeProviderV1 for PrebuiltPrivacyPrfProvider {
    fn handle(&self) -> &str {
        PREBUILT_PRIVACY_PRF_HANDLE
    }
    fn qualification(
        &self,
    ) -> Result<sorafs_node::TransparencyRuntimeProviderQualificationV1, String> {
        Ok(sorafs_node::TransparencyRuntimeProviderQualificationV1::new(1, [0xC7; 32]))
    }
}
struct PrebuiltPrivacyReleaseAnchor;
impl sorafs_node::PrivacyReleaseAnchorV1 for PrebuiltPrivacyReleaseAnchor {
    fn finalized_head(
        &self,
        query_id: [u8; 32],
    ) -> Result<sorafs_node::PrivacyReleaseAnchorHeadV1, sorafs_node::PrivacyReleaseAnchorErrorV1>
    {
        Ok(sorafs_node::PrivacyReleaseAnchorHeadV1::genesis(query_id))
    }
    fn compare_and_set_finalized_head(
        &self,
        _expected: sorafs_node::PrivacyReleaseAnchorHeadV1,
        _next: sorafs_node::PrivacyReleaseAnchorHeadV1,
        _lease: &sorafs_node::TransparencyLeaderLeaseGrantV1,
    ) -> Result<(), sorafs_node::PrivacyReleaseAnchorErrorV1> {
        Ok(())
    }
}
impl sorafs_node::ProductionTransparencyRuntimeProviderV1 for PrebuiltPrivacyReleaseAnchor {
    fn handle(&self) -> &str {
        PREBUILT_PRIVACY_ANCHOR_HANDLE
    }
    fn qualification(
        &self,
    ) -> Result<sorafs_node::TransparencyRuntimeProviderQualificationV1, String> {
        Ok(sorafs_node::TransparencyRuntimeProviderQualificationV1::new(1, [0xD7; 32]))
    }
}
struct PrebuiltTransparencyLeaderLeaseProvider;
impl sorafs_node::TransparencyLeaderLeaseProviderV1 for PrebuiltTransparencyLeaderLeaseProvider {
    fn acquire(
        &self,
        _request: &sorafs_node::TransparencyLeaderLeaseAcquireRequestV1,
    ) -> Result<
        sorafs_node::TransparencyLeaderLeaseGrantV1,
        sorafs_node::TransparencyLeaderLeaseProviderErrorV1,
    > {
        Err(sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Internal)
    }
    fn renew(
        &self,
        _request: &sorafs_node::TransparencyLeaderLeaseRenewRequestV1,
    ) -> Result<
        sorafs_node::TransparencyLeaderLeaseGrantV1,
        sorafs_node::TransparencyLeaderLeaseProviderErrorV1,
    > {
        Err(sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Internal)
    }
    fn release(
        &self,
        _request: &sorafs_node::TransparencyLeaderLeaseReleaseRequestV1,
    ) -> Result<
        sorafs_node::TransparencyLeaderLeaseReleaseReceiptV1,
        sorafs_node::TransparencyLeaderLeaseProviderErrorV1,
    > {
        Err(sorafs_node::TransparencyLeaderLeaseProviderErrorV1::Internal)
    }
}
impl sorafs_node::ProductionTransparencyRuntimeProviderV1
    for PrebuiltTransparencyLeaderLeaseProvider
{
    fn handle(&self) -> &str {
        PREBUILT_TRANSPARENCY_LEADER_LEASE_HANDLE
    }
    fn qualification(
        &self,
    ) -> Result<sorafs_node::TransparencyRuntimeProviderQualificationV1, String> {
        Ok(sorafs_node::TransparencyRuntimeProviderQualificationV1::new(1, [0xE7; 32]))
    }
}
#[derive(Debug)]
struct PrebuiltFencedTransparencyProvider;
impl sorafs_node::FencedTransparencyPublisherV1 for PrebuiltFencedTransparencyProvider {
    fn handle(&self) -> &str {
        PREBUILT_FENCED_PRIVACY_HANDLE
    }
    fn qualification(
        &self,
    ) -> Result<sorafs_node::GovernanceDagRuntimeProviderQualificationV1, String> {
        Ok(
            sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(
                1,
                PREBUILT_FENCED_PRIVACY_POLICY_DIGEST,
            ),
        )
    }
    fn compare_and_append_privacy(
        &self,
        _request: &sorafs_node::FencedPrivacyPublicationRequestV1,
    ) -> Result<
        sorafs_node::FencedPrivacyPublicationReceiptV1,
        sorafs_node::FencedTransparencyPublishErrorV1,
    > {
        Err(sorafs_node::FencedTransparencyPublishErrorV1::Rejected)
    }
}
impl sorafs_node::FencedTransparencyAuthoritativeHeadReaderV1
    for PrebuiltFencedTransparencyProvider
{
    fn handle(&self) -> &str {
        PREBUILT_FENCED_PRIVACY_HANDLE
    }
    fn qualification(
        &self,
    ) -> Result<sorafs_node::GovernanceDagRuntimeProviderQualificationV1, String> {
        Ok(
            sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(
                1,
                PREBUILT_FENCED_PRIVACY_POLICY_DIGEST,
            ),
        )
    }
    fn read_authoritative_head_with_ancestry(
        &self,
        required_ancestors: &[sorafs_node::FencedTransparencyTargetHeadV1],
        required_publications: &[sorafs_node::FencedTransparencyPublicationInclusionV1],
    ) -> Result<sorafs_node::FencedTransparencyHeadAncestryProofV1, String> {
        if !required_ancestors.is_empty() || !required_publications.is_empty() {
            return Err(
                    "fresh fused privacy target cannot prove retained ancestry or publication inclusion"
                        .to_owned(),
                );
        }
        sorafs_node::FencedTransparencyHeadAncestryProofV1::try_new(
            None,
            Vec::new(),
            Vec::new(),
            [0xF8; 32],
        )
        .map_err(|_| "fresh fused privacy target returned a malformed genesis proof".to_owned())
    }
}
#[derive(Debug)]
struct SubstitutedFencedTransparencyHeadReader;
impl sorafs_node::FencedTransparencyAuthoritativeHeadReaderV1
    for SubstitutedFencedTransparencyHeadReader
{
    fn handle(&self) -> &str {
        PREBUILT_FENCED_PRIVACY_HANDLE
    }
    fn qualification(
        &self,
    ) -> Result<sorafs_node::GovernanceDagRuntimeProviderQualificationV1, String> {
        Ok(
            sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(
                2,
                PREBUILT_FENCED_PRIVACY_POLICY_DIGEST,
            ),
        )
    }
    fn read_authoritative_head_with_ancestry(
        &self,
        required_ancestors: &[sorafs_node::FencedTransparencyTargetHeadV1],
        required_publications: &[sorafs_node::FencedTransparencyPublicationInclusionV1],
    ) -> Result<sorafs_node::FencedTransparencyHeadAncestryProofV1, String> {
        if !required_ancestors.is_empty() || !required_publications.is_empty() {
            return Err(
                    "fresh substituted privacy reader cannot prove retained ancestry or publication inclusion"
                        .to_owned(),
                );
        }
        sorafs_node::FencedTransparencyHeadAncestryProofV1::try_new(
            None,
            Vec::new(),
            Vec::new(),
            [0xF9; 32],
        )
        .map_err(|_| {
            "fresh substituted privacy reader returned a malformed genesis proof".to_owned()
        })
    }
}
fn prebuilt_privacy_runtime_deps_without_fenced_target() -> sorafs_node::NodeRuntimeDeps {
    sorafs_node::NodeRuntimeDeps::default()
        .with_privacy_cycle_prf_provider(Arc::new(PrebuiltPrivacyPrfProvider))
        .with_privacy_release_anchor(Arc::new(PrebuiltPrivacyReleaseAnchor))
        .with_transparency_leader_lease_provider(Arc::new(PrebuiltTransparencyLeaderLeaseProvider))
        .with_governance_dag_signer(prebuilt_governance_dag_runtime_signer())
        .with_governance_dag_checkpoint_store(prebuilt_governance_dag_checkpoint_store())
}
fn prebuilt_governance_dag_runtime_signer() -> Arc<dyn sorafs_node::GovernanceDagRuntimeSigner> {
    Arc::new(PrebuiltGovernanceDagSigner::new())
}
fn prebuilt_governance_dag_checkpoint_store()
-> Arc<dyn sorafs_node::GovernanceDagSealedCheckpointStore> {
    Arc::new(PrebuiltGovernanceDagCheckpointStore::exact())
}
fn prebuilt_fenced_transparency_runtime() -> (
    Arc<dyn sorafs_node::FencedTransparencyPublisherV1>,
    Arc<dyn sorafs_node::FencedTransparencyAuthoritativeHeadReaderV1>,
) {
    let provider = Arc::new(PrebuiltFencedTransparencyProvider);
    let publisher: Arc<dyn sorafs_node::FencedTransparencyPublisherV1> = provider.clone();
    let head_reader: Arc<dyn sorafs_node::FencedTransparencyAuthoritativeHeadReaderV1> = provider;
    (publisher, head_reader)
}
fn prebuilt_privacy_runtime_deps() -> sorafs_node::NodeRuntimeDeps {
    let (publisher, head_reader) = prebuilt_fenced_transparency_runtime();
    prebuilt_privacy_runtime_deps_without_fenced_target()
        .with_fenced_transparency_publisher(publisher)
        .with_fenced_transparency_head_reader(head_reader)
}
fn prebuilt_privacy_storage_config(
    data_dir: PathBuf,
    prf_revision: u64,
    fenced_publisher_revision: u64,
) -> sorafs_node::config::StorageConfig {
    let governance_dir = data_dir.join("governance");
    prebuilt_privacy_storage_config_with_governance_dir(
        data_dir,
        governance_dir,
        prf_revision,
        fenced_publisher_revision,
    )
}
fn prebuilt_privacy_storage_config_with_governance_dir(
    data_dir: PathBuf,
    governance_dir: PathBuf,
    prf_revision: u64,
    fenced_publisher_revision: u64,
) -> sorafs_node::config::StorageConfig {
    let mut storage = actual::SorafsStorage::default();
    storage.enabled = true;
    storage.provider_id = Some(iroha_data_model::sorafs::capacity::ProviderId::new(
        [0x91; 32],
    ));
    storage.data_dir = data_dir.clone();
    let governance_signer = PrebuiltGovernanceDagSigner::new();
    storage.governance_dag_dir = Some(governance_dir);
    storage.governance_dag_publisher_peer_id = Some(
        String::from_utf8(PREBUILT_GOVERNANCE_SIGNER_PEER_ID.to_vec())
            .expect("Governance DAG peer id is UTF-8"),
    );
    storage.governance_dag_signer_handle = Some(PREBUILT_GOVERNANCE_SIGNER_HANDLE.to_owned());
    storage.governance_dag_signer_revision = Some(1);
    storage.governance_dag_signer_policy_digest = Some(PREBUILT_GOVERNANCE_SIGNER_POLICY_DIGEST);
    storage.governance_dag_publisher_public_key_hex =
        Some(hex::encode(governance_signer.public_key_bytes()));
    storage.governance_dag_service.checkpoint_store_handle =
        Some(PREBUILT_GOVERNANCE_CHECKPOINT_STORE_HANDLE.to_owned());
    storage.governance_dag_service.checkpoint_store_revision = Some(1);
    storage
        .governance_dag_service
        .checkpoint_store_policy_digest = Some(PREBUILT_GOVERNANCE_CHECKPOINT_STORE_POLICY_DIGEST);
    storage.privacy_aggregates = actual::SorafsPrivacyAggregateSchedule {
        enabled: true,
        cycle_seconds: 100,
        first_cycle_start_unix: 100,
        publish_delay_seconds: 10,
        query_id: Some([0xB0; 32]),
        population_inventory: vec![actual::SorafsPrivacyAggregatePopulation {
            label: "jurisdiction-a".to_owned(),
            digest: [0xA0; 32],
        }],
        metric_schema: vec![actual::SorafsPrivacyAggregateMetric {
            key: "moderation_actions".to_owned(),
            unit: "count".to_owned(),
        }],
        policy_digest: Some([0xC0; 32]),
        cycle_prf_provider: Some(actual::SorafsTransparencyRuntimeProviderBinding {
            handle: PREBUILT_PRIVACY_PRF_HANDLE.to_owned(),
            revision: prf_revision,
            policy_digest: [0xC7; 32],
        }),
        release_anchor_provider: Some(actual::SorafsTransparencyRuntimeProviderBinding {
            handle: PREBUILT_PRIVACY_ANCHOR_HANDLE.to_owned(),
            revision: 1,
            policy_digest: [0xD7; 32],
        }),
        leader_lease_provider: Some(actual::SorafsTransparencyRuntimeProviderBinding {
            handle: PREBUILT_TRANSPARENCY_LEADER_LEASE_HANDLE.to_owned(),
            revision: 1,
            policy_digest: [0xE7; 32],
        }),
        fenced_privacy_publisher: Some(actual::SorafsTransparencyRuntimeProviderBinding {
            handle: PREBUILT_FENCED_PRIVACY_HANDLE.to_owned(),
            revision: fenced_publisher_revision,
            policy_digest: PREBUILT_FENCED_PRIVACY_POLICY_DIGEST,
        }),
        ..actual::SorafsPrivacyAggregateSchedule::default()
    };
    sorafs_node::config::StorageConfig::from(&storage)
}
fn prebuilt_governance_storage_config(data_dir: PathBuf) -> sorafs_node::config::StorageConfig {
    let governance_signer = PrebuiltGovernanceDagSigner::new();
    sorafs_node::config::StorageConfig::builder()
        .enabled(true)
        .data_dir(data_dir.clone())
        .governance_dir(Some(data_dir.join("governance")))
        .governance_dag_publisher_peer_id(Some(
            String::from_utf8(PREBUILT_GOVERNANCE_SIGNER_PEER_ID.to_vec())
                .expect("Governance DAG peer id is UTF-8"),
        ))
        .governance_dag_signer_handle(Some(PREBUILT_GOVERNANCE_SIGNER_HANDLE.to_owned()))
        .governance_dag_signer_qualification(Some(
            sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(
                1,
                PREBUILT_GOVERNANCE_SIGNER_POLICY_DIGEST,
            ),
        ))
        .governance_dag_checkpoint_store_handle(Some(
            PREBUILT_GOVERNANCE_CHECKPOINT_STORE_HANDLE.to_owned(),
        ))
        .governance_dag_checkpoint_store_qualification(Some(
            sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(
                1,
                PREBUILT_GOVERNANCE_CHECKPOINT_STORE_POLICY_DIGEST,
            ),
        ))
        .governance_dag_publisher_public_key_hex(Some(hex::encode(
            governance_signer.public_key_bytes(),
        )))
        .build()
}
#[test]
fn prebuilt_sorafs_node_accepts_exact_privacy_provider_bindings() {
    let temp_dir = tempfile::tempdir().expect("create prebuilt privacy temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical prebuilt privacy temp dir");
    let config = prebuilt_privacy_storage_config(root.join("storage"), 1, 1);
    let node = sorafs_node::NodeHandle::try_new_with_runtime_deps(
        config.clone(),
        prebuilt_privacy_runtime_deps(),
    )
    .expect("start prebuilt SoraFS node with exact privacy bindings");
    preflight_sorafs_fenced_privacy_runtime(
        &config,
        &ToriiRuntimeDeps::new(
            crate::build_identity_test_fixture::build_identity(),
            routing::MaybeTelemetry::disabled(),
        )
        .with_sorafs_node(node.clone()),
    )
    .expect("live-revalidate the prebuilt SoraFS fused privacy runtime");
    validate_prebuilt_sorafs_privacy_provider_bindings(
        &node, &config, false, false, false, false, false,
    )
    .expect("exact privacy provider bindings are accepted");
}
#[test]
fn fused_privacy_preflight_rejects_substituted_signed_governance_root() {
    let temp_dir = tempfile::tempdir().expect("create signed-root preflight temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical signed-root preflight temp dir");
    let data_dir = root.join("storage");
    let retained_config = prebuilt_privacy_storage_config(data_dir.clone(), 1, 1);
    let node = sorafs_node::NodeHandle::try_new_with_runtime_deps(
        retained_config,
        prebuilt_privacy_runtime_deps(),
    )
    .expect("start prebuilt SoraFS node with exact signed root");
    let substituted_config = prebuilt_privacy_storage_config_with_governance_dir(
        data_dir,
        root.join("substituted-governance"),
        1,
        1,
    );
    let error = preflight_sorafs_fenced_privacy_runtime(
        &substituted_config,
        &ToriiRuntimeDeps::new(
            crate::build_identity_test_fixture::build_identity(),
            routing::MaybeTelemetry::disabled(),
        )
        .with_sorafs_node(node),
    )
    .expect_err("prebuilt signed Governance root substitution must fail preflight");
    assert!(
        error.contains("signed Governance root and signer binding does not match"),
        "unexpected error: {error}"
    );
}
#[test]
fn fused_privacy_preflight_live_qualifies_exact_raw_pair() {
    let temp_dir = tempfile::tempdir().expect("create raw privacy preflight temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical raw privacy preflight temp dir");
    let config = prebuilt_privacy_storage_config(root.join("storage"), 1, 1);
    let (publisher, head_reader) = prebuilt_fenced_transparency_runtime();
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_fenced_transparency_publisher(publisher)
    .with_sorafs_fenced_transparency_head_reader(head_reader)
    .with_sorafs_governance_dag_signer(prebuilt_governance_dag_runtime_signer())
    .with_sorafs_governance_dag_checkpoint_store(prebuilt_governance_dag_checkpoint_store());
    preflight_sorafs_fenced_privacy_runtime(&config, &runtime_deps)
        .expect("live-qualify the exact raw fused privacy pair");
}
#[test]
fn fused_privacy_preflight_requires_raw_governance_signer() {
    let temp_dir = tempfile::tempdir().expect("create signer preflight temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical signer preflight temp dir");
    let config = prebuilt_privacy_storage_config(root.join("storage"), 1, 1);
    let (publisher, head_reader) = prebuilt_fenced_transparency_runtime();
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_fenced_transparency_publisher(publisher)
    .with_sorafs_fenced_transparency_head_reader(head_reader)
    .with_sorafs_governance_dag_checkpoint_store(prebuilt_governance_dag_checkpoint_store());
    let error = preflight_sorafs_fenced_privacy_runtime(&config, &runtime_deps)
        .expect_err("standalone signed Governance publication must require its raw signer");
    assert!(
        error.contains("requires a raw runtime signer"),
        "unexpected error: {error}"
    );
}
#[test]
fn fused_privacy_preflight_rejects_substituted_raw_governance_signer() {
    let temp_dir = tempfile::tempdir().expect("create signer substitution temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical signer substitution temp dir");
    let config = prebuilt_privacy_storage_config(root.join("storage"), 1, 1);
    let (publisher, head_reader) = prebuilt_fenced_transparency_runtime();
    let substituted_signer: Arc<dyn sorafs_node::GovernanceDagRuntimeSigner> =
        Arc::new(PrebuiltGovernanceDagSigner::from_seed(0x98));
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_fenced_transparency_publisher(publisher)
    .with_sorafs_fenced_transparency_head_reader(head_reader)
    .with_sorafs_governance_dag_signer(substituted_signer)
    .with_sorafs_governance_dag_checkpoint_store(prebuilt_governance_dag_checkpoint_store());
    let error = preflight_sorafs_fenced_privacy_runtime(&config, &runtime_deps)
        .expect_err("substituted raw Governance signer must fail preflight");
    assert!(
        error.contains("does not match the exact configured binding"),
        "unexpected error: {error}"
    );
}
#[test]
fn governance_checkpoint_preflight_rejects_missing_raw_store() {
    let temp_dir = tempfile::tempdir().expect("create checkpoint preflight temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical checkpoint preflight temp dir");
    let config = prebuilt_governance_storage_config(root.join("storage"));
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_governance_dag_signer(prebuilt_governance_dag_runtime_signer());
    let error = preflight_sorafs_fenced_privacy_runtime(&config, &runtime_deps)
        .expect_err("configured producer must require its raw sealed checkpoint store");
    assert!(
        error.contains("requires a raw sealed checkpoint store"),
        "unexpected error: {error}"
    );
}
#[test]
fn governance_checkpoint_preflight_rejects_substituted_raw_store() {
    let temp_dir = tempfile::tempdir().expect("create checkpoint substitution temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical checkpoint substitution temp dir");
    let config = prebuilt_governance_storage_config(root.join("storage"));
    let substituted_store: Arc<dyn sorafs_node::GovernanceDagSealedCheckpointStore> =
        Arc::new(PrebuiltGovernanceDagCheckpointStore::with_binding(
            PREBUILT_GOVERNANCE_CHECKPOINT_STORE_HANDLE,
            sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(
                2,
                PREBUILT_GOVERNANCE_CHECKPOINT_STORE_POLICY_DIGEST,
            ),
        ));
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_governance_dag_signer(prebuilt_governance_dag_runtime_signer())
    .with_sorafs_governance_dag_checkpoint_store(substituted_store);
    let error = preflight_sorafs_fenced_privacy_runtime(&config, &runtime_deps)
        .expect_err("substituted raw checkpoint store must fail preflight");
    assert!(
        error
            .contains("checkpoint-store qualification does not match the exact configured binding"),
        "unexpected error: {error}"
    );
}
#[test]
fn governance_checkpoint_preflight_rejects_ambiguous_prebuilt_and_raw_store() {
    let temp_dir = tempfile::tempdir().expect("create checkpoint ambiguity temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical checkpoint ambiguity temp dir");
    let config = prebuilt_governance_storage_config(root.join("storage"));
    let node = sorafs_node::NodeHandle::try_new_with_runtime_deps(
        config.clone(),
        sorafs_node::NodeRuntimeDeps::default()
            .with_governance_dag_signer(prebuilt_governance_dag_runtime_signer())
            .with_governance_dag_checkpoint_store(prebuilt_governance_dag_checkpoint_store()),
    )
    .expect("start prebuilt SoraFS node with exact checkpoint binding");
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_node(node)
    .with_sorafs_governance_dag_checkpoint_store(prebuilt_governance_dag_checkpoint_store());
    let error = preflight_sorafs_fenced_privacy_runtime(&config, &runtime_deps)
        .expect_err("prebuilt node and raw checkpoint store must be mutually exclusive");
    assert!(
        error.contains("must not also receive a raw Governance DAG checkpoint store"),
        "unexpected error: {error}"
    );
}
#[test]
fn standalone_node_retains_and_live_revalidates_raw_governance_checkpoint_store() {
    let temp_dir = tempfile::tempdir().expect("create checkpoint retention temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical checkpoint retention temp dir");
    let config = prebuilt_governance_storage_config(root.join("storage"));
    let checkpoint_store = Arc::new(PrebuiltGovernanceDagCheckpointStore::exact());
    let runtime_checkpoint_store: Arc<dyn sorafs_node::GovernanceDagSealedCheckpointStore> =
        checkpoint_store.clone();
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_governance_dag_signer(prebuilt_governance_dag_runtime_signer())
    .with_sorafs_governance_dag_checkpoint_store(runtime_checkpoint_store);
    preflight_sorafs_fenced_privacy_runtime(&config, &runtime_deps)
        .expect("exact raw checkpoint store passes early preflight");
    let node_runtime_deps = sorafs_node::NodeRuntimeDeps::default()
        .with_governance_dag_signer(Arc::clone(
            runtime_deps
                .sorafs_governance_dag_signer
                .as_ref()
                .expect("raw Governance signer retained"),
        ))
        .with_governance_dag_checkpoint_store(Arc::clone(
            runtime_deps
                .sorafs_governance_dag_checkpoint_store
                .as_ref()
                .expect("raw checkpoint store retained"),
        ));
    let node = sorafs_node::NodeHandle::try_new_with_runtime_deps(config, node_runtime_deps)
        .expect("standalone node retains exact checkpoint provider");
    assert_eq!(
        node.governance_dag_checkpoint_store_binding(),
        Some((
            PREBUILT_GOVERNANCE_CHECKPOINT_STORE_HANDLE,
            sorafs_node::GovernanceDagRuntimeProviderQualificationV1::new(
                1,
                PREBUILT_GOVERNANCE_CHECKPOINT_STORE_POLICY_DIGEST,
            ),
        ))
    );
    node.revalidate_fenced_privacy_runtime()
        .expect("retained checkpoint store live-revalidates");
    checkpoint_store.refuse_qualification();
    let error = node
        .revalidate_fenced_privacy_runtime()
        .expect_err("built node must keep consulting the retained checkpoint provider");
    assert!(
        error.to_string().contains("checkpoint store"),
        "unexpected error: {error}"
    );
}
#[test]
fn fused_privacy_preflight_rejects_missing_raw_pair() {
    let temp_dir = tempfile::tempdir().expect("create raw privacy preflight temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical raw privacy preflight temp dir");
    let config = prebuilt_privacy_storage_config(root.join("storage"), 1, 1);
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_governance_dag_signer(prebuilt_governance_dag_runtime_signer())
    .with_sorafs_governance_dag_checkpoint_store(prebuilt_governance_dag_checkpoint_store());
    let error = preflight_sorafs_fenced_privacy_runtime(&config, &runtime_deps)
        .expect_err("configured fused privacy target must require both raw roles");
    assert!(
        error.contains("requires both a raw writer and authenticated-head reader"),
        "unexpected error: {error}"
    );
}
#[test]
fn fused_privacy_preflight_rejects_substituted_raw_writer() {
    let temp_dir = tempfile::tempdir().expect("create raw privacy preflight temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical raw privacy preflight temp dir");
    let config = prebuilt_privacy_storage_config(root.join("storage"), 1, 2);
    let (publisher, head_reader) = prebuilt_fenced_transparency_runtime();
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_fenced_transparency_publisher(publisher)
    .with_sorafs_fenced_transparency_head_reader(head_reader)
    .with_sorafs_governance_dag_signer(prebuilt_governance_dag_runtime_signer())
    .with_sorafs_governance_dag_checkpoint_store(prebuilt_governance_dag_checkpoint_store());
    let error = preflight_sorafs_fenced_privacy_runtime(&config, &runtime_deps)
        .expect_err("substituted raw writer must fail preflight");
    assert!(
        error.contains("raw fused privacy writer failed live qualification"),
        "unexpected error: {error}"
    );
}
#[test]
fn fused_privacy_preflight_rejects_substituted_raw_head_reader() {
    let temp_dir = tempfile::tempdir().expect("create raw privacy preflight temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical raw privacy preflight temp dir");
    let config = prebuilt_privacy_storage_config(root.join("storage"), 1, 1);
    let (publisher, _) = prebuilt_fenced_transparency_runtime();
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_fenced_transparency_publisher(publisher)
    .with_sorafs_fenced_transparency_head_reader(Arc::new(SubstitutedFencedTransparencyHeadReader))
    .with_sorafs_governance_dag_signer(prebuilt_governance_dag_runtime_signer())
    .with_sorafs_governance_dag_checkpoint_store(prebuilt_governance_dag_checkpoint_store());
    let error = preflight_sorafs_fenced_privacy_runtime(&config, &runtime_deps)
        .expect_err("substituted raw head reader must fail preflight");
    assert!(
        error.contains("raw fused privacy authenticated-head reader failed live qualification"),
        "unexpected error: {error}"
    );
}
#[test]
fn prebuilt_sorafs_node_rejects_mismatched_privacy_provider_binding() {
    let temp_dir = tempfile::tempdir().expect("create prebuilt privacy temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical prebuilt privacy temp dir");
    let retained_config = prebuilt_privacy_storage_config(root.join("storage"), 1, 1);
    let node = sorafs_node::NodeHandle::try_new_with_runtime_deps(
        retained_config,
        prebuilt_privacy_runtime_deps(),
    )
    .expect("start prebuilt SoraFS node with exact privacy bindings");
    let substituted_config = prebuilt_privacy_storage_config(root.join("storage"), 2, 1);
    assert_eq!(
        validate_prebuilt_sorafs_privacy_provider_bindings(
            &node,
            &substituted_config,
            false,
            false,
            false,
            false,
            false,
        ),
        Err("injected SoraFS node threshold-PRF provider binding does not match configuration"),
    );
}
#[test]
fn prebuilt_sorafs_node_rejects_substituted_fenced_privacy_binding() {
    let temp_dir = tempfile::tempdir().expect("create prebuilt privacy temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical prebuilt privacy temp dir");
    let retained_config = prebuilt_privacy_storage_config(root.join("storage"), 1, 1);
    let node = sorafs_node::NodeHandle::try_new_with_runtime_deps(
        retained_config,
        prebuilt_privacy_runtime_deps(),
    )
    .expect("start prebuilt SoraFS node with exact privacy bindings");
    let substituted_config = prebuilt_privacy_storage_config(root.join("storage"), 1, 2);
    assert_eq!(
        validate_prebuilt_sorafs_privacy_provider_bindings(
            &node,
            &substituted_config,
            false,
            false,
            false,
            false,
            false,
        ),
        Err("injected SoraFS node fused privacy publisher binding does not match configuration"),
    );
}
#[test]
fn prebuilt_sorafs_node_rejects_ambiguous_raw_privacy_provider() {
    let temp_dir = tempfile::tempdir().expect("create prebuilt privacy temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical prebuilt privacy temp dir");
    let config = prebuilt_privacy_storage_config(root.join("storage"), 1, 1);
    let node = sorafs_node::NodeHandle::try_new_with_runtime_deps(
        config.clone(),
        prebuilt_privacy_runtime_deps(),
    )
    .expect("start prebuilt SoraFS node with exact privacy bindings");
    assert_eq!(
        validate_prebuilt_sorafs_privacy_provider_bindings(
            &node, &config, true, false, false, false, false,
        ),
        Err(
            "a prebuilt SoraFS node must not also receive a raw threshold-PRF provider through Torii"
        ),
    );
}
#[test]
fn prebuilt_sorafs_node_rejects_ambiguous_raw_fenced_privacy_publisher() {
    let temp_dir = tempfile::tempdir().expect("create prebuilt privacy temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical prebuilt privacy temp dir");
    let config = prebuilt_privacy_storage_config(root.join("storage"), 1, 1);
    let node = sorafs_node::NodeHandle::try_new_with_runtime_deps(
        config.clone(),
        prebuilt_privacy_runtime_deps(),
    )
    .expect("start prebuilt SoraFS node with exact privacy bindings");
    assert_eq!(
        validate_prebuilt_sorafs_privacy_provider_bindings(
            &node, &config, false, false, false, true, false,
        ),
        Err(
            "a prebuilt SoraFS node must not also receive a raw fused privacy publisher through Torii"
        ),
    );
}
#[test]
fn prebuilt_sorafs_node_rejects_ambiguous_raw_fenced_privacy_head_reader() {
    let temp_dir = tempfile::tempdir().expect("create prebuilt privacy temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical prebuilt privacy temp dir");
    let config = prebuilt_privacy_storage_config(root.join("storage"), 1, 1);
    let node = sorafs_node::NodeHandle::try_new_with_runtime_deps(
        config.clone(),
        prebuilt_privacy_runtime_deps(),
    )
    .expect("start prebuilt SoraFS node with exact privacy bindings");
    assert_eq!(
        validate_prebuilt_sorafs_privacy_provider_bindings(
            &node, &config, false, false, false, false, true,
        ),
        Err(
            "a prebuilt SoraFS node must not also receive a raw authenticated privacy-head reader through Torii"
        ),
    );
}
#[test]
fn fused_privacy_preflight_rejects_prebuilt_and_raw_ambiguity() {
    let temp_dir = tempfile::tempdir().expect("create prebuilt privacy temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical prebuilt privacy temp dir");
    let config = prebuilt_privacy_storage_config(root.join("storage"), 1, 1);
    let node = sorafs_node::NodeHandle::try_new_with_runtime_deps(
        config.clone(),
        prebuilt_privacy_runtime_deps(),
    )
    .expect("start prebuilt SoraFS node with exact privacy bindings");
    let (publisher, _) = prebuilt_fenced_transparency_runtime();
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_node(node)
    .with_sorafs_fenced_transparency_publisher(publisher);
    let error = preflight_sorafs_fenced_privacy_runtime(&config, &runtime_deps)
        .expect_err("prebuilt and raw fused runtimes must be mutually exclusive");
    assert!(
        error.contains("prebuilt SoraFS node is mutually exclusive"),
        "unexpected error: {error}"
    );
}
#[test]
fn fused_privacy_preflight_rejects_prebuilt_and_raw_governance_signer() {
    let temp_dir = tempfile::tempdir().expect("create prebuilt signer temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical prebuilt signer temp dir");
    let config = prebuilt_privacy_storage_config(root.join("storage"), 1, 1);
    let node = sorafs_node::NodeHandle::try_new_with_runtime_deps(
        config.clone(),
        prebuilt_privacy_runtime_deps(),
    )
    .expect("start prebuilt SoraFS node with exact privacy bindings");
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_node(node)
    .with_sorafs_governance_dag_signer(prebuilt_governance_dag_runtime_signer());
    let error = preflight_sorafs_fenced_privacy_runtime(&config, &runtime_deps)
        .expect_err("prebuilt node and raw Governance signer must be mutually exclusive");
    assert!(
        error.contains("prebuilt SoraFS node is mutually exclusive"),
        "unexpected error: {error}"
    );
}
#[test]
fn standalone_sorafs_node_rejects_incomplete_fenced_privacy_pairs() {
    for (label, inject_publisher, inject_reader, expected) in [
        (
            "missing-writer",
            false,
            true,
            "requires an injected fused target writer",
        ),
        (
            "missing-reader",
            true,
            false,
            "requires an injected authenticated authoritative-head reader",
        ),
    ] {
        let temp_dir = tempfile::tempdir().expect("create standalone privacy temp dir");
        let root = temp_dir
            .path()
            .canonicalize()
            .expect("canonical standalone privacy temp dir");
        let config = prebuilt_privacy_storage_config(root.join(format!("storage-{label}")), 1, 1);
        let (publisher, reader) = prebuilt_fenced_transparency_runtime();
        let mut torii_runtime_deps = ToriiRuntimeDeps::new(
            crate::build_identity_test_fixture::build_identity(),
            routing::MaybeTelemetry::disabled(),
        )
        .with_sorafs_governance_dag_signer(prebuilt_governance_dag_runtime_signer())
        .with_sorafs_governance_dag_checkpoint_store(prebuilt_governance_dag_checkpoint_store());
        if inject_publisher {
            torii_runtime_deps = torii_runtime_deps
                .with_sorafs_fenced_transparency_publisher(Arc::clone(&publisher));
        }
        if inject_reader {
            torii_runtime_deps =
                torii_runtime_deps.with_sorafs_fenced_transparency_head_reader(Arc::clone(&reader));
        }
        let preflight_error =
            preflight_sorafs_fenced_privacy_runtime(&config, &torii_runtime_deps).expect_err(label);
        assert!(
            preflight_error.contains("one complete pair"),
            "{label} produced unexpected preflight error: {preflight_error}"
        );
        let mut runtime_deps = prebuilt_privacy_runtime_deps_without_fenced_target();
        if inject_publisher {
            runtime_deps = runtime_deps.with_fenced_transparency_publisher(publisher);
        }
        if inject_reader {
            runtime_deps = runtime_deps.with_fenced_transparency_head_reader(reader);
        }
        let error = sorafs_node::NodeHandle::try_new_with_runtime_deps(config, runtime_deps)
            .expect_err(label);
        assert!(
            error.to_string().contains(expected),
            "{label} produced unexpected error: {error}"
        );
    }
}
#[test]
fn standalone_sorafs_node_rejects_unexpected_fenced_privacy_pair() {
    let temp_dir = tempfile::tempdir().expect("create standalone privacy temp dir");
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonical standalone privacy temp dir");
    let config = sorafs_node::config::StorageConfig::builder()
        .data_dir(root.join("storage"))
        .build();
    let (publisher, reader) = prebuilt_fenced_transparency_runtime();
    let torii_runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_fenced_transparency_publisher(Arc::clone(&publisher))
    .with_sorafs_fenced_transparency_head_reader(Arc::clone(&reader));
    let preflight_error = preflight_sorafs_fenced_privacy_runtime(&config, &torii_runtime_deps)
        .expect_err("disabled privacy publication must fail Torii preflight");
    assert!(
        preflight_error.contains("unexpected without a configured target binding"),
        "unexpected preflight error: {preflight_error}"
    );
    let error = sorafs_node::NodeHandle::try_new_with_runtime_deps(
        config,
        sorafs_node::NodeRuntimeDeps::default()
            .with_fenced_transparency_publisher(publisher)
            .with_fenced_transparency_head_reader(reader),
    )
    .expect_err("disabled privacy publication must reject the fused pair");
    assert!(
        error
            .to_string()
            .contains("fused privacy target writer is unexpected"),
        "unexpected error: {error}"
    );
}
#[test]
fn torii_runtime_deps_retain_fenced_privacy_pair() {
    let (publisher, reader) = prebuilt_fenced_transparency_runtime();
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_fenced_transparency_publisher(publisher)
    .with_sorafs_fenced_transparency_head_reader(reader)
    .with_sorafs_governance_dag_signer(prebuilt_governance_dag_runtime_signer())
    .with_sorafs_governance_dag_checkpoint_store(prebuilt_governance_dag_checkpoint_store());
    assert!(runtime_deps.sorafs_fenced_transparency_publisher.is_some());
    assert!(
        runtime_deps
            .sorafs_fenced_transparency_head_reader
            .is_some()
    );
    assert!(runtime_deps.sorafs_governance_dag_signer.is_some());
    assert!(
        runtime_deps
            .sorafs_governance_dag_checkpoint_store
            .is_some()
    );
}
#[tokio::test]
async fn new_with_handle_preflights_fused_privacy_before_startup() {
    tokio::task::yield_now().await;
    let cfg = crate::test_utils::mk_minimal_root_cfg();
    let (kiso, _child) = KisoHandle::start(cfg.clone());
    let kura = Kura::blank_kura_for_testing();
    let state = Arc::new(IrohaState::new_for_testing(
        World::default(),
        kura.clone(),
        LiveQueryStore::start_test(),
    ));
    let queue_cfg = iroha_config::parameters::actual::Queue {
        capacity: NonZeroUsize::new(100).expect("queue capacity non-zero"),
        capacity_per_user: NonZeroUsize::new(100).expect("queue per-user capacity non-zero"),
        transaction_time_to_live: Duration::from_secs(60),
        ..Default::default()
    };
    let queue_events: iroha_core::EventsSender = tokio::sync::broadcast::channel(1).0;
    let queue = Arc::new(Queue::from_config(queue_cfg, queue_events));
    let (_peers_tx, peers_rx) = tokio::sync::watch::channel(<_>::default());
    let (publisher, _) = prebuilt_fenced_transparency_runtime();
    let runtime_deps = ToriiRuntimeDeps::new(
        crate::build_identity_test_fixture::build_identity(),
        routing::MaybeTelemetry::disabled(),
    )
    .with_sorafs_fenced_transparency_publisher(publisher);
    let error = Torii::new_with_handle(
        ChainId::from("fused-privacy-preflight-test"),
        signed_query_test_network_id(),
        kiso,
        cfg.torii.clone(),
        queue,
        tokio::sync::broadcast::channel(1).0,
        LiveQueryStore::start_test(),
        kura,
        state,
        cfg.common.key_pair.clone(),
        OnlinePeersProvider::new(peers_rx),
        None,
        runtime_deps,
    )
    .err()
    .expect("an incomplete fused-privacy pair must fail construction");
    assert!(matches!(
        error,
        ToriiBuildError::InvalidRuntimeDependency {
            component: "sorafs.storage",
            ..
        }
    ));
    assert!(
        error
            .to_string()
            .contains("standalone fused privacy runtime requires the raw writer and authenticated-head reader as one complete pair"),
        "unexpected construction error: {error}"
    );
}

#[cfg(feature = "telemetry")]
use crate::tests_runtime_handlers::mk_norito_rpc_test_harness;
#[cfg(feature = "app_api")]
use crate::tests_runtime_handlers::{
    bind_account_alias_for_test, bind_contract_alias_for_test, bind_dynamic_account_alias_for_test,
    configure_private_ingress_routes_for_test, world_with_account_bound_to_dataspace,
    world_with_target_and_caller_bound_to_dataspace,
};
use crate::{
    limits,
    tests_runtime_handlers::{
        app_auth_test_guard, checked_torii_test_account_id, checked_torii_test_ed25519_keypair,
        mk_app_state_for_tests, mk_app_state_for_tests_with_iso_bridge,
        mk_app_state_for_tests_with_options, mk_app_state_for_tests_with_world,
        record_latest_committed_header_for_test, signed_app_headers, world_with_account,
    },
};
use iroha_core::smartcontracts::Execute;
#[test]
fn stark_fri_backend_label_is_singular_and_exact() {
    assert!(iroha_data_model::zk::is_stark_fri_v1_backend_label(
        "stark/fri/poseidon-x7-goldilocks-6x64-v1"
    ));
    assert!(!iroha_data_model::zk::is_stark_fri_v1_backend_label(
        "stark/fri"
    ));
    assert!(!iroha_data_model::zk::is_stark_fri_v1_backend_label(
        "stark/fri/poseidon2-goldilocks"
    ));
    assert!(!iroha_data_model::zk::is_stark_fri_v1_backend_label(
        "stark/fri/sha256_goldilocks.v1"
    ));
    assert!(!iroha_data_model::zk::is_stark_fri_v1_backend_label(
        "stark/fri/"
    ));
    assert!(!iroha_data_model::zk::is_stark_fri_v1_backend_label(
        "stark/fri/latest"
    ));
    assert!(!iroha_data_model::zk::is_stark_fri_v1_backend_label(
        "stark/fri/random-profile"
    ));
    assert!(!iroha_data_model::zk::is_stark_fri_v1_backend_label(
        "stark/fri/sha512-goldilocks"
    ));
    assert!(!iroha_data_model::zk::is_stark_fri_v1_backend_label(
        "stark/fri/kzg"
    ));
    assert!(!iroha_data_model::zk::is_stark_fri_v1_backend_label(
        "stark/fri/bn254"
    ));
    assert!(!iroha_data_model::zk::is_stark_fri_v1_backend_label(
        "stark/fri/debug"
    ));
    assert!(!iroha_data_model::zk::is_stark_fri_v1_backend_label(
        "stark/fri/debug-proof"
    ));
    assert!(!iroha_data_model::zk::is_stark_fri_v1_backend_label(
        "stark/fri/mock"
    ));
    assert!(!iroha_data_model::zk::is_stark_fri_v1_backend_label(
        "stark/fri/mock-proof"
    ));
    assert!(!iroha_data_model::zk::is_stark_fri_v1_backend_label(
        "stark/fri-v2"
    ));
}
#[test]
fn parse_pipeline_status_scope_accepts_only_exact_current_values() {
    assert_eq!(
        parse_pipeline_status_scope(None).expect("default scope"),
        PipelineStatusReadScope::Global
    );
    assert_eq!(
        parse_pipeline_status_scope(Some("global")).expect("global scope"),
        PipelineStatusReadScope::Global
    );
    assert_eq!(
        parse_pipeline_status_scope(Some("local")).expect("local scope"),
        PipelineStatusReadScope::Local
    );
}
#[test]
fn parse_pipeline_status_scope_rejects_noncanonical_and_injected_values() {
    for raw in [
        "",
        "auto",
        "AUTO",
        " global",
        "global ",
        "LOCAL",
        "auto&scope=local",
        "global&scope=local",
        "local,global",
        "../global",
        "global\nscope=local",
    ] {
        let err = parse_pipeline_status_scope(Some(raw)).expect_err("invalid scope");
        assert!(
            format!("{err:?}").contains("expected local|global"),
            "unexpected error for {raw:?}: {err:?}"
        );
    }
}
fn bind_asset_alias_for_test(
    app: &SharedAppState,
    authority: &AccountId,
    definition_id: &AssetDefinitionId,
    alias: &AssetDefinitionAlias,
    lease_expiry_ms: Option<u64>,
    height: u64,
    creation_time_ms: u64,
) {
    let header = BlockHeader::new(
        NonZeroU64::new(height).expect("non-zero height"),
        None,
        None,
        creation_time_ms,
        0,
    );
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    use iroha_executor_data_model::permission::asset_definition::{
        AssetDefinitionAliasPermissionScope, CanManageAssetDefinitionAlias,
    };
    let resolved = iroha_data_model::asset::ResolvedAssetDefinitionAliasV1::resolve_catalog(
        alias.as_ref(),
        &app.state.nexus_snapshot().dataspace_catalog,
        definition_id.clone(),
    )
    .expect("asset alias parent resolves in the fixture catalog");
    tx.world_mut_for_testing().add_account_permission(
        authority,
        Permission::from(CanManageAssetDefinitionAlias {
            scope: AssetDefinitionAliasPermissionScope::Alias(resolved),
        }),
    );
    iroha_data_model::isi::SetAssetDefinitionAlias::bind(
        definition_id.clone(),
        alias.clone(),
        lease_expiry_ms,
    )
    .execute(authority, &mut tx)
    .expect("bind asset alias for test");
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit asset alias for test");
}
fn sample_iso_bridge_config(alias: &str, account_id: &AccountId) -> actual::IsoBridge {
    let signer_keypair =
        checked_torii_test_ed25519_keypair(0x80, "derive ISO bridge signer fixture key");
    let originator_operator =
        checked_torii_test_ed25519_keypair(0x81, "derive ISO originator operator fixture key");
    let counterparty_operator =
        checked_torii_test_ed25519_keypair(0x82, "derive ISO counterparty operator fixture key");
    actual::IsoBridge {
        enabled: true,
        max_body_bytes: iroha_config::parameters::defaults::torii::ISO_BRIDGE_MAX_BODY_BYTES,
        dedupe_ttl_secs: 30,
        default_profile: "generic-iso20022".to_owned(),
        profiles: Vec::new(),
        store_dir: None,
        store_retention_secs:
            iroha_config::parameters::defaults::torii::ISO_BRIDGE_STORE_RETENTION_SECS,
        store_max_records: iroha_config::parameters::defaults::torii::ISO_BRIDGE_STORE_MAX_RECORDS,
        audit_export_dir: None,
        embedded_signature_policy: None,
        signer: Some(actual::IsoBridgeSigner {
            account_id: account_id.to_string(),
            private_key: signer_keypair.private_key().clone(),
        }),
        participants: vec![
            actual::IsoBridgeParticipant {
                id: "originator-bank".to_owned(),
                operator_keys: vec![originator_operator.public_key().clone()],
                financial_identifiers: vec!["DEUTDEFF".to_owned()],
                allowed_profiles: vec!["generic-iso20022".to_owned()],
                roles: vec!["originator".to_owned(), "counterparty".to_owned()],
            },
            actual::IsoBridgeParticipant {
                id: "counterparty-bank".to_owned(),
                operator_keys: vec![counterparty_operator.public_key().clone()],
                financial_identifiers: vec!["MARKDEFF".to_owned()],
                allowed_profiles: vec!["generic-iso20022".to_owned()],
                roles: vec!["originator".to_owned(), "counterparty".to_owned()],
            },
        ],
        audit_admin_keys: Vec::new(),
        account_aliases: vec![actual::IsoAccountAlias {
            iban: alias.to_string(),
            account_id: account_id.to_string(),
        }],
        currency_assets: Vec::new(),
        reference_data: actual::IsoReferenceData::default(),
    }
}
#[test]
fn iso_lifecycle_persistence_error_is_retryable_without_rejection() {
    let app = mk_app_state_for_tests_with_iso_bridge(Some(sample_iso_bridge_config(
        "DE89370400440532013000",
        &ALICE_ID,
    )));
    let runtime = app.iso_bridge.as_ref().expect("ISO bridge enabled");
    let message_id = "handler-persistence-unavailable";
    assert!(runtime.check_and_record_message(message_id));

    let error = map_iso_lifecycle_apply_error(
        runtime,
        message_id,
        IsoLifecycleApplyError::PersistenceUnavailable,
    );
    assert!(matches!(
        error,
        Error::AppServiceUnavailable {
            code: "iso_lifecycle_persistence_unavailable",
            ..
        }
    ));
    assert_eq!(
        runtime
            .message_status(message_id)
            .expect("admitted lifecycle record remains retryable")
            .status_label(),
        "Pending"
    );
}
fn local_connect_info() -> axum::extract::ConnectInfo<std::net::SocketAddr> {
    axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
}
#[tokio::test]
async fn iso_audit_messages_endpoint_exports_digest_bound_manifest() {
    let app = mk_app_state_for_tests_with_iso_bridge(Some(sample_iso_bridge_config(
        "DE89370400440532013000",
        &ALICE_ID,
    )));
    let runtime = app.iso_bridge.as_ref().expect("iso bridge enabled");
    assert!(runtime.check_and_record_message("handler-audit"));
    runtime.mark_accepted("handler-audit", "handler-tx");
    let operator = operator_signatures::AuthenticatedOperatorPublicKey(
        checked_torii_test_ed25519_keypair(0x81, "derive ISO audit reader fixture key")
            .public_key()
            .clone(),
    );
    let (status, JsonBody(body)) = handler_iso_audit_messages(
        State(app),
        Extension(operator),
        HeaderMap::new(),
        local_connect_info(),
    )
    .await
    .expect("audit endpoint");
    assert_eq!(status, StatusCode::OK);
    let body = body.as_object().expect("audit manifest object");
    assert_eq!(
        body.get("record_count")
            .and_then(norito::json::Value::as_u64),
        Some(1)
    );
    assert!(
        body.get("index_sha256")
            .and_then(norito::json::Value::as_str)
            .is_some_and(|digest| digest.len() == 64)
    );
    let records = body
        .get("records")
        .and_then(norito::json::Value::as_array)
        .expect("audit records");
    assert_eq!(
        records[0]
            .as_object()
            .and_then(|entry| entry.get("message_id"))
            .and_then(norito::json::Value::as_str),
        Some("handler-audit")
    );
}
#[tokio::test]
async fn iso_audit_messages_endpoint_rejects_disabled_bridge() {
    let err = handler_iso_audit_messages(
        State(mk_app_state_for_tests()),
        Extension(operator_signatures::AuthenticatedOperatorPublicKey(
            checked_torii_test_ed25519_keypair(0x81, "derive disabled ISO reader fixture key")
                .public_key()
                .clone(),
        )),
        HeaderMap::new(),
        local_connect_info(),
    )
    .await
    .expect_err("disabled bridge should reject audit export");
    assert!(
        matches!(
            &err,
            Error::Query(iroha_data_model::ValidationFail::NotPermitted(message))
                if message.contains("iso20022 bridge disabled")
        ),
        "unexpected error: {err:?}"
    );
}
fn sample_identifier_policy(
    owner: &AccountId,
    signer: &KeyPair,
    policy_id: &IdentifierPolicyId,
) -> (IdentifierPolicy, RamLfeProgramPolicy) {
    let program_id = sample_program_id(policy_id);
    let commitment = iroha_crypto::policy_commitment(b"resolver-secret", Vec::new())
        .expect("supported HKDF policy commitment");
    let program_policy = RamLfeProgramPolicy::new(
        program_id.clone(),
        owner.clone(),
        RamLfeBackend::HkdfSha3_512PrfV1,
        RamLfeVerificationMode::Signed,
        commitment,
        signer.public_key().clone(),
    );
    let policy = IdentifierPolicy::new(
        policy_id.clone(),
        owner.clone(),
        IdentifierNormalization::Exact,
        program_id,
    );
    (policy, program_policy)
}
fn sample_program_id(policy_id: &IdentifierPolicyId) -> RamLfeProgramId {
    policy_id
        .to_string()
        .replace('#', "_")
        .parse()
        .expect("program id")
}

fn identifier_fixture_error_message(error: &Error) -> &str {
    match error {
        Error::AppServiceUnavailable { code, message } => {
            assert_eq!(*code, "ram_lfe_encryption_unavailable");
            message
        }
        Error::Query(ValidationFail::InternalError(message))
        | Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(message),
        )) => message,
        other => panic!("expected identifier conversion/internal error, got {other:?}"),
    }
}
fn registered_hkdf_identifier_app(
    seed: u8,
) -> (
    SharedAppState,
    AccountId,
    KeyPair,
    IdentifierPolicy,
    RamLfeProgramPolicy,
) {
    let authority = checked_torii_test_account_id(seed, "HKDF identifier fixture owner");
    let signer = checked_torii_test_ed25519_keypair(seed.wrapping_add(1), "HKDF fixture signer");
    let domain_id = DomainId::try_new("directory", "universal").expect("domain id");
    let account = Account::new(authority.clone())
        .with_uaid(Some(UniversalAccountId::from_hash(Hash::new(
            b"fixture-uaid",
        ))))
        .build(&authority);
    let world = World::with([Domain::new(domain_id).build(&authority)], [account], []);
    let mut app = crate::tests_runtime_handlers::native_ingress_app_with_world_for_test(world);
    let policy_id = "string#retail".parse().expect("policy id");
    let (policy, program_policy) = sample_identifier_policy(&authority, &signer, &policy_id);
    let resolver = identifier_resolution::IdentifierResolutionService::new();
    resolver.register_program_runtime(
        program_policy.program_id.clone(),
        iroha_crypto::RamLfeSecret::try_from(b"resolver-secret".to_vec()).expect("test secret"),
        iroha_crypto::default_bfv_programmed_hidden_program(),
        signer.clone(),
        Some(30_000),
    );
    Arc::get_mut(&mut app)
        .expect("unique app")
        .identifier_resolver = Some(Arc::new(resolver));
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    register_and_activate_identifier_policy_bundle(&authority, &mut tx, &policy, &program_policy);
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit fixture");
    (app, authority, signer, policy, program_policy)
}
// Typed signed metadata for HTTP projection/error controls. It does not claim
// that a private program executed or that any ciphertext has been decrypted.
fn synthetic_execution_receipt(
    program: &RamLfeProgramPolicy,
    signer: &KeyPair,
    executed_at_ms: u64,
    expires_at_ms: Option<u64>,
) -> iroha_data_model::ram_lfe::RamLfeExecutionReceipt {
    let payload = iroha_data_model::ram_lfe::RamLfeExecutionReceiptPayload {
        program_id: program.program_id.clone(),
        program_digest: Hash::new(b"synthetic-program"),
        backend: program.backend,
        verification_mode: program.verification_mode,
        input_ciphertext_hash: Hash::new(b"synthetic-input-ciphertext"),
        output_ciphertext_hash: ram_lfe_output_hash(b"synthetic-output-ciphertext"),
        parameter_digest: Hash::new(b"synthetic-parameters"),
        evaluation_key_digest: Hash::new(b"synthetic-evaluation-keys"),
        output_hash: ram_lfe_output_hash(b"synthetic-output-ciphertext"),
        associated_data_hash: Hash::new(b"synthetic-associated-data"),
        executed_at_ms,
        expires_at_ms,
    };
    let signature = SignatureOf::try_new(signer.private_key(), &payload)
        .expect("sign typed fixture")
        .into();
    iroha_data_model::ram_lfe::RamLfeExecutionReceipt {
        payload,
        attestation: iroha_data_model::ram_lfe::RamLfeReceiptAttestation::Signed(signature),
    }
}
fn dummy_output_opening_for_access_test() -> RamLfeOutputOpening {
    let signer =
        checked_torii_test_ed25519_keypair(0x81, "derive RAM-LFE dummy output opening fixture key");
    let payload = RamLfeOutputOpeningPayload {
        program_id: "access_test".parse().expect("program id"),
        input_ciphertext_hash: Hash::new(b"access-test-input"),
        output_ciphertext_hash: Hash::new(b"access-test-output"),
        parameter_digest: Hash::new(b"access-test-parameters"),
        evaluation_key_digest: Hash::new(b"access-test-evaluation-key"),
        opened_output_hash: Hash::new(b"access-test-opened-output"),
        opened_at_ms: 0,
        expires_at_ms: None,
    };
    RamLfeOutputOpening {
        signature: SignatureOf::try_new(signer.private_key(), &payload)
            .expect("sign dummy RAM-LFE output opening fixture")
            .into(),
        payload,
    }
}
fn register_and_activate_identifier_policy_bundle(
    authority: &AccountId,
    tx: &mut iroha_core::state::StateTransaction<'_, '_>,
    policy: &IdentifierPolicy,
    program_policy: &RamLfeProgramPolicy,
) {
    RegisterRamLfeProgramPolicy {
        policy: program_policy.clone(),
    }
    .execute(authority, tx)
    .expect("register program policy");
    ActivateRamLfeProgramPolicy {
        program_id: program_policy.program_id.clone(),
    }
    .execute(authority, tx)
    .expect("activate program policy");
    RegisterIdentifierPolicy {
        policy: policy.clone(),
    }
    .execute(authority, tx)
    .expect("register policy");
    ActivateIdentifierPolicy {
        policy_id: policy.id.clone(),
    }
    .execute(authority, tx)
    .expect("activate policy");
}
fn seed_proof_record_at_height(
    app: &SharedAppState,
    backend: &str,
    proof_hash: [u8; 32],
    verified_at_height: u64,
) -> String {
    let height = verified_at_height.max(1);
    // Ensure the core state height is aligned with the proof being seeded to avoid
    // commit-height mismatches when tests inject multiple proof blocks.
    set_latest_block_height(app, height.saturating_sub(1));
    let header = BlockHeader::new(NonZeroU64::new(height).expect("height>0"), None, None, 0, 0);
    let mut block = app.state.block(header);
    let mut stx = block.transaction();
    let id = ProofId {
        backend: backend.to_string(),
        proof_hash,
    };
    let rec = ProofRecord {
        id: id.clone(),
        vk_ref: None,
        vk_commitment: None,
        status: ProofStatus::Verified,
        verified_at_height: Some(verified_at_height),
        bridge: None,
    };
    stx.world.proofs_mut_for_testing().insert(id.clone(), rec);
    stx.apply();
    // This is a synthetic index fixture, not finalized chain evidence. Retain the
    // actual header hash as well as empty membership through the existing owner.
    block
        .commit_empty_block_for_testing()
        .expect("seed proof block commit should succeed");
    id.to_string()
}
fn seed_proof_record(app: &SharedAppState, backend: &str, proof_hash: [u8; 32]) -> String {
    seed_proof_record_at_height(app, backend, proof_hash, 1)
}
fn current_block_height(app: &SharedAppState) -> u64 {
    app.state
        .transactions_latest_height_for_testing()
        .try_into()
        .expect("height should fit into u64")
}
fn next_block_height(app: &SharedAppState) -> u64 {
    current_block_height(app).saturating_add(1).max(1)
}

fn set_latest_block_height(app: &SharedAppState, height: u64) {
    let mut current_height = current_block_height(app);
    while current_height < height {
        let next_height = current_height.saturating_add(1);
        let header = BlockHeader::new(
            NonZeroU64::new(next_height).expect("height>0"),
            None,
            None,
            0,
            0,
        );
        app.state
            .block(header)
            .commit_empty_block_for_testing()
            .expect("set latest block height commit should succeed");
        current_height = next_height;
    }
}
#[tokio::test]
async fn proof_record_fixture_retains_exact_hash_and_membership_while_unfilled_tip_refuses() {
    // The old membership-only setup must still refuse; a test helper must not
    // weaken the production requirement to fill the original reserved hash tip.
    let app = mk_app_state_for_tests();
    let header = BlockHeader::new(NonZeroU64::new(1).expect("height>0"), None, None, 0, 0);
    let mut unfinished = app.state.block(header);
    unfinished
        .transactions
        .insert_block(HashSet::new(), NonZeroUsize::new(1).expect("height>0"));
    let error = unfinished
        .commit()
        .expect_err("membership without the original header hash must refuse");
    assert_eq!(format!("{error:?}"), "SnapshotObservationChanged");
    assert_eq!(current_block_height(&app), 0);
    assert_eq!(app.state.block_hashes.committed_height(), 0);
    assert_eq!(app.state.latest_block_hash_fast(), None);

    let proof_hash = [0xE1; 32];
    let id = seed_proof_record_at_height(&app, "halo2/ipa", proof_hash, 3);
    assert_eq!(current_block_height(&app), 3);
    assert_eq!(app.state.block_hashes.committed_height(), 3);
    let expected_hash =
        BlockHeader::new(NonZeroU64::new(3).expect("height>0"), None, None, 0, 0).hash();
    assert_eq!(app.state.latest_block_hash_fast(), Some(expected_hash));
    let proof_id = ProofId {
        backend: "halo2/ipa".to_owned(),
        proof_hash,
    };
    assert_eq!(id, proof_id.to_string());
    {
        let view = app.state.view();
        let record = view
            .world()
            .proofs()
            .get(&proof_id)
            .expect("retained proof record");
        assert_eq!(record.id, proof_id);
        assert_eq!(record.status, ProofStatus::Verified);
        assert_eq!(record.verified_at_height, Some(3));
    }
    set_latest_block_height(&app, 5);
    assert_eq!(current_block_height(&app), 5);
    assert_eq!(app.state.block_hashes.committed_height(), 5);
    let expected_hash =
        BlockHeader::new(NonZeroU64::new(5).expect("height>0"), None, None, 0, 0).hash();
    assert_eq!(app.state.latest_block_hash_fast(), Some(expected_hash));
    let view = app.state.view();
    let record = view
        .world()
        .proofs()
        .get(&proof_id)
        .expect("proof survives synthetic index advance");
    assert_eq!(record.id, proof_id);
    assert_eq!(record.status, ProofStatus::Verified);
    assert_eq!(record.verified_at_height, Some(3));
}
// Seed canonical identity before adding its independently owned primary alias.
fn bind_primary_account_alias_for_test(
    app: &SharedAppState,
    account: &AccountId,
    alias: &AccountAlias,
) {
    let catalog = app.state.nexus_snapshot().dataspace_catalog.clone();
    let literal = alias.to_literal(&catalog).expect("primary alias literal");
    bind_account_alias_for_test(app, account, &literal);
    let height = next_block_height(app);
    let header = BlockHeader::new(NonZeroU64::new(height).expect("height>0"), None, None, 0, 0);
    let mut block = app.state.block(header);
    let mut tx = block.transaction();
    tx.world_mut_for_testing()
        .account_mut(account)
        .expect("canonical account was seeded first")
        .set_label(Some(alias.clone()));
    tx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit primary alias label after its authoritative binding");
    assert_eq!(next_block_height(app), height);
}
fn grant_alias_resolve_permissions(
    app: &SharedAppState,
    account_id: &AccountId,
    alias: &AccountAlias,
) {
    let height = next_block_height(app);
    let header = BlockHeader::new(NonZeroU64::new(height).expect("height>0"), None, None, 0, 0);
    let mut block = app.state.block(header);
    let mut stx = block.transaction();
    let scope = match alias
        .domain_id(&app.state.nexus_snapshot().dataspace_catalog)
        .expect("test alias dataspace must resolve")
    {
        Some(domain) => AccountAliasPermissionScope::Domain(domain),
        None => AccountAliasPermissionScope::Dataspace(alias.dataspace),
    };
    stx.world_mut_for_testing().add_account_permission(
        account_id,
        Permission::from(CanResolveAccountAlias { scope }),
    );
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit should persist alias resolve permission");
}
fn signed_alias_resolve_headers_for_test(
    app: &SharedAppState,
    account_id: &AccountId,
    keypair: &KeyPair,
    alias: &AccountAlias,
    body: &[u8],
) -> HeaderMap {
    grant_alias_resolve_permissions(app, account_id, alias);
    let method = Method::POST;
    let uri: Uri = "/v1/aliases/resolve"
        .parse()
        .expect("alias resolve test URI");
    crate::tests_runtime_handlers::signed_network_app_headers(
        app.state.network_id_ref(),
        account_id,
        keypair,
        &method,
        &uri,
        body,
    )
}
fn grant_alias_resolve_dataspace_permission(
    app: &SharedAppState,
    account_id: &AccountId,
    dataspace: DataSpaceId,
) {
    let height = next_block_height(app);
    let header = BlockHeader::new(NonZeroU64::new(height).expect("height>0"), None, None, 0, 0);
    let mut block = app.state.block(header);
    let mut stx = block.transaction();
    stx.world_mut_for_testing().add_account_permission(
        account_id,
        Permission::from(CanResolveAccountAlias {
            scope: AccountAliasPermissionScope::Dataspace(dataspace),
        }),
    );
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit should persist alias dataspace resolve permission");
}
fn recipient_lookup_sbp_dataspace_for_test() -> DataSpaceId {
    DataSpaceId::new(20)
}
fn recipient_lookup_cbuae_dataspace_for_test() -> DataSpaceId {
    DataSpaceId::new(10)
}
fn recipient_lookup_aed_definition_for_test() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("fx", "universal").expect("FX domain"),
        "aed".parse().expect("AED name"),
    )
}
fn recipient_lookup_world_for_test(caller: &AccountId, target: &AccountId) -> World {
    let definition_id = recipient_lookup_aed_definition_for_test();
    let definition_domain = DomainId::try_new("fx", "universal").expect("FX domain");
    World::with_assets(
        [Domain::new(definition_domain.clone()).build(caller)],
        [
            Account::new(caller.clone()).build(caller),
            Account::new(target.clone()).build(caller),
        ],
        [iroha_data_model::asset::AssetDefinition::numeric(
            definition_id.clone(),
            "aed".to_owned(),
            AssetBalancePolicy::DataspaceRestricted,
            Some(definition_domain),
        )
        .build(caller)],
        [iroha_data_model::asset::Asset::new(
            AssetId::with_scope(
                definition_id,
                caller.clone(),
                AssetBalanceScope::Dataspace(recipient_lookup_cbuae_dataspace_for_test()),
            ),
            Quantity::from(100_u32),
        )],
        [],
    )
}
fn recipient_lookup_nexus_for_test(
    visibility: iroha_data_model::nexus::LaneVisibility,
) -> actual::Nexus {
    let sbp_dataspace = recipient_lookup_sbp_dataspace_for_test();
    let cbuae_dataspace = recipient_lookup_cbuae_dataspace_for_test();
    let cbuae_lane = LaneId::new(1);
    let sbp_lane = LaneId::new(2);
    let lane_catalog = iroha_data_model::nexus::LaneCatalog::new(
        std::num::NonZeroU32::new(3).expect("nonzero lane count"),
        vec![
            iroha_data_model::nexus::LaneConfig::default(),
            iroha_data_model::nexus::LaneConfig {
                id: cbuae_lane,
                dataspace_id: cbuae_dataspace,
                alias: "cbuae".to_owned(),
                visibility: iroha_data_model::nexus::LaneVisibility::Restricted,
                ..iroha_data_model::nexus::LaneConfig::default()
            },
            iroha_data_model::nexus::LaneConfig {
                id: sbp_lane,
                dataspace_id: sbp_dataspace,
                alias: "sbp".to_owned(),
                visibility,
                ..iroha_data_model::nexus::LaneConfig::default()
            },
        ],
    )
    .expect("lane catalog");
    let dataspace_catalog = iroha_data_model::nexus::DataSpaceCatalog::new(vec![
        iroha_data_model::nexus::DataSpaceMetadata::default(),
        iroha_data_model::nexus::DataSpaceMetadata {
            id: cbuae_dataspace,
            alias: "cbuae".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
        iroha_data_model::nexus::DataSpaceMetadata {
            id: sbp_dataspace,
            alias: "sbp".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("dataspace catalog");
    actual::Nexus {
        lane_config: actual::LaneConfig::from_catalog(&lane_catalog),
        configured_lane_catalog: lane_catalog.clone(),
        configured_dataspace_catalog: dataspace_catalog.clone(),
        lane_catalog,
        dataspace_catalog,
        ..actual::Nexus::default()
    }
}
fn configure_recipient_lookup_sbp_dataspace_for_test(
    app: &mut SharedAppState,
    visibility: iroha_data_model::nexus::LaneVisibility,
) {
    let nexus = recipient_lookup_nexus_for_test(visibility);
    let app_state = Arc::get_mut(app).expect("unique app state");
    let state = Arc::get_mut(&mut app_state.state).expect("unique state");
    crate::tests_runtime_handlers::assert_initial_nexus_catalog_for_test(state, &nexus);
    let state_view = app_state.state.view();
    app_state.queue.reconfigure_nexus(&nexus, &state_view, None);
}
fn onboarding_alias_test_world(authority: &AccountId, domain_owner: &AccountId) -> World {
    let mut accounts = vec![Account::new(authority.clone()).build(authority)];
    if domain_owner != authority {
        accounts.push(Account::new(domain_owner.clone()).build(domain_owner));
    }
    let domains = [
        Domain::new(DomainId::try_new("hbl", "sbp").expect("HBL domain")).build(domain_owner),
        Domain::new(DomainId::try_new("ubl", "sbp").expect("UBL domain")).build(domain_owner),
    ];
    let fee_asset_id: AssetDefinitionId =
        iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
            .parse()
            .expect("default fee asset id");
    let fee_definition = iroha_data_model::asset::AssetDefinition::numeric(
        fee_asset_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(authority);
    let fee_asset = iroha_data_model::asset::Asset::new(
        iroha_data_model::asset::AssetId::of(fee_asset_id, authority.clone()),
        Quantity::from(100_u32),
    );
    let mut world = World::with_assets(domains, accounts, [fee_definition], [fee_asset], []);
    install_account_alias_policy_for_test(&mut world, authority);
    install_onboarding_parent_leases_for_test(&mut world, domain_owner);
    world
}
fn onboarding_alias_test_app(authority: &AccountId, domain_owner: &AccountId) -> SharedAppState {
    let world = onboarding_alias_test_world(authority, domain_owner);
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world,
        recipient_lookup_nexus_for_test(iroha_data_model::nexus::LaneVisibility::Restricted),
    );
    configure_recipient_lookup_sbp_dataspace_for_test(
        &mut app,
        iroha_data_model::nexus::LaneVisibility::Restricted,
    );
    app
}
fn install_account_alias_policy_for_test(world: &mut World, authority: &AccountId) {
    // Use the same full alias grammar and pricing as first-release State initialization.
    iroha_core::sns::seed_default_namespace_policies(world);
    let mut policy = iroha_core::sns::policy_by_id(
        &world.view(),
        iroha_data_model::sns::ACCOUNT_ALIAS_SUFFIX_ID,
    )
    .expect("read native account alias policy")
    .expect("native account alias policy is installed");
    policy.steward = authority.clone();
    policy.fund_splitter_account = authority.clone();
    world.smart_contract_state_mut_for_testing().insert(
        iroha_core::sns::policy_storage_key(iroha_data_model::sns::ACCOUNT_ALIAS_SUFFIX_ID),
        norito::codec::Encode::encode(&policy),
    );
}
fn install_onboarding_parent_leases_for_test(world: &mut World, owner: &AccountId) {
    let controller = iroha_data_model::sns::NameControllerV1::account(
        &AccountAddress::from_account_id(owner).expect("parent lease owner address"),
    );
    let dataspace_selector =
        iroha_core::sns::selector_for_dataspace_alias("sbp").expect("SBP selector");
    let mut dataspace_metadata = iroha_model_base::metadata::Metadata::default();
    dataspace_metadata.insert(
        iroha_core::sns::SNS_DATASPACE_ID_METADATA_KEY
            .parse()
            .expect("dataspace metadata key"),
        iroha_primitives::json::Json::new(recipient_lookup_sbp_dataspace_for_test().as_u64()),
    );
    let dataspace_record = iroha_data_model::sns::NameRecordV1::new(
        dataspace_selector.clone(),
        owner.clone(),
        vec![controller.clone()],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        dataspace_metadata,
    );
    world.smart_contract_state_mut_for_testing().insert(
        iroha_core::sns::record_storage_key(&dataspace_selector),
        norito::codec::Encode::encode(&dataspace_record),
    );
    for name in ["hbl", "ubl"] {
        let domain = DomainId::try_new(name, "sbp").expect("onboarding parent domain");
        let selector = iroha_core::sns::selector_for_domain(&domain).expect("domain selector");
        let record = iroha_data_model::sns::NameRecordV1::new(
            selector.clone(),
            owner.clone(),
            vec![controller.clone()],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            iroha_model_base::metadata::Metadata::default(),
        );
        world.smart_contract_state_mut_for_testing().insert(
            iroha_core::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
    }
}
fn grant_account_permissions_for_test(
    app: &SharedAppState,
    authority: &AccountId,
    permissions: impl IntoIterator<Item = Permission>,
) {
    let height = next_block_height(app);
    let header = BlockHeader::new(NonZeroU64::new(height).expect("height>0"), None, None, 0, 0);
    let mut block = app.state.block(header);
    let mut stx = block.transaction();
    for permission in permissions {
        stx.world_mut_for_testing()
            .add_account_permission(authority, permission);
    }
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit should persist onboarding permissions without an empty block");
}
fn onboarding_credential_domain_permissions(domain: &DomainId) -> [Permission; 1] {
    [Permission::from(CanManageAccountAlias {
        scope: AccountAliasPermissionScope::Domain(domain.clone()),
    })]
}
fn onboarding_fee_sponsor_program_for_test(account: &AccountId) -> FeeSponsorProgramId {
    FeeSponsorProgramId::new(
        account.clone(),
        "retail".parse().expect("retail fee sponsor program name"),
    )
}
fn onboarding_fee_sponsor_enrollment_permission(program_id: &FeeSponsorProgramId) -> Permission {
    Permission::from(CanEnrollFeeSponsorProgram {
        program_id: program_id.clone(),
    })
}
fn register_fee_sponsor_program_for_test(app: &SharedAppState, program_id: FeeSponsorProgramId) {
    let height = next_block_height(app);
    let header = BlockHeader::new(NonZeroU64::new(height).expect("height>0"), None, None, 0, 0);
    let mut block = app.state.block(header);
    let mut stx = block.transaction();
    iroha_data_model::isi::nexus::CreateFeeSponsorProgram {
        program: FeeSponsorProgram::new(program_id.clone(), program_id.sponsor.clone()),
    }
    .execute(&program_id.sponsor, &mut stx)
    .expect("sponsor may register its program");
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit fee sponsor program fixture without an empty block");
}
fn onboarding_alias_test_app_with_role_permissions(
    authority: &AccountId,
    domain_owner: &AccountId,
    permissions: impl IntoIterator<Item = Permission>,
) -> SharedAppState {
    let mut accounts = vec![Account::new(authority.clone()).build(authority)];
    if domain_owner != authority {
        accounts.push(Account::new(domain_owner.clone()).build(domain_owner));
    }
    let domains = [
        Domain::new(DomainId::try_new("hbl", "sbp").expect("HBL domain")).build(domain_owner),
        Domain::new(DomainId::try_new("ubl", "sbp").expect("UBL domain")).build(domain_owner),
    ];
    let role_id: RoleId = "onboarding_credential_role".parse().expect("role id");
    let role = permissions
        .into_iter()
        .fold(
            Role::new(role_id.clone(), authority.clone()),
            |role, permission| role.add_permission(permission),
        )
        .build(authority);
    let fee_asset_id: AssetDefinitionId =
        iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
            .parse()
            .expect("default fee asset id");
    let fee_definition = iroha_data_model::asset::AssetDefinition::numeric(
        fee_asset_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(authority);
    let fee_asset = iroha_data_model::asset::Asset::new(
        iroha_data_model::asset::AssetId::of(fee_asset_id, authority.clone()),
        Quantity::from(100_u32),
    );
    let mut world = World::with_assets_and_roles(
        domains,
        accounts,
        [fee_definition],
        [fee_asset],
        std::iter::empty::<iroha_data_model::nft::Nft>(),
        [role],
    );
    install_account_alias_policy_for_test(&mut world, authority);
    install_onboarding_parent_leases_for_test(&mut world, domain_owner);
    world.grant_role_for_tests(authority.clone(), role_id);
    let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world_and_nexus(
        world,
        recipient_lookup_nexus_for_test(iroha_data_model::nexus::LaneVisibility::Restricted),
    );
    configure_recipient_lookup_sbp_dataspace_for_test(
        &mut app,
        iroha_data_model::nexus::LaneVisibility::Restricted,
    );
    app
}
fn onboarding_alias_signer_for_test(key_pair: &KeyPair) -> AccountOnboardingSigner {
    AccountOnboardingSigner {
        authority: AccountId::new(key_pair.public_key().clone()),
        private_key: ExposedPrivateKey(key_pair.private_key().clone()),
        api_token_hashes_by_domain: BTreeMap::new(),
        api_token_hashes_by_dataspace: BTreeMap::new(),
        allowed_permissions: BTreeSet::new(),
        fee_sponsor_program_id: None,
        alias_lease_term_years: 1,
        owner_auto_renew: None,
    }
}
