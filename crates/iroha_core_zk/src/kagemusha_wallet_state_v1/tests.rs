//! State-control and persistence tests. Proof fixtures are explicit mocks; receipts use real
//! P-256 signatures. These tests do not establish Λ/Ω cryptographic validity or phone gates.

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletCustodyDirV1 as Dir, KagemushaWalletEntryNameV1 as Name,
    KagemushaWalletFsV1 as Fs, KagemushaWalletMarkerRecordV1 as MarkerRecord,
    KagemushaWalletSimFaultV1 as Fault, KagemushaWalletSimFsV1 as SimFs,
    KagemushaWalletSimPowerLossV1 as PowerLoss, KagemushaWalletSlotIdV1 as Slot,
    KagemushaWalletTransitionOwnerV1 as OwnerTrait,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

fn vectors() -> norito::json::Value {
    norito::json::from_str(include_str!(
        "../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .expect("vectors")
}

pub(super) fn fixture<T>(name: &str) -> T
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    let all = vectors();
    let row = all["objects"]
        .as_array()
        .expect("objects")
        .iter()
        .find(|row| row["type"].as_str() == Some(name))
        .expect("fixture");
    archive::decode(&hex::decode(row["canonical_hex"].as_str().expect("hex")).expect("hex"))
        .expect("canonical fixture")
}

fn credential() -> KagemushaWalletCredentialV1 {
    fixture("KagemushaWalletCredentialV1")
}

pub(super) fn enrollment_issuer(
    credential: &KagemushaWalletCredentialV1,
) -> KagemushaWalletSignerCertificateV1 {
    // The standalone certificate vector exercises a different signer role. Recover the
    // actual enrollment original from the authenticated session that carries this wallet.
    for row in vectors()["envelopes"].as_array().expect("envelopes") {
        let envelope: KagemushaWalletEnvelopeV1 = archive::decode(
            &hex::decode(row["canonical_hex"].as_str().expect("hex")).expect("hex"),
        )
        .expect("envelope");
        let certificates = match envelope.message {
            KagemushaWalletMessageV1::Offer { offer } => offer.certificates,
            KagemushaWalletMessageV1::Request { request } => request.certificates,
            _ => continue,
        };
        if let Some(certificate) = certificates.certificates.iter().find(|certificate| {
            certificate.certificate_digest() == credential.body.issuer_certificate
        }) {
            credential
                .verify(&fixture("KagemushaWalletSchemeV1"), certificate)
                .expect("actual enrollment issuer");
            return *certificate;
        }
    }
    panic!("fixture enrollment issuer")
}

pub(super) fn signer(credential: &KagemushaWalletCredentialV1) -> SigningKey {
    for key in vectors()["keys"].as_array().expect("keys") {
        let signing = SigningKey::from_slice(
            &hex::decode(key["scalar_hex"].as_str().expect("scalar")).expect("hex"),
        )
        .expect("key");
        let public = KagemushaDevicePublicKeyV1::from_sec1_bytes(
            signing.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .expect("public");
        if public == credential.body.payment_key {
            return signing;
        }
    }
    panic!("fixture payment key")
}

pub(super) fn field(value: u8) -> [u8; 32] {
    let mut out = [0; 32];
    out[0] = value;
    out
}

fn received_credit() -> [u8; 32] {
    fixture::<KagemushaWalletPaymentV1>("KagemushaWalletPaymentV1")
        .digests()
        .unwrap()
        .credit_id
}
fn received_payment() -> [u8; 32] {
    fixture::<KagemushaWalletPaymentV1>("KagemushaWalletPaymentV1")
        .digests()
        .unwrap()
        .payment
}
// This envelope is constructed only by the test custody implementation. The production
// adapter obtains MarkerRecord exclusively from the actual Advance provider.
#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::zk::kagemusha_wallet_advance_v1::MarkerFileV1")]
struct TestMarkerFile {
    version: u16,
    slot: [u8; 32],
    anchor_kind: u8,
    written_boot_id: [u8; 32],
    completion_digest: [u8; 32],
    selected_generation: u128,
    archive_checkpoint: [u8; 32],
    marker: Vec<u8>,
}

fn marker_record(marker: KagemushaWalletMarkerV1, completion_digest: [u8; 32]) -> MarkerRecord {
    let scheme = marker.scheme_id;
    let bytes = archive::encode(&TestMarkerFile {
        version: 1,
        slot: [0x55; 32],
        anchor_kind: 0,
        written_boot_id: [0x44; 32],
        completion_digest,
        selected_generation: if matches!(marker.state, KagemushaWalletMarkerStateV1::Head { .. }) {
            if completion_digest == [0; 32] {
                marker.generation
            } else {
                marker.generation - 1
            }
        } else {
            0
        },
        archive_checkpoint: [0; 32],
        marker: marker.to_canonical_bytes().expect("marker"),
    })
    .expect("envelope");
    MarkerRecord::decode(&bytes, &Slot([0x55; 32]), &scheme).expect("marker record")
}

fn enrollment() -> KagemushaWalletMarkerV1 {
    fixture("KagemushaWalletMarkerV1")
}

/// Seal synthetic, structurally valid test DATA with a fixed opening, never production entropy.
pub(crate) fn seal_body(body: KagemushaWalletRecoveryBodyV1) -> KagemushaWalletRecoveryCapsuleV1 {
    body.freeze()
        .expect("valid synthetic body")
        .seal([0; 32])
        .expect("synthetic opening")
}

pub(super) fn frozen(
    previous: Option<&FrozenTransition>,
    effect: KagemushaWalletEffectV1,
) -> FrozenTransition {
    let credential = credential();
    let mut c = fixture::<KagemushaWalletRecoveryCapsuleV1>("KagemushaWalletRecoveryCapsuleV1")
        .body()
        .clone();
    let kind = effect.kind();
    let request_input = c
        .retained_inputs
        .iter()
        .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::Request)
        .expect("fixture Request")
        .clone();
    c.scheme_id = credential.body.scheme_id;
    c.wallet_id = credential.body.wallet_id;
    c.kind = kind;
    c.statement.scheme_id = c.scheme_id;
    c.statement.asset_digest = credential.body.asset_digest;
    c.statement.credential_digest = credential.credential_digest();
    c.statement.lifecycle = if kind == KagemushaWalletOperationKindV1::Retiring {
        KagemushaWalletLifecycleV1::Retiring
    } else {
        KagemushaWalletLifecycleV1::Active
    };
    c.statement.sequence = previous.map_or(0, |p| p.capsule.body().statement.sequence + 1);
    c.statement.next_load = match effect {
        KagemushaWalletEffectV1::Load { load_ordinal, .. } => load_ordinal + 1,
        _ => previous.map_or(0, |p| p.capsule.body().statement.next_load),
    };
    c.statement.enabled_controls = 0;
    c.statement.lineage_burned_total = 0;
    c.statement.lineage_pending_outgoing_root = [0; 32];
    c.statement.predecessor = previous
        .map_or(KagemushaWalletStateCommitmentV1 { value: [0; 32] }, |p| {
            p.capsule.body().statement.successor
        });
    c.statement.effect = effect;
    c.predecessor_capsule_digest = previous.map_or([0; 32], |p| p.capsule.custody_digest());
    c.predecessor_lineage = KagemushaWalletLineageSlotV1::None;
    if kind.consumes_lineage() {
        let payment: KagemushaWalletPaymentV1 = fixture("KagemushaWalletPaymentV1");
        let mut lineage = payment.send.lineage.lineage().expect("lineage").clone();
        lineage.public.head = c.statement.predecessor;
        lineage.public.wallet_id = c.wallet_id;
        lineage.public.credential_digest = c.statement.credential_digest;
        lineage.public.payment_key = credential.body.payment_key;
        lineage.public.enabled_controls = c.statement.enabled_controls;
        lineage.public.lifecycle = KagemushaWalletLifecycleV1::Active;
        c.statement.lineage_burned_total = lineage.public.burned_total;
        c.statement.lineage_pending_outgoing_root = lineage.public.pending_outgoing_root;
        c.predecessor_lineage = KagemushaWalletLineageSlotV1::Present { lineage };
    }
    c.payment_digest = if kind == KagemushaWalletOperationKindV1::Receive {
        received_payment()
    } else {
        [0; 32]
    };
    // The vector is a Receive with an already populated consumed map. It supplies signed
    // object fixtures, never the initial local map descriptor. Mock steps carry their actual
    // selected predecessor fields; Bootstrap starts with the protocol's empty local stores.
    c.successor_state = previous.map_or_else(
        || KagemushaWalletStateV1::bootstrap(&credential, field(92)).expect("empty state"),
        |previous| previous.capsule.body().successor_state,
    );
    let state = &mut c.successor_state;
    state.core.scheme_id = c.scheme_id;
    state.core.wallet_id = c.wallet_id;
    state.core.asset_digest = credential.body.asset_digest;
    state.core.credential_digest = credential.credential_digest();
    state.core.sequence = c.statement.sequence;
    state.core.lifecycle = c.statement.lifecycle;
    state.core.next_load = c.statement.next_load;
    state.core.balance = 20;
    state.core.enabled_controls = 0;
    state.core.burned_total = c.statement.lineage_burned_total;
    c.statement.successor = state.commitment().expect("state");
    c.operation_id = c.statement.operation_id(&c.wallet_id).expect("operation");
    c.output = KagemushaWalletOutputDescriptorV1::for_transition(
        &c.statement,
        &c.proof_digest().expect("proof digest"),
        &c.payment_digest,
    )
    .expect("output");
    c.map_openings.clear();
    c.retained_inputs = match kind {
        KagemushaWalletOperationKindV1::Receive => vec![
            KagemushaWalletRetainedInputRoleV1::Request,
            KagemushaWalletRetainedInputRoleV1::Payment,
            KagemushaWalletRetainedInputRoleV1::CertificateSet,
            KagemushaWalletRetainedInputRoleV1::Credential,
        ],
        KagemushaWalletOperationKindV1::Load => vec![
            KagemushaWalletRetainedInputRoleV1::LoadReceipt,
            KagemushaWalletRetainedInputRoleV1::LoadFinality,
        ],
        KagemushaWalletOperationKindV1::RefreshPolicy => vec![
            KagemushaWalletRetainedInputRoleV1::PolicyUpdate,
            KagemushaWalletRetainedInputRoleV1::CertificateSet,
        ],
        _ => Vec::new(),
    }
    .into_iter()
    .map(|role| KagemushaWalletRetainedInputV1 {
        role,
        bytes: if role == KagemushaWalletRetainedInputRoleV1::Payment {
            fixture::<KagemushaWalletPaymentV1>("KagemushaWalletPaymentV1")
                .to_canonical_bytes()
                .unwrap()
        } else {
            vec![1]
        },
    })
    .collect();
    if kind == KagemushaWalletOperationKindV1::Send {
        c.retained_inputs = vec![request_input];
    }
    let result = FrozenTransition {
        credential,
        capsule: seal_body(c),
    };
    result.validate().expect("frozen");
    result
}

pub(super) fn bootstrap() -> FrozenTransition {
    frozen(
        None,
        KagemushaWalletEffectV1::Bootstrap {
            enrollment_id: credential().body.enrollment_id,
            enrollment_marker: enrollment().marker_digest().expect("marker digest"),
        },
    )
}

// Structural refusal fixtures only. Issuer authentication and every operation proof remain
// mandatory in NativeProofs; these tests establish no authentic credential reissuance.
fn rebind_frozen_successor(value: &mut FrozenTransition, mut c: KagemushaWalletRecoveryBodyV1) {
    c.statement.credential_digest = value.credential.credential_digest();
    c.successor_state.core.credential_digest = c.statement.credential_digest;
    c.statement.successor = c.successor_state.commitment().expect("successor state");
    c.operation_id = c.statement.operation_id(&c.wallet_id).expect("operation");
    c.output = KagemushaWalletOutputDescriptorV1::for_transition(
        &c.statement,
        &c.proof_digest().expect("proof digest"),
        &c.payment_digest,
    )
    .expect("output");
    value.capsule = c
        .freeze()
        .expect("valid synthetic body")
        .seal([0; 32])
        .expect("synthetic opening");
    let c = &value.capsule;
    // Each existing self-contained boundary still passes after the commitment is rebound.
    assert_eq!(
        KagemushaWalletRecoveryCapsuleV1::decode_canonical(
            &c.to_canonical_bytes(),
            &c.body().scheme_id
        )
        .expect("self-contained capsule"),
        *c
    );
    value.credential.validate().expect("structural credential");
    c.body()
        .statement
        .validate_for_credential(&value.credential)
        .expect("statement credential");
}

#[test]
fn frozen_rejects_rebound_successor_with_unenrolled_regulatory_controls() {
    let mut value = bootstrap();
    assert_eq!(
        value.credential.body.regulatory_policy.permitted_controls,
        0
    );
    let mut body = value.capsule.body().clone();
    // A structurally valid quota policy (its response bound is nonzero) the credential lacks.
    body.successor_state.rest.permitted_controls = KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1;
    body.successor_state.core.time_anchor_max_response_ms = 1;
    rebind_frozen_successor(&mut value, body);
    assert!(value.validate().is_err());
}

#[test]
fn frozen_rejects_rebound_successor_with_another_credential_lease() {
    let mut value = bootstrap();
    // A structurally consistent lease policy on both objects isolates the lease mismatch.
    // The changed fixture signature is deliberately not authenticated by this unit test.
    value.credential.body.regulatory_policy.permitted_controls =
        KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1;
    value
        .credential
        .body
        .regulatory_policy
        .time_anchor_max_response_ms = 1;
    value.credential.body.lease_expires_at_ms = 1;
    let mut body = value.capsule.body().clone();
    body.successor_state.rest.permitted_controls = KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1;
    body.successor_state.core.time_anchor_max_response_ms = 1;
    body.successor_state.core.lease_expires_at_ms = 2;
    rebind_frozen_successor(&mut value, body);
    assert_eq!(
        value.capsule.body().successor_state.regulatory_policy(),
        value.credential.body.regulatory_policy
    );
    assert!(value.validate().is_err());
}

#[derive(Clone)]
pub(super) struct MemoryArchive {
    scheme: [u8; 32],
    wallet: [u8; 32],
    records: Arc<Mutex<BTreeMap<ArchiveKey, Vec<u8>>>>,
    reads: Arc<AtomicUsize>,
    draft_reads: Arc<AtomicUsize>,
    pub(super) fail_remove: bool,
    capsule_writes: Arc<AtomicUsize>,
    fail_put: Arc<Mutex<Option<(ArchiveKey, bool)>>>,
    // Content-addressed objects whose reads fail: once (transient) or until revealed.
    hidden: Arc<Mutex<BTreeMap<[u8; 32], bool>>>,
}
impl MemoryArchive {
    pub(super) fn new() -> Self {
        let c = credential();
        Self {
            scheme: c.body.scheme_id,
            wallet: c.body.wallet_id,
            records: Arc::default(),
            reads: Arc::default(),
            draft_reads: Arc::default(),
            fail_remove: false,
            capsule_writes: Arc::default(),
            fail_put: Arc::default(),
            hidden: Arc::default(),
        }
    }
    /// The next read of this object fails once with a transient storage error.
    pub(super) fn hide_object_once(&self, key: [u8; 32]) {
        self.hidden.lock().expect("hidden").insert(key, true);
    }
    /// Every read of this object reports it missing until it is revealed.
    pub(super) fn hide_object(&self, key: [u8; 32]) {
        self.hidden.lock().expect("hidden").insert(key, false);
    }
    pub(super) fn reveal_object(&self, key: [u8; 32]) {
        self.hidden.lock().expect("hidden").remove(&key);
    }
}
impl MemoryArchive {
    fn keys(&mut self) -> Result<Vec<ArchiveKey>, Error> {
        Ok(self
            .records
            .lock()
            .expect("records")
            .keys()
            .copied()
            .collect())
    }
}
impl ArchiveStore for MemoryArchive {
    fn remove(&mut self, key: ArchiveKey) -> Result<(), Error> {
        if std::mem::take(&mut self.fail_remove) {
            return Err(Error::WitnessLost("test removal unavailable"));
        }
        self.records.lock().expect("records").remove(&key);
        Ok(())
    }

    fn binding(&self) -> ([u8; 32], [u8; 32]) {
        (self.scheme, self.wallet)
    }
    fn get(
        &mut self,
        key: ArchiveKey,
        max_bytes: usize,
    ) -> Result<Option<PrivateArchiveBytes>, Error> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if matches!(key, ArchiveKey::PreparationDraft(_)) {
            self.draft_reads.fetch_add(1, Ordering::SeqCst);
        }
        if let ArchiveKey::Object(object) = key {
            let mut hidden = self.hidden.lock().expect("hidden");
            match hidden.get(&object).copied() {
                Some(true) => {
                    hidden.remove(&object);
                    return Err(Error::Storage(std::io::ErrorKind::Interrupted.into()));
                }
                Some(false) => return Ok(None),
                None => {}
            }
        }
        if self
            .records
            .lock()
            .expect("records")
            .get(&key)
            .is_some_and(|bytes| bytes.len() > max_bytes)
        {
            return Err(Error::WitnessLost("record size"));
        }
        self.records
            .lock()
            .expect("records")
            .get(&key)
            .map(|bytes| PrivateArchiveBytes::copy_from(bytes).map_err(Error::Storage))
            .transpose()
    }
    fn put(&mut self, key: ArchiveKey, bytes: &[u8]) -> Result<(), Error> {
        let fault = {
            let mut fault = self.fail_put.lock().unwrap();
            if fault.as_ref().is_some_and(|(selected, _)| *selected == key) {
                fault.take().map(|(_, after)| after)
            } else {
                None
            }
        };
        if fault == Some(false) {
            return Err(Error::Storage(std::io::ErrorKind::Other.into()));
        }
        let mut records = self.records.lock().expect("records");
        if records.get(&key).is_some_and(|old| old != bytes) {
            return Err(Error::WitnessLost("immutable conflict"));
        }
        records.insert(key, bytes.to_vec());
        if matches!(key, ArchiveKey::Capsule(_)) {
            self.capsule_writes.fetch_add(1, Ordering::SeqCst);
        }
        if fault == Some(true) {
            return Err(Error::Storage(std::io::ErrorKind::Other.into()));
        }
        Ok(())
    }
}

pub(super) struct TestCustody {
    checkpoint: Option<([u8; 32], Vec<u8>)>,
    status: SlotStatus,
    retained: BTreeMap<[u8; 32], Retained<KagemushaWalletCompletionRecordV1>>,
    tombstones: BTreeMap<[u8; 32], crate::kagemusha_wallet_advance_v1::KagemushaWalletTombstoneV1>,
    pending: Option<AdvanceRequest<KagemushaWalletRecoveryCapsuleV1>>,
    pause: bool,
    pub(super) signatures: usize,
    unavailable: bool,
    delivery_lost: bool,
    pub(super) fail_publication: Option<bool>,
    publication_calls: usize,
    fail_publication_at: Option<(usize, bool)>,
    status_calls: usize,
    status_replacement: Option<(usize, SlotStatus)>,
    status_unavailable_at: Option<usize>,
    status_error: Option<ProviderError>,
    checkpoint_calls: usize,
    checkpoint_replacement: Option<(usize, ([u8; 32], Vec<u8>))>,
    // A genuine custody head reported by status once `move_head` is set: an Advance that
    // the archive checkpoint has not indexed yet.
    moved_status: Option<SlotStatus>,
    move_head: Arc<AtomicBool>,
    pub(super) resources: crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeResourcesV1,
    pub(super) resource_queries: usize,
    fail_resources: bool,
}
impl TestCustody {
    /// Replace one existing test completion without changing its selected manifest or marker.
    pub(super) fn replace_retained(
        &mut self,
        retained: Retained<KagemushaWalletCompletionRecordV1>,
    ) -> Retained<KagemushaWalletCompletionRecordV1> {
        self.retained
            .insert(retained.operation_id, retained)
            .expect("existing retained test operation")
    }

    fn new() -> Self {
        Self {
            checkpoint: None,
            status: SlotStatus::Enrollment(marker_record(enrollment(), [0; 32])),
            retained: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            pending: None,
            pause: false,
            signatures: 0,
            unavailable: false,
            delivery_lost: false,
            fail_publication: None,
            publication_calls: 0,
            fail_publication_at: None,
            status_calls: 0,
            status_replacement: None,
            status_unavailable_at: None,
            status_error: None,
            checkpoint_calls: 0,
            checkpoint_replacement: None,
            moved_status: None,
            move_head: Arc::default(),
            resources: crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeResourcesV1 {
                storage_bytes: u64::MAX / 2,
                memory_bytes: Some(u64::MAX / 2),
            },
            resource_queries: 0,
            fail_resources: false,
        }
    }
}
impl Custody for TestCustody {
    fn runtime_resources(
        &mut self,
    ) -> Result<crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeResourcesV1, ProviderError>
    {
        self.resource_queries += 1;
        if self.fail_resources {
            return Err(ProviderError::Unavailable(
                crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Locked,
            ));
        }
        Ok(self.resources)
    }
    fn collect_capsule(
        &mut self,
        generation: u128,
        _capsule: [u8; 32],
    ) -> Result<(), ProviderError> {
        let status = self.status()?;
        assert!(generation < status.marker().unwrap().selected_generation().unwrap());
        Ok(())
    }
    fn prune_completion(
        &mut self,
        operation: [u8; 32],
        kind: u8,
    ) -> Result<crate::kagemusha_wallet_advance_v1::KagemushaWalletTombstoneV1, ProviderError> {
        self.status()?;
        if let Some(prior) = self.tombstones.get(&operation) {
            return Ok(*prior);
        }
        let retained = self.retained.remove(&operation).expect("known completion");
        let tombstone = crate::kagemusha_wallet_advance_v1::KagemushaWalletTombstoneV1 {
            version: 1,
            operation_id: operation,
            kind,
            selected_generation: retained.selected_generation,
            capsule_digest: retained.capsule_digest,
            completion_digest: retained.completion_digest,
        };
        self.tombstones.insert(operation, tombstone);
        Ok(tombstone)
    }
    fn archive_checkpoint(&mut self) -> Result<Option<([u8; 32], Vec<u8>)>, ProviderError> {
        self.checkpoint_calls += 1;
        if let Some((at, replacement)) = &self.checkpoint_replacement {
            if self.checkpoint_calls == *at {
                return Ok(Some(replacement.clone()));
            }
        }
        Ok(self.checkpoint.clone())
    }
    fn publish_archive_checkpoint(
        &mut self,
        expected: [u8; 32],
        bytes: &[u8],
    ) -> Result<[u8; 32], ProviderError> {
        self.publication_calls += 1;
        let fail = if self
            .fail_publication_at
            .is_some_and(|(at, _)| at == self.publication_calls)
        {
            self.fail_publication_at.take().map(|(_, after)| after)
        } else {
            self.fail_publication.take()
        };
        if fail == Some(false) {
            return Err(ProviderError::Invalid {
                field: "test publication before commit",
            });
        }
        let digest =
            crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_checkpoint_digest_v1(
                bytes,
            );
        if self.checkpoint.as_ref().map_or([0; 32], |c| c.0) != expected {
            return Err(ProviderError::Invalid {
                field: "stale test checkpoint",
            });
        }
        self.checkpoint = Some((digest, bytes.to_vec()));
        // Test custody must select metadata exactly as production does, preserving the original
        // payment selection and completion while publishing a new nonmonetary generation.
        if let SlotStatus::Released(record) = &self.status {
            let mut file: TestMarkerFile = archive::decode(record.file_bytes()).unwrap();
            let mut marker = record.marker().clone();
            marker.generation += 1;
            file.marker = marker.to_canonical_bytes().unwrap();
            file.archive_checkpoint = digest;
            self.status = SlotStatus::Released(
                MarkerRecord::decode(
                    &archive::encode(&file).unwrap(),
                    record.slot(),
                    &marker.scheme_id,
                )
                .unwrap(),
            );
        }
        if fail == Some(true) {
            return Err(ProviderError::Invalid {
                field: "test publication after commit",
            });
        }
        Ok(digest)
    }

    fn status(&mut self) -> Result<SlotStatus, ProviderError> {
        self.status_calls += 1;
        if let Some(error) = self.status_error {
            return Err(error);
        }
        if self.move_head.load(Ordering::SeqCst) {
            if let Some(moved) = &self.moved_status {
                return Ok(moved.clone());
            }
        }
        if self.status_unavailable_at == Some(self.status_calls) {
            return Err(ProviderError::Unavailable(
                crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Locked,
            ));
        }
        if let Some((at, replacement)) = &self.status_replacement {
            if self.status_calls == *at {
                return Ok(replacement.clone());
            }
        }
        if self.unavailable {
            return Err(ProviderError::Unavailable(
                crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Locked,
            ));
        }
        Ok(self.status.clone())
    }
    fn lookup(
        &mut self,
        operation_id: &[u8; 32],
    ) -> Result<Lookup<KagemushaWalletCompletionRecordV1>, ProviderError> {
        if self.unavailable {
            return Err(ProviderError::Unavailable(
                crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Locked,
            ));
        }
        if self.delivery_lost {
            return Ok(Lookup::DeliveryDataLoss);
        }
        Ok(if let Some(retained) = self.retained.get(operation_id) {
            Lookup::Retained(Box::new(retained.clone()))
        } else if let Some(tombstone) = self.tombstones.get(operation_id) {
            Lookup::Archived(Box::new(*tombstone))
        } else if let Some(request) = self
            .pending
            .as_ref()
            .filter(|r| r.operation_id == *operation_id)
        {
            Lookup::SelectedUnsigned {
                capsule_digest: request.capsule.custody_digest(),
            }
        } else {
            Lookup::Unknown
        })
    }
    fn advance(
        &mut self,
        owner: &TransitionOwner,
        request: &AdvanceRequest<KagemushaWalletRecoveryCapsuleV1>,
    ) -> Result<AdvanceOutcome<KagemushaWalletCompletionRecordV1>, ProviderError> {
        let capsule = &request.capsule;
        let digest = capsule.custody_digest();
        if let Some(retained) = self.retained.get(&request.operation_id) {
            if retained.capsule_digest != digest {
                return Err(ProviderError::Invalid {
                    field: "operation conflict",
                });
            }
            return Ok(AdvanceOutcome::Released {
                retained: Box::new(retained.clone()),
                resumed: true,
            });
        }
        if self.pause {
            self.pending = Some(request.clone());
            let mut marker = enrollment();
            marker.generation = capsule.body().statement.sequence * 2 + 1;
            marker.state = capsule.head_marker_state();
            self.status = SlotStatus::Pending(marker_record(marker, [0; 32]));
            return Ok(AdvanceOutcome::Pending {
                operation_id: request.operation_id,
            });
        }
        let body = owner.receipt_body(capsule, &digest)?;
        let signing = signer(&credential());
        let message =
            kagemusha_wallet_signing_message_v1(KagemushaWalletSigningDomainV1::Receipt, &body);
        let signature: Signature = signing.sign(&message);
        let signature = signature.normalize_s().unwrap_or(signature);
        let signature =
            KagemushaDeviceSignatureV1::from_raw_bytes(&signature.to_bytes()).expect("signature");
        self.signatures += 1;
        let record = owner.assemble(capsule, &digest, &signature)?;
        let retained = Retained {
            operation_id: capsule.body().operation_id,
            capsule_digest: digest,
            selected_generation: capsule.body().statement.sequence * 2 + 1,
            completion_digest: record.completion_digest().expect("digest"),
            frame: record.to_canonical_bytes().expect("frame"),
            record,
        };
        let mut marker = enrollment();
        marker.generation = capsule.body().statement.sequence * 2 + 2;
        marker.state = capsule.head_marker_state();
        self.status = SlotStatus::Released(marker_record(marker, retained.completion_digest));
        self.retained
            .insert(capsule.body().operation_id, retained.clone());
        self.pending = None;
        Ok(AdvanceOutcome::Released {
            retained: Box::new(retained),
            resumed: false,
        })
    }
}

#[derive(Clone, Default)]
pub(super) struct TestProofs {
    verifies: Arc<AtomicUsize>,
    folds: Arc<AtomicUsize>,
    reject: bool,
    burn: bool,
    checkpoint_bytes: u32,
    checkpoint_stages: u8,
    ledger_scope: Option<(KagemushaWalletSchemeV1, String)>,
    preparations: Arc<AtomicUsize>,
    preparation_proofs: Arc<AtomicUsize>,
    // Mock native derivations: plans, validations and commits with a prepared plan.
    validations: Arc<AtomicUsize>,
    derivations: Arc<AtomicUsize>,
    proof_origins: Arc<Mutex<Vec<lifecycle::TestOriginV1>>>,
    prove_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    fail_preparation_proof: bool,
    fail_preparation_plan: bool,
    fail_preparation_validation: bool,
    fail_commit_derivation: bool,
    preparation_payload: Vec<u8>,
    advance_checks: Arc<AtomicUsize>,
    capsule_writes: Option<Arc<AtomicUsize>>,
    expire_during_publication: bool,
    fold_pause: Option<Arc<folding_preemption_tests::Pause>>,
    pub(super) capacity: crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeCapacityV1,
    // D6b with mock proof work: the marker each sub-proof leaves and what each locked
    // prepare was handed. The marker carries no proof state; it only shows slot ownership.
    retention: Arc<Mutex<TestRetention>>,
}

/// The mock's retained marker: which sub-proof left it and how many checkpoints it saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TestRetainedV1 {
    pub(super) mark: usize,
    pub(super) sequence: u128,
    pub(super) checkpoints: usize,
}

#[derive(Default)]
pub(super) struct TestRetention {
    marks: usize,
    /// For every mock `fold_prepare`, the marker it was handed, if any.
    pub(super) handed: Vec<Option<TestRetainedV1>>,
    /// Every marker a mock proof left, in order.
    pub(super) left: Vec<TestRetainedV1>,
}

impl TestProofs {
    /// The marker the last locked prepare was handed.
    pub(super) fn last_handed(&self) -> Option<TestRetainedV1> {
        self.retention
            .lock()
            .expect("retention log")
            .handed
            .last()
            .copied()
            .flatten()
    }
    /// The marker the last mock proof left.
    pub(super) fn last_left(&self) -> TestRetainedV1 {
        *self
            .retention
            .lock()
            .expect("retention log")
            .left
            .last()
            .expect("a retained marker")
    }
}

mod fold_retention_tests;
mod folding_preemption_tests;
mod storage_counters;
mod verification_baseline_tests;

#[path = "lifecycle/delivery_tests.rs"]
mod bound_delivery;
#[path = "lifecycle/projection_tests.rs"]
mod credit_projection;
#[path = "lifecycle/tests.rs"]
mod lifecycle;
#[path = "transition_custody/tests.rs"]
mod transition_custody_tests;
impl NativeProofs for TestProofs {
    type AdvanceCheck = usize;
    fn verify_credited(
        &self,
        credited: &KagemushaWalletCreditedV1,
        request: &KagemushaWalletRequestV1,
        payment: &KagemushaWalletPaymentV1,
    ) -> Result<(), Error> {
        // Explicit host probe only; never installed monetary proof authority.
        if self.reject {
            return Err(Error::Proof("mock Credited proof refusal"));
        }
        valid(credited.verify_for(&self.ledger_scope()?.0, request, payment)).map(|_| ())
    }
    fn enrollment_certificates(
        &self,
        credential: &KagemushaWalletCredentialV1,
    ) -> Result<Vec<u8>, Error> {
        let certificate = enrollment_issuer(credential);
        if certificate.certificate_digest() != credential.body.issuer_certificate {
            return Err(Error::Invalid("test enrollment issuer"));
        }
        archive::encode(&KagemushaWalletCertificateSetV1::new(vec![certificate]).unwrap())
    }
    fn ledger_scope(&self) -> Result<(KagemushaWalletSchemeV1, String), Error> {
        Ok(self.ledger_scope.clone().unwrap_or_else(|| {
            (
                fixture("KagemushaWalletSchemeV1"),
                "wallet-test-chain".into(),
            )
        }))
    }

    fn runtime_capacity(
        &self,
    ) -> Result<crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeCapacityV1, Error> {
        Ok(self.capacity)
    }

    fn fold_schedule(
        &self,
        _witness: &ReleasedStep,
        _predecessor: Option<&KagemushaWalletFoldRecordV1>,
        _custody: Option<&mut FoldCustodyV1<'_>>,
    ) -> Result<Vec<CheckpointLayout>, Error> {
        Ok((0..self.checkpoint_stages.max(1))
            .map(|stage| CheckpointLayout {
                artifact_digest: field(99 + stage),
                payload_bytes: if self.checkpoint_bytes == 0 {
                    3
                } else {
                    self.checkpoint_bytes
                },
            })
            .collect())
    }

    fn verify_transition(
        &self,
        next: &FrozenTransition,
        previous: Option<&ReleasedStep>,
        _folded: Option<&KagemushaWalletFoldRecordV1>,
        custody: &mut TransitionCustodyV1<'_>,
    ) -> Result<Self::AdvanceCheck, Error> {
        if self.reject {
            return Err(Error::Proof("test rejection"));
        }
        if custody.prepared().is_some() {
            // The native owner derives again from the durable plan here.
            self.derivations.fetch_add(1, Ordering::SeqCst);
            if self.fail_commit_derivation {
                return Err(Error::Proof("injected commit derivation refusal"));
            }
        }
        if let Some(previous) = previous {
            assert_eq!(
                next.capsule.body().statement.predecessor,
                previous.frozen.capsule.body().statement.successor
            );
        }
        Ok(self
            .capsule_writes
            .as_ref()
            .map_or(0, |count| count.load(Ordering::SeqCst)))
    }
    fn check_advance(&self, before: Self::AdvanceCheck) -> Result<(), Error> {
        self.advance_checks.fetch_add(1, Ordering::SeqCst);
        if self.expire_during_publication {
            let now = self
                .capsule_writes
                .as_ref()
                .expect("test clock")
                .load(Ordering::SeqCst);
            assert!(
                now > before,
                "freshness must follow the final durable capsule write"
            );
            return Err(Error::Invalid("test controls expired during publication"));
        }
        Ok(())
    }
    fn verify_lineage(
        &self,
        lineage: &KagemushaWalletLineageV1,
        cancellation: Option<&Cancellation>,
    ) -> Result<(), Error> {
        if let Some(token) = cancellation {
            token.check()?;
        }
        self.verifies.fetch_add(1, Ordering::SeqCst);
        if self.reject || lineage.proof != [1, 2, 3] {
            return Err(Error::Proof("mock proof identity"));
        }
        Ok(())
    }
    fn fold_prepare(
        &self,
        witness: &ReleasedStep,
        predecessor: Option<&KagemushaWalletFoldRecordV1>,
        checkpoints: Vec<PrivateArchiveBytes>,
        _custody: Option<&mut FoldCustodyV1<'_>>,
        retained: Option<FoldRetentionV1>,
        cancellation: &Cancellation,
    ) -> Result<Box<dyn NativeFoldJobV1>, Error> {
        cancellation.check()?;
        self.folds.fetch_add(1, Ordering::SeqCst);
        // Only this mock's own marker is recognized; it decides nothing.
        let handed = retained.and_then(FoldRetentionV1::downcast::<TestRetainedV1>);
        self.retention
            .lock()
            .expect("retention log")
            .handed
            .push(handed);
        Ok(Box::new(TestFoldJob {
            proofs: self.clone(),
            witness: witness.clone(),
            predecessor: predecessor.cloned(),
            checkpoints,
        }))
    }
}

/// Explicit mock proof work of one prepared sub-proof; it holds no custody handle.
struct TestFoldJob {
    proofs: TestProofs,
    witness: ReleasedStep,
    predecessor: Option<KagemushaWalletFoldRecordV1>,
    checkpoints: Vec<PrivateArchiveBytes>,
}
impl NativeFoldJobV1 for TestFoldJob {
    fn prove(
        self: Box<Self>,
        cancellation: &Cancellation,
    ) -> Result<(FoldProgress, Option<FoldRetentionV1>), Error> {
        let Self {
            proofs,
            witness,
            predecessor,
            checkpoints,
        } = *self;
        let checkpoints = checkpoints.as_slice();
        let predecessor = predecessor.as_ref();
        cancellation.check()?;
        if let Some(pause) = &proofs.fold_pause {
            pause.run(checkpoints, cancellation)?;
        }
        let original = |stage: usize| {
            if proofs.checkpoint_bytes == 0 {
                vec![9, 8, 7 - u8::try_from(stage).expect("test stage")]
            } else {
                vec![9; usize::try_from(proofs.checkpoint_bytes).expect("layout")]
            }
        };
        let stages = usize::from(proofs.checkpoint_stages.max(1));
        assert!(checkpoints.len() <= stages);
        for (stage, original_bytes) in checkpoints.iter().enumerate() {
            assert_eq!(
                original_bytes.as_slice(),
                original(stage).as_slice(),
                "all original source checkpoints"
            );
        }
        if checkpoints.len() < stages {
            let left = {
                let mut retention = proofs.retention.lock().expect("retention log");
                retention.marks += 1;
                let left = TestRetainedV1 {
                    mark: retention.marks,
                    sequence: witness.frozen.capsule.body().statement.sequence,
                    checkpoints: checkpoints.len(),
                };
                retention.left.push(left);
                left
            };
            return Ok((
                FoldProgress::Checkpoint(PrivateArchiveBytes::copy_from(&original(
                    checkpoints.len(),
                ))?),
                Some(FoldRetentionV1::new(left)),
            ));
        }
        let c = &witness.frozen.capsule;
        let mut tree = KagemushaWalletIndexedTreeV1::new();
        if let KagemushaWalletEffectV1::Receive { credit_id, .. } = c.body().statement.effect {
            // Tests use one Receive. Native production proofs must handle the complete map.
            KagemushaWalletCreditDigestLeafV1 {
                credit_id,
                payment_digest: c.body().payment_digest,
                burned: proofs.burn,
            }
            .record(&mut tree)
            .expect("credit");
        }
        let credit_root = if matches!(
            c.body().statement.effect,
            KagemushaWalletEffectV1::Receive { .. }
        ) {
            tree.root()
        } else {
            predecessor.map_or(tree.root(), |pred| pred.lineage.public.credit_digest_root)
        };
        Ok((
            FoldProgress::Complete {
                lineage: KagemushaWalletLineageV1 {
                    public: KagemushaWalletLineagePublicV1 {
                        version: 1,
                        scheme_id: c.body().scheme_id,
                        relation_id: c.body().statement.relation_id,
                        head: c.body().statement.successor,
                        wallet_id: c.body().wallet_id,
                        credential_digest: c.body().statement.credential_digest,
                        payment_key: witness.frozen.credential.body.payment_key,
                        lifecycle: c.body().statement.lifecycle,
                        policy_epoch: c.body().successor_state.core.policy_epoch,
                        enabled_controls: c.body().successor_state.core.enabled_controls,
                        burned_total: c.body().successor_state.core.burned_total,
                        pending_outgoing_root: c.body().successor_state.core.pending_outgoing_root,
                        credit_digest_root: credit_root,
                    },
                    proof: vec![1, 2, 3],
                },
                burned: proofs.burn && c.body().kind == KagemushaWalletOperationKindV1::Receive,
            },
            None,
        ))
    }
}

pub(super) type Wallet = Coordinator<TestCustody, MemoryArchive, TestProofs>;
/// Synthetic already-indexed head for testing payout metadata publication, not a monetary
/// transition or a native lineage proof. Finality is verified independently by the caller.
pub(super) fn synthetic_payout_wallet(scheme: KagemushaWalletSchemeV1, chain: String) -> Wallet {
    let mut custody = TestCustody::new();
    let mut marker = enrollment();
    marker.scheme_id = scheme.scheme_id();
    marker.generation = 2;
    marker.state = bootstrap().capsule.head_marker_state();
    custody.status = SlotStatus::Released(marker_record(marker.clone(), field(73)));
    let mut archive = MemoryArchive::new();
    archive.scheme = scheme.scheme_id();
    let manifest = manifest::Manifest {
        scheme_id: scheme.scheme_id(),
        wallet_id: marker.wallet_id,
        indexed: Some(0),
        capsule: custody.status.marker().unwrap().head().unwrap().2,
        steps: IndexRoot::default(),
        credits: IndexRoot::default(),
        outgoing: IndexRoot::default(),
        folds: IndexRoot::default(),
        claims: IndexRoot::default(),
        preparations: IndexRoot::default(),
        blacklist: None,
        capsule_plans: IndexRoot::default(),
        capsule_sources: IndexRoot::default(),
        issued_requests: IndexRoot::default(),
        sessions: IndexRoot::default(),
        activation: None,
        close_loads: IndexRoot::default(),
        ledger_checkpoint: None,
        ledger_retired: None,
        finality_epochs: IndexRoot::default(),
        finality_epoch: None,
        ledger_load_plans: IndexRoot::default(),
        ledger_load_ordinals: IndexRoot::default(),
        ledger_unload_confirmations: IndexRoot::default(),
        ledger_unload_proofs: IndexRoot::default(),
        ledger_unload_retired: None,
        direct_anchors: IndexRoot::default(),
        fold_pending: IndexRoot::default(),
        folded: None,
        checkpoint_count: 0,
        checkpoint_digest: [0; 32],
        credit_tree: credit_tree::CreditTree::default(),
        collection: None,
    };
    custody
        .publish_archive_checkpoint([0; 32], &archive::encode(&manifest).unwrap())
        .unwrap();
    Coordinator::new(
        custody,
        archive,
        TestProofs {
            ledger_scope: Some((scheme.clone(), chain)),
            ..TestProofs::default()
        },
        scheme.scheme_id(),
        marker.wallet_id,
    )
    .unwrap()
}
pub(super) fn wallet() -> Wallet {
    let c = credential();
    Coordinator::new(
        TestCustody::new(),
        MemoryArchive::new(),
        TestProofs::default(),
        c.body.scheme_id,
        c.body.wallet_id,
    )
    .expect("wallet")
}

#[test]
fn completion_retry_and_pending_resume_use_exact_receipt_bytes() {
    let mut w = wallet();
    let boot = bootstrap();
    w.custody.pause = true;
    assert_eq!(w.commit(boot.clone()).expect("commit"), Completion::Pending);
    assert_eq!(
        w.retry(&boot.capsule.body().operation_id).expect("retry"),
        Some(Completion::Pending)
    );
    assert_eq!(w.custody.signatures, 0);
    w.custody.pause = false;
    let complete = w.resume().expect("resume").expect("pending");
    assert!(matches!(complete, Completion::Complete(_)));
    assert_eq!(
        w.retry(&boot.capsule.body().operation_id).expect("retry"),
        Some(complete.clone())
    );
    assert_eq!(w.commit(boot.clone()).expect("same inputs"), complete);
    assert_eq!(w.custody.signatures, 1);
    assert_eq!(w.released_steps().expect("steps").len(), 1);
    let mut changed = boot;
    let mut body = changed.capsule.body().clone();
    body.step_proof.bytes.push(9);
    body.output = KagemushaWalletOutputDescriptorV1::for_transition(
        &body.statement,
        &body.proof_digest().expect("proof"),
        &body.payment_digest,
    )
    .expect("output");
    changed.capsule = seal_body(body);
    assert!(w.commit(changed).is_err());
    assert_eq!(w.custody.signatures, 1);
}

#[test]
fn local_blacklist_install_waits_for_a_pending_operation_and_never_changes_its_resume() {
    let list: KagemushaWalletBlacklistV1 = fixture("KagemushaWalletBlacklistV1");
    let original = list.to_canonical_bytes().expect("list");
    let certificates = archive::encode(
        &KagemushaWalletCertificateSetV1::new(vec![fixture("KagemushaWalletSignerCertificateV1")])
            .expect("certificate set"),
    )
    .expect("certificates");
    let mut w = wallet();
    let boot = bootstrap();
    w.commit(boot.clone()).expect("boot");
    let receive = frozen(
        Some(&boot),
        KagemushaWalletEffectV1::Receive {
            credit_id: field(101),
            payer_wallet_id: [0x88; 32],
            amount: 1,
        },
    );
    w.custody.pause = true;
    assert_eq!(
        w.commit(receive.clone()).expect("pending"),
        Completion::Pending
    );
    // A list is never selected beside an unfinished Advance.
    assert!(matches!(
        w.install_blacklist(&original, &certificates),
        Err(Error::Pending)
    ));
    w.custody.pause = false;
    let complete = w.resume().expect("resume").expect("pending");
    assert!(matches!(complete, Completion::Complete(_)));
    assert_eq!(
        w.install_blacklist(&original, &certificates)
            .expect("install"),
        Completion::Complete(list.blacklist_digest().to_vec())
    );
    assert_eq!(
        w.retry(&receive.capsule.body().operation_id)
            .expect("retry"),
        Some(complete)
    );
    assert_eq!(w.local_blacklist().expect("local list"), Some(list));
    assert_eq!(w.custody.signatures, 2);
}

#[test]
fn rejected_native_proof_never_reaches_advance_or_archive() {
    let mut w = wallet();
    w.proofs.reject = true;
    assert!(matches!(w.commit(bootstrap()), Err(Error::Proof(_))));
    assert_eq!(w.custody.signatures, 0);
    assert!(w.archive.keys().expect("keys").is_empty());
}

#[test]
fn checkpoint_restart_credit_status_and_duplicate_receive_preserve_first_digest() {
    for burn in [false, true] {
        let mut w = wallet();
        w.proofs.burn = burn;
        let boot = bootstrap();
        w.commit(boot.clone()).expect("bootstrap");
        assert_eq!(w.fold_once().expect("inactive"), FoldStatus::Idle);
        w.scheduler().set_activity(true, false);
        assert_eq!(
            w.fold_once().expect("checkpoint"),
            FoldStatus::Checkpoint {
                sequence: 0,
                ordinal: 0
            }
        );
        let (custody, archive, proofs, scheme, wallet) =
            (w.custody, w.archive, w.proofs, w.scheme_id, w.wallet_id);
        let mut w = Coordinator::new(custody, archive, proofs, scheme, wallet).expect("restart");
        w.scheduler().set_activity(false, true);
        assert_eq!(w.fold_once().expect("fold"), FoldStatus::Folded(0));
        let verifies = w.proofs.verifies.load(Ordering::SeqCst);
        assert_eq!(w.fold_once().expect("done"), FoldStatus::CaughtUp);
        assert_eq!(
            w.proofs.verifies.load(Ordering::SeqCst),
            verifies,
            "recorded Ω is reused"
        );
        let receive = frozen(
            Some(&boot),
            KagemushaWalletEffectV1::Receive {
                credit_id: received_credit(),
                payer_wallet_id: [0x88; 32],
                amount: fixture::<KagemushaWalletPaymentV1>("KagemushaWalletPaymentV1")
                    .signed_request()
                    .unwrap()
                    .body
                    .amount,
            },
        );
        let exact = w.commit(receive.clone()).expect("Receive");
        assert_eq!(
            w.consumed_credit(&received_credit(), &received_payment())
                .expect("credit")
                .expect("present")
                .amount,
            fixture::<KagemushaWalletPaymentV1>("KagemushaWalletPaymentV1")
                .signed_request()
                .unwrap()
                .body
                .amount
        );
        assert!(matches!(
            w.credit_status(&received_credit(), &received_payment()),
            Err(Error::FoldRequired)
        ));
        let signatures = w.custody.signatures;
        assert_eq!(w.commit(receive.clone()).expect("duplicate"), exact);
        assert_eq!(w.custody.signatures, signatures);
        assert!(matches!(
            w.consumed_credit(&received_credit(), &field(73)),
            Err(Error::CreditConflict)
        ));
        assert!(matches!(
            w.fold_once().expect("checkpoint"),
            FoldStatus::Checkpoint { sequence: 1, .. }
        ));
        assert_eq!(w.fold_once().expect("fold receive"), FoldStatus::Folded(1));
        let status = w
            .credit_status(&received_credit(), &received_payment())
            .expect("CreditStatus");
        assert_eq!(status.opening.burned, burn);
        assert_eq!(status.opening.payment_digest, received_payment());
        status.validate().expect("native receipt and opening");
        let record = w
            .archive
            .get(ArchiveKey::Fold(1), 20_000)
            .expect("record")
            .expect("present");
        assert!(
            w.archive
                .put(ArchiveKey::Fold(1), b"replacement proof")
                .is_err()
        );
        assert_eq!(
            w.archive.get(ArchiveKey::Fold(1), 20_000).expect("record"),
            Some(record)
        );
        w.archive
            .records
            .lock()
            .expect("records")
            .remove(&ArchiveKey::Fold(1));
        // A caught-up wake reads no recorded Ω; every folded-state read refuses the loss.
        assert_eq!(w.fold_once().expect("caught-up wake"), FoldStatus::CaughtUp);
        assert!(matches!(w.snapshot(), Err(Error::WitnessLost(_))));
        assert!(matches!(
            w.credit_status(&received_credit(), &received_payment()),
            Err(Error::WitnessLost(_))
        ));
    }
}

#[test]
fn missing_marker_bound_witness_is_loss_and_archive_cannot_invent_completion() {
    let mut w = wallet();
    let boot = bootstrap();
    w.archive
        .put(
            ArchiveKey::Capsule(boot.capsule.custody_digest()),
            &archive::encode(&boot).expect("encode"),
        )
        .expect("staging");
    assert!(
        w.retry(&boot.capsule.body().operation_id)
            .expect("retry")
            .is_none()
    );
    let exact = w.commit(boot.clone()).expect("commit");
    assert!(matches!(&exact, Completion::Complete(_)));
    let signatures = w.custody.signatures;
    // Losing W prevents reconstruction, but the authenticated StepEntry still
    // binds the exact retained completion without requiring its private opening.
    assert!(
        w.archive
            .records
            .lock()
            .expect("records")
            .remove(&ArchiveKey::Capsule(boot.capsule.custody_digest()))
            .is_some()
    );
    assert!(matches!(w.released_steps(), Err(Error::WitnessLost(_))));
    assert_eq!(
        w.retry(&boot.capsule.body().operation_id)
            .expect("exact authority"),
        Some(exact)
    );
    // Losing the authenticated index as well cannot promote archive contents
    // or an unauthenticated retained record into a completed operation.
    w.archive.records.lock().expect("records").clear();
    assert!(matches!(
        w.retry(&boot.capsule.body().operation_id),
        Err(Error::WitnessLost(_))
    ));
    assert_eq!(w.custody.signatures, signatures);
}

#[test]
fn cancelled_fold_restoration_never_populates_the_verification_cache() {
    let mut w = wallet();
    w.commit(bootstrap()).expect("commit");
    let scheduler = w.scheduler();
    scheduler.set_activity(true, false);
    w.fold_once().expect("checkpoint");
    w.fold_once().expect("fold");
    let step = w.released_steps().expect("steps").remove(0);
    w.verified_folds.clear();
    let before = w.proofs.verifies.load(Ordering::SeqCst);
    let running = scheduler.start().expect("background permit");
    scheduler.set_activity(false, false);
    assert!(matches!(
        w.read_fold_cancellable(&step, Some(&running.token)),
        Err(Error::Cancelled)
    ));
    assert!(w.verified_folds.is_empty());
    assert_eq!(w.proofs.verifies.load(Ordering::SeqCst), before);
    drop(running);
    assert!(w.read_fold(&step).expect("fresh read").is_some());
    assert_eq!(w.proofs.verifies.load(Ordering::SeqCst), before + 1);
}

#[test]
fn whole_lineage_bytes_are_required_for_session_reuse() {
    let mut w = wallet();
    w.commit(bootstrap()).expect("commit");
    w.scheduler().set_activity(true, false);
    w.fold_once().expect("checkpoint");
    w.fold_once().expect("fold");
    let step = w.released_steps().expect("steps").remove(0);
    let mut lineage = w
        .read_fold(&step)
        .expect("fold")
        .expect("present")
        .record
        .lineage;
    let mut cache = LineageCache::default();
    assert!(!cache.verify(&w.proofs, &lineage).expect("verify"));
    assert!(cache.verify(&w.proofs, &lineage).expect("reuse"));
    let before = w.proofs.verifies.load(Ordering::SeqCst);
    lineage.public.policy_epoch += 1;
    assert!(
        !cache
            .verify(&w.proofs, &lineage)
            .expect("public bytes differ")
    );
    assert_eq!(w.proofs.verifies.load(Ordering::SeqCst), before + 1);
    lineage.proof[0] ^= 1;
    assert!(cache.verify(&w.proofs, &lineage).is_err());
}

#[test]
fn payment_preempts_fold_and_frees_memory_before_admission() {
    let scheduler = Scheduler::new();
    scheduler.set_activity(true, false);
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let dropped = Arc::new(AtomicUsize::new(0));
    let worker = scheduler.clone();
    let freed = dropped.clone();
    let join = std::thread::spawn(move || {
        let guard = worker.start().expect("fold permit");
        struct Workspace(Arc<AtomicUsize>, Vec<u8>);
        impl Drop for Workspace {
            fn drop(&mut self) {
                self.0.store(self.1.len(), Ordering::SeqCst);
            }
        }
        let _workspace = Workspace(freed, vec![0; 1024]);
        started_tx.send(()).expect("started");
        while guard.token.check().is_ok() {
            std::thread::yield_now();
        }
    });
    started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker");
    let payment = scheduler.payment();
    assert_eq!(dropped.load(Ordering::SeqCst), 1024);
    assert!(scheduler.start().is_none());
    drop(payment);
    join.join().expect("worker");
    assert!(scheduler.start().is_some());
    scheduler.set_activity(false, false);
    assert!(scheduler.start().is_none());
}

fn prepared_fs() -> (SimFs, Dir) {
    let fs = SimFs::new();
    let mut directory = Dir::root();
    for component in ["slots", &hex::encode([0x55; 32]), "archive"] {
        fs.mkdir(&directory, component).expect("mkdir");
        fs.sync_dir(&directory).expect("sync parent");
        directory = directory.child(&Name::new(component).expect("name"));
    }
    (fs, directory)
}

#[test]
fn fs_archive_is_canonical_bound_redundant_and_immutable() {
    let (fs, directory) = prepared_fs();
    let c = credential();
    let mut store = FsArchive::new(
        fs.clone(),
        Slot([0x55; 32]),
        c.body.scheme_id,
        c.body.wallet_id,
    )
    .expect("archive");
    let key = ArchiveKey::Checkpoint {
        sequence: 9,
        ordinal: 2,
    };
    assert!(store.get(key, 100).expect("absent").is_none());
    store.put(key, b"proof checkpoint").expect("put");
    fs.power_loss(PowerLoss::DropUnsynced);
    assert_eq!(
        store.get(key, 100).expect("get").as_deref(),
        Some(b"proof checkpoint".as_slice())
    );
    assert_eq!(store.keys().expect("keys"), [key]);
    assert!(store.put(key, b"different proof").is_err());
    let primary = fs
        .visible_names(&directory)
        .into_iter()
        .find(|name| name.ends_with(".arc"))
        .expect("primary");
    fs.unlink(&directory, &primary).expect("remove first copy");
    fs.sync_dir(&directory).expect("sync");
    assert_eq!(
        store.get(key, 100).expect("replica").as_deref(),
        Some(b"proof checkpoint".as_slice())
    );
    store.put(key, b"proof checkpoint").expect("repair");
    let mut other = FsArchive::new(fs.clone(), Slot([0x55; 32]), c.body.scheme_id, [0x99; 32])
        .expect("other archive");
    assert!(other.get(key, 100).is_err());
    fs.inject(fs.steps(), Fault::Error);
    assert!(
        store.keys().is_err(),
        "list error must not read as no checkpoints"
    );
}

#[test]
fn every_archive_write_crash_resumes_only_identical_bytes() {
    let (base, _) = prepared_fs();
    let c = credential();
    let probe = base.fork();
    let mut store = FsArchive::new(
        probe.clone(),
        Slot([0x55; 32]),
        c.body.scheme_id,
        c.body.wallet_id,
    )
    .expect("archive");
    let from = probe.steps();
    store
        .put(ArchiveKey::Fold(2), b"exact recorded proof")
        .expect("probe");
    let count = probe.steps() - from;
    for offset in 0..count {
        let fs = base.fork();
        let mut store = FsArchive::new(
            fs.clone(),
            Slot([0x55; 32]),
            c.body.scheme_id,
            c.body.wallet_id,
        )
        .expect("archive");
        fs.inject(fs.steps() + offset, Fault::CrashAfter);
        let _ = store.put(ArchiveKey::Fold(2), b"exact recorded proof");
        fs.power_loss(PowerLoss::DropUnsynced);
        store
            .put(ArchiveKey::Fold(2), b"exact recorded proof")
            .expect("resume identical");
        fs.power_loss(PowerLoss::DropUnsynced);
        assert_eq!(
            store
                .get(ArchiveKey::Fold(2), 20_000)
                .expect("read")
                .as_deref(),
            Some(b"exact recorded proof".as_slice())
        );
    }
}

#[test]
fn checkpoint_binding_gap_and_interrupted_fold_publication_fail_closed() {
    let mut w = wallet();
    w.commit(bootstrap()).expect("commit");
    w.scheduler().set_activity(true, false);
    w.fold_once().expect("checkpoint");
    let key = ArchiveKey::Checkpoint {
        sequence: 0,
        ordinal: 0,
    };
    let original = w
        .archive
        .get(key, 20_000)
        .expect("get")
        .expect("checkpoint");
    let mut wrong: Checkpoint = archive::decode(&original).expect("decode");
    wrong.capsule_digest[0] ^= 1;
    w.archive
        .records
        .lock()
        .expect("records")
        .insert(key, archive::encode(&wrong).expect("encode"));
    assert!(matches!(w.fold_once(), Err(Error::WitnessLost(_))));
    {
        let mut records = w.archive.records.lock().expect("records");
        records.remove(&key);
        records.insert(
            ArchiveKey::Checkpoint {
                sequence: 0,
                ordinal: 1,
            },
            original.as_slice().to_vec(),
        );
    }
    assert!(matches!(w.fold_once(), Err(Error::WitnessLost(_))));
    {
        let mut records = w.archive.records.lock().expect("records");
        records.remove(&ArchiveKey::Checkpoint {
            sequence: 0,
            ordinal: 1,
        });
        records.insert(key, original.as_slice().to_vec());
    }
    let prior_checkpoint = w.custody.checkpoint.clone();
    assert_eq!(w.fold_once().expect("fold"), FoldStatus::Folded(0));
    let folds = w.proofs.folds.load(Ordering::SeqCst);
    let before = w.archive.get(ArchiveKey::Fold(0), 20_000).expect("get");
    // Simulate publication interrupted after exact Ω bytes, before the source manifest.
    w.custody.checkpoint = prior_checkpoint;
    w.verified_folds.clear();
    assert_eq!(
        w.fold_once().expect("adopt publication"),
        FoldStatus::Folded(0)
    );
    assert_eq!(
        w.proofs.folds.load(Ordering::SeqCst),
        folds,
        "no replacement proof"
    );
    assert_eq!(
        w.archive.get(ArchiveKey::Fold(0), 20_000).expect("get"),
        before
    );
    assert_eq!(w.manifest().expect("source manifest").1.folded, Some(0));
}

#[test]
fn native_decide_failure_does_not_record_a_fold() {
    let mut w = wallet();
    w.commit(bootstrap()).expect("commit");
    w.scheduler().set_activity(true, false);
    w.fold_once().expect("checkpoint");
    w.proofs.reject = true;
    assert!(matches!(w.fold_once(), Err(Error::Proof(_))));
    assert!(
        w.archive
            .get(ArchiveKey::Fold(0), 20_000)
            .expect("record")
            .is_none()
    );
    assert_eq!(w.manifest().expect("source manifest").1.folded, None);
}

#[test]
fn archive_binding_rejects_mixing_wallets_before_work() {
    let c = credential();
    let mut archive = MemoryArchive::new();
    archive.wallet[0] ^= 1;
    assert!(matches!(
        Coordinator::new(
            TestCustody::new(),
            archive,
            TestProofs::default(),
            c.body.scheme_id,
            c.body.wallet_id
        ),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn send_requires_recorded_predecessor_and_owner_assembles_canonical_payment() {
    let mut w = wallet();
    let boot = bootstrap();
    w.commit(boot.clone()).expect("boot");
    let template: KagemushaWalletPaymentV1 = fixture("KagemushaWalletPaymentV1");
    let send = frozen(Some(&boot), template.send.statement.effect);
    assert!(matches!(w.commit(send.clone()), Err(Error::FoldRequired)));
    assert_eq!(w.custody.signatures, 1);
    let owner = TransitionOwner::new(&send.credential);
    let c = &send.capsule;
    let digest = c.custody_digest();
    let body = owner.receipt_body(c, &digest).expect("preflight");
    let signature: Signature = signer(&send.credential).sign(&kagemusha_wallet_signing_message_v1(
        KagemushaWalletSigningDomainV1::Receipt,
        &body,
    ));
    let signature = signature.normalize_s().unwrap_or(signature);
    let signature =
        KagemushaDeviceSignatureV1::from_raw_bytes(&signature.to_bytes()).expect("signature");
    let record = owner.assemble(c, &digest, &signature).expect("Payment");
    let payment = KagemushaWalletPaymentV1::decode_canonical(&record.output, &c.body().scheme_id)
        .expect("canonical Payment");
    assert_eq!(payment.send.statement, c.body().statement);
    assert_eq!(payment.send.step_proof, c.body().step_proof);
    assert_eq!(payment.send.receipt, record.receipt);
    record
        .verify(&send.credential, c)
        .expect("receipt and exact capsule binding");
    owner
        .require_completion(c, &record)
        .expect("full completion admission");
    for mutation in 0..4 {
        let mut changed = record.clone();
        match mutation {
            0 => changed.capsule_digest[0] ^= 1,
            1 => changed.receipt.capsule_commitment[0] ^= 1,
            2 => changed.output.push(0),
            _ => {
                let other: Signature = signer(&send.credential).sign(b"wrong receipt message");
                let other = other.normalize_s().unwrap_or(other);
                changed.receipt.signature =
                    KagemushaDeviceSignatureV1::from_raw_bytes(&other.to_bytes()).unwrap();
            }
        }
        assert!(
            owner.require_completion(c, &changed).is_err(),
            "completion mutation {mutation}"
        );
    }
    let mut opening = [0; 32];
    opening[0] = 1;
    let resealed = c.body().clone().freeze().unwrap().seal(opening).unwrap();
    let mut stale_public = record.clone();
    stale_public.capsule_digest = resealed.custody_digest();
    assert!(
        owner.require_completion(&resealed, &stale_public).is_err(),
        "changed private wrapper cannot retain the old signed public commitment"
    );
    let mut duplicate = c.body().clone();
    duplicate
        .retained_inputs
        .push(duplicate.retained_inputs[0].clone());
    let duplicate = seal_body(duplicate);
    assert!(
        owner
            .receipt_body(&duplicate, &duplicate.custody_digest())
            .is_err()
    );
    let mut oversized = c.body().clone();
    oversized.retained_inputs[0]
        .bytes
        .resize(KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 + 1, 0);
    let oversized = seal_body(oversized);
    assert!(
        owner
            .receipt_body(&oversized, &oversized.custody_digest())
            .is_err(),
        "Request message bound must be enforced before signing, not during fee indexing"
    );
}

#[test]
fn native_fold_receives_all_source_checkpoints_in_order_after_restart() {
    // Scheduler/custody contract only: the test owner never stands in for native proofs.
    let mut w = wallet();
    w.proofs.checkpoint_stages = 3;
    w.commit(bootstrap()).expect("commit");
    w.scheduler().set_activity(true, false);
    for ordinal in 0..3 {
        assert_eq!(
            w.fold_once().expect("one stage"),
            FoldStatus::Checkpoint {
                sequence: 0,
                ordinal
            }
        );
        // Drop the complete coordinator between every stage, so no in-memory source history
        // can replace the actual source-selected durable checkpoint chain.
        let (custody, archive, proofs, scheme, wallet) =
            (w.custody, w.archive, w.proofs, w.scheme_id, w.wallet_id);
        w = Coordinator::new(custody, archive, proofs, scheme, wallet).expect("restart");
        w.scheduler().set_activity(true, false);
    }
    assert_eq!(w.fold_once().expect("final fold"), FoldStatus::Folded(0));
    assert_eq!(w.proofs.folds.load(Ordering::SeqCst), 4);
}

#[test]
fn exact_authenticated_checkpoint_layout_accepts_large_real_stage_shapes() {
    let mut w = wallet();
    w.proofs.checkpoint_bytes = 10_528;
    w.commit(bootstrap()).expect("commit");
    w.scheduler().set_activity(true, false);
    assert!(matches!(
        w.fold_once().expect("descriptor-sized checkpoint"),
        FoldStatus::Checkpoint { .. }
    ));
    let key = ArchiveKey::Checkpoint {
        sequence: 0,
        ordinal: 0,
    };
    let saved = w
        .archive
        .get(key, 20_000)
        .expect("read")
        .expect("checkpoint");
    let mut checkpoint: Checkpoint = archive::decode(&saved).expect("decode");
    assert_eq!(checkpoint.proof.len(), 10_528);
    checkpoint.layout.artifact_digest[0] ^= 1;
    w.archive
        .records
        .lock()
        .expect("records")
        .insert(key, archive::encode(&checkpoint).expect("encode"));
    assert!(matches!(w.fold_once(), Err(Error::WitnessLost(_))));
    w.archive
        .records
        .lock()
        .expect("records")
        .insert(key, saved.as_slice().to_vec());
    assert_eq!(w.fold_once().expect("fold"), FoldStatus::Folded(0));
}

#[test]
fn source_manifest_detects_fold_pair_deletion_and_index_loss_after_restart() {
    for delete_index in [false, true] {
        let mut w = wallet();
        w.commit(bootstrap()).expect("boot");
        w.scheduler().set_activity(true, false);
        w.fold_once().expect("checkpoint");
        w.fold_once().expect("fold");
        if delete_index {
            let (_, manifest) = w.manifest().expect("manifest");
            w.archive
                .records
                .lock()
                .expect("records")
                .remove(&ArchiveKey::Object(manifest.folds.0));
        } else {
            let mut records = w.archive.records.lock().expect("records");
            records.remove(&ArchiveKey::Fold(0));
        }
        let (custody, archive, proofs, scheme, wallet) =
            (w.custody, w.archive, w.proofs, w.scheme_id, w.wallet_id);
        assert!(matches!(
            Coordinator::new(custody, archive, proofs, scheme, wallet),
            Err(Error::WitnessLost(_))
        ));
    }
}

#[test]
fn replay_reads_are_bounded_and_retry_never_converts_unavailable_to_unknown() {
    let mut w = wallet();
    let mut previous = bootstrap();
    w.commit(previous.clone()).expect("boot");
    let mut first = None;
    for number in 1u8..=48 {
        let next = frozen(
            Some(&previous),
            KagemushaWalletEffectV1::Receive {
                credit_id: field(number + 100),
                payer_wallet_id: [0x88; 32],
                amount: 1,
            },
        );
        let complete = w.commit(next.clone()).expect("receive");
        if first.is_none() {
            first = Some((next.clone(), complete));
        }
        previous = next;
    }
    let (first, exact) = first.expect("first");
    let KagemushaWalletEffectV1::Receive { credit_id, .. } = first.capsule.body().statement.effect
    else {
        panic!("receive")
    };
    let before = w.archive.reads.load(Ordering::SeqCst);
    assert!(
        w.consumed_credit(&credit_id, &first.capsule.body().payment_digest)
            .expect("index")
            .is_some()
    );
    assert!(
        w.archive.reads.load(Ordering::SeqCst) - before <= 257,
        "one bounded Patricia path"
    );
    let before_retry = w.archive.reads.load(Ordering::SeqCst);
    assert_eq!(
        w.retry(&first.capsule.body().operation_id).expect("exact"),
        Some(exact)
    );
    assert!(
        w.archive.reads.load(Ordering::SeqCst) - before_retry <= 260,
        "retry uses one authenticated step path, not a history scan"
    );
    assert_eq!(w.retry(&[0xa5; 32]).expect("unknown"), None);
    let signatures = w.custody.signatures;
    w.custody.unavailable = true;
    assert!(matches!(
        w.retry(&first.capsule.body().operation_id),
        Err(Error::Provider(ProviderError::Unavailable(_)))
    ));
    assert!(matches!(
        w.retry(&[0xa5; 32]),
        Err(Error::Provider(ProviderError::Unavailable(_)))
    ));
    w.custody.unavailable = false;
    w.custody.delivery_lost = true;
    assert_eq!(
        w.retry(&first.capsule.body().operation_id).expect("loss"),
        Some(Completion::DeliveryDataLoss)
    );
    assert_eq!(w.custody.signatures, signatures);
}

#[test]
fn collection_is_source_selected_bounded_restartable_and_keeps_credit_replay() {
    let mut w = wallet();
    w.scheduler().set_activity(true, false);
    let boot = bootstrap();
    w.commit(boot.clone()).unwrap();
    w.fold_once().unwrap();
    w.fold_once().unwrap();
    let mut receive = frozen(
        Some(&boot),
        KagemushaWalletEffectV1::Receive {
            credit_id: received_credit(),
            payer_wallet_id: [0x88; 32],
            amount: fixture::<KagemushaWalletPaymentV1>("KagemushaWalletPaymentV1")
                .signed_request()
                .unwrap()
                .body
                .amount,
        },
    );
    // Dispatcher intake also decodes credential/certificates. Replace the general
    // simulator's [1] placeholders with the genuine same-payer Offer originals.
    let payer = vectors()["envelopes"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|row| {
            let envelope: KagemushaWalletEnvelopeV1 =
                archive::decode(&hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap())
                    .unwrap();
            match envelope.message {
                KagemushaWalletMessageV1::Offer { offer } => Some(offer),
                _ => None,
            }
        })
        .unwrap();
    let payment: KagemushaWalletPaymentV1 = fixture("KagemushaWalletPaymentV1");
    assert_eq!(
        payer.payer_credential.credential_digest(),
        payment.send.statement.credential_digest
    );
    payer.verify(&fixture("KagemushaWalletSchemeV1")).unwrap();
    let mut body = receive.capsule.body().clone();
    for input in &mut body.retained_inputs {
        match input.role {
            KagemushaWalletRetainedInputRoleV1::Credential => {
                input.bytes = payer.payer_credential.to_canonical_bytes().unwrap()
            }
            KagemushaWalletRetainedInputRoleV1::CertificateSet => {
                input.bytes = archive::encode(&payer.certificates).unwrap()
            }
            _ => {}
        }
    }
    receive.capsule = seal_body(body);
    w.commit(receive.clone()).unwrap();
    let input = |role| {
        receive
            .capsule
            .body()
            .retained_inputs
            .iter()
            .find(|input| input.role == role)
            .unwrap()
            .bytes
            .clone()
    };
    let replay = OperationRequestV1 {
        request_id: [0x9b; 32],
        action: OperationActionV1::Receive {
            payment: input(KagemushaWalletRetainedInputRoleV1::Payment),
            payer_credential: input(KagemushaWalletRetainedInputRoleV1::Credential),
            certificates: input(KagemushaWalletRetainedInputRoleV1::CertificateSet),
        },
    };
    w.retain_collected_receive_test_request(replay.clone(), &receive)
        .unwrap();

    w.fold_once().unwrap();
    w.fold_once().unwrap();
    assert!(matches!(
        w.collect_retained_step(1),
        Err(Error::FoldRequired)
    ));
    let next = frozen(
        Some(&receive),
        KagemushaWalletEffectV1::Load {
            load_ordinal: 0,
            receipt_digest: field(99),
            amount: 1,
            online_charge: 0,
        },
    );
    w.commit(next.clone()).unwrap();
    w.fold_once().unwrap();
    w.fold_once().unwrap();
    let signatures = w.custody.signatures;
    w.scheduler().set_activity(false, false);
    assert_eq!(w.collect_retained_step(1).unwrap(), CollectionStatus::Idle);
    w.scheduler().set_activity(true, false);
    let payment = w.scheduler().payment();
    assert_eq!(w.collect_retained_step(1).unwrap(), CollectionStatus::Idle);
    drop(payment);
    assert!(matches!(
        w.collect_retained_step(2),
        Err(Error::FoldRequired)
    ));
    let covering = ArchiveKey::Fold(2);
    let exact_fold = w.archive.get(covering, 100_000).unwrap().unwrap();
    w.archive.remove(covering).unwrap();
    assert!(w.collect_retained_step(1).is_err(), "missing covering fold");
    let mut forged_fold = zeroize::Zeroizing::new(exact_fold.as_slice().to_vec());
    forged_fold[0] ^= 1;
    w.archive.put(covering, &forged_fold).unwrap();
    assert!(w.collect_retained_step(1).is_err(), "forged covering fold");
    w.archive.remove(covering).unwrap();
    w.archive.put(covering, &exact_fold).unwrap();
    let (_, unchanged) = w.manifest().unwrap();
    assert!(unchanged.collection.is_none());
    assert!(!w.step_entry(&unchanged, 1).unwrap().collected);
    w.custody.fail_publication = Some(false);
    assert!(w.collect_retained_step(1).is_err());
    let (_, manifest) = w.manifest().unwrap();
    assert!(!w.step_entry(&manifest, 1).unwrap().collected);
    assert!(manifest.collection.is_none());
    w.custody.fail_publication = Some(true);
    assert!(w.collect_retained_step(1).is_err());
    let (_, manifest) = w.manifest().unwrap();
    assert!(w.step_entry(&manifest, 1).unwrap().collected);
    assert!(manifest.collection.is_some());
    assert!(
        w.archive
            .get(
                ArchiveKey::Capsule(receive.capsule.custody_digest()),
                100_000
            )
            .unwrap()
            .is_some(),
        "intent precedes deletion"
    );
    w.archive.fail_remove = true;
    assert!(
        w.resume_collection().is_err(),
        "removal failure keeps the selected intent"
    );
    assert!(w.manifest().unwrap().1.collection.is_some());
    for _ in 0..10 {
        let (custody, archive, proofs, scheme, wallet) =
            (w.custody, w.archive, w.proofs, w.scheme_id, w.wallet_id);
        w = Coordinator::new(custody, archive, proofs, scheme, wallet).unwrap();
        w.scheduler().set_activity(true, false);
        let result = w.resume_collection().unwrap();
        if result == Some(CollectionStatus::Collected(1)) {
            break;
        }
        assert_eq!(result, Some(CollectionStatus::Progress(1)));
    }
    assert!(w.resume_collection().unwrap().is_none());
    assert_eq!(
        w.collect_retained_step(1).unwrap(),
        CollectionStatus::Collected(1)
    );
    assert!(matches!(w.released_steps(), Err(Error::Collected)));
    assert!(matches!(
        w.retry(&receive.capsule.body().operation_id).unwrap(),
        Some(Completion::Archived)
    ));
    let Completion::CreditStatus(replayed) = w.execute(replay.clone()).unwrap() else {
        panic!("same Receive request must return permanent CreditStatus after collection")
    };
    let status: KagemushaWalletCreditStatusV1 = archive::decode(&replayed).unwrap();
    assert_eq!(status.opening.payment_digest, received_payment());
    assert_eq!(
        w.retry_request(&replay.request_id).unwrap(),
        RequestStatusV1::Outcome(Completion::CreditStatus(replayed.clone()))
    );
    assert_eq!(
        w.execute(replay.clone()).unwrap(),
        Completion::CreditStatus(replayed)
    );
    assert_eq!(w.custody.signatures, signatures);
    assert_eq!(w.proofs.preparations.load(Ordering::SeqCst), 0);
    assert_eq!(w.proofs.preparation_proofs.load(Ordering::SeqCst), 0);
    let mut changed_request = replay;
    changed_request.action = OperationActionV1::Retire;
    assert!(matches!(
        w.execute(changed_request),
        Err(Error::OperationConflict)
    ));
    let duplicate = frozen(
        Some(&next),
        KagemushaWalletEffectV1::Receive {
            credit_id: received_credit(),
            payer_wallet_id: [0x88; 32],
            amount: fixture::<KagemushaWalletPaymentV1>("KagemushaWalletPaymentV1")
                .signed_request()
                .unwrap()
                .body
                .amount,
        },
    );
    let mut changed = duplicate.clone();
    let mut body = changed.capsule.body().clone();
    body.retained_inputs
        .iter_mut()
        .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::Payment)
        .unwrap()
        .bytes[0] ^= 1;
    changed.capsule = seal_body(body);
    assert!(
        w.commit(changed).is_err(),
        "a claimed digest cannot replace the original Payment"
    );
    let Completion::CreditStatus(bytes) = w.commit(duplicate.clone()).unwrap() else {
        panic!("native CreditStatus")
    };
    let status: KagemushaWalletCreditStatusV1 = archive::decode(&bytes).unwrap();
    assert_eq!(status.opening.payment_digest, received_payment());
    assert_eq!(w.custody.signatures, signatures);
    assert!(
        w.archive
            .get(ArchiveKey::Capsule(next.capsule.custody_digest()), 100_000)
            .unwrap()
            .is_some()
    );
    assert!(
        w.archive
            .get(ArchiveKey::Fold(2), 20_000)
            .unwrap()
            .is_some()
    );
    w.custody.unavailable = true;
    assert!(w.commit(duplicate).is_err());
}

#[test]
fn earned_fee_payment_has_independent_exact_custody_and_missing_copy_is_not_paid() {
    let mut w = wallet();
    let boot = bootstrap();
    w.commit(boot.clone()).unwrap();
    let payment: KagemushaWalletPaymentV1 = fixture("KagemushaWalletPaymentV1");
    assert!(payment.signed_request().unwrap().body.fee > 0);
    let bytes = payment.to_canonical_bytes().unwrap();
    let digests = payment.digests().unwrap();
    let send = frozen(Some(&boot), payment.send.statement.effect);
    let mut record: KagemushaWalletCompletionRecordV1 =
        fixture("KagemushaWalletCompletionRecordV1");
    record.output = bytes.clone();
    // Exercise archive retention in isolation. Completion authority and exact receipt binding
    // are exercised by the real-provider adapter tests; this synthetic step is not advanced.
    let step = ReleasedStep {
        frozen: send,
        retained: Retained {
            operation_id: record.operation_id,
            capsule_digest: [7; 32],
            selected_generation: 3,
            completion_digest: record.completion_digest().unwrap(),
            frame: record.to_canonical_bytes().unwrap(),
            record,
        },
    };
    let (old, mut manifest) = w.sync_manifest().unwrap();
    let original_manifest = archive::encode(&manifest).unwrap();
    for limits in [
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64),
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
    ] {
        let refused =
            norito::with_decode_limits_scope(limits, || w.retain_fee_claim(&mut manifest, &step));
        assert!(matches!(refused, Err(Error::DecodeResource(ref cause))
            if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
        assert_eq!(archive::encode(&manifest).unwrap(), original_manifest);
        assert_eq!(w.manifest().unwrap().0, old);
        assert!(
            w.archive
                .get(
                    ArchiveKey::FeeClaim(digests.credit_id),
                    fee_claims::FEE_CLAIM_MAX_BYTES_V1
                )
                .unwrap()
                .is_none()
        );
    }
    w.retain_fee_claim(&mut manifest, &step).unwrap();
    w.publish_manifest(old, &manifest).unwrap();
    assert_eq!(
        w.fee_claim(digests.credit_id)
            .unwrap()
            .map(|claim| claim.payment),
        Some(bytes.clone())
    );
    for limits in [
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64),
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
    ] {
        let refused = norito::with_decode_limits_scope(limits, || {
            w.require_fee_claim(&manifest, digests.credit_id, &bytes)
        });
        assert!(matches!(refused, Err(Error::DecodeResource(ref cause))
            if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
        let refused = norito::with_decode_limits_scope(limits, || w.fee_claim(digests.credit_id));
        assert!(matches!(refused, Err(Error::DecodeResource(ref cause))
            if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
        w.require_fee_claim(&manifest, digests.credit_id, &bytes)
            .unwrap();
        assert_eq!(
            w.fee_claim(digests.credit_id).unwrap().unwrap().payment,
            bytes
        );
    }
    assert!(
        w.require_fee_claim(&manifest, digests.credit_id, b"changed payment")
            .is_err()
    );
    let saved = w
        .archive
        .records
        .lock()
        .unwrap()
        .remove(&ArchiveKey::FeeClaim(digests.credit_id))
        .unwrap();
    assert!(matches!(
        w.fee_claim(digests.credit_id),
        Err(Error::WitnessLost(_))
    ));
    w.archive
        .put(ArchiveKey::FeeClaim(digests.credit_id), &saved)
        .unwrap();
    w.archive
        .records
        .lock()
        .unwrap()
        .get_mut(&ArchiveKey::FeeClaim(digests.credit_id))
        .unwrap()[0] ^= 1;
    assert!(w.fee_claim(digests.credit_id).is_err());
}

#[test]
fn fixed_step_metadata_stays_inside_the_authenticated_index_bound() {
    let entry = manifest::StepEntry {
        capsule: [1; 32],
        operation: [2; 32],
        selected_generation: u128::MAX,
        completion: [3; 32],
        kind: KagemushaWalletOperationKindV1::Send,
        checkpoints: u32::MAX,
        collected: true,
    };
    assert!(archive::encode(&entry).unwrap().len() <= index::INDEX_VALUE_LIMIT);
}

#[test]
fn every_archive_collection_crash_resumes_only_the_selected_object() {
    let (base, _) = prepared_fs();
    let c = credential();
    let open = |fs: SimFs| {
        FsArchive::new(fs, Slot([0x55; 32]), c.body.scheme_id, c.body.wallet_id).unwrap()
    };
    let key = ArchiveKey::FeeClaim(field(80));
    let keep = ArchiveKey::FeeClaim(field(81));
    let mut store = open(base.clone());
    store.put(key, b"paid claim").unwrap();
    store.put(keep, b"unpaid claim").unwrap();
    let probe = base.fork();
    let mut store = open(probe.clone());
    let from = probe.steps();
    store.remove(key).unwrap();
    let steps = probe.steps() - from;
    for offset in 0..steps {
        for fault in [Fault::Error, Fault::CrashAfter] {
            let fs = base.fork();
            let mut store = open(fs.clone());
            fs.inject(fs.steps() + offset, fault);
            assert!(store.remove(key).is_err());
            fs.power_loss(PowerLoss::DropUnsynced);
            store.remove(key).unwrap();
            fs.power_loss(PowerLoss::DropUnsynced);
            assert_eq!(store.get(key, 64).unwrap(), None);
            assert_eq!(
                store.get(keep, 64).unwrap().as_deref(),
                Some(b"unpaid claim".as_slice())
            );
        }
    }
}

#[test]
fn send_collection_requires_latest_pending_root_absence_and_keeps_unpaid_fee() {
    fn retain_map(w: &mut Wallet, pending: &map_tree::PersistentMapV1) {
        // The explicit mock proof owner does not persist real fold map descriptors. Publish
        // actual persistent-map DATA into its selected manifest for this boundary regression.
        let (old, mut manifest) = w.manifest().unwrap();
        let sequence = manifest.folded.unwrap();
        let address = w
            .archive
            .write_object(&archive::encode(pending).unwrap(), 2048)
            .unwrap();
        manifest.fold_pending = manifest
            .fold_pending
            .set(&mut w.archive, manifest::sequence_key(sequence), &address)
            .unwrap();
        w.publish_manifest(old, &manifest).unwrap();
    }
    fn rebind(value: &mut FrozenTransition, mut c: KagemushaWalletRecoveryBodyV1) {
        c.statement.successor = c.successor_state.commitment().unwrap();
        c.operation_id = c.statement.operation_id(&c.wallet_id).unwrap();
        c.output = KagemushaWalletOutputDescriptorV1::for_transition(
            &c.statement,
            &c.proof_digest().unwrap(),
            &c.payment_digest,
        )
        .unwrap();
        value.capsule = c
            .freeze()
            .expect("valid synthetic body")
            .seal([0; 32])
            .expect("synthetic opening");
        value.validate().unwrap();
    }
    let mut w = wallet();
    w.scheduler().set_activity(true, false);
    let template: KagemushaWalletPaymentV1 = fixture("KagemushaWalletPaymentV1");
    let boot = bootstrap();
    w.commit(boot.clone()).unwrap();
    w.fold_once().unwrap();
    w.fold_once().unwrap();
    // Bootstrap holds no policy. This explicit mock Refresh creates the test's selected
    // policy head; the test still does not claim a real policy or recursive proof.
    let mut policy = frozen(
        Some(&boot),
        KagemushaWalletEffectV1::RefreshPolicy {
            update_kind: KagemushaWalletPolicyUpdateKindV1::SchemePolicy,
            update: template.request.scheme_policy,
            accepted_time_floor_ms: boot
                .capsule
                .body()
                .successor_state
                .core
                .accepted_time_floor_ms,
        },
    );
    let mut body = policy.capsule.body().clone();
    body.successor_state.core.policy_epoch = template.request.policy_epoch;
    body.successor_state.rest.scheme_policy = template.request.scheme_policy;
    rebind(&mut policy, body);
    w.commit(policy.clone()).unwrap();
    w.fold_once().unwrap();
    w.fold_once().unwrap();
    let step = w.released_steps().unwrap().pop().unwrap();
    let fold = w.read_fold(&step).unwrap().unwrap();
    let credit = template.digests().unwrap().credit_id;
    let mut pending = KagemushaWalletIndexedTreeV1::new();
    pending.insert(credit, field(42)).unwrap();
    let mut send = frozen(Some(&policy), template.send.statement.effect);
    let send_sequence = send.capsule.body().statement.sequence;
    let mut body = send.capsule.body().clone();
    body.predecessor_lineage = KagemushaWalletLineageSlotV1::Present {
        lineage: fold.record.lineage.clone(),
    };
    body.statement.lineage_burned_total = fold.record.lineage.public.burned_total;
    body.statement.lineage_pending_outgoing_root = fold.record.lineage.public.pending_outgoing_root;
    body.successor_state.core.pending_outgoing_root = pending.root();
    body.successor_state.core.policy_epoch = template.request.policy_epoch;
    body.successor_state.rest.scheme_policy = template.request.scheme_policy;
    rebind(&mut send, body);
    let Completion::Complete(payment) = w.commit(send.clone()).unwrap() else {
        panic!("committed Send")
    };
    w.fold_once().unwrap();
    w.fold_once().unwrap();
    let mut after = frozen(
        Some(&send),
        KagemushaWalletEffectV1::Load {
            receipt_digest: field(98),
            load_ordinal: 0,
            amount: 1,
            online_charge: 0,
        },
    );
    let mut body = after.capsule.body().clone();
    body.successor_state.core.pending_outgoing_root = pending.root();
    rebind(&mut after, body);
    w.commit(after.clone()).unwrap();
    w.fold_once().unwrap();
    w.fold_once().unwrap();
    let empty = KagemushaWalletIndexedTreeV1::new();
    assert!(
        w.collect_retained_step(send_sequence).is_err(),
        "missing selected map"
    );
    let native_empty = map_tree::PersistentMapV1::default();
    retain_map(&mut w, &native_empty);
    assert!(
        w.collect_retained_step(send_sequence).is_err(),
        "map under another root"
    );
    let mut native_pending = native_empty.clone();
    native_pending
        .insert(&mut w.archive, credit, field(42))
        .unwrap();
    assert_eq!(native_pending.root(), pending.root());
    retain_map(&mut w, &native_pending);
    assert!(
        w.collect_retained_step(send_sequence).is_err(),
        "undelivered Send is present"
    );
    let (_, retained) = w.manifest().unwrap();
    assert!(retained.collection.is_none());
    assert!(!w.step_entry(&retained, send_sequence).unwrap().collected);
    assert_eq!(
        w.retry(&send.capsule.body().operation_id).unwrap(),
        Some(Completion::Complete(payment.clone()))
    );
    // The explicit test proof provider now reports a later verified root without this credit.
    // Real production proofs must establish the ArchiveSent effect; the coordinator independently
    // checks its exact nonmembership root and does not infer removal from an operation name.
    let mut cleared = frozen(
        Some(&after),
        KagemushaWalletEffectV1::Load {
            receipt_digest: field(97),
            load_ordinal: 1,
            amount: 1,
            online_charge: 0,
        },
    );
    let mut body = cleared.capsule.body().clone();
    body.successor_state.core.pending_outgoing_root = empty.root();
    rebind(&mut cleared, body);
    w.commit(cleared).unwrap();
    w.fold_once().unwrap();
    w.fold_once().unwrap();
    assert!(
        w.collect_retained_step(send_sequence).is_err(),
        "prior map cannot cover a later fold"
    );
    retain_map(&mut w, &native_empty);
    assert_eq!(
        w.collect_retained_step(send_sequence).unwrap(),
        CollectionStatus::Progress(send_sequence)
    );
    for _ in 0..10 {
        if w.resume_collection().unwrap() == Some(CollectionStatus::Collected(send_sequence)) {
            break;
        }
    }
    assert!(matches!(
        w.retry(&send.capsule.body().operation_id).unwrap(),
        Some(Completion::Archived)
    ));
    assert_eq!(
        w.fee_claim(credit).unwrap().map(|claim| claim.payment),
        Some(payment)
    );
}

// Snapshot tests use the existing explicit mock NativeProofs. They establish source selection,
// arithmetic and error propagation, not real σ/Ω verification or stock-device qualification.
fn snapshot_test_fold(w: &mut Wallet) {
    w.scheduler().set_activity(true, false);
    assert!(matches!(
        w.fold_once().unwrap(),
        FoldStatus::Checkpoint { .. }
    ));
    assert!(matches!(w.fold_once().unwrap(), FoldStatus::Folded(_)));
}
fn snapshot_test_replace_fold(
    w: &mut Wallet,
    sequence: u128,
    mutate: impl FnOnce(&mut RecordedFold),
) {
    let key = ArchiveKey::Fold(sequence);
    let bytes = w.archive.get(key, 20_000).unwrap().unwrap();
    let mut fold: RecordedFold = archive::decode(&bytes).unwrap();
    mutate(&mut fold);
    let bytes = archive::encode(&fold).unwrap();
    // Deliberate source corruption/mock-proof public changes for negative arithmetic tests.
    w.archive.records.lock().unwrap().insert(key, bytes.clone());
    let (digest, mut manifest) = w.manifest().unwrap();
    manifest.folds = manifest
        .folds
        .set(
            &mut w.archive,
            manifest::sequence_key(sequence),
            &crate::kagemusha_wallet_advance_v1::kagemusha_wallet_provider_digest_v1(
                "wallet-recorded-fold",
                &bytes,
            ),
        )
        .unwrap();
    w.publish_manifest(digest, &manifest).unwrap();
    w.verified_folds.clear();
}

#[test]
fn pending_custody_parks_folding_without_proof_and_resumes_after_release() {
    use std::ops::ControlFlow;

    let mut w = wallet();
    let boot = bootstrap();
    let operation = boot.capsule.body().operation_id;
    w.custody.pause = true;
    assert_eq!(w.commit(boot).unwrap(), Completion::Pending);
    w.scheduler().set_activity(true, false);
    let originals = w.archive.records.lock().unwrap().clone();
    let checkpoint = w.custody.checkpoint.clone();
    for _ in 0..3 {
        let ControlFlow::Break(ended) = w.fold_prepare().expect("Pending is idle") else {
            panic!("Pending custody cannot prepare a proof");
        };
        assert_eq!(ended.status, FoldStatus::Idle);
        assert_eq!(ended.backlog, None);
    }
    assert_eq!(w.proofs.folds.load(Ordering::SeqCst), 0);
    assert_eq!(w.custody.signatures, 0);
    assert_eq!(*w.archive.records.lock().unwrap(), originals);
    assert_eq!(w.custody.checkpoint, checkpoint);
    assert_eq!(w.retry(&operation).unwrap(), Some(Completion::Pending));
    assert!(matches!(w.snapshot(), Err(Error::Pending)));

    // The same ABI family also carries actual uncertain writes. Only the typed
    // custody Pending answer may park; storage uncertainty must remain an error.
    let uncertain = ProviderError::Uncertain(
        crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Io(5),
    );
    w.custody.status_error = Some(uncertain);
    assert!(matches!(w.fold_prepare(), Err(Error::Provider(error)) if error == uncertain));
    assert_eq!(w.proofs.folds.load(Ordering::SeqCst), 0);
    w.custody.status_error = None;

    w.custody.pause = false;
    let complete = w.resume().unwrap().expect("same selected operation");
    assert!(matches!(complete, Completion::Complete(_)));
    assert_eq!(w.retry(&operation).unwrap(), Some(complete));
    assert_eq!(w.custody.signatures, 1);
    assert_eq!(
        w.fold_once().unwrap(),
        FoldStatus::Checkpoint {
            sequence: 0,
            ordinal: 0
        }
    );
    assert_eq!(w.fold_once().unwrap(), FoldStatus::Folded(0));
    assert_eq!(w.fold_once().unwrap(), FoldStatus::CaughtUp);
    assert_eq!(w.proofs.folds.load(Ordering::SeqCst), 2);
    assert_eq!(w.custody.signatures, 1);
}

#[test]
fn snapshot_before_bootstrap_pending_or_locked_never_projects_a_balance() {
    let mut w = wallet();
    assert!(matches!(w.snapshot(), Err(Error::NoHead)));
    w.custody.pause = true;
    w.commit(bootstrap()).unwrap();
    assert!(matches!(w.snapshot(), Err(Error::Pending)));
    w.custody.unavailable = true;
    assert!(matches!(
        w.snapshot(),
        Err(Error::Provider(ProviderError::Unavailable(_)))
    ));
}
#[test]
fn snapshot_unfolded_bootstrap_preserves_owned_value_and_reports_the_actual_backlog() {
    let mut w = wallet();
    let boot = bootstrap();
    w.commit(boot.clone()).unwrap();
    let snapshot = w.snapshot().unwrap();
    assert_eq!(snapshot.head, boot.capsule.body().statement.successor.value);
    assert_eq!(
        snapshot.credential_digest,
        boot.credential.credential_digest()
    );
    assert_eq!(
        snapshot.balance,
        boot.capsule.body().successor_state.core.balance
    );
    assert_eq!(
        snapshot.known_burned_total,
        boot.capsule.body().successor_state.core.burned_total
    );
    assert_eq!(snapshot.owned_balance, 20);
    assert_eq!(snapshot.folded_balance, None);
    assert_eq!(snapshot.verified_fold, None);
    assert_eq!(snapshot.fold_backlog, 1);
}
#[test]
fn snapshot_only_the_exact_current_fold_reports_folded_balance() {
    let mut w = wallet();
    let boot = bootstrap();
    w.commit(boot.clone()).unwrap();
    snapshot_test_fold(&mut w);
    let before = w.snapshot().unwrap();
    assert_eq!(before.folded_balance, Some(20));
    assert_eq!(before.fold_backlog, 0);
    let receive = frozen(
        Some(&boot),
        KagemushaWalletEffectV1::Receive {
            credit_id: received_credit(),
            payer_wallet_id: [0x88; 32],
            amount: 1,
        },
    );
    w.commit(receive.clone()).unwrap();
    let after = w.snapshot().unwrap();
    assert_eq!(after.head, receive.capsule.body().statement.successor.value);
    assert_eq!(after.verified_fold.unwrap().head, before.head);
    assert_eq!(after.verified_fold.unwrap().sequence, 0);
    assert_eq!(after.owned_balance, 20);
    assert_eq!(after.folded_balance, None);
    assert_eq!(after.fold_backlog, 1);
}
#[test]
fn snapshot_p4_burns_adjust_owned_value_even_when_the_retained_core_is_stale() {
    let mut w = wallet();
    let boot = bootstrap();
    w.commit(boot.clone()).unwrap();
    snapshot_test_fold(&mut w);
    let receive = frozen(
        Some(&boot),
        KagemushaWalletEffectV1::Receive {
            credit_id: received_credit(),
            payer_wallet_id: [0x88; 32],
            amount: 1,
        },
    );
    w.commit(receive.clone()).unwrap();
    snapshot_test_fold(&mut w);
    snapshot_test_replace_fold(&mut w, 1, |fold| {
        fold.record.lineage.public.burned_total = 5;
    });
    let folded = w.snapshot().unwrap();
    assert_eq!(
        (folded.core_burned_total, folded.known_burned_total),
        (0, 5)
    );
    assert_eq!(
        (folded.owned_balance, folded.folded_balance),
        (15, Some(15))
    );
    let load = frozen(
        Some(&receive),
        KagemushaWalletEffectV1::Load {
            receipt_digest: field(80),
            load_ordinal: 0,
            amount: 1,
            online_charge: 0,
        },
    );
    w.commit(load).unwrap();
    let unfolded = w.snapshot().unwrap();
    assert_eq!(
        (unfolded.core_burned_total, unfolded.known_burned_total),
        (0, 5)
    );
    assert_eq!(
        (unfolded.owned_balance, unfolded.folded_balance),
        (15, None)
    );
    assert_eq!(unfolded.fold_backlog, 1);
}
#[test]
fn snapshot_burns_above_gross_value_are_an_error_not_a_zero_balance() {
    let mut w = wallet();
    w.commit(bootstrap()).unwrap();
    snapshot_test_fold(&mut w);
    snapshot_test_replace_fold(&mut w, 0, |fold| {
        fold.record.lineage.public.burned_total = 21;
    });
    assert!(w.snapshot().is_err());
}
#[test]
fn snapshot_a_fold_cannot_substitute_another_key_head_or_credential() {
    for field in 0..4 {
        let mut w = wallet();
        w.commit(bootstrap()).unwrap();
        snapshot_test_fold(&mut w);
        snapshot_test_replace_fold(&mut w, 0, |fold| match field {
            0 => fold.record.lineage.public.head.value[0] ^= 1,
            1 => fold.record.lineage.public.credential_digest[0] ^= 1,
            2 => fold.record.lineage.public.wallet_id[0] ^= 1,
            _ => {
                let key = SigningKey::from_slice(&[77; 32]).unwrap();
                fold.record.lineage.public.payment_key =
                    KagemushaDevicePublicKeyV1::from_sec1_bytes(
                        key.verifying_key().to_encoded_point(false).as_bytes(),
                    )
                    .unwrap();
            }
        });
        assert!(w.snapshot().is_err());
    }
}
#[test]
fn snapshot_selected_fold_missing_or_replaced_never_looks_unfolded() {
    for missing in [false, true] {
        let mut w = wallet();
        w.commit(bootstrap()).unwrap();
        snapshot_test_fold(&mut w);
        let mut records = w.archive.records.lock().unwrap();
        if missing {
            records.remove(&ArchiveKey::Fold(0));
        } else {
            records.insert(ArchiveKey::Fold(0), vec![1, 2, 3]);
        }
        drop(records);
        assert!(matches!(w.snapshot(), Err(Error::WitnessLost(_))));
    }
}
#[test]
fn snapshot_a_native_fold_rejection_is_preserved() {
    let mut w = wallet();
    w.commit(bootstrap()).unwrap();
    snapshot_test_fold(&mut w);
    w.verified_folds.clear();
    w.proofs.reject = true;
    assert!(matches!(w.snapshot(), Err(Error::Proof(_))));
}
#[test]
fn snapshot_rechecks_the_full_selected_marker_after_all_witness_reads() {
    let mut w = wallet();
    w.commit(bootstrap()).unwrap();
    let SlotStatus::Released(record) = &w.custody.status else {
        panic!("released");
    };
    let mut file: TestMarkerFile = archive::decode(record.file_bytes()).unwrap();
    let mut marker = record.marker().clone();
    marker.generation += 1;
    file.marker = marker.to_canonical_bytes().unwrap();
    let replacement = MarkerRecord::decode(
        &archive::encode(&file).unwrap(),
        record.slot(),
        &marker.scheme_id,
    )
    .unwrap();
    w.custody.status_calls = 0;
    w.custody.status_replacement = Some((3, SlotStatus::Released(replacement)));
    assert!(matches!(
        w.snapshot(),
        Err(Error::WitnessLost("snapshot source marker changed"))
    ));
}
#[test]
fn snapshot_rechecks_the_manifest_original_and_protected_storage_after_reads() {
    let mut w = wallet();
    w.commit(bootstrap()).unwrap();
    let (_, mut manifest) = w.manifest().unwrap();
    manifest.capsule[0] ^= 1;
    let bytes = archive::encode(&manifest).unwrap();
    let digest =
        crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_checkpoint_digest_v1(&bytes);
    w.custody.checkpoint_calls = 0;
    w.custody.checkpoint_replacement = Some((3, (digest, bytes)));
    assert!(matches!(
        w.snapshot(),
        Err(Error::WitnessLost("snapshot source manifest changed"))
    ));
    w.custody.checkpoint_replacement = None;
    w.custody.status_calls = 0;
    w.custody.status_unavailable_at = Some(4);
    assert!(matches!(
        w.snapshot(),
        Err(Error::Provider(ProviderError::Unavailable(_)))
    ));
}
#[test]
fn snapshot_reads_one_indexed_head_instead_of_scanning_permanent_history() {
    let mut w = wallet();
    let mut previous = bootstrap();
    w.commit(previous.clone()).unwrap();
    for number in 1u8..=48 {
        let next = frozen(
            Some(&previous),
            KagemushaWalletEffectV1::Receive {
                credit_id: field(number + 100),
                payer_wallet_id: [0x88; 32],
                amount: 1,
            },
        );
        w.commit(next.clone()).unwrap();
        previous = next;
    }
    // An unselected fold file is never evidence of a verified source-indexed fold.
    w.archive
        .records
        .lock()
        .unwrap()
        .insert(ArchiveKey::Fold(48), vec![1, 2, 3]);
    let before = w.archive.reads.load(Ordering::SeqCst);
    let snapshot = w.snapshot().unwrap();
    assert_eq!(snapshot.fold_backlog, 49);
    assert_eq!(snapshot.verified_fold, None);
    assert!(
        w.archive.reads.load(Ordering::SeqCst) - before <= 260,
        "one bounded index path and current capsule"
    );
}
#[test]
fn snapshot_retiring_reports_folded_remaining_value_without_an_operation_permission() {
    let mut w = wallet();
    let boot = bootstrap();
    w.commit(boot.clone()).unwrap();
    snapshot_test_fold(&mut w);
    let step = w.released_steps().unwrap().remove(0);
    let fold = w.read_fold(&step).unwrap().unwrap();
    let mut retiring = frozen(Some(&boot), KagemushaWalletEffectV1::Retiring);
    let mut c = retiring.capsule.body().clone();
    // Retiring consumes the exact recorded Ω, including its authenticated lineage fields.
    c.predecessor_lineage = KagemushaWalletLineageSlotV1::Present {
        lineage: fold.record.lineage.clone(),
    };
    c.statement.lineage_burned_total = fold.record.lineage.public.burned_total;
    c.statement.lineage_pending_outgoing_root = fold.record.lineage.public.pending_outgoing_root;
    c.successor_state.core.burned_total = c.statement.lineage_burned_total;
    c.statement.successor = c.successor_state.commitment().unwrap();
    c.operation_id = c.statement.operation_id(&c.wallet_id).unwrap();
    c.output = KagemushaWalletOutputDescriptorV1::for_transition(
        &c.statement,
        &c.proof_digest().unwrap(),
        &c.payment_digest,
    )
    .unwrap();
    retiring.capsule = c
        .freeze()
        .expect("valid synthetic body")
        .seal([0; 32])
        .expect("synthetic opening");
    retiring.validate().unwrap();
    w.commit(retiring).unwrap();
    snapshot_test_fold(&mut w);
    let snapshot = w.snapshot().unwrap();
    assert_eq!(snapshot.lifecycle, KagemushaWalletLifecycleV1::Retiring);
    assert_eq!(snapshot.folded_balance, Some(snapshot.owned_balance));
}

#[test]
fn snapshot_fold_burns_cannot_regress_below_the_selected_core() {
    let mut w = wallet();
    let boot = bootstrap();
    w.commit(boot.clone()).unwrap();
    snapshot_test_fold(&mut w);
    snapshot_test_replace_fold(&mut w, 0, |fold| {
        fold.record.lineage.public.burned_total = 4;
    });
    let mut load = frozen(
        Some(&boot),
        KagemushaWalletEffectV1::Load {
            receipt_digest: field(80),
            load_ordinal: 0,
            amount: 1,
            online_charge: 0,
        },
    );
    // Explicit mock relation admits this inconsistent successor for a projection rejection test.
    let mut c = load.capsule.body().clone();
    c.successor_state.core.burned_total = 5;
    // Load does not consume Ω, so its statement lineage inputs remain zero. The explicit
    // mock still admits the inconsistent core to exercise snapshot's burn regression error.
    c.statement.successor = c.successor_state.commitment().unwrap();
    c.operation_id = c.statement.operation_id(&c.wallet_id).unwrap();
    c.output = KagemushaWalletOutputDescriptorV1::for_transition(
        &c.statement,
        &c.proof_digest().unwrap(),
        &c.payment_digest,
    )
    .unwrap();
    load.capsule = c
        .freeze()
        .expect("valid synthetic body")
        .seal([0; 32])
        .expect("synthetic opening");
    load.validate().unwrap();
    w.commit(load).unwrap();
    assert!(matches!(
        w.snapshot(),
        Err(Error::WitnessLost("snapshot burn regression"))
    ));
}
#[test]
fn snapshot_source_manifest_cannot_name_a_future_fold_as_an_ancestor() {
    let mut w = wallet();
    w.commit(bootstrap()).unwrap();
    let (digest, mut manifest) = w.manifest().unwrap();
    manifest.folded = Some(1);
    w.publish_manifest(digest, &manifest).unwrap();
    assert!(matches!(
        w.snapshot(),
        Err(Error::WitnessLost("archive manifest binding"))
    ));
}

#[test]
fn source_reads_preserve_exact_released_head_without_signing() {
    let mut wallet = wallet();
    assert!(matches!(
        wallet.status().unwrap(),
        SlotStatus::Enrollment(_)
    ));
    assert!(wallet.released_steps().unwrap().is_empty());
    assert!(matches!(wallet.snapshot(), Err(Error::NoHead)));
    let frozen = bootstrap();
    wallet.commit(frozen.clone()).unwrap();
    let signatures = wallet.custody.signatures;
    let snapshot = wallet.snapshot().unwrap();
    assert_eq!(
        snapshot.head,
        frozen.capsule.body().statement.successor.value
    );
    assert!(snapshot.verified_fold.is_none());
    let step = wallet.released_steps().unwrap().pop().unwrap();
    assert_eq!(step.frozen.capsule, frozen.capsule);
    assert_eq!(
        wallet.retry(&frozen.capsule.body().operation_id).unwrap(),
        Some(Completion::Complete(step.retained.record.output.clone()))
    );
    assert_eq!(wallet.custody.signatures, signatures);
    snapshot_test_fold(&mut wallet);
    let snapshot = wallet.snapshot().unwrap();
    let current = wallet.released_steps().unwrap().pop().unwrap();
    assert_eq!(current.retained.frame, step.retained.frame);
    assert_eq!(
        wallet
            .read_fold(&current)
            .unwrap()
            .unwrap()
            .record
            .capsule_digest,
        frozen.capsule.custody_digest()
    );
    assert_eq!(
        snapshot.verified_fold.unwrap().head,
        frozen.capsule.body().statement.successor.value
    );
    assert_eq!(wallet.custody.signatures, signatures);
}

// Re-encode each mutation so a self-consistent completion frame cannot stand in for the
// source-selected completion digest. Shared by operation-ID and request-ID retry tests.
fn mutate_retained_completion(
    retained: &mut Retained<KagemushaWalletCompletionRecordV1>,
    mutation: usize,
) {
    match mutation {
        0 => retained.record.output[0] ^= 1,
        1 => retained.record.output[6] ^= 1,
        2 => retained.record.output[4] = 2,
        3 => retained.record.output[39] ^= 2,
        4 => {
            let mut package: KagemushaWalletPackageV1 =
                archive::decode(&retained.record.output).unwrap();
            package.statement.sequence += 1;
            retained.record.output = archive::encode(&package).unwrap();
        }
        5 => {
            retained.record.capsule_digest[0] ^= 1;
            retained.capsule_digest = retained.record.capsule_digest;
        }
        6 => retained.record.receipt.capsule_commitment[0] ^= 1,
        7 => retained.record.output.push(0),
        8 => {
            let original: KagemushaWalletPackageV1 =
                archive::decode(&retained.record.output).unwrap();
            let mut changed = original.clone();
            changed.step_proof.bytes[0] ^= 1;
            retained.record.output = archive::encode(&changed).unwrap();
            let decoded = KagemushaWalletPackageV1::decode_canonical(
                &retained.record.output,
                &original.statement.scheme_id,
            )
            .unwrap();
            assert_eq!(decoded.statement, original.statement);
            assert_eq!(decoded.receipt, original.receipt);
            assert_ne!(decoded.step_proof, original.step_proof);
        }
        _ => panic!("unknown completion mutation"),
    }
    retained.frame = retained.record.to_canonical_bytes().unwrap();
    retained.completion_digest = retained.record.completion_digest().unwrap();
}

/// Build an alternative valid low-S receipt for the same mock-proof frozen test body.
/// Selected recovery may sign again if no completion survives, so validity alone cannot
/// identify which completion was ultimately selected for release.
pub(super) fn alternate_retained_completion(
    frozen: &FrozenTransition,
    original: &Retained<KagemushaWalletCompletionRecordV1>,
) -> Retained<KagemushaWalletCompletionRecordV1> {
    use p256::ecdsa::signature::RandomizedSigner as _;

    let owner = TransitionOwner::new(frozen.credential.clone());
    let body = owner
        .receipt_body(&frozen.capsule, &frozen.capsule.custody_digest())
        .unwrap();
    let message =
        kagemusha_wallet_signing_message_v1(KagemushaWalletSigningDomainV1::Receipt, &body);
    let signature: Signature =
        signer(&frozen.credential).sign_with_rng(&mut rand_core_06::OsRng, &message);
    let signature = signature.normalize_s().unwrap_or(signature);
    let signature = KagemushaDeviceSignatureV1::from_raw_bytes(&signature.to_bytes()).unwrap();
    assert_ne!(signature, original.record.receipt.signature);
    let mut alternate = original.clone();
    alternate.record.receipt.signature = signature;
    let mut package: KagemushaWalletPackageV1 = archive::decode(&original.record.output).unwrap();
    package.receipt = alternate.record.receipt;
    alternate.record.output = archive::encode(&package).unwrap();
    alternate.frame = alternate.record.to_canonical_bytes().unwrap();
    alternate.completion_digest = alternate.record.completion_digest().unwrap();
    alternate
        .record
        .verify(&frozen.credential, &frozen.capsule)
        .unwrap();
    assert_eq!(alternate.operation_id, original.operation_id);
    assert_eq!(alternate.capsule_digest, original.capsule_digest);
    assert_eq!(alternate.selected_generation, original.selected_generation);
    assert_ne!(alternate.record.output, original.record.output);
    assert_ne!(alternate.completion_digest, original.completion_digest);
    alternate
}

#[test]
fn historical_commit_requires_selected_bytes_even_for_another_valid_receipt() {
    let mut w = wallet();
    let boot = bootstrap();
    let exact = w.commit(boot.clone()).unwrap();
    w.commit(frozen(
        Some(&boot),
        KagemushaWalletEffectV1::Load {
            load_ordinal: 0,
            receipt_digest: field(113),
            amount: 1,
            online_charge: 0,
        },
    ))
    .unwrap();
    let operation = boot.capsule.body().operation_id;
    let original = w.custody.retained.get(&operation).unwrap().clone();
    let signatures = w.custody.signatures;
    let selected = w.custody.checkpoint.clone();
    assert_eq!(w.commit(boot.clone()).unwrap(), exact);
    let alternate = alternate_retained_completion(&boot, &original);
    w.custody.replace_retained(alternate);
    assert!(matches!(
        w.commit(boot.clone()),
        Err(Error::WitnessLost("retry selected completion binding"))
    ));
    w.custody.replace_retained(original);
    assert_eq!(w.commit(boot).unwrap(), exact);
    assert_eq!(w.custody.signatures, signatures);
    assert_eq!(w.custody.checkpoint, selected);
}

#[test]
fn retry_rejects_forged_output_header_sequence_and_private_public_pair() {
    for mutation in 0..8 {
        let mut w = wallet();
        let boot = bootstrap();
        w.commit(boot.clone()).unwrap();
        let operation = boot.capsule.body().operation_id;
        let retained = w.custody.retained.get_mut(&operation).unwrap();
        mutate_retained_completion(retained, mutation);
        let signatures = w.custody.signatures;
        assert!(w.retry(&operation).is_err(), "mutation {mutation}");
        assert_eq!(w.custody.signatures, signatures);
    }
}

#[test]
fn retry_requires_exact_authenticated_step_metadata() {
    for mutation in 0..5 {
        let mut w = wallet();
        let boot = bootstrap();
        w.commit(boot.clone()).unwrap();
        let (root, mut manifest) = w.manifest().unwrap();
        let mut entry = w.step_entry(&manifest, 0).unwrap();
        match mutation {
            0 => entry.capsule[0] ^= 1,
            1 => entry.completion[0] ^= 1,
            2 => entry.operation[0] ^= 1,
            3 => entry.selected_generation += 1,
            _ => entry.kind = KagemushaWalletOperationKindV1::Load,
        }
        manifest.steps = manifest
            .steps
            .set(
                &mut w.archive,
                manifest::sequence_key(0),
                &archive::encode(&entry).unwrap(),
            )
            .unwrap();
        w.publish_manifest(root, &manifest).unwrap();
        let signatures = w.custody.signatures;
        assert!(
            w.retry(&boot.capsule.body().operation_id).is_err(),
            "source mutation {mutation}"
        );
        assert_eq!(w.custody.signatures, signatures);
    }
}

#[test]
fn retry_authenticates_released_before_index_and_preserves_pending_historical_reads() {
    let mut w = wallet();
    let boot = bootstrap();
    // Existing publication fault leaves the actual Released marker before indexing.
    w.custody.fail_publication = Some(false);
    assert!(w.commit(boot.clone()).is_err());
    assert!(matches!(w.status().unwrap(), SlotStatus::Released(_)));
    let operation = boot.capsule.body().operation_id;
    let exact = w
        .custody
        .retained
        .get(&operation)
        .unwrap()
        .record
        .output
        .clone();
    let before = w.archive.reads.load(Ordering::SeqCst);
    assert_eq!(
        w.retry(&operation).unwrap(),
        Some(Completion::Complete(exact.clone()))
    );
    assert!(w.archive.reads.load(Ordering::SeqCst) - before <= 4);
    w.sync_manifest().unwrap();
    let next = frozen(
        Some(&boot),
        KagemushaWalletEffectV1::Load {
            load_ordinal: 0,
            receipt_digest: field(31),
            amount: 1,
            online_charge: 0,
        },
    );
    w.custody.pause = true;
    assert_eq!(w.commit(next.clone()).unwrap(), Completion::Pending);
    let signatures = w.custody.signatures;
    assert_eq!(
        w.retry(&operation).unwrap(),
        Some(Completion::Complete(exact))
    );
    assert_eq!(
        w.retry(&next.capsule.body().operation_id).unwrap(),
        Some(Completion::Pending)
    );
    assert_eq!(w.custody.signatures, signatures);
}

#[test]
fn retry_preserves_collected_load_control_output_with_bounded_source_join() {
    let mut w = wallet();
    let boot = bootstrap();
    w.commit(boot.clone()).unwrap();
    snapshot_test_fold(&mut w);
    let first = frozen(
        Some(&boot),
        KagemushaWalletEffectV1::Load {
            load_ordinal: 0,
            receipt_digest: field(31),
            amount: 1,
            online_charge: 0,
        },
    );
    let exact = w.commit(first.clone()).unwrap();
    snapshot_test_fold(&mut w);
    let next = frozen(
        Some(&first),
        KagemushaWalletEffectV1::Load {
            load_ordinal: 1,
            receipt_digest: field(32),
            amount: 1,
            online_charge: 0,
        },
    );
    w.commit(next).unwrap();
    snapshot_test_fold(&mut w);
    for _ in 0..16 {
        if w.collect_retained_step(1).unwrap() == CollectionStatus::Collected(1) {
            break;
        }
    }
    let (_, manifest) = w.manifest().unwrap();
    assert!(w.step_entry(&manifest, 1).unwrap().collected);
    assert!(
        w.archive
            .get(ArchiveKey::Capsule(first.capsule.custody_digest()), 100_000)
            .unwrap()
            .is_none()
    );
    let signatures = w.custody.signatures;
    let before = w.archive.reads.load(Ordering::SeqCst);
    assert_eq!(
        w.retry(&first.capsule.body().operation_id).unwrap(),
        Some(exact)
    );
    assert!(w.archive.reads.load(Ordering::SeqCst) - before <= 260);
    assert_eq!(w.custody.signatures, signatures);
}

#[test]
fn retained_package_read_refusal_preserves_exact_completion_and_retry() {
    let mut w = wallet();
    let boot = bootstrap();
    let operation = boot.capsule.body().operation_id;
    let exact = w.commit(boot).unwrap();
    let retained = match w.custody.lookup(&operation).unwrap() {
        Lookup::Retained(retained) => retained,
        _ => panic!("actual test custody retained Bootstrap"),
    };
    w.require_retained_output(&operation, &retained).unwrap();
    let root = w.manifest().unwrap().0;
    let signatures = w.custody.signatures;
    for limits in [
        norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64),
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
    ] {
        // This direct retained-output path reads its declared Package schema before
        // any index read, so the refusal reaches the repaired model decode itself.
        let error = norito::with_decode_limits_scope(limits, || {
            w.require_retained_output(&operation, &retained)
        })
        .unwrap_err();
        assert!(matches!(error, Error::DecodeResource(ref cause)
            if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
        assert_eq!(w.manifest().unwrap().0, root);
        w.require_retained_output(&operation, &retained).unwrap();
        assert_eq!(w.retry(&operation).unwrap(), Some(exact.clone()));
        assert_eq!(w.custody.signatures, signatures);
    }
}

#[test]
fn frozen_quota_validation_preserves_nested_original_refusal_and_exact_retry() {
    let before = bootstrap();
    let mut value = frozen(
        Some(&before),
        KagemushaWalletEffectV1::RefreshPolicy {
            update_kind: KagemushaWalletPolicyUpdateKindV1::TimeAnchor,
            update: field(123),
            accepted_time_floor_ms: 0,
        },
    );
    let mut body = value.capsule.body().clone();
    body.statement.effect = KagemushaWalletEffectV1::RefreshPolicy {
        update_kind: KagemushaWalletPolicyUpdateKindV1::QuotaShare,
        update: field(123),
        accepted_time_floor_ms: 0,
    };
    body.retained_inputs.push(KagemushaWalletRetainedInputV1 {
        role: KagemushaWalletRetainedInputRoleV1::QuotaRefreshWitness,
        bytes: KagemushaWalletQuotaRefreshWitnessV1::from_usage(
            &KagemushaWalletQuotaUsageArrayV1::empty(),
        )
        .unwrap()
        .to_canonical_bytes()
        .unwrap(),
    });
    rebind_frozen_successor(&mut value, body);
    value.validate().unwrap();
    let original = archive::encode(&value).unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64);
    let error = norito::with_decode_limits_scope(limits, || value.validate()).unwrap_err();
    assert!(matches!(error, Error::DecodeResource(ref cause)
        if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
    assert_eq!(archive::encode(&value).unwrap(), original);
    value.validate().unwrap();
    let mut malformed = value.capsule.body().clone();
    malformed
        .retained_inputs
        .iter_mut()
        .find(|entry| entry.role == KagemushaWalletRetainedInputRoleV1::QuotaRefreshWitness)
        .unwrap()
        .bytes = vec![0];
    assert!(matches!(
        read_model_original(|| malformed.validate(), Error::Invalid("G1 validation")),
        Err(Error::Invalid("G1 validation"))
    ));
}
