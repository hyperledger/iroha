//! Independently signed custody/receipt/observer simulations, never physical signer evidence.

use super::signer_finality::{FinalityFloorV1, HistoricalFinalityV1, SignerFinalityV1};
use super::signer_lifecycle::{SignerClockV1, SignerDriverV1};
use super::*;
use iroha_crypto::{Algorithm, KeyPair, Signature};
use iroha_data_model::sorafs::capacity::ProviderId;
use sorafs_manifest::signer::{
    custody::*,
    protocol::*,
    receipt::{
        SignerCompletedOperationV1, SignerOperationFinalizedAnchorV1, SignerOperationProvenanceV1,
    },
    stream_token::*,
    stream_token_evidence::*,
};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, AtomicUsize},
    time::{SystemTime, UNIX_EPOCH},
};

pub const PROVIDER: [u8; 32] = [0x11; 32];
pub const NOW_MS: u64 = 1_731_234_000_500;
pub const CHAIN: &str = "sorafs-reference";
pub const NETWORK: [u8; 32] = [0x71; 32];
const HARDWARE_HANDLE: &str = "hsm://sorafs/stream-token/primary";
const OBSERVER_HANDLE: &str = "observer:prod/stream-token/primary";

fn key(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).unwrap()
}
fn public(seed: u8) -> [u8; 32] {
    key(seed)
        .public_key()
        .try_to_bytes()
        .unwrap()
        .1
        .try_into()
        .unwrap()
}
fn digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}
fn canonical<T: norito::NoritoSerialize>(domain: &[u8], value: &T) -> [u8; 32] {
    digest(domain, &[&norito::encode_canonical(value).unwrap()])
}
fn signed(
    purpose: SignerKeyOperationPurposeV1,
    message: &[u8],
    seed: u8,
) -> SignerOperationSignatureV1 {
    SignerOperationSignatureV1 {
        purpose,
        message_digest: digest(b"iroha.sorafs.signer.operation.message.v1", &[message]),
        signature: Signature::try_new(key(seed).private_key(), message)
            .unwrap()
            .payload()
            .to_vec(),
    }
}
fn signatures_digest(signatures: &[SignerOperationSignatureV1]) -> [u8; 32] {
    canonical(
        b"iroha.sorafs.signer.operation.signatures.v1",
        &signatures
            .iter()
            .map(|part| {
                (
                    part.purpose,
                    part.message_digest,
                    digest(
                        b"iroha.sorafs.signer.operation.signature.v1",
                        &[&part.signature],
                    ),
                )
            })
            .collect::<Vec<_>>(),
    )
}

pub struct FixedClock {
    pub now: AtomicU64,
    next_challenge: AtomicU64,
}
impl FixedClock {
    pub(crate) fn new(now: u64) -> Self {
        Self {
            now: AtomicU64::new(now),
            next_challenge: AtomicU64::new(1),
        }
    }
}
impl SignerClockV1 for FixedClock {
    fn now_unix_ms(&self) -> Result<u64, StreamTokenIssuerError> {
        Ok(self.now.load(Ordering::SeqCst))
    }
    fn challenge(&self) -> Result<[u8; 32], StreamTokenIssuerError> {
        let mut challenge = [0x91; 32];
        challenge[..8].copy_from_slice(
            &self
                .next_challenge
                .fetch_add(1, Ordering::SeqCst)
                .to_be_bytes(),
        );
        Ok(challenge)
    }
}

fn block_hash(height: u64) -> [u8; 32] {
    digest(b"simulated-finalized-block", &[&height.to_be_bytes()])
}
pub fn anchor(height: u64) -> SignerCustodyAnchorV1 {
    SignerCustodyAnchorV1 {
        height,
        block_hash: block_hash(height),
        state_digest: [0x83; 32],
    }
}

pub struct SimulatedFinality {
    pub tip: AtomicU64,
    pub unavailable: std::sync::atomic::AtomicBool,
    pub completed_proof_source_available: std::sync::atomic::AtomicBool,
    pub validations: AtomicUsize,
    pub advance_clock: Mutex<Option<(usize, Arc<FixedClock>, u64)>>,
}
impl SimulatedFinality {
    pub(crate) fn new() -> Self {
        Self {
            tip: AtomicU64::new(100),
            unavailable: false.into(),
            completed_proof_source_available: true.into(),
            validations: AtomicUsize::new(0),
            advance_clock: Mutex::new(None),
        }
    }
    fn known(&self, candidate: SignerCustodyAnchorV1) -> bool {
        (90..=self.tip.load(Ordering::SeqCst)).contains(&candidate.height)
            && candidate.block_hash == block_hash(candidate.height)
    }
}
impl SignerFinalityV1 for SimulatedFinality {
    fn prepare_completed_check(
        &self,
        _receipt: &SignerStreamTokenReceiptV1,
        _phase: SignerStreamTokenObservationPhaseV1,
        _observer: &dyn StreamTokenStateObserverClientV1,
    ) -> Result<super::signer_completed_finality::PendingCompletedFinalityV1, StreamTokenIssuerError>
    {
        self.require_completed_proof_source()?;
        Ok(
            super::signer_completed_finality::PendingCompletedFinalityV1::Simulated {
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(60),
            },
        )
    }
    fn require_completed_proof_source(&self) -> Result<(), StreamTokenIssuerError> {
        if !self.completed_proof_source_available.load(Ordering::SeqCst) {
            return Err(StreamTokenIssuerError::SignerFinalityUnavailable);
        }
        Ok(())
    }
    fn capture(
        &self,
        minimum: SignerCustodyAnchorV1,
    ) -> Result<FinalityFloorV1, StreamTokenIssuerError> {
        if self.unavailable.load(Ordering::SeqCst) || !self.known(minimum) {
            return Err(StreamTokenIssuerError::SignerFinalityUnavailable);
        }
        let height = self.tip.load(Ordering::SeqCst);
        Ok(FinalityFloorV1 {
            height,
            block_hash: block_hash(height),
        })
    }
    fn validate(
        &self,
        minimum: SignerCustodyAnchorV1,
        candidate: SignerCustodyAnchorV1,
        floor: FinalityFloorV1,
        historical: &[HistoricalFinalityV1],
        observation: &SignerStreamTokenStateObservationBodyV1,
        _completed: Option<&super::signer_completed_finality::CompletedFinalityV1>,
    ) -> Result<(), StreamTokenIssuerError> {
        let call = self.validations.fetch_add(1, Ordering::SeqCst) + 1;
        if self.unavailable.load(Ordering::SeqCst)
            || !self.known(minimum)
            || !self.known(candidate)
            || candidate.height < minimum.height
            || candidate.height < floor.height
            || candidate.height < self.tip.load(Ordering::SeqCst)
            || floor.block_hash != block_hash(floor.height)
            || (candidate.height == minimum.height && candidate != minimum)
            || historical.is_empty()
            || historical.len() > 3
            || observation.current_anchor != candidate
            || !matches!(historical[0], HistoricalFinalityV1::Custody(anchor)
                if anchor == observation.active_head.approved_anchor)
            || historical.iter().any(|anchor| {
                let anchor = anchor.coordinates();
                !(90..=candidate.height).contains(&anchor.height)
                    || anchor.block_hash != block_hash(anchor.height)
            })
        {
            return Err(StreamTokenIssuerError::SignerFinalityUnavailable);
        }
        if let Some((at, clock, now)) = &*self.advance_clock.lock().unwrap() {
            if *at == call {
                clock.now.store(*now, Ordering::SeqCst);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum TestSignerMode {
    Sign,
    Unavailable,
    Refused,
    WrongKey,
    Malformed,
    Ambiguous,
    AmbiguousRecoverFailure,
    HistoricalSigning,
    HistoricalCompletion,
}
#[derive(Clone, Copy, Debug)]
pub enum ObserverFault {
    Unavailable,
    WrongKey,
    WrongRequest,
    WrongPhase,
    SignerRevoked,
    AttesterRevoked,
    WrongRecord,
    WrongChain,
    Stale,
    WrongCompletion,
    WrongFinality,
    RenewedCustody,
}

struct Stored {
    receipt: SignerStreamTokenReceiptV1,
    completion: SignerCompletedOperationV1,
}
pub struct SignedFixture {
    pub storage: actual::SorafsStorage,
    pub pins: StreamTokenSignerPinsV1,
    pub clock: Arc<FixedClock>,
    pub finality: Arc<SimulatedFinality>,
    pub handle: String,
    pub observer_handle: String,
    pub mode: TestSignerMode,
    signer_seed: u8,
    initial_time: u64,
    record: Vec<u8>,
    current: SignerCustodyUseContextV1,
    rows: Mutex<BTreeMap<[u8; 32], Stored>>,
    audit: Mutex<SignerOperationAuditHeadV1>,
    pub faults: Mutex<BTreeMap<usize, ObserverFault>>,
    pub observer_return_clock: Mutex<BTreeMap<usize, u64>>,
    pub observer_return_tip: Mutex<BTreeMap<usize, u64>>,
    pub requests: Mutex<Vec<SignerStreamTokenObservationRequestV1>>,
    pub signing_payloads: Mutex<Vec<Vec<u8>>>,
    pub calls: AtomicUsize,
    pub recover_calls: AtomicUsize,
    pub observer_calls: AtomicUsize,
    observation_lifetime: AtomicU64,
}

fn authority_config(
    service: &str,
    administrator: &str,
    seed: u8,
) -> actual::SorafsStreamTokenAuthorityConfig {
    actual::SorafsStreamTokenAuthorityConfig {
        service_id: service.into(),
        administrator_id: administrator.into(),
        public_key: public(seed),
        key_revision: 3,
        policy_revision: 5,
        policy_digest: [seed; 32],
        active_from_unix_ms: NOW_MS - 10_000,
        active_until_unix_ms: NOW_MS + 3_600_000,
    }
}
pub fn storage_config(limit: u32) -> actual::SorafsStorage {
    actual::SorafsStorage {
        enabled: true,
        provider_id: Some(ProviderId(PROVIDER)),
        stream_tokens: actual::SorafsTokenConfig {
            enabled: true,
            signer: Some(actual::SorafsStreamTokenSignerConfig {
                native: None,
                clock_uncertainty_ms: 250,
                runtime_handle: HARDWARE_HANDLE.into(),
                key_handle: "pkcs11:production/stream-token/key-4".into(),
                service_id: "stream-primary".into(),
                administrator_id: "stream-security-primary".into(),
                public_key: public(0x33),
                key_revision: 4,
                policy_revision: 9,
                policy_digest: [0xb4; 32],
                attester: actual::SorafsStreamTokenAttesterConfig {
                    authority: authority_config(
                        "custody-primary",
                        "custody-security-primary",
                        0x44,
                    ),
                    max_validity_ms: 1_801_000,
                    max_anchor_age_ms: 10_000,
                },
                observer: actual::SorafsStreamTokenObserverConfig {
                    runtime_handle: OBSERVER_HANDLE.into(),
                    authority: authority_config(
                        "observer-primary",
                        "observer-security-primary",
                        0x55,
                    ),
                    max_state_age_ms: 5_000,
                },
            }),
            default_ttl_secs: 900,
            default_max_streams: 2,
            default_rate_limit_bytes: 512 * 1024,
            default_requests_per_minute: limit,
            ..actual::SorafsTokenConfig::default()
        },
        ..Default::default()
    }
}

impl SignedFixture {
    pub(crate) fn new(limit: u32, mode: TestSignerMode) -> Arc<Self> {
        Self::from_storage(storage_config(limit), mode, 0x33, NOW_MS)
    }

    pub(crate) fn with_expiry_case(case: u8) -> Arc<Self> {
        let mut storage = storage_config(1);
        let signer_backend = storage.stream_tokens.signer.as_mut().unwrap();
        match case {
            2 => signer_backend.attester.max_validity_ms = 1400,
            3 => signer_backend.attester.authority.active_until_unix_ms = NOW_MS + 400,
            4 => signer_backend.observer.authority.active_until_unix_ms = NOW_MS + 400,
            _ => {}
        }
        let fixture = Self::from_storage(storage, TestSignerMode::Sign, 0x33, NOW_MS);
        if case == 1 {
            fixture.observation_lifetime.store(400, Ordering::SeqCst);
        }
        fixture
    }

    pub(crate) fn with_clock_uncertainty(uncertainty_ms: u64) -> Arc<Self> {
        let mut storage = storage_config(1);
        storage
            .stream_tokens
            .signer
            .as_mut()
            .unwrap()
            .clock_uncertainty_ms = uncertainty_ms;
        let fixture = Self::from_storage(storage, TestSignerMode::Sign, 0x33, NOW_MS);
        fixture.observation_lifetime.store(5_000, Ordering::SeqCst);
        fixture
    }

    pub(crate) fn substitute_historical_custody(&mut self) {
        let mut record: SignerCustodyRecordV1 = norito::decode_canonical(&self.record).unwrap();
        record.statement.anchor.block_hash[0] ^= 1;
        let mut payload = b"iroha:sorafs:signer-custody:v1\0".to_vec();
        payload.extend(norito::encode_canonical(&record.statement).unwrap());
        record.attestation = Signature::try_new(key(0x44).private_key(), &payload)
            .unwrap()
            .payload()
            .try_into()
            .unwrap();
        self.record = norito::encode_canonical(&record).unwrap();
        let enrolled = verify_signer_custody_enrollment_v1(
            &self.record,
            self.pins.binding(),
            self.pins.custody_trust(),
            &SignerCustodyEnrollmentContextV1 {
                now_unix_ms: self.initial_time,
                anchor_observed_at_unix_ms: self.initial_time,
                current_anchor: record.statement.anchor,
                next_sequence: 1,
                predecessor_digest: [0; 32],
                signer_revoked: false,
                attester_revoked: false,
            },
        )
        .expect("actual attestation remains valid; membership in local history is still required");
        self.current.active_head.record_digest = enrolled.record_digest();
        self.current.active_head.approved_anchor = record.statement.anchor;
        assert_eq!(self.current.current_anchor, anchor(100));
        verify_signer_custody_use_v1(
            &self.record,
            self.pins.binding(),
            self.pins.custody_trust(),
            &self.current,
        )
        .unwrap();
    }

    pub(crate) fn renewed_custody(&self) -> (Vec<u8>, SignerCustodyUseContextV1) {
        let original: SignerCustodyRecordV1 = norito::decode_canonical(&self.record).unwrap();
        let mut statement = original.statement.clone();
        statement.sequence = 2;
        statement.predecessor_digest = self.current.active_head.record_digest;
        statement.anchor = anchor(101);
        statement.issued_at_unix_ms = self.initial_time - self.pins.clock_uncertainty_ms();
        let mut payload = b"iroha:sorafs:signer-custody:v1\0".to_vec();
        payload.extend(norito::encode_canonical(&statement).unwrap());
        let record = norito::encode_canonical(&SignerCustodyRecordV1 {
            statement,
            attestation: Signature::try_new(key(0x44).private_key(), &payload)
                .unwrap()
                .payload()
                .try_into()
                .unwrap(),
        })
        .unwrap();
        let enrolled = verify_signer_custody_enrollment_v1(
            &record,
            self.pins.binding(),
            self.pins.custody_trust(),
            &SignerCustodyEnrollmentContextV1 {
                now_unix_ms: self.initial_time,
                anchor_observed_at_unix_ms: self.initial_time,
                current_anchor: anchor(101),
                next_sequence: 2,
                predecessor_digest: self.current.active_head.record_digest,
                signer_revoked: false,
                attester_revoked: false,
            },
        )
        .expect("new independently attested same-key renewal enrolls at sequence two");
        let mut current = self.current.clone();
        current.current_anchor = anchor(101);
        current.active_head.record_digest = enrolled.record_digest();
        current.active_head.sequence = 2;
        current.active_head.approved_anchor = anchor(101);
        let verified = verify_signer_custody_use_v1(
            &record,
            self.pins.binding(),
            self.pins.custody_trust(),
            &current,
        )
        .expect("renewed active record is independently usable for a new operation");
        assert_eq!(verified.statement().binding, original.statement.binding);
        assert_ne!(
            enrolled.record_digest(),
            self.current.active_head.record_digest
        );
        (record, current)
    }

    pub(crate) fn assert_original_receipt_retained(&self) {
        let rows = self.rows.lock().unwrap();
        assert_eq!(rows.len(), 1);
        let stored = rows.values().next().unwrap();
        assert_eq!(stored.receipt.custody_record, self.record);
        assert_eq!(
            stored.receipt.request.original_custody.record_digest,
            self.current.active_head.record_digest
        );
        assert_eq!(
            stored.completion.original_custody,
            stored.receipt.request.original_custody
        );
        assert_eq!(stored.completion.anchor.height, 100);
    }

    pub(crate) fn for_api(provider: [u8; 32], revision: u64, mode: TestSignerMode) -> Arc<Self> {
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        Self::for_api_at(provider, revision, mode, now)
    }

    pub(crate) fn for_api_at(
        provider: [u8; 32],
        revision: u64,
        mode: TestSignerMode,
        now: u64,
    ) -> Arc<Self> {
        let mut storage = storage_config(3);
        storage.provider_id = Some(ProviderId(provider));
        let signer_backend = storage.stream_tokens.signer.as_mut().unwrap();
        signer_backend.public_key = public(0x51);
        signer_backend.key_revision = revision;
        for authority in [
            &mut signer_backend.attester.authority,
            &mut signer_backend.observer.authority,
        ] {
            authority.active_from_unix_ms = now - 10_000;
            authority.active_until_unix_ms = now + 3_600_000;
        }
        let defaults = actual::SorafsTokenConfig::default();
        storage.stream_tokens.default_ttl_secs = defaults.default_ttl_secs;
        storage.stream_tokens.default_max_streams = defaults.default_max_streams;
        storage.stream_tokens.default_rate_limit_bytes = defaults.default_rate_limit_bytes;
        Self::from_storage(storage, mode, 0x51, now)
    }

    fn from_storage(
        storage: actual::SorafsStorage,
        mode: TestSignerMode,
        signer_seed: u8,
        now: u64,
    ) -> Arc<Self> {
        let pins = StreamTokenSignerPinsV1::from_config(&storage, CHAIN, NETWORK)
            .unwrap()
            .unwrap();
        let statement = SignerCustodyStatementV1 {
            magic: SIGNER_CUSTODY_MAGIC_V1,
            version: SIGNER_CUSTODY_VERSION_V1,
            binding: pins.binding().clone(),
            authority: pins.custody_trust().authority.clone(),
            anchor: anchor(90),
            sequence: 1,
            predecessor_digest: [0; 32],
            issued_at_unix_ms: now - 1000,
            expires_at_unix_ms: (now + pins.custody_trust().max_validity_ms - 1000)
                .min(pins.custody_trust().active_until_unix_ms),
            evidence_digest: [0x55; 32],
            revoked: false,
        };
        let mut preimage = b"iroha:sorafs:signer-custody:v1\0".to_vec();
        preimage.extend(norito::encode_canonical(&statement).unwrap());
        let record = norito::encode_canonical(&SignerCustodyRecordV1 {
            statement,
            attestation: Signature::try_new(key(0x44).private_key(), &preimage)
                .unwrap()
                .payload()
                .try_into()
                .unwrap(),
        })
        .unwrap();
        let enrolled = verify_signer_custody_enrollment_v1(
            &record,
            pins.binding(),
            pins.custody_trust(),
            &SignerCustodyEnrollmentContextV1 {
                now_unix_ms: now,
                anchor_observed_at_unix_ms: now,
                current_anchor: anchor(90),
                next_sequence: 1,
                predecessor_digest: [0; 32],
                signer_revoked: false,
                attester_revoked: false,
            },
        )
        .expect("real separately signed simulated custody enrollment");
        let current = SignerCustodyUseContextV1 {
            now_unix_ms: now,
            anchor_observed_at_unix_ms: now,
            current_anchor: anchor(100),
            active_head: SignerCustodyActiveHeadV1 {
                record_digest: enrolled.record_digest(),
                sequence: 1,
                approved_anchor: anchor(90),
                key_revision: pins.binding().key_revision,
                policy_revision: pins.binding().policy_revision,
                policy_digest: pins.binding().policy_digest,
            },
            signer_revoked: false,
            attester_revoked: false,
        };
        verify_signer_custody_use_v1(&record, pins.binding(), pins.custody_trust(), &current)
            .unwrap();
        Arc::new(Self {
            storage,
            pins,
            clock: Arc::new(FixedClock::new(now)),
            finality: Arc::new(SimulatedFinality::new()),
            handle: HARDWARE_HANDLE.into(),
            observer_handle: OBSERVER_HANDLE.into(),
            mode,
            signer_seed,
            initial_time: now,
            record,
            current,
            rows: Mutex::new(BTreeMap::new()),
            audit: Mutex::new(SignerOperationAuditHeadV1 {
                sequence: 0,
                digest: [0; 32],
            }),
            faults: Mutex::new(BTreeMap::new()),
            observer_return_clock: Mutex::new(BTreeMap::new()),
            observer_return_tip: Mutex::new(BTreeMap::new()),
            requests: Mutex::new(Vec::new()),
            signing_payloads: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
            recover_calls: AtomicUsize::new(0),
            observer_calls: AtomicUsize::new(0),
            observation_lifetime: AtomicU64::new(1000),
        })
    }

    pub(crate) fn issuer(self: &Arc<Self>) -> Result<StreamTokenIssuer, StreamTokenIssuerError> {
        self.issuer_with_storage(&self.storage)
    }
    pub(crate) fn issuer_with_storage(
        self: &Arc<Self>,
        storage: &actual::SorafsStorage,
    ) -> Result<StreamTokenIssuer, StreamTokenIssuerError> {
        let pins = StreamTokenSignerPinsV1::from_config(storage, CHAIN, NETWORK)?
            .ok_or(StreamTokenIssuerError::InvalidSignerConfig)?;
        let approved =
            StreamTokenApprovedCustodyAnchorV1::new(pins.config_digest(), anchor(100)).unwrap();
        let driver = SignerDriverV1::new(
            pins,
            self.clone(),
            Arc::new(SignedObserver(self.clone())),
            approved,
            self.finality.clone(),
            self.clock.clone(),
        )?;
        StreamTokenIssuer::from_signer(&storage.stream_tokens, driver)
    }

    fn receipt(&self, expected: &SignerStreamTokenExpectedV1, body: &StreamTokenBodyV1) -> Vec<u8> {
        assert_eq!(
            &SignerStreamTokenExpectedV1::new(body, self.pins.binding()).unwrap(),
            expected
        );
        let custody = verify_signer_custody_use_v1(
            &self.record,
            self.pins.binding(),
            self.pins.custody_trust(),
            &self.current,
        )
        .unwrap();
        let request = SignerStreamTokenRequestV1::new(&custody, expected, body).unwrap();
        let mut head = self.audit.lock().unwrap();
        let intent = SignerOperationIntentV1 {
            action: SignerOperationActionV1::Sign,
            operation_id: expected.operation_id(),
            request_digest: request.digest().unwrap(),
            previous_audit: *head,
        };
        let intent_digest = canonical(b"iroha.sorafs.signer.operation.intent.v1", &intent);
        let reservation = SignerOperationReservationV1 {
            reservation_id: digest(b"simulated-stream-reservation", &[&expected.operation_id()]),
            fence: head.sequence + 1,
            expires_at_unix_ms: (self.initial_time + 10_000)
                .min(custody.statement().expires_at_unix_ms),
        };
        let mut payload = b"sorafs.stream-token.signature.v1\0".to_vec();
        payload.extend(norito::encode_canonical(body).unwrap());
        let role = signed(
            SignerKeyOperationPurposeV1::RolePayload,
            &payload,
            self.signer_seed,
        );
        let audit = SignerOperationAuditHeadV1 {
            sequence: head.sequence + 1,
            digest: canonical(
                b"iroha.sorafs.signer.stream-token.audit.v1",
                &(
                    request,
                    intent_digest,
                    reservation,
                    digest(
                        b"iroha.sorafs.signer.operation.signature.v1",
                        &[&role.signature],
                    ),
                ),
            ),
        };
        let mut signing_anchor = match self.mode {
            TestSignerMode::HistoricalSigning => anchor(99),
            TestSignerMode::HistoricalCompletion => anchor(98),
            _ => anchor(100),
        };
        if matches!(self.mode, TestSignerMode::HistoricalSigning) {
            signing_anchor.block_hash[0] ^= 1;
        }
        let provenance = SignerOperationProvenanceV1 {
            original_custody: request.original_custody,
            signing_anchor,
            intent_digest,
            reservation,
            audit,
        };
        let mut signatures = vec![
            role,
            signed(
                SignerKeyOperationPurposeV1::AuditRecord,
                &audit.signing_message(),
                self.signer_seed,
            ),
            signed(
                SignerKeyOperationPurposeV1::Provenance,
                &provenance.signing_message().unwrap(),
                self.signer_seed,
            ),
        ];
        let commitment = SignerOperationCommitmentV1 {
            audit,
            response_digest: canonical(
                b"iroha.sorafs.signer.stream-token.response.v1",
                &(request, provenance, signatures_digest(&signatures)),
            ),
        };
        signatures.push(signed(
            SignerKeyOperationPurposeV1::Response,
            &commitment.response_signing_message(),
            self.signer_seed,
        ));
        let receipt = SignerStreamTokenReceiptV1 {
            magic: SIGNER_STREAM_TOKEN_RECEIPT_MAGIC_V1,
            version: 1,
            custody_record: self.record.clone(),
            request,
            intent,
            reservation,
            provenance,
            commitment,
            signatures,
        };
        let token = StreamTokenV1 {
            body: body.clone(),
            signature: receipt.signatures[0].signature.clone(),
        };
        validate_stream_token_signatures_v1(&receipt, &token, expected, &custody)
            .expect("independent producer positive validates actual token and all four signatures");
        let completion_anchor = if matches!(self.mode, TestSignerMode::HistoricalCompletion) {
            let mut hash = block_hash(99);
            hash[0] ^= 1;
            SignerOperationFinalizedAnchorV1 {
                height: 99,
                block_hash: hash,
                operation_state_digest: [0x92; 32],
            }
        } else {
            SignerOperationFinalizedAnchorV1 {
                height: 100,
                block_hash: block_hash(100),
                operation_state_digest: [0x92; 32],
            }
        };
        let completion = SignerCompletedOperationV1 {
            operation_id: expected.operation_id(),
            intent_digest,
            original_custody: request.original_custody,
            reservation,
            commitment,
            signatures_digest: signatures_digest(&receipt.signatures),
            completed_at_unix_ms: self.initial_time,
            anchor: completion_anchor,
        };
        let bytes = receipt.encode_canonical().unwrap();
        let mut rows = self.rows.lock().unwrap();
        assert!(
            !rows.contains_key(&expected.operation_id()),
            "an operation is signed only once"
        );
        rows.insert(
            expected.operation_id(),
            Stored {
                receipt,
                completion,
            },
        );
        *head = audit;
        bytes
    }
}

impl StreamTokenSignerClientV1 for SignedFixture {
    fn handle(&self) -> &str {
        &self.handle
    }
    fn sign(
        &self,
        expected: &SignerStreamTokenExpectedV1,
        body: &StreamTokenBodyV1,
    ) -> Result<StreamTokenSignerReceiptV1, StreamTokenSignerCallErrorV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.signing_payloads
            .lock()
            .unwrap()
            .push(body.signing_payload_bytes().unwrap());
        match self.mode {
            TestSignerMode::Unavailable => Err(StreamTokenSignerCallErrorV1::Unavailable),
            TestSignerMode::Refused => Err(StreamTokenSignerCallErrorV1::Refused),
            TestSignerMode::Malformed => StreamTokenSignerReceiptV1::new(vec![0; 64]),
            _ => {
                let mut bytes = self.receipt(expected, body);
                if matches!(
                    self.mode,
                    TestSignerMode::Ambiguous | TestSignerMode::AmbiguousRecoverFailure
                ) {
                    return Err(StreamTokenSignerCallErrorV1::AmbiguousCompletion);
                }
                if matches!(self.mode, TestSignerMode::WrongKey) {
                    let mut receipt = SignerStreamTokenReceiptV1::decode_canonical(&bytes).unwrap();
                    receipt.signatures[0] = signed(
                        SignerKeyOperationPurposeV1::RolePayload,
                        &body.signing_payload_bytes().unwrap(),
                        0x7a,
                    );
                    bytes = receipt.encode_canonical().unwrap();
                }
                StreamTokenSignerReceiptV1::new(bytes)
            }
        }
    }
    fn recover(
        &self,
        expected: &SignerStreamTokenExpectedV1,
        body: &StreamTokenBodyV1,
    ) -> Result<StreamTokenSignerReceiptV1, StreamTokenSignerCallErrorV1> {
        self.recover_calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            &SignerStreamTokenExpectedV1::new(body, self.pins.binding()).unwrap(),
            expected
        );
        if matches!(self.mode, TestSignerMode::AmbiguousRecoverFailure) {
            return Err(StreamTokenSignerCallErrorV1::Unavailable);
        }
        let rows = self.rows.lock().unwrap();
        let stored = rows
            .get(&expected.operation_id())
            .ok_or(StreamTokenSignerCallErrorV1::Refused)?;
        StreamTokenSignerReceiptV1::new(stored.receipt.encode_canonical().unwrap())
    }
}

pub struct SignedObserver(pub Arc<SignedFixture>);
impl StreamTokenStateObserverClientV1 for SignedObserver {
    fn finalize_check(
        &self,
        _instruction: &iroha_data_model::isi::sorafs::MutateSorafsStreamTokenAuthority,
    ) -> Result<iroha_data_model::transaction::SignedTransaction, StreamTokenSignerCallErrorV1>
    {
        Err(StreamTokenSignerCallErrorV1::Unavailable)
    }
    #[expect(
        clippy::misnamed_getters,
        reason = "the observer trait exposes the observer identity; the fixture also has a separate signer handle"
    )]
    fn handle(&self) -> &str {
        &self.0.observer_handle
    }
    fn observe(
        &self,
        request: &SignerStreamTokenObservationRequestV1,
    ) -> Result<StreamTokenObserverReplyV1, StreamTokenSignerCallErrorV1> {
        let fixture = &self.0;
        let index = fixture.observer_calls.fetch_add(1, Ordering::SeqCst) + 1;
        fixture.requests.lock().unwrap().push(request.clone());
        let fault = fixture.faults.lock().unwrap().get(&index).copied();
        if matches!(fault, Some(ObserverFault::Unavailable)) {
            return Err(StreamTokenSignerCallErrorV1::Unavailable);
        }
        let subject = match &request.subject {
            SignerStreamTokenObservationRequestSubjectV1::CurrentCustody { .. } => {
                SignerStreamTokenStateSubjectV1::CurrentCustody {
                    binding_digest: stream_token_binding_digest_v1(fixture.pins.binding()).unwrap(),
                }
            }
            SignerStreamTokenObservationRequestSubjectV1::CompletedOperation {
                operation_id,
                receipt_digest,
                signatures_digest: committed_signatures,
                ..
            } => {
                let rows = fixture.rows.lock().unwrap();
                let stored = rows
                    .get(operation_id)
                    .ok_or(StreamTokenSignerCallErrorV1::Refused)?;
                assert_eq!(
                    *receipt_digest,
                    digest(
                        b"iroha.sorafs.signer.stream-token.receipt.v1",
                        &[&stored.receipt.encode_canonical().unwrap()]
                    )
                );
                assert_eq!(*committed_signatures, stored.completion.signatures_digest);
                SignerStreamTokenStateSubjectV1::CompletedOperation {
                    binding_digest: stored.receipt.request.binding_digest,
                    operation_id: stored.receipt.request.operation_id,
                    signing_payload_digest: stored.receipt.request.signing_payload_digest,
                    signing_payload_size: stored.receipt.request.signing_payload_size,
                    completed_operation: Box::new(stored.completion),
                }
            }
        };
        let now = fixture.clock.now.load(Ordering::SeqCst);
        let mut body = SignerStreamTokenStateObservationBodyV1 {
            magic: SignerStreamTokenStateObservationBodyV1::magic(),
            request_digest: canonical(b"iroha.sorafs.stream-token.observation-request.v1", request),
            phase: request.phase,
            subject,
            authority: fixture.pins.observer_trust().authority.clone(),
            chain_id: CHAIN.into(),
            network_id: NETWORK,
            observed_at_unix_ms: now,
            expires_at_unix_ms: (now + fixture.observation_lifetime.load(Ordering::SeqCst))
                .min(fixture.pins.observer_trust().active_until_unix_ms),
            current_anchor: anchor(100),
            active_head: fixture.current.active_head,
            signer_revoked: false,
            attester_revoked: false,
        };
        let mut current_record = fixture.record.clone();
        if matches!(fault, Some(ObserverFault::RenewedCustody)) {
            let (record, current) = fixture.renewed_custody();
            fixture.finality.tip.store(101, Ordering::SeqCst);
            current_record = record;
            body.current_anchor = current.current_anchor;
            body.active_head = current.active_head;
        }
        match fault {
            Some(ObserverFault::WrongRequest) => body.request_digest[0] ^= 1,
            Some(ObserverFault::WrongPhase) => {
                body.phase = SignerStreamTokenObservationPhaseV1::AfterProvider
            }
            Some(ObserverFault::SignerRevoked) => body.signer_revoked = true,
            Some(ObserverFault::AttesterRevoked) => body.attester_revoked = true,
            Some(ObserverFault::WrongRecord) => body.active_head.record_digest[0] ^= 1,
            Some(ObserverFault::WrongChain) => body.chain_id = "another-chain".into(),
            Some(ObserverFault::Stale) => body.observed_at_unix_ms = now - 6000,
            Some(ObserverFault::WrongFinality) => body.current_anchor = anchor(101),
            Some(ObserverFault::WrongCompletion) => {
                let SignerStreamTokenStateSubjectV1::CompletedOperation {
                    completed_operation,
                    ..
                } = &mut body.subject
                else {
                    panic!("completed fault phase")
                };
                completed_operation.signatures_digest[0] ^= 1;
            }
            _ => {}
        }
        let mut preimage = b"iroha.sorafs.stream-token.finalized-state.v1\0".to_vec();
        preimage.extend(norito::encode_canonical(&body).unwrap());
        let seed = if matches!(fault, Some(ObserverFault::WrongKey)) {
            0x7a
        } else {
            0x55
        };
        let state = SignerStreamTokenStateObservationV1 {
            body,
            signature: Signature::try_new(key(seed).private_key(), &preimage)
                .unwrap()
                .payload()
                .try_into()
                .unwrap(),
        };
        let bytes = norito::encode_canonical(&state).unwrap();
        if let Some(now) = fixture.observer_return_clock.lock().unwrap().get(&index) {
            fixture.clock.now.store(*now, Ordering::SeqCst);
        }
        if let Some(tip) = fixture.observer_return_tip.lock().unwrap().get(&index) {
            fixture.finality.tip.store(*tip, Ordering::SeqCst);
        }
        if matches!(
            request.subject,
            SignerStreamTokenObservationRequestSubjectV1::CurrentCustody { .. }
        ) {
            StreamTokenObserverReplyV1::current(current_record, bytes)
        } else {
            StreamTokenObserverReplyV1::completed(bytes)
        }
    }
}
