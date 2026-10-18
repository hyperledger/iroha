//! Tokio actor Peer
//!
//! Live sessions use `run::granted` and receive-credit framing. Superseded batching
//! helpers are retained only as unit-test fixtures for their regression coverage.
pub(crate) mod post_admission;
#[cfg(feature = "quic")]
mod quic_datagram;
pub(crate) mod receive_credit;
pub(crate) mod tenure;

#[cfg(feature = "quic")]
pub(crate) use quic_datagram::QuicDatagramIngress;

#[cfg(test)]
use crate::puzzle_work_admission::{
    DEFAULT_INBOUND_VERIFY_CAPACITY, DEFAULT_OUTBOUND_MINT_CAPACITY,
};
use crate::{
    ConsensusConfigCaps, ConsensusHandshakeCaps, ConsensusMode, Error, RelayRole,
    boilerplate::*,
    preauth::{InboundAuthCompletion, PreauthDeadline},
    puzzle_work_admission::{
        SoranetOutboundWorkControl, SoranetOutboundWorkOutcome, SoranetPuzzleWorkAdmission,
        run_soranet_admission_work, run_soranet_outbound_search,
    },
};
#[cfg(test)]
use bytes::BytesMut;
use iroha_config::parameters::actual::SoranetPow as ActualSoranetPow;
#[cfg(any(test, feature = "iroha-core-tests"))]
use iroha_crypto::soranet::pow::TicketRevocationStoreLimits;
use iroha_crypto::soranet::{
    handshake::{
        HarnessError, RelayAuthenticationSignerV1, RelayAuthenticationVerifierV1, RuntimeParams,
        build_client_hello, client_handle_relay_hello, parse_capabilities, process_client_hello,
        validate_client_capability_vector, validate_runtime_configuration,
    },
    pow::{self, Ticket as PowTicket, TicketRevocationInsertStatus, TicketRevocationStore},
    puzzle::{self, ChallengeBinding as PuzzleBinding, Parameters as PuzzleParameters},
};
#[cfg(test)]
use iroha_crypto::{Algorithm, KeyPair};
use iroha_model_base::peer::PeerId;
use message::*;
use norito::{
    codec::{Decode, DecodeAll, Encode},
    core as ncore,
};
use rand::rand_core::TryCryptoRng;
use rand::{SeedableRng, rngs::StdRng};
use soranet_pq::MlKemSuite;
#[cfg(test)]
use std::num::{NonZeroU32, NonZeroUsize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    time::Duration,
};
const SORANET_CONSTANT_RATE_CAPABILITY_TYPE: u16 = 0x0203;
const SORANET_CONSTANT_RATE_STRICT_FLAG: u8 = 0x01;
// (keep fully-qualified uses inline; avoid unused import warnings)
#[cfg(test)]
fn test_network_id(seed: &str) -> iroha_data_model::NetworkId {
    iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        iroha_crypto::Hash::new(seed.as_bytes()),
    ))
}
#[cfg(test)]
fn test_ticket_revocation_store() -> Arc<Mutex<TicketRevocationStore>> {
    let limits = TicketRevocationStoreLimits::new(1_024, Duration::from_secs(900))
        .expect("test replay-store limits must be valid");
    let store = TicketRevocationStore::in_memory(limits)
        .expect("test in-memory replay store must be available");
    Arc::new(Mutex::new(store))
}
#[cfg(test)]
fn random_node_key_pair() -> KeyPair {
    KeyPair::random_with_algorithm(Algorithm::BlsNormal)
}
#[cfg(test)]
fn random_node_peer_id() -> PeerId {
    PeerId::from(random_node_key_pair().public_key().clone())
}
/// Largest encrypted identity-handshake payload representable by its length prefix.
const MAX_HANDSHAKE_LENGTH: u16 = u16::MAX;
/// Default associated data for AEAD
/// [`Authenticated encryption`](https://en.wikipedia.org/wiki/Authenticated_encryption)
const DEFAULT_AAD: &[u8; 10] = b"Iroha3 AAD";
/// Maximum distinct byte owners retained while assembling one inbound frame:
/// the process-wide source budget and, for progress traffic, one `PeerId` reserve.
/// Incremental chunks from the same owner are coalesced into its existing lease.
#[cfg(test)]
const SOURCE_RETENTION_MAX_LEASES: usize = 2;
/// Upper bound for preallocating per-connection message buffers to reduce growth.
#[cfg(test)]
const DEFAULT_MESSAGE_PREALLOC_CAP: usize = 512 * 1024;
/// Largest idle per-connection message buffer retained after a large frame.
#[cfg(test)]
const MAX_RETAINED_MESSAGE_BUFFER_CAP: usize = DEFAULT_MESSAGE_PREALLOC_CAP;
/// Prefix byte used to indicate a versioned handshake hello payload.
const HANDSHAKE_HELLO_VERSION_PREFIX: u8 = 0xFF;
/// Single supported handshake hello payload version.
const HANDSHAKE_HELLO_VERSION: u8 = 1;
#[cfg(test)]
fn compact_sparse_bytes_to_cap(buffer: &mut BytesMut, retained_cap: usize) {
    if buffer.capacity() <= retained_cap || buffer.len() > retained_cap {
        return;
    }
    let mut compact = BytesMut::with_capacity(retained_cap.max(buffer.len()));
    compact.extend_from_slice(buffer);
    *buffer = compact;
}
/// Count of handshake failures (timeout or verification error).
static HANDSHAKE_FAILURES: AtomicU64 = AtomicU64::new(0);
// Handshake error taxonomy counters
static HSE_TIMEOUT: AtomicU64 = AtomicU64::new(0);
static HSE_PREFACE: AtomicU64 = AtomicU64::new(0);
static HSE_VERIFY: AtomicU64 = AtomicU64::new(0);
static HSE_DECRYPT: AtomicU64 = AtomicU64::new(0);
static HSE_CODEC: AtomicU64 = AtomicU64::new(0);
static HSE_IO: AtomicU64 = AtomicU64::new(0);
static HSE_OTHER: AtomicU64 = AtomicU64::new(0);
// Handshake latency histogram buckets (ms)
const HN: usize = 12;
static HANDSHAKE_BUCKETS_MS: [u64; HN] = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2000, 5000];
static HANDSHAKE_BUCKET_COUNTS: [AtomicU64; HN] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static HANDSHAKE_MS_SUM: AtomicU64 = AtomicU64::new(0);
static HANDSHAKE_MS_COUNT: AtomicU64 = AtomicU64::new(0);
fn soranet_handshake_rng() -> Result<StdRng, Error> {
    StdRng::try_from_os_rng()
        .map_err(|err| Error::HandshakeSoranet(format!("SoraNet OS RNG failed: {err}")))
}
fn generate_soranet_transport_delegation_challenge<R>(
    rng: &mut R,
) -> Result<SoranetTransportDelegationChallenge, Error>
where
    R: TryCryptoRng,
    R::Error: std::fmt::Display,
{
    let mut challenge = [0u8; SORANET_TRANSPORT_DELEGATION_CHALLENGE_BYTES];
    rng.try_fill_bytes(&mut challenge).map_err(|error| {
        Error::HandshakeSoranet(format!("SoraNet delegation challenge RNG failed: {error}"))
    })?;
    if challenge.iter().all(|byte| *byte == 0) {
        return Err(Error::HandshakeSoranet(
            "SoraNet delegation challenge RNG returned an all-zero value".to_owned(),
        ));
    }
    if challenge.iter().all(|byte| *byte == challenge[0]) {
        return Err(Error::HandshakeSoranet(
            "SoraNet delegation challenge RNG returned all-identical-byte material".to_owned(),
        ));
    }
    Ok(challenge)
}
/// Bound pending ticket identities to the hard ceiling for inbound crypto work.
const MAX_PENDING_TICKET_REPLAYS: usize = ActualSoranetPow::MAX_PUZZLE_WORK_CAPACITY_PER_DIRECTION;

struct PendingTicketReplays {
    fingerprints: Mutex<HashSet<[u8; 32]>>,
}
impl std::fmt::Debug for PendingTicketReplays {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingTicketReplays")
            .field("fingerprints", &"[REDACTED]")
            .field("capacity", &MAX_PENDING_TICKET_REPLAYS)
            .finish()
    }
}
struct PendingTicketReplayReservation {
    pending: Arc<PendingTicketReplays>,
    fingerprint: [u8; 32],
    active: bool,
}
impl PendingTicketReplayReservation {
    fn release(&mut self) -> Result<(), &'static str> {
        if !self.active {
            return Ok(());
        }
        let mut fingerprints = self
            .pending
            .fingerprints
            .lock()
            .map_err(|_| "pending_lock_poisoned")?;
        if !fingerprints.remove(&self.fingerprint) {
            return Err("pending_reservation_missing");
        }
        self.active = false;
        Ok(())
    }
}
impl std::fmt::Debug for PendingTicketReplayReservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingTicketReplayReservation")
            .field("pending", &"[REDACTED]")
            .field("fingerprint", &"[REDACTED]")
            .field("active", &self.active)
            .finish()
    }
}
impl Drop for PendingTicketReplayReservation {
    fn drop(&mut self) {
        let _ = self.release();
        self.fingerprint.fill(0);
        std::hint::black_box(&mut self.fingerprint[..]);
    }
}
/// Process-owned state that must remain identical across handshake-policy reloads.
#[derive(Debug, Clone)]
pub(crate) struct SoranetHandshakeSharedState {
    revocation_store: Arc<Mutex<TicketRevocationStore>>,
    pending_ticket_replays: Arc<PendingTicketReplays>,
    puzzle_work_admission: Arc<SoranetPuzzleWorkAdmission>,
}
impl SoranetHandshakeSharedState {
    pub(crate) fn new(
        revocation_store: Arc<Mutex<TicketRevocationStore>>,
        puzzle_work_admission: Arc<SoranetPuzzleWorkAdmission>,
    ) -> Self {
        Self {
            revocation_store,
            pending_ticket_replays: Arc::new(PendingTicketReplays {
                fingerprints: Mutex::new(HashSet::new()),
            }),
            puzzle_work_admission,
        }
    }
}
/// Transcript-bound handshake policy inputs, separate from shared replay/work authority.
pub(crate) struct SoranetHandshakeParams {
    pub(crate) descriptor_commit: Vec<u8>,
    pub(crate) client_capabilities: Vec<u8>,
    pub(crate) relay_capabilities: Vec<u8>,
    pub(crate) trust_gossip: bool,
    pub(crate) kem_id: u8,
    pub(crate) sig_id: u8,
    pub(crate) resume_hash: Option<Vec<u8>>,
    pub(crate) puzzle_params: PuzzleParameters,
    pub(crate) ticket_ttl: Duration,
}

/// Runtime configuration shared across `SoraNet` handshake attempts.
#[derive(Debug, Clone)]
pub struct SoranetHandshakeConfig {
    descriptor_commit: Arc<Vec<u8>>,
    client_capabilities: Arc<Vec<u8>>,
    relay_capabilities: Arc<Vec<u8>>,
    trust_gossip: bool,
    kem_id: u8,
    sig_id: u8,
    resume_hash: Option<Arc<Vec<u8>>>,
    ticket_ttl: Duration,
    puzzle_params: Arc<PuzzleParameters>,
    revocation_store: Arc<Mutex<TicketRevocationStore>>,
    pending_ticket_replays: Arc<PendingTicketReplays>,
    puzzle_work_admission: Arc<SoranetPuzzleWorkAdmission>,
}
impl SoranetHandshakeConfig {
    #[cfg(test)]
    pub(crate) fn new(
        parameters: SoranetHandshakeParams,
        revocation_store: Arc<Mutex<TicketRevocationStore>>,
    ) -> Result<Self, Error> {
        let shared_state = SoranetHandshakeSharedState::new(
            revocation_store,
            Arc::new(SoranetPuzzleWorkAdmission::new(
                DEFAULT_OUTBOUND_MINT_CAPACITY,
                DEFAULT_INBOUND_VERIFY_CAPACITY,
            )),
        );
        Self::new_with_shared_state(parameters, shared_state)
    }
    pub(crate) fn new_with_shared_state(
        SoranetHandshakeParams {
            descriptor_commit,
            client_capabilities,
            relay_capabilities,
            trust_gossip,
            kem_id,
            sig_id,
            resume_hash,
            puzzle_params,
            ticket_ttl,
        }: SoranetHandshakeParams,
        shared_state: SoranetHandshakeSharedState,
    ) -> Result<Self, Error> {
        if MlKemSuite::from_kem_id(kem_id).is_none() {
            return Err(Error::HandshakeSoranet(format!(
                "unsupported SoraNet ML-KEM identifier {kem_id}"
            )));
        }
        if sig_id != 1 {
            return Err(Error::HandshakeSoranet(format!(
                "unsupported SoraNet signature identifier {sig_id}"
            )));
        }
        if descriptor_commit.len() != iroha_crypto::Hash::LENGTH {
            return Err(Error::HandshakeSoranet(format!(
                "SoraNet descriptor commitment must be {} bytes, got {}",
                iroha_crypto::Hash::LENGTH,
                descriptor_commit.len()
            )));
        }
        if let Some(resume_hash) = resume_hash.as_ref()
            && resume_hash.len() != iroha_crypto::Hash::LENGTH
        {
            return Err(Error::HandshakeSoranet(format!(
                "SoraNet resume hash must be {} bytes, got {}",
                iroha_crypto::Hash::LENGTH,
                resume_hash.len()
            )));
        }
        validate_client_capability_vector(&client_capabilities).map_err(|error| {
            Error::HandshakeSoranet(format!("invalid SoraNet client capability vector: {error}"))
        })?;
        let parsed_client_capabilities =
            parse_capabilities(&client_capabilities).map_err(|error| {
                Error::HandshakeSoranet(format!(
                    "invalid SoraNet client capability vector: {error}"
                ))
            })?;
        // Relay ordering is intentionally transcript-bound rather than subject
        // to the client's canonical nondecreasing-order rule.
        let parsed_relay_capabilities =
            parse_capabilities(&relay_capabilities).map_err(|error| {
                Error::HandshakeSoranet(format!("invalid SoraNet relay capability vector: {error}"))
            })?;
        // TODO: Remove this construction-time rejection when iroha_p2p routes
        // every application payload through the authenticated fixed-rate
        // DATAGRAM mux. Accepting the transcript flag before then would make a
        // false traffic-shape guarantee while normal peer messages use streams.
        if parsed_client_capabilities
            .iter()
            .chain(parsed_relay_capabilities.iter())
            .any(|capability| {
                capability.ty == SORANET_CONSTANT_RATE_CAPABILITY_TYPE
                    && capability
                        .value
                        .get(1)
                        .is_some_and(|flags| flags & SORANET_CONSTANT_RATE_STRICT_FLAG != 0)
            })
        {
            return Err(Error::HandshakeSoranet(
                "strict SoraNet constant-rate capability is unavailable for iroha_p2p until peer payload uses the authenticated fixed-rate DATAGRAM mux"
                    .to_owned(),
            ));
        }
        validate_runtime_configuration(&RuntimeParams {
            descriptor_commit: &descriptor_commit,
            client_capabilities: &client_capabilities,
            relay_capabilities: &relay_capabilities,
            kem_id,
            sig_id,
            transport_alpn: b"iroha-p2p/1",
            tls_server_name: "iroha-quic",
            resume_hash: resume_hash.as_deref(),
        })
        .map_err(|error| {
            let detail = match error {
                HarnessError::Downgrade { warnings, .. } => warnings
                    .into_iter()
                    .map(|warning| warning.message)
                    .collect::<Vec<_>>()
                    .join("; "),
                other => other.to_string(),
            };
            Error::HandshakeSoranet(format!(
                "invalid SoraNet runtime handshake configuration: {detail}"
            ))
        })?;
        Ok(Self {
            descriptor_commit: Arc::new(descriptor_commit),
            client_capabilities: Arc::new(client_capabilities),
            relay_capabilities: Arc::new(relay_capabilities),
            trust_gossip,
            kem_id,
            sig_id,
            resume_hash: resume_hash.map(Arc::new),
            ticket_ttl,
            puzzle_params: Arc::new(puzzle_params),
            revocation_store: shared_state.revocation_store,
            pending_ticket_replays: shared_state.pending_ticket_replays,
            puzzle_work_admission: shared_state.puzzle_work_admission,
        })
    }
    #[cfg(test)]
    pub(crate) fn shares_security_state_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.revocation_store, &other.revocation_store)
            && Arc::ptr_eq(&self.pending_ticket_replays, &other.pending_ticket_replays)
            && Arc::ptr_eq(&self.puzzle_work_admission, &other.puzzle_work_admission)
    }
    #[cfg(test)]
    pub(crate) fn puzzle_work_capacities(&self) -> (NonZeroUsize, NonZeroUsize) {
        self.puzzle_work_admission.capacities()
    }
    fn effective_ticket_ttl(&self) -> Duration {
        self.ticket_ttl
            .min(self.puzzle_params.max_future_skew())
            .max(self.puzzle_params.min_ticket_ttl())
    }
    fn puzzle_binding<'a>(&'a self, transcript_hash: &'a [u8; 32]) -> PuzzleBinding<'a> {
        PuzzleBinding::new(
            self.descriptor_commit.as_slice(),
            transcript_hash,
            transcript_hash,
        )
    }
    fn lock_revocation_store(
        &self,
    ) -> Result<MutexGuard<'_, TicketRevocationStore>, ChallengeVerifyError> {
        self.revocation_store.lock().map_err(|_| {
            iroha_logger::error!("soranet pow revocation store lock poisoned");
            if let Some(metrics) = iroha_telemetry::metrics::global() {
                metrics.inc_soranet_pow_revocation_store("lock_poisoned");
            }
            ChallengeVerifyError::RevocationStore("lock_poisoned".to_string())
        })
    }
    fn map_pow_verification_error(error: pow::Error) -> ChallengeVerifyError {
        match error {
            pow::Error::Replay => ChallengeVerifyError::Replay,
            pow::Error::RevocationStore(message) => {
                iroha_logger::warn!(error = %message, "soranet pow revocation store error");
                if let Some(metrics) = iroha_telemetry::metrics::global() {
                    metrics.inc_soranet_pow_revocation_store(&message);
                }
                ChallengeVerifyError::RevocationStore(message)
            }
            other => ChallengeVerifyError::Pow(other),
        }
    }
    fn reserve_ticket_replay(
        &self,
        ticket: &PowTicket,
        now: SystemTime,
    ) -> Result<PendingTicketReplayReservation, ChallengeVerifyError> {
        let fingerprint = ticket.revocation_fingerprint();
        let mut store_guard = self.lock_revocation_store()?;
        if store_guard
            .is_ticket_payload_revoked(ticket, now)
            .map_err(|error| {
                Self::map_pow_verification_error(pow::Error::RevocationStore(error.to_string()))
            })?
        {
            return Err(ChallengeVerifyError::Replay);
        }
        let mut pending = self
            .pending_ticket_replays
            .fingerprints
            .lock()
            .map_err(|_| {
                Self::map_pow_verification_error(pow::Error::RevocationStore(
                    "pending_lock_poisoned".to_owned(),
                ))
            })?;
        if pending.contains(&fingerprint) {
            return Err(ChallengeVerifyError::Replay);
        }
        if pending.len() >= MAX_PENDING_TICKET_REPLAYS {
            return Err(Self::map_pow_verification_error(
                pow::Error::RevocationStore("pending_capacity".to_owned()),
            ));
        }
        pending.try_reserve(1).map_err(|_| {
            Self::map_pow_verification_error(pow::Error::RevocationStore(
                "pending_allocation".to_owned(),
            ))
        })?;
        pending.insert(fingerprint);
        Ok(PendingTicketReplayReservation {
            pending: Arc::clone(&self.pending_ticket_replays),
            fingerprint,
            active: true,
        })
    }
    fn commit_ticket_replay(
        &self,
        ticket: &PowTicket,
        mut reservation: PendingTicketReplayReservation,
        now: SystemTime,
    ) -> Result<(), ChallengeVerifyError> {
        {
            let mut store_guard = self.lock_revocation_store()?;
            let outcome = store_guard
                .revoke_ticket_payload(ticket, now)
                .map_err(|error| {
                    Self::map_pow_verification_error(pow::Error::RevocationStore(error.to_string()))
                })?;
            match outcome.status {
                TicketRevocationInsertStatus::Accepted => {}
                TicketRevocationInsertStatus::Duplicate => {
                    return Err(ChallengeVerifyError::Replay);
                }
                TicketRevocationInsertStatus::Expired => {
                    let now_secs = now
                        .duration_since(UNIX_EPOCH)
                        .map_err(puzzle::Error::Clock)?
                        .as_secs();
                    return Err(ChallengeVerifyError::Puzzle(puzzle::Error::Expired(
                        ticket.expires_at,
                        now_secs,
                    )));
                }
                TicketRevocationInsertStatus::TtlExceeded => {
                    return Err(Self::map_pow_verification_error(
                        pow::Error::RevocationStore(
                            "revocation ttl exceeded configured maximum".to_owned(),
                        ),
                    ));
                }
                TicketRevocationInsertStatus::Capacity => {
                    return Err(Self::map_pow_verification_error(
                        pow::Error::RevocationStore("revocation store at capacity".to_owned()),
                    ));
                }
            }
        }
        reservation.release().map_err(|reason| {
            Self::map_pow_verification_error(pow::Error::RevocationStore(reason.to_owned()))
        })
    }
    fn admission(&self) -> ChallengeAdmission {
        ChallengeAdmission {
            ticket_ttl: self.effective_ticket_ttl(),
            puzzle: *self.puzzle_params,
        }
    }
    /// Whether this peer participates in trust gossip exchange.
    pub fn trust_gossip(&self) -> bool {
        self.trust_gossip
    }
    #[cfg(test)]
    pub(crate) fn defaults() -> Self {
        Self::new(
            SoranetHandshakeParams {
                descriptor_commit: iroha_crypto::soranet::handshake::DEFAULT_DESCRIPTOR_COMMIT
                    .to_vec(),
                client_capabilities: iroha_crypto::soranet::handshake::DEFAULT_CLIENT_CAPABILITIES
                    .to_vec(),
                relay_capabilities: iroha_crypto::soranet::handshake::DEFAULT_RELAY_CAPABILITIES
                    .to_vec(),
                trust_gossip: true,
                kem_id: 1,
                sig_id: 1,
                resume_hash: None,
                puzzle_params: PuzzleParameters::try_new(
                    NonZeroU32::new(puzzle::MIN_MEMORY_KIB).unwrap(),
                    NonZeroU32::new(1).unwrap(),
                    NonZeroU32::new(1).unwrap(),
                    1,
                    Duration::from_secs(300),
                    Duration::from_secs(30),
                )
                .expect("built-in puzzle parameters must be valid"),
                ticket_ttl: Duration::from_secs(60),
            },
            test_ticket_revocation_store(),
        )
        .expect("built-in SoraNet handshake defaults must be valid")
    }
    pub(crate) fn runtime_params(&self) -> RuntimeParams<'_> {
        RuntimeParams {
            descriptor_commit: self.descriptor_commit.as_slice(),
            client_capabilities: self.client_capabilities.as_slice(),
            relay_capabilities: self.relay_capabilities.as_slice(),
            kem_id: self.kem_id,
            sig_id: self.sig_id,
            transport_alpn: b"iroha-p2p/1",
            tls_server_name: "iroha-quic",
            resume_hash: self
                .resume_hash
                .as_ref()
                .map(|value| value.as_ref().as_slice()),
        }
    }
    /// Removes expired revocations from the backing store and returns the number of entries purged.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(crate) fn purge_expired_revocations(&self) -> Result<usize, ChallengeVerifyError> {
        let mut guard = self.lock_revocation_store()?;
        guard.purge_expired(SystemTime::now()).map_err(|err| {
            iroha_logger::error!(
                error = %err,
                "failed to purge soranet pow revocation store"
            );
            ChallengeVerifyError::RevocationStore(err.to_string())
        })
    }
    /// Returns the number of active revocation fingerprints currently tracked.
    #[must_use = "check the active revocation count or its storage error"]
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(crate) fn active_revocations(&self) -> Result<usize, ChallengeVerifyError> {
        let mut guard = self.lock_revocation_store()?;
        guard.len(SystemTime::now()).map_err(|error| {
            iroha_logger::error!(
                %error,
                "soranet pow revocation store unavailable while counting active entries"
            );
            ChallengeVerifyError::RevocationStore(error.to_string())
        })
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(crate) fn ticket_ttl(&self) -> Duration {
        self.effective_ticket_ttl()
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(crate) fn puzzle_parameters(&self) -> PuzzleParameters {
        *self.puzzle_params
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub(crate) fn admission_summary(&self) -> ChallengeAdmission {
        self.admission()
    }
    #[cfg(test)]
    pub(crate) fn mint_challenge_ticket<R: TryCryptoRng>(
        &self,
        transcript_hash: &[u8; 32],
        rng: &mut R,
    ) -> Result<MintedChallenge, puzzle::MintError> {
        let ttl = self.effective_ticket_ttl();
        let binding = self.puzzle_binding(transcript_hash);
        let ticket = puzzle::mint_ticket(self.puzzle_params.as_ref(), &binding, ttl, rng)?;
        let admission = self.admission();
        Ok(MintedChallenge {
            credential: ticket.to_vec(),
            admission,
        })
    }
    pub(crate) fn verify_challenge_ticket(
        &self,
        bytes: &[u8],
        transcript_hash: &[u8; 32],
    ) -> Result<ChallengeAdmission, ChallengeVerifyError> {
        self.verify_ticket_bytes(bytes, transcript_hash)
    }
    fn verify_ticket_bytes(
        &self,
        bytes: &[u8],
        transcript_hash: &[u8; 32],
    ) -> Result<ChallengeAdmission, ChallengeVerifyError> {
        let ticket = PowTicket::parse(bytes).map_err(ChallengeVerifyError::Pow)?;
        let now = SystemTime::now();
        // Reserve the canonical identity while holding the store only for its
        // durable preflight. The RAII guard excludes concurrent duplicates but
        // leaves distinct ML-DSA/Argon2 work free to run in parallel.
        let reservation = self.reserve_ticket_replay(&ticket, now)?;
        let binding = self.puzzle_binding(transcript_hash);
        puzzle::verify_at(&ticket, &binding, self.puzzle_params.as_ref(), now)
            .map_err(ChallengeVerifyError::Puzzle)?;
        let admission = self.admission();
        // Re-check revocation/expiry at commit time so slow Argon2 work cannot
        // accept a ticket that expired after its initial verification instant.
        self.commit_ticket_replay(&ticket, reservation, SystemTime::now())?;
        Ok(admission)
    }
}
/// Errors encountered while verifying `SoraNet` handshake challenges.
#[derive(Debug, Error)]
pub enum ChallengeVerifyError {
    /// Underlying `PoW` ticket verification failure.
    #[error("pow ticket verification failed: {0}")]
    Pow(#[from] pow::Error),
    /// Argon2 puzzle verification failure.
    #[error("puzzle ticket verification failed: {0}")]
    Puzzle(#[from] puzzle::Error),
    /// Ticket replay detected by the revocation store.
    #[error("replay")]
    Replay,
    /// Revocation store failed to accept or load the entry.
    #[error("store_error")]
    RevocationStore(String),
}
/// Admission policy snapshot returned alongside minted or verified tickets.
#[derive(Debug, Clone, Copy)]
pub struct ChallengeAdmission {
    /// Ticket TTL after applying policy clamps.
    pub ticket_ttl: Duration,
    /// Effective mandatory Argon2 puzzle parameters.
    pub puzzle: PuzzleParameters,
}
/// Minted ticket bytes alongside the admission policy summary.
pub struct MintedChallenge {
    /// Self-minted puzzle ticket to send before the client hello.
    pub credential: Vec<u8>,
    /// Admission policy applied when minting the ticket.
    pub admission: ChallengeAdmission,
}
fn clear_sensitive_vec(bytes: &mut Vec<u8>) {
    // Initialize the existing spare allocation before clearing so a caller
    // cannot leave an earlier, truncated credential resident in capacity.
    bytes.resize(bytes.capacity(), 0);
    bytes.fill(0);
    std::hint::black_box(bytes.as_mut_slice());
    bytes.clear();
}
impl std::fmt::Debug for MintedChallenge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MintedChallenge")
            .field("credential", &"[REDACTED]")
            .field("admission", &self.admission)
            .finish()
    }
}
impl MintedChallenge {
    fn clear_sensitive_bytes(&mut self) {
        clear_sensitive_vec(&mut self.credential);
    }
}
impl Drop for MintedChallenge {
    fn drop(&mut self) {
        self.clear_sensitive_bytes();
    }
}

/// One raw inbound admission credential retained across asynchronous work.
struct SensitiveHandshakeFrame(Vec<u8>);
impl SensitiveHandshakeFrame {
    fn clear(&mut self) {
        clear_sensitive_vec(&mut self.0);
    }
}
impl From<Vec<u8>> for SensitiveHandshakeFrame {
    fn from(frame: Vec<u8>) -> Self {
        Self(frame)
    }
}
impl AsRef<[u8]> for SensitiveHandshakeFrame {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl std::ops::Deref for SensitiveHandshakeFrame {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::fmt::Debug for SensitiveHandshakeFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SensitiveHandshakeFrame([REDACTED])")
    }
}
impl Drop for SensitiveHandshakeFrame {
    fn drop(&mut self) {
        self.clear();
    }
}
async fn mint_handshake_challenge(
    config: Arc<SoranetHandshakeConfig>,
    transcript_hash: [u8; 32],
    mut rng: StdRng,
) -> Result<MintedChallenge, Error> {
    // Spare searches share the original process gate and yield to other
    // handshakes. Advancing the OS-seeded parent gives each worker an
    // independent CSPRNG stream, including helpers started after contention.
    run_soranet_outbound_search(Arc::clone(&config.puzzle_work_admission), move || {
        let config = Arc::clone(&config);
        let mut worker_rng = StdRng::from_rng(&mut rng);
        move |control: SoranetOutboundWorkControl| {
            let binding = config.puzzle_binding(&transcript_hash);
            let ticket = match puzzle::mint_ticket_while(
                config.puzzle_params.as_ref(),
                &binding,
                config.effective_ticket_ttl(),
                &mut worker_rng,
                || control.should_continue(),
            ) {
                Ok(ticket) => ticket,
                Err(puzzle::MintError::Cancelled) if control.yielded() => {
                    return Ok(SoranetOutboundWorkOutcome::Yielded);
                }
                Err(error) => return Err(Error::HandshakeSoranet(error.to_string())),
            };
            Ok(SoranetOutboundWorkOutcome::Completed(MintedChallenge {
                credential: ticket.to_vec(),
                admission: config.admission(),
            }))
        }
    })
    .await
}
async fn verify_handshake_challenge(
    config: Arc<SoranetHandshakeConfig>,
    ticket: SensitiveHandshakeFrame,
    transcript_hash: [u8; 32],
) -> Result<ChallengeAdmission, Error> {
    verify_handshake_challenge_with_gate(
        Arc::clone(&config),
        ticket,
        transcript_hash,
        config.puzzle_work_admission.inbound_verify_gate(),
    )
    .await
}
async fn verify_handshake_challenge_with_gate(
    config: Arc<SoranetHandshakeConfig>,
    ticket: SensitiveHandshakeFrame,
    transcript_hash: [u8; 32],
    gate: Arc<Semaphore>,
) -> Result<ChallengeAdmission, Error> {
    // Argon2 verification must never run on a peer task, and every verifier
    // shares the bounded inbound work gate.
    run_soranet_admission_work(gate, move |_cancellation| {
        config
            .verify_challenge_ticket(&ticket, &transcript_hash)
            .map_err(|error| Error::HandshakeSoranet(error.to_string()))
    })
    .await
}
#[cfg(test)]
mod handshake_config_tests {
    include!("peer_handshake_config_tests.rs");
}
/// Returns the number of handshake failures observed in this process.
pub fn handshake_failure_count() -> u64 {
    HANDSHAKE_FAILURES.load(Ordering::Relaxed)
}
/// Returns the number of handshake timeouts observed.
pub fn handshake_error_timeout() -> u64 {
    HSE_TIMEOUT.load(Ordering::Relaxed)
}
/// Returns the number of preface (magic/version) errors observed.
pub fn handshake_error_preface() -> u64 {
    HSE_PREFACE.load(Ordering::Relaxed)
}
/// Returns the number of signature/verification errors observed.
pub fn handshake_error_verify() -> u64 {
    HSE_VERIFY.load(Ordering::Relaxed)
}
/// Returns the number of decryption errors observed.
pub fn handshake_error_decrypt() -> u64 {
    HSE_DECRYPT.load(Ordering::Relaxed)
}
/// Returns the number of Norito codec errors observed during handshake.
pub fn handshake_error_codec() -> u64 {
    HSE_CODEC.load(Ordering::Relaxed)
}
/// Returns the number of I/O errors observed during handshake.
pub fn handshake_error_io() -> u64 {
    HSE_IO.load(Ordering::Relaxed)
}
/// Returns the number of miscellaneous handshake errors observed.
pub fn handshake_error_other() -> u64 {
    HSE_OTHER.load(Ordering::Relaxed)
}
/// Returns the histogram bucket upper bounds (milliseconds) for handshake latency.
pub fn handshake_bucket_bounds_ms() -> &'static [u64] {
    &HANDSHAKE_BUCKETS_MS
}
/// Returns the current handshake latency histogram counts per bucket.
pub fn handshake_bucket_counts() -> Vec<u64> {
    HANDSHAKE_BUCKET_COUNTS
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .collect()
}
/// Returns the total sum (milliseconds) of observed handshake latencies.
pub fn handshake_ms_sum() -> u64 {
    HANDSHAKE_MS_SUM.load(Ordering::Relaxed)
}
/// Returns the total count of observed handshakes.
pub fn handshake_ms_count() -> u64 {
    HANDSHAKE_MS_COUNT.load(Ordering::Relaxed)
}
fn observe_handshake_ms(ms: u64) {
    HANDSHAKE_MS_SUM.fetch_add(ms, Ordering::Relaxed);
    HANDSHAKE_MS_COUNT.fetch_add(1, Ordering::Relaxed);
    for (i, b) in HANDSHAKE_BUCKETS_MS.iter().enumerate() {
        if ms <= *b {
            HANDSHAKE_BUCKET_COUNTS[i].fetch_add(1, Ordering::Relaxed);
            break;
        }
    }
}
// Pre-handshake magic/version used to quickly reject garbage before entering
// the cryptographic handshake. The initiator's preface also carries the fresh
// challenge and its exact observation of the underlying transport binding.
const PRE_MAGIC: &[u8; 4] = b"I2P2";
const PRE_VERSION: u8 = 5;
const SORANET_TRANSPORT_DELEGATION_CHALLENGE_BYTES: usize = 32;
const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1_952;
/// Exact first-release allocation ceiling for one complete V5 certificate and proof frame.
///
/// The current canonical V5 wire image is exactly 4,459 bytes without a channel binding and
/// 4,525 bytes with one. The latter is the admitted transport shape and defines the ceiling.
const MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES: usize = 4_525;
const SORANET_TRANSPORT_CERTIFICATE_SIGNATURE_DOMAIN: &[u8] =
    b"iroha:p2p:soranet-transport-certificate:v5|";
const SORANET_TRANSPORT_CERTIFICATE_DIGEST_DOMAIN: &[u8] =
    b"iroha:p2p:soranet-transport-certificate-digest:v5|";
const SORANET_TRANSPORT_PROOF_SIGNATURE_DOMAIN: &[u8] = b"iroha:p2p:soranet-transport-proof:v5|";
const SORANET_TRANSPORT_DELEGATION_BINDING_DOMAIN: &[u8] =
    b"iroha:p2p:soranet-transport-delegation-binding:v5|";
type SoranetTransportDelegationChallenge = [u8; SORANET_TRANSPORT_DELEGATION_CHALLENGE_BYTES];
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
struct SoranetTransportCertificateV5 {
    p2p_preface_version: u8,
    network_id: iroha_data_model::NetworkId,
    node_id: PeerId,
    transport_public_key: iroha_crypto::PublicKey,
    relay_authentication_mldsa65_public_key: iroha_crypto::PublicKey,
}
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq, norito::NoritoSchema)]
#[norito_schema(name = "iroha_p2p::peer::SignedSoranetTransportCertificateV5")]
struct SignedSoranetTransportCertificateV5 {
    certificate: SoranetTransportCertificateV5,
    node_signature: Vec<u8>,
}
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
struct SoranetTransportProofStatementV5 {
    certificate_digest: [u8; iroha_crypto::Hash::LENGTH],
    challenge: SoranetTransportDelegationChallenge,
    transport_binding: Option<TransportBinding>,
}
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
struct SignedSoranetTransportProofV5 {
    statement: SoranetTransportProofStatementV5,
    transport_signature: Vec<u8>,
}
#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq, norito::NoritoSchema)]
#[norito_schema(name = "iroha_p2p::peer::SignedSoranetTransportDelegationV5")]
struct SignedSoranetTransportDelegationV5 {
    certificate: SignedSoranetTransportCertificateV5,
    proof: SignedSoranetTransportProofV5,
}
/// Process-lifetime BLS authorization and dual online-authentication signer.
#[derive(Debug)]
pub(crate) struct LocalSoranetTransportCertificateV5 {
    signed_certificate: SignedSoranetTransportCertificateV5,
    digest: [u8; iroha_crypto::Hash::LENGTH],
    relay_authentication_signer: Arc<RelayAuthenticationSignerV1>,
}
#[derive(Debug)]
struct LocalSoranetTransportDelegationV5 {
    canonical_signed_frame: Vec<u8>,
    binding: [u8; iroha_crypto::Hash::LENGTH],
}
#[derive(Debug)]
struct VerifiedSoranetTransportDelegationV5 {
    relay_authentication_verifier: RelayAuthenticationVerifierV1,
    binding: [u8; iroha_crypto::Hash::LENGTH],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ClientPreHandshakeV5 {
    challenge: SoranetTransportDelegationChallenge,
    transport_binding: Option<TransportBinding>,
}
fn domain_separated_payload<T: Encode>(domain: &[u8], value: &T) -> Vec<u8> {
    let encoded = value.encode();
    let mut payload = Vec::with_capacity(domain.len().saturating_add(encoded.len()));
    payload.extend_from_slice(domain);
    payload.extend_from_slice(&encoded);
    payload
}
fn soranet_transport_certificate_signature_payload_v5(
    certificate: &SoranetTransportCertificateV5,
) -> Vec<u8> {
    domain_separated_payload(SORANET_TRANSPORT_CERTIFICATE_SIGNATURE_DOMAIN, certificate)
}
fn soranet_transport_proof_signature_payload_v5(
    statement: &SoranetTransportProofStatementV5,
) -> Vec<u8> {
    domain_separated_payload(SORANET_TRANSPORT_PROOF_SIGNATURE_DOMAIN, statement)
}
fn domain_separated_hash(domain: &[u8], bytes: &[u8]) -> [u8; iroha_crypto::Hash::LENGTH] {
    let mut preimage = Vec::with_capacity(domain.len().saturating_add(bytes.len()));
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(bytes);
    iroha_crypto::Hash::new(preimage).into()
}
fn soranet_transport_certificate_digest_v5(
    canonical_signed_certificate: &[u8],
) -> [u8; iroha_crypto::Hash::LENGTH] {
    domain_separated_hash(
        SORANET_TRANSPORT_CERTIFICATE_DIGEST_DOMAIN,
        canonical_signed_certificate,
    )
}
fn soranet_transport_delegation_binding_v5(
    canonical_signed_frame: &[u8],
) -> [u8; iroha_crypto::Hash::LENGTH] {
    domain_separated_hash(
        SORANET_TRANSPORT_DELEGATION_BINDING_DOMAIN,
        canonical_signed_frame,
    )
}
/// Construct the process-lifetime V5 certificate and dual-authentication signer.
pub(crate) fn create_soranet_transport_certificate_v5(
    node_key_pair: &iroha_crypto::KeyPair,
    soranet_transport_key_pair: Arc<iroha_crypto::KeyPair>,
    relay_authentication_mldsa65_key_pair: Arc<iroha_crypto::KeyPair>,
    network_id: &iroha_data_model::NetworkId,
) -> Result<Arc<LocalSoranetTransportCertificateV5>, crate::Error> {
    use crate::SoranetTransportDelegationError as DelegationError;
    if node_key_pair.algorithm() != iroha_crypto::Algorithm::BlsNormal {
        return Err(DelegationError::LocalNodeAlgorithmMismatch {
            found: node_key_pair.algorithm(),
        }
        .into());
    }
    if soranet_transport_key_pair.algorithm() != iroha_crypto::Algorithm::Ed25519 {
        return Err(DelegationError::LocalTransportAlgorithmMismatch {
            found: soranet_transport_key_pair.algorithm(),
        }
        .into());
    }
    if relay_authentication_mldsa65_key_pair.algorithm() != iroha_crypto::Algorithm::MlDsa {
        return Err(Error::HandshakeSoranet(format!(
            "local SoraNet online-authentication identity must be ML-DSA-65, found {:?}",
            relay_authentication_mldsa65_key_pair.algorithm()
        )));
    }
    let (_, mldsa65_public_key_payload) = relay_authentication_mldsa65_key_pair
        .public_key()
        .try_to_bytes()
        .map_err(|error| Error::HandshakeSoranet(error.to_string()))?;
    if mldsa65_public_key_payload.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(Error::HandshakeSoranet(format!(
            "local ML-DSA-65 public key is {} bytes; expected {ML_DSA_65_PUBLIC_KEY_BYTES}",
            mldsa65_public_key_payload.len()
        )));
    }
    let certificate = SoranetTransportCertificateV5 {
        p2p_preface_version: PRE_VERSION,
        network_id: *network_id,
        node_id: PeerId::from(node_key_pair.public_key().clone()),
        transport_public_key: soranet_transport_key_pair.public_key().clone(),
        relay_authentication_mldsa65_public_key: relay_authentication_mldsa65_key_pair
            .public_key()
            .clone(),
    };
    let signature_payload = soranet_transport_certificate_signature_payload_v5(&certificate);
    let node_signature =
        iroha_crypto::Signature::try_new(node_key_pair.private_key(), &signature_payload)
            .map_err(|error| DelegationError::DelegationSigning(error.to_string()))?
            .payload()
            .to_vec();
    let signed_certificate = SignedSoranetTransportCertificateV5 {
        certificate,
        node_signature,
    };
    let canonical_signed_certificate = norito::encode_canonical(&signed_certificate)
        .map_err(|error| DelegationError::DelegationEncoding(error.to_string()))?;
    if canonical_signed_certificate.is_empty() {
        return Err(
            DelegationError::DelegationEncoding("empty canonical certificate".to_owned()).into(),
        );
    }
    if canonical_signed_certificate.len() > MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES {
        return Err(DelegationError::FrameTooLarge {
            found: canonical_signed_certificate.len(),
            max: MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES,
        }
        .into());
    }
    let digest = soranet_transport_certificate_digest_v5(&canonical_signed_certificate);
    let relay_authentication_signer = RelayAuthenticationSignerV1::try_new(
        soranet_transport_key_pair,
        relay_authentication_mldsa65_key_pair,
        digest,
    )
    .map_err(|error| Error::HandshakeSoranet(error.to_string()))?;
    Ok(Arc::new(LocalSoranetTransportCertificateV5 {
        signed_certificate,
        digest,
        relay_authentication_signer: Arc::new(relay_authentication_signer),
    }))
}
/// Sign one cheap challenge/binding proof with the cached Ed25519 transport key.
fn sign_soranet_transport_delegation_v5(
    certificate: &LocalSoranetTransportCertificateV5,
    soranet_transport_key_pair: &iroha_crypto::KeyPair,
    challenge: SoranetTransportDelegationChallenge,
    transport_binding: Option<TransportBinding>,
) -> Result<LocalSoranetTransportDelegationV5, crate::Error> {
    use crate::SoranetTransportDelegationError as DelegationError;
    if soranet_transport_key_pair.algorithm() != iroha_crypto::Algorithm::Ed25519 {
        return Err(DelegationError::LocalTransportAlgorithmMismatch {
            found: soranet_transport_key_pair.algorithm(),
        }
        .into());
    }
    if &certificate
        .signed_certificate
        .certificate
        .transport_public_key
        != soranet_transport_key_pair.public_key()
    {
        return Err(Error::HandshakeSoranet(
            "cached SoraNet certificate does not authorize the local transport key".to_owned(),
        ));
    }
    let statement = SoranetTransportProofStatementV5 {
        certificate_digest: certificate.digest,
        challenge,
        transport_binding,
    };
    let signature_payload = soranet_transport_proof_signature_payload_v5(&statement);
    let transport_signature = iroha_crypto::Signature::try_new(
        soranet_transport_key_pair.private_key(),
        &signature_payload,
    )
    .map_err(|error| DelegationError::DelegationSigning(error.to_string()))?
    .payload()
    .to_vec();
    let signed = SignedSoranetTransportDelegationV5 {
        certificate: certificate.signed_certificate.clone(),
        proof: SignedSoranetTransportProofV5 {
            statement,
            transport_signature,
        },
    };
    let canonical_signed_frame = norito::encode_canonical(&signed)
        .map_err(|error| DelegationError::DelegationEncoding(error.to_string()))?;
    if canonical_signed_frame.is_empty() {
        return Err(DelegationError::DelegationEncoding("empty canonical frame".to_owned()).into());
    }
    if canonical_signed_frame.len() > MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES {
        return Err(DelegationError::FrameTooLarge {
            found: canonical_signed_frame.len(),
            max: MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES,
        }
        .into());
    }
    let binding = soranet_transport_delegation_binding_v5(&canonical_signed_frame);
    Ok(LocalSoranetTransportDelegationV5 {
        canonical_signed_frame,
        binding,
    })
}
fn verify_soranet_transport_delegation_v5(
    canonical_signed_frame: &[u8],
    expected_network_id: &iroha_data_model::NetworkId,
    expected_peer_id: &PeerId,
    expected_challenge: &SoranetTransportDelegationChallenge,
    expected_transport_binding: Option<TransportBinding>,
) -> Result<VerifiedSoranetTransportDelegationV5, crate::Error> {
    use crate::SoranetTransportDelegationError as DelegationError;
    const ED25519_PUBLIC_KEY_BYTES: usize = 32;
    if canonical_signed_frame.is_empty() {
        return Err(DelegationError::EmptyFrame.into());
    }
    if canonical_signed_frame.len() > MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES {
        return Err(DelegationError::FrameTooLarge {
            found: canonical_signed_frame.len(),
            max: MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES,
        }
        .into());
    }
    let signed: SignedSoranetTransportDelegationV5 = norito::decode_canonical_with_limits(
        canonical_signed_frame,
        norito::DecodeLimits::new(
            MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES.saturating_mul(8),
            MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES,
            MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES.saturating_mul(8),
            MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES.saturating_mul(128),
            16,
        ),
    )
    .map_err(|error| DelegationError::NonCanonicalEncoding(error.to_string()))?;
    if signed.certificate.certificate.p2p_preface_version != PRE_VERSION {
        return Err(DelegationError::UnsupportedVersion {
            expected: PRE_VERSION,
            found: signed.certificate.certificate.p2p_preface_version,
        }
        .into());
    }
    if &signed.proof.statement.challenge != expected_challenge {
        return Err(DelegationError::ChallengeMismatch {
            expected: *expected_challenge,
            found: signed.proof.statement.challenge,
        }
        .into());
    }
    if signed.proof.statement.transport_binding != expected_transport_binding {
        return Err(Error::HandshakeSoranet(
            "SoraNet transport proof binding mismatch".to_owned(),
        ));
    }
    if &signed.certificate.certificate.network_id != expected_network_id {
        return Err(DelegationError::NetworkMismatch {
            expected: *expected_network_id,
            found: signed.certificate.certificate.network_id,
        }
        .into());
    }
    let node_algorithm = signed
        .certificate
        .certificate
        .node_id
        .public_key()
        .try_algorithm()
        .map_err(|error| DelegationError::NonCanonicalEncoding(error.to_string()))?;
    if node_algorithm != iroha_crypto::Algorithm::BlsNormal {
        return Err(DelegationError::NodeAlgorithmMismatch {
            found: node_algorithm,
        }
        .into());
    }
    if &signed.certificate.certificate.node_id != expected_peer_id {
        return Err(DelegationError::PeerMismatch {
            expected: expected_peer_id.clone(),
            found: signed.certificate.certificate.node_id,
        }
        .into());
    }
    let (transport_algorithm, transport_public_key) = signed
        .certificate
        .certificate
        .transport_public_key
        .try_to_bytes()
        .map_err(|error| DelegationError::NonCanonicalEncoding(error.to_string()))?;
    if transport_algorithm != iroha_crypto::Algorithm::Ed25519 {
        return Err(DelegationError::TransportAlgorithmMismatch {
            found: transport_algorithm,
        }
        .into());
    }
    if transport_public_key.len() != ED25519_PUBLIC_KEY_BYTES {
        return Err(DelegationError::TransportKeyLength {
            expected: ED25519_PUBLIC_KEY_BYTES,
            found: transport_public_key.len(),
        }
        .into());
    }
    let (relay_authentication_algorithm, relay_authentication_public_key) = signed
        .certificate
        .certificate
        .relay_authentication_mldsa65_public_key
        .try_to_bytes()
        .map_err(|error| DelegationError::NonCanonicalEncoding(error.to_string()))?;
    if relay_authentication_algorithm != iroha_crypto::Algorithm::MlDsa {
        return Err(Error::HandshakeSoranet(format!(
            "delegated online-authentication identity must be ML-DSA-65, found {relay_authentication_algorithm:?}"
        )));
    }
    if relay_authentication_public_key.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(Error::HandshakeSoranet(format!(
            "delegated ML-DSA-65 public key is {} bytes; expected {ML_DSA_65_PUBLIC_KEY_BYTES}",
            relay_authentication_public_key.len()
        )));
    }
    let expected_signature_len = iroha_crypto::Algorithm::BlsNormal.signature_payload_len();
    if signed.certificate.node_signature.len() != expected_signature_len {
        return Err(DelegationError::NodeSignatureLength {
            expected: expected_signature_len,
            found: signed.certificate.node_signature.len(),
        }
        .into());
    }
    let signature = iroha_crypto::Signature::try_from_bytes(&signed.certificate.node_signature)
        .map_err(|_| DelegationError::MalformedNodeSignature)?;
    let signature_payload =
        soranet_transport_certificate_signature_payload_v5(&signed.certificate.certificate);
    signature
        .verify(expected_peer_id.public_key(), &signature_payload)
        .map_err(|_| DelegationError::InvalidNodeSignature)?;
    let canonical_certificate = norito::encode_canonical(&signed.certificate)
        .map_err(|error| DelegationError::NonCanonicalEncoding(error.to_string()))?;
    let certificate_digest = soranet_transport_certificate_digest_v5(&canonical_certificate);
    if signed.proof.statement.certificate_digest != certificate_digest {
        return Err(Error::HandshakeSoranet(
            "SoraNet transport proof certificate digest mismatch".to_owned(),
        ));
    }
    let expected_transport_signature_len = iroha_crypto::Algorithm::Ed25519.signature_payload_len();
    if signed.proof.transport_signature.len() != expected_transport_signature_len {
        return Err(Error::HandshakeSoranet(format!(
            "SoraNet transport proof signature is {} bytes; expected {expected_transport_signature_len}",
            signed.proof.transport_signature.len()
        )));
    }
    let transport_signature = iroha_crypto::Signature::try_from_bytes(
        &signed.proof.transport_signature,
    )
    .map_err(|_| {
        Error::HandshakeSoranet("SoraNet transport proof signature is malformed".to_owned())
    })?;
    let proof_payload = soranet_transport_proof_signature_payload_v5(&signed.proof.statement);
    transport_signature
        .verify(
            &signed.certificate.certificate.transport_public_key,
            &proof_payload,
        )
        .map_err(|_| {
            Error::HandshakeSoranet(
                "SoraNet transport proof signature verification failed".to_owned(),
            )
        })?;
    let relay_authentication_verifier = RelayAuthenticationVerifierV1::try_new(
        signed.certificate.certificate.transport_public_key,
        signed
            .certificate
            .certificate
            .relay_authentication_mldsa65_public_key,
        certificate_digest,
    )
    .map_err(|error| Error::HandshakeSoranet(error.to_string()))?;
    Ok(VerifiedSoranetTransportDelegationV5 {
        relay_authentication_verifier,
        binding: soranet_transport_delegation_binding_v5(canonical_signed_frame),
    })
}
async fn write_soranet_transport_delegation_v5<W>(
    write: &mut W,
    canonical_signed_frame: &[u8],
) -> Result<(), crate::Error>
where
    W: AsyncWrite + Unpin,
{
    let payload = canonical_signed_frame;
    if payload.is_empty() {
        return Err(crate::SoranetTransportDelegationError::EmptyFrame.into());
    }
    if payload.len() > MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES {
        return Err(crate::SoranetTransportDelegationError::FrameTooLarge {
            found: payload.len(),
            max: MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES,
        }
        .into());
    }
    let len = u16::try_from(payload.len()).map_err(|_| {
        crate::SoranetTransportDelegationError::FrameTooLarge {
            found: payload.len(),
            max: MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES,
        }
    })?;
    write.write_all(&len.to_be_bytes()).await?;
    write.write_all(payload).await?;
    write.flush().await?;
    Ok(())
}
async fn read_and_verify_soranet_transport_delegation_v5<R>(
    read: &mut R,
    expected_network_id: &iroha_data_model::NetworkId,
    expected_peer_id: &PeerId,
    expected_challenge: &SoranetTransportDelegationChallenge,
    expected_transport_binding: Option<TransportBinding>,
) -> Result<VerifiedSoranetTransportDelegationV5, crate::Error>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    read.read_exact(&mut len_buf).await?;
    let len = usize::from(u16::from_be_bytes(len_buf));
    if len == 0 {
        return Err(crate::SoranetTransportDelegationError::EmptyFrame.into());
    }
    if len > MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES {
        return Err(crate::SoranetTransportDelegationError::FrameTooLarge {
            found: len,
            max: MAX_SORANET_TRANSPORT_DELEGATION_FRAME_BYTES,
        }
        .into());
    }
    let mut payload = vec![0_u8; len];
    read.read_exact(&mut payload).await?;
    verify_soranet_transport_delegation_v5(
        &payload,
        expected_network_id,
        expected_peer_id,
        expected_challenge,
        expected_transport_binding,
    )
}
async fn write_client_pre_handshake_header<W>(
    write: &mut W,
    challenge: &SoranetTransportDelegationChallenge,
    transport_binding: Option<TransportBinding>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write.write_all(PRE_MAGIC).await?;
    write.write_all(&[PRE_VERSION]).await?;
    write.write_all(challenge).await?;
    match transport_binding {
        Some(binding) => {
            write.write_all(&[1]).await?;
            write.write_all(&binding).await?;
        }
        None => write.write_all(&[0]).await?,
    }
    write.flush().await?;
    Ok(())
}
async fn read_and_verify_client_pre_handshake_header<R>(
    read: &mut R,
) -> std::io::Result<ClientPreHandshakeV5>
where
    R: AsyncRead + Unpin,
{
    let mut magic = [0u8; 4];
    let mut ver = [0u8; 1];
    let mut challenge = [0u8; SORANET_TRANSPORT_DELEGATION_CHALLENGE_BYTES];
    let mut binding_tag = [0u8; 1];
    read.read_exact(&mut magic).await?;
    read.read_exact(&mut ver).await?;
    if &magic != PRE_MAGIC || ver[0] != PRE_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad pre-handshake header",
        ));
    }
    read.read_exact(&mut challenge).await?;
    if challenge.iter().all(|byte| *byte == 0) || challenge.iter().all(|byte| *byte == challenge[0])
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "degenerate pre-handshake challenge",
        ));
    }
    read.read_exact(&mut binding_tag).await?;
    let transport_binding = match binding_tag[0] {
        0 => None,
        1 => {
            let mut binding = [0u8; iroha_crypto::Hash::LENGTH];
            read.read_exact(&mut binding).await?;
            Some(binding)
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid pre-handshake transport-binding tag",
            ));
        }
    };
    Ok(ClientPreHandshakeV5 {
        challenge,
        transport_binding,
    })
}
async fn write_server_pre_handshake_header<W>(write: &mut W) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write.write_all(PRE_MAGIC).await?;
    write.write_all(&[PRE_VERSION]).await?;
    write.flush().await?;
    Ok(())
}
async fn read_and_verify_server_pre_handshake_header<R>(read: &mut R) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut magic = [0u8; 4];
    let mut ver = [0u8; 1];
    read.read_exact(&mut magic).await?;
    read.read_exact(&mut ver).await?;
    if &magic != PRE_MAGIC || ver[0] != PRE_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad pre-handshake header",
        ));
    }
    Ok(())
}
async fn write_handshake_frame<W>(write: &mut W, payload: &[u8]) -> Result<(), crate::Error>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_HANDSHAKE_LENGTH as usize {
        return Err(crate::Error::HandshakeMessageTooLarge);
    }
    let len = u16::try_from(payload.len()).map_err(|_| crate::Error::HandshakeMessageTooLarge)?;
    write.write_all(&len.to_be_bytes()).await?;
    write.write_all(payload).await?;
    write.flush().await?;
    Ok(())
}
async fn read_handshake_frame<R>(read: &mut R) -> Result<Vec<u8>, crate::Error>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    read.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf);
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut payload = vec![0u8; len as usize];
    read.read_exact(&mut payload).await?;
    Ok(payload)
}

fn soranet_admission_transcript(
    client_hello: &[u8],
    transport_delegation_binding: &[u8; iroha_crypto::Hash::LENGTH],
) -> [u8; iroha_crypto::Hash::LENGTH] {
    const DOMAIN: &[u8] = b"iroha:p2p:soranet-admission:v5|";
    let hello_transcript = pow::derive_admission_transcript(client_hello);
    let mut preimage = Vec::with_capacity(
        DOMAIN
            .len()
            .saturating_add(hello_transcript.len())
            .saturating_add(transport_delegation_binding.len()),
    );
    preimage.extend_from_slice(DOMAIN);
    preimage.extend_from_slice(&hello_transcript);
    // This hashes the complete canonical v5 certificate+proof frame, which in
    // turn authenticates the exact server PeerId, transport key, fresh
    // challenge, and underlying TLS/QUIC/WSS observation.
    preimage.extend_from_slice(transport_delegation_binding);
    iroha_crypto::Hash::new(preimage).into()
}
mod post_channel {
    use tokio::sync::mpsc;
    pub type Sender<T> = mpsc::Sender<T>;
    pub type Receiver<T> = mpsc::Receiver<T>;
    pub fn channel<T>(cap: usize) -> (Sender<T>, Receiver<T>) {
        mpsc::channel(cap)
    }
}
/// Checked aggregate byte ownership shared by bounded transport queues.
///
/// Ordinary traffic may use at most `ordinary_max_bytes`; safety traffic may
/// use otherwise-idle ordinary capacity plus the protected reserve. Once an
/// ordinary producer is queued, new safety ownership is limited to the
/// additive reserve until the ordinary FIFO drains, so borrowing cannot starve
/// a progress-relevant handoff. A lease wakes blocked producers only after its
/// retained bytes have been released.
#[derive(Debug)]
pub(crate) struct SharedByteBudget {
    max_bytes: usize,
    safety_reserve_bytes: usize,
    state: Mutex<SharedBudgetState>,
    released: tokio::sync::Notify,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SharedRetainedBytes {
    total: usize,
    ordinary: usize,
}
#[derive(Debug, Default)]
struct SharedBudgetState {
    retained: SharedRetainedBytes,
    next_ticket: u64,
    ordinary_waiters: VecDeque<u64>,
    safety_waiters: VecDeque<u64>,
}
impl SharedByteBudget {
    pub(crate) fn new(ordinary_max_bytes: usize, safety_reserve_bytes: usize) -> Option<Arc<Self>> {
        let max_bytes = ordinary_max_bytes.checked_add(safety_reserve_bytes)?;
        Some(Arc::new(Self {
            max_bytes,
            safety_reserve_bytes,
            state: Mutex::new(SharedBudgetState::default()),
            released: tokio::sync::Notify::new(),
        }))
    }
    fn effective_safety(&self, safety: bool) -> bool {
        safety && self.safety_reserve_bytes != 0
    }
    fn class_max_bytes(&self, safety: bool) -> usize {
        if self.effective_safety(safety) {
            self.max_bytes
        } else {
            self.max_bytes - self.safety_reserve_bytes
        }
    }
    fn class_waiters(state: &SharedBudgetState, safety: bool) -> &VecDeque<u64> {
        if safety {
            &state.safety_waiters
        } else {
            &state.ordinary_waiters
        }
    }
    fn class_waiters_mut(state: &mut SharedBudgetState, safety: bool) -> &mut VecDeque<u64> {
        if safety {
            &mut state.safety_waiters
        } else {
            &mut state.ordinary_waiters
        }
    }
    fn allocate_waiter_ticket(state: &mut SharedBudgetState) -> Option<u64> {
        if let Some(next_ticket) = state.next_ticket.checked_add(1) {
            let ticket = state.next_ticket;
            state.next_ticket = next_ticket;
            return Some(ticket);
        }
        if state.ordinary_waiters.is_empty() && state.safety_waiters.is_empty() {
            // No live ticket can collide with a restarted sequence.  Resetting
            // anywhere else could let cancellation or FIFO checks target the
            // wrong producer, so exhaustion with waiters fails closed.
            state.next_ticket = 1;
            Some(0)
        } else {
            None
        }
    }
    fn try_reserve_locked(
        self: &Arc<Self>,
        state: &mut SharedBudgetState,
        bytes: usize,
        safety: bool,
        waiter: Option<u64>,
    ) -> Option<SharedByteLease> {
        let safety = self.effective_safety(safety);
        match waiter {
            Some(ticket) if Self::class_waiters(state, safety).front() == Some(&ticket) => {}
            Some(_) => return None,
            None if !Self::class_waiters(state, safety).is_empty() => return None,
            None => {}
        }
        let class_retained = if safety {
            state.retained.total.checked_sub(state.retained.ordinary)?
        } else {
            state.retained.ordinary
        };
        let next_class = class_retained.checked_add(bytes)?;
        let class_max_bytes = if safety && !state.ordinary_waiters.is_empty() {
            self.safety_reserve_bytes
        } else {
            self.class_max_bytes(safety)
        };
        if next_class > class_max_bytes {
            return None;
        }
        let total = state.retained.total.checked_add(bytes)?;
        if total > self.max_bytes {
            return None;
        }
        state.retained.total = total;
        if !safety {
            state.retained.ordinary = next_class;
        }
        if waiter.is_some() {
            let popped = Self::class_waiters_mut(state, safety).pop_front();
            debug_assert_eq!(popped, waiter);
        }
        Some(SharedByteLease {
            budget: Arc::clone(self),
            bytes,
            safety,
        })
    }
    pub(crate) fn try_reserve(
        self: &Arc<Self>,
        bytes: usize,
        safety: bool,
    ) -> Option<SharedByteLease> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.try_reserve_locked(&mut state, bytes, safety, None)
    }
    pub(crate) async fn reserve(
        self: &Arc<Self>,
        bytes: usize,
        safety: bool,
    ) -> Option<SharedByteLease> {
        let safety = self.effective_safety(safety);
        if bytes > self.class_max_bytes(safety) {
            return None;
        }
        let ticket = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let ticket = Self::allocate_waiter_ticket(&mut state)?;
            Self::class_waiters_mut(&mut state, safety).push_back(ticket);
            ticket
        };
        let mut registration = SharedBudgetWaiter {
            budget: Arc::clone(self),
            ticket,
            safety,
            active: true,
        };
        loop {
            let released = self.released.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            let lease = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                self.try_reserve_locked(&mut state, bytes, safety, Some(ticket))
            };
            if let Some(lease) = lease {
                registration.active = false;
                self.released.notify_waiters();
                return Some(lease);
            }
            released.await;
        }
    }
    #[cfg(test)]
    fn retained(&self) -> SharedRetainedBytes {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retained
    }
    #[cfg(test)]
    pub(crate) fn retained_total(&self) -> usize {
        self.retained().total
    }
    #[cfg(test)]
    pub(crate) fn retained_ordinary(&self) -> usize {
        self.retained().ordinary
    }
}
struct SharedBudgetWaiter {
    budget: Arc<SharedByteBudget>,
    ticket: u64,
    safety: bool,
    active: bool,
}
impl Drop for SharedBudgetWaiter {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        {
            let mut state = self
                .budget
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            SharedByteBudget::class_waiters_mut(&mut state, self.safety)
                .retain(|ticket| *ticket != self.ticket);
        }
        self.budget.released.notify_waiters();
    }
}
#[derive(Debug)]
pub(crate) struct SharedByteLease {
    budget: Arc<SharedByteBudget>,
    bytes: usize,
    safety: bool,
}
impl SharedByteLease {
    #[cfg(test)]
    fn same_owner(&self, other: &Self) -> bool {
        self.safety == other.safety && Arc::ptr_eq(&self.budget, &other.budget)
    }
    /// Fold another already-accounted lease into this representation.
    ///
    /// Budget counters already include both leases. Transferring `other.bytes`
    /// into `self` therefore must not release and reacquire capacity: doing so
    /// could transiently hand source ownership to a competing waiter between
    /// incremental frame reads.
    #[cfg(test)]
    fn merge(&mut self, mut other: Self) -> Result<(), Self> {
        if !self.same_owner(&other) {
            return Err(other);
        }
        let Some(bytes) = self.bytes.checked_add(other.bytes) else {
            return Err(other);
        };
        self.bytes = bytes;
        // Defuse `other` before it drops. Its accounted bytes now belong to
        // `self`; the zero-byte drop only releases the redundant Arc handle.
        other.bytes = 0;
        Ok(())
    }
}
/// Shared PeerId-count geometry for every authenticated source owner.
///
/// Credit owners plus inbound and outbound progress-reserve owners use one
/// weak registry and one actor-installed protected projection. This prevents
/// three individually bounded maps from admitting three disjoint sets of `N`
/// identities.
#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedSourceGeometry {
    max_sources: usize,
    registry: Arc<Mutex<AuthenticatedSourceOwnerRegistry>>,
}
#[derive(Debug, Default)]
struct AuthenticatedSourceOwnerRegistry {
    credit_owners: HashMap<PeerId, Weak<AuthenticatedSourceCreditOwner>>,
    inbound_progress_owners: HashMap<PeerId, Weak<SharedByteBudget>>,
    outbound_progress_owners: HashMap<PeerId, Weak<SharedByteBudget>>,
    protected_sources: Option<HashSet<PeerId>>,
}
/// Process-wide byte owners for reliable connected-peer outbound traffic.
///
/// Ordinary high traffic shares one `H` owner and low traffic shares one `L`
/// owner. Each authenticated peer gets exactly one `R` progress reserve, reused
/// by duplicate sessions through the shared source geometry. A post lease is
/// retained while the message is encoded, encrypted, queued, batched, and
/// written. The configured connection cap therefore bounds the process by
/// `H + L + N * R` without letting a non-reader consume another peer's
/// application path.
#[derive(Clone, Debug)]
pub(crate) struct OutboundPostByteBudgets {
    semantic: Arc<Mutex<Weak<post_admission::Pool>>>,
    high: Arc<SharedByteBudget>,
    low: Arc<SharedByteBudget>,
    progress_reserve_bytes_per_peer: usize,
    source_geometry: AuthenticatedSourceGeometry,
}
#[derive(Clone, Debug)]
#[cfg(test)]
pub(super) struct OutboundHighByteBudget {
    shared: Arc<SharedByteBudget>,
    peer_reserve: Option<Arc<SharedByteBudget>>,
}
#[cfg(test)]
impl OutboundHighByteBudget {
    fn shared_only(shared: Arc<SharedByteBudget>) -> Self {
        Self {
            shared,
            peer_reserve: None,
        }
    }
    fn try_reserve(&self, bytes: usize, progress: bool) -> Option<SharedByteLease> {
        if !progress {
            return self.shared.try_reserve(bytes, false);
        }
        self.shared.try_reserve(bytes, false).or_else(|| {
            self.peer_reserve
                .as_ref()
                .and_then(|reserve| reserve.try_reserve(bytes, false))
        })
    }
}
impl OutboundPostByteBudgets {
    pub(crate) fn install_semantic(
        &self,
        maximum: [usize; crate::TransportAdmissionClass::COUNT],
    ) -> Result<Arc<post_admission::Pool>, Error> {
        let mut slot = self
            .semantic
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.upgrade().is_some() {
            return Err(Error::Format);
        }
        let pool = post_admission::Pool::new(self.clone(), maximum)?;
        *slot = Arc::downgrade(&pool);
        Ok(pool)
    }
    fn semantic(&self) -> Result<Arc<post_admission::Pool>, Error> {
        self.semantic
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upgrade()
            .ok_or(Error::Format)
    }

    pub(crate) fn new(
        high_max_bytes: usize,
        low_max_bytes: usize,
        progress_reserve_bytes_per_peer: usize,
        max_peer_reserves: usize,
    ) -> Option<Self> {
        Self::new_with_source_geometry(
            high_max_bytes,
            low_max_bytes,
            progress_reserve_bytes_per_peer,
            AuthenticatedSourceGeometry::new(max_peer_reserves),
        )
    }
    pub(crate) fn new_with_source_geometry(
        high_max_bytes: usize,
        low_max_bytes: usize,
        progress_reserve_bytes_per_peer: usize,
        source_geometry: AuthenticatedSourceGeometry,
    ) -> Option<Self> {
        progress_reserve_bytes_per_peer
            .checked_mul(source_geometry.max_sources)
            .and_then(|reserve| reserve.checked_add(high_max_bytes))
            .and_then(|high| high.checked_add(low_max_bytes))?;
        Some(Self {
            semantic: Arc::new(Mutex::new(Weak::new())),
            high: SharedByteBudget::new(high_max_bytes, 0)?,
            low: SharedByteBudget::new(low_max_bytes, 0)?,
            progress_reserve_bytes_per_peer,
            source_geometry,
        })
    }
    #[cfg(test)]
    fn high(&self, peer_id: &PeerId) -> Option<OutboundHighByteBudget> {
        if self.progress_reserve_bytes_per_peer == 0 {
            self.source_geometry.admit_ownerless_source(peer_id)?;
            return Some(OutboundHighByteBudget::shared_only(Arc::clone(&self.high)));
        }
        let peer_reserve = self
            .source_geometry
            .outbound_progress_owner(peer_id, self.progress_reserve_bytes_per_peer)?;
        Some(OutboundHighByteBudget {
            shared: Arc::clone(&self.high),
            peer_reserve: Some(peer_reserve),
        })
    }

    #[cfg(test)]
    fn low(&self) -> Arc<SharedByteBudget> {
        Arc::clone(&self.low)
    }
    #[cfg(test)]
    fn retained_high_total(&self) -> usize {
        let reserves = self.source_geometry.retained_outbound_progress_bytes();
        self.high
            .retained_total()
            .checked_add(reserves)
            .expect("configured test ownership geometry must fit")
    }
    #[cfg(test)]
    fn retained_high_ordinary(&self) -> usize {
        self.high.retained_ordinary()
    }
    #[cfg(test)]
    fn retained_low_total(&self) -> usize {
        self.low.retained_total()
    }
}
impl Default for OutboundPostByteBudgets {
    fn default() -> Self {
        let limits = OutboundFrameQueueLimits::default();
        Self::new(
            limits.high_max_bytes,
            limits.low_max_bytes,
            limits.progress_reserve_bytes,
            iroha_config::parameters::defaults::network::lane_profile::CORE_MAX_TOTAL_CONNECTIONS,
        )
        .expect("default process-wide outbound byte geometry must fit")
    }
}
impl Drop for SharedByteLease {
    fn drop(&mut self) {
        // `merge` defuses its redundant representation. Do not even take the
        // budget lock or notify waiters here: no capacity was released, and a
        // maximum-size frame may coalesce tens of thousands of chunks.
        if self.bytes == 0 {
            return;
        }
        {
            let mut state = self
                .budget
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.retained.total = state
                .retained
                .total
                .checked_sub(self.bytes)
                .expect("byte lease must have matching aggregate ownership");
            if !self.safety {
                state.retained.ordinary = state
                    .retained
                    .ordinary
                    .checked_sub(self.bytes)
                    .expect("ordinary byte lease must have matching ownership");
            }
        }
        self.budget.released.notify_waiters();
    }
}
/// Frame-allocation owners shared by every authenticated peer reader in one
/// network instance. High and low streams are separate so best-effort input
/// cannot consume progress-stream allocation capacity; each authenticated peer
/// also has exactly one source reserve shared across duplicate sessions.
/// Decryption reuses the source allocation, while alignment scratch is charged
/// to separate process-wide high/low pools with the corresponding configured
/// byte ceilings.
#[derive(Clone, Debug)]
pub(crate) struct InboundFrameByteBudgets {
    receive_credit_pool: Arc<Mutex<Weak<receive_credit::Pool>>>,
    high: Arc<SharedByteBudget>,
    low: Arc<SharedByteBudget>,
    high_decode_scratch: Arc<SharedByteBudget>,
    low_decode_scratch: Arc<SharedByteBudget>,
    progress_reserve_bytes_per_peer: usize,
    source_geometry: AuthenticatedSourceGeometry,
}
#[derive(Debug)]
struct AuthenticatedSourceCreditOwner {
    receive_partition: Mutex<Option<Arc<receive_credit::SourcePartition>>>,
    per_lane_capacity: usize,
    safety: Arc<Semaphore>,
    high: Arc<Semaphore>,
    low: Arc<Semaphore>,
}
impl AuthenticatedSourceCreditOwner {
    fn new(per_lane_capacity: usize) -> Self {
        assert!(
            per_lane_capacity > 0,
            "authenticated-source credit capacity must be non-zero"
        );
        Self {
            per_lane_capacity,
            receive_partition: Mutex::new(None),
            safety: Arc::new(Semaphore::new(per_lane_capacity)),
            high: Arc::new(Semaphore::new(per_lane_capacity)),
            low: Arc::new(Semaphore::new(per_lane_capacity)),
        }
    }
}
impl AuthenticatedSourceOwnerRegistry {
    fn prune(&mut self) {
        self.credit_owners
            .retain(|_, owner| owner.strong_count() != 0);
        self.inbound_progress_owners
            .retain(|_, owner| owner.strong_count() != 0);
        self.outbound_progress_owners
            .retain(|_, owner| owner.strong_count() != 0);
    }
    fn live_and_protected_sources(&self) -> Option<HashSet<PeerId>> {
        let mut sources = self.protected_sources.clone()?;
        sources.extend(self.credit_owners.keys().cloned());
        sources.extend(self.inbound_progress_owners.keys().cloned());
        sources.extend(self.outbound_progress_owners.keys().cloned());
        Some(sources)
    }
}
impl AuthenticatedSourceGeometry {
    pub(crate) fn new(max_sources: usize) -> Self {
        Self {
            max_sources,
            registry: Arc::new(Mutex::new(AuthenticatedSourceOwnerRegistry::default())),
        }
    }
    fn admit_ownerless_source(&self, peer_id: &PeerId) -> Option<()> {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.prune();
        let mut required = registry.live_and_protected_sources()?;
        required.insert(peer_id.clone());
        (required.len() <= self.max_sources).then_some(())
    }
    fn credit_owner(
        &self,
        peer_id: &PeerId,
        per_lane_capacity: usize,
    ) -> Option<Arc<AuthenticatedSourceCreditOwner>> {
        if per_lane_capacity == 0 {
            return None;
        }
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.prune();
        if let Some(owner) = registry.credit_owners.get(peer_id).and_then(Weak::upgrade) {
            return (owner.per_lane_capacity == per_lane_capacity).then_some(owner);
        }
        let mut required = registry.live_and_protected_sources()?;
        required.insert(peer_id.clone());
        if required.len() > self.max_sources {
            return None;
        }
        let owner = Arc::new(AuthenticatedSourceCreditOwner::new(per_lane_capacity));
        registry
            .credit_owners
            .insert(peer_id.clone(), Arc::downgrade(&owner));
        Some(owner)
    }
    fn inbound_progress_owner(
        &self,
        peer_id: &PeerId,
        bytes: usize,
    ) -> Option<Arc<SharedByteBudget>> {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.prune();
        if let Some(owner) = registry
            .inbound_progress_owners
            .get(peer_id)
            .and_then(Weak::upgrade)
        {
            return Some(owner);
        }
        let mut required = registry.live_and_protected_sources()?;
        required.insert(peer_id.clone());
        if required.len() > self.max_sources {
            return None;
        }
        let owner = SharedByteBudget::new(bytes, 0)
            .expect("non-zero inbound per-source progress reserve cannot overflow");
        registry
            .inbound_progress_owners
            .insert(peer_id.clone(), Arc::downgrade(&owner));
        Some(owner)
    }
    fn outbound_progress_owner(
        &self,
        peer_id: &PeerId,
        bytes: usize,
    ) -> Option<Arc<SharedByteBudget>> {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.prune();
        if let Some(owner) = registry
            .outbound_progress_owners
            .get(peer_id)
            .and_then(Weak::upgrade)
        {
            return Some(owner);
        }
        let mut required = registry.live_and_protected_sources()?;
        required.insert(peer_id.clone());
        if required.len() > self.max_sources {
            return None;
        }
        let owner = SharedByteBudget::new(bytes, 0)
            .expect("non-zero outbound per-source progress reserve cannot overflow");
        registry
            .outbound_progress_owners
            .insert(peer_id.clone(), Arc::downgrade(&owner));
        Some(owner)
    }
    fn install_protected_sources(&self, protected_sources: HashSet<PeerId>) -> bool {
        if protected_sources.len() > self.max_sources {
            return false;
        }
        self.registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .protected_sources = Some(protected_sources);
        true
    }
    fn protected_sources(&self) -> Option<HashSet<PeerId>> {
        self.registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .protected_sources
            .clone()
    }
    fn protected_source_geometry_fits(&self) -> bool {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.prune();
        registry
            .live_and_protected_sources()
            .is_some_and(|sources| sources.len() <= self.max_sources)
    }
    #[cfg(test)]
    fn retained_outbound_progress_bytes(&self) -> usize {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.prune();
        registry
            .outbound_progress_owners
            .values()
            .filter_map(Weak::upgrade)
            .map(|budget| budget.retained_total())
            .sum()
    }
}
#[derive(Clone, Debug)]
struct InboundSourceByteBudget {
    #[cfg(any(test, feature = "quic"))]
    shared: Arc<SharedByteBudget>,
    peer_reserve: Option<Arc<SharedByteBudget>>,
    #[cfg(test)]
    decode_scratch: Arc<SharedByteBudget>,
}
impl InboundSourceByteBudget {
    #[cfg(any(test, feature = "quic"))]
    fn try_reserve(&self, bytes: usize) -> Option<SharedByteLease> {
        self.shared.try_reserve(bytes, false).or_else(|| {
            self.peer_reserve
                .as_ref()
                .and_then(|reserve| reserve.try_reserve(bytes, false))
        })
    }
    #[cfg(test)]
    async fn reserve(&self, bytes: usize) -> Option<SharedByteLease> {
        if let Some(lease) = self.try_reserve(bytes) {
            return Some(lease);
        }
        let Some(peer_reserve) = self.peer_reserve.as_ref() else {
            return self.shared.reserve(bytes, false).await;
        };
        let shared_can_fit = bytes <= self.shared.class_max_bytes(false);
        let peer_can_fit = bytes <= peer_reserve.class_max_bytes(false);
        match (shared_can_fit, peer_can_fit) {
            (false, false) => return None,
            (true, false) => return self.shared.reserve(bytes, false).await,
            (false, true) => return peer_reserve.reserve(bytes, false).await,
            (true, true) => {}
        }
        // Register with both fair owners.  This matters when duplicate or
        // replacement sessions for one authenticated peer overlap: the
        // shared pool may remain saturated by ordinary traffic while the
        // peer-local progress reserve becomes available. Dropping the losing
        // reservation future removes its ticket, so cancellation and the
        // successful branch cannot leave a phantom waiter behind.
        tokio::select! {
            biased;
            lease = self.shared.reserve(bytes, false) => lease,
            lease = peer_reserve.reserve(bytes, false) => lease,
        }
    }
    #[cfg(test)]
    async fn reserve_decode_scratch(&self, bytes: usize) -> Option<SharedByteLease> {
        self.decode_scratch.reserve(bytes, false).await
    }
}
impl InboundFrameByteBudgets {
    fn admitted_receive_credit_pool(&self) -> Result<Arc<receive_credit::Pool>, Error> {
        self.receive_credit_pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upgrade()
            .ok_or(Error::Format)
    }

    pub(crate) fn new(
        high_max_bytes: usize,
        low_max_bytes: usize,
        progress_reserve_bytes_per_peer: usize,
        max_peer_reserves: usize,
    ) -> Option<Self> {
        Self::new_with_source_geometry(
            high_max_bytes,
            low_max_bytes,
            progress_reserve_bytes_per_peer,
            AuthenticatedSourceGeometry::new(max_peer_reserves),
        )
    }
    pub(crate) fn new_with_source_geometry(
        high_max_bytes: usize,
        low_max_bytes: usize,
        progress_reserve_bytes_per_peer: usize,
        source_geometry: AuthenticatedSourceGeometry,
    ) -> Option<Self> {
        progress_reserve_bytes_per_peer
            .checked_mul(source_geometry.max_sources)
            .and_then(|reserve| reserve.checked_add(high_max_bytes))
            .and_then(|high| high.checked_add(low_max_bytes))
            .and_then(|source| source.checked_add(high_max_bytes))
            .and_then(|source_and_high_scratch| {
                source_and_high_scratch.checked_add(low_max_bytes)
            })?;
        Some(Self {
            high: SharedByteBudget::new(high_max_bytes, 0)?,
            low: SharedByteBudget::new(low_max_bytes, 0)?,
            receive_credit_pool: Arc::new(Mutex::new(Weak::new())),
            high_decode_scratch: SharedByteBudget::new(high_max_bytes, 0)?,
            low_decode_scratch: SharedByteBudget::new(low_max_bytes, 0)?,
            progress_reserve_bytes_per_peer,
            source_geometry,
        })
    }
    /// Install the complete protected authenticated-source projection.
    ///
    /// This changes only the virtual reservation set; live owner identity and
    /// permits are untouched. An unrepresentable projection is rejected and
    /// leaves the last installed authority intact.
    pub(crate) fn install_protected_sources(&self, protected_sources: HashSet<PeerId>) -> bool {
        self.source_geometry
            .install_protected_sources(protected_sources)
    }
    /// Return the actor-installed protected source projection, if initialized.
    pub(crate) fn protected_sources(&self) -> Option<HashSet<PeerId>> {
        self.source_geometry.protected_sources()
    }
    /// Return whether every live owner and installed protected identity fits.
    pub(crate) fn protected_source_geometry_fits(&self) -> bool {
        self.source_geometry.protected_source_geometry_fits()
    }
    /// Return the one count-credit owner for an authenticated peer identity.
    ///
    /// Existing owners are reused before any cardinality check. For a new
    /// identity `x`, admission is exactly
    /// `|live owners ∪ protected sources ∪ {x}| <= max_peer_reserves`.
    /// The registry remains fail-closed until the actor installs its first
    /// protected projection.
    pub(crate) fn source_credits(
        &self,
        peer_id: &PeerId,
        per_lane_capacity: usize,
    ) -> Option<message::AuthenticatedSourceCredits> {
        if per_lane_capacity == 0 {
            return None;
        }
        let owner = self
            .source_geometry
            .credit_owner(peer_id, per_lane_capacity)?;
        Some(message::AuthenticatedSourceCredits::from_owner(owner))
    }
    fn high(&self, peer_id: &PeerId) -> Option<InboundSourceByteBudget> {
        if self.progress_reserve_bytes_per_peer == 0 {
            self.source_geometry.admit_ownerless_source(peer_id)?;
            return Some(InboundSourceByteBudget {
                #[cfg(any(test, feature = "quic"))]
                shared: Arc::clone(&self.high),
                peer_reserve: None,
                #[cfg(test)]
                decode_scratch: Arc::clone(&self.high_decode_scratch),
            });
        }
        let peer_reserve = self
            .source_geometry
            .inbound_progress_owner(peer_id, self.progress_reserve_bytes_per_peer)?;
        Some(InboundSourceByteBudget {
            #[cfg(any(test, feature = "quic"))]
            shared: Arc::clone(&self.high),
            peer_reserve: Some(peer_reserve),
            #[cfg(test)]
            decode_scratch: Arc::clone(&self.high_decode_scratch),
        })
    }
    #[cfg(test)]
    fn low(&self) -> InboundSourceByteBudget {
        InboundSourceByteBudget {
            shared: Arc::clone(&self.low),
            peer_reserve: None,
            decode_scratch: Arc::clone(&self.low_decode_scratch),
        }
    }
}
impl Default for InboundFrameByteBudgets {
    fn default() -> Self {
        let high =
            iroha_config::parameters::defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_BYTES
                .get();
        let high_peer_reserve = crate::frame_queue_charge(
            iroha_config::parameters::defaults::network::MAX_PLAINTEXT_FRAME_BYTES.get(),
        )
        .expect("default maximum progress-frame charge must fit");
        Self::new(
            high,
            iroha_config::parameters::defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_BYTES
                .get(),
            high_peer_reserve,
            iroha_config::parameters::defaults::network::lane_profile::CORE_MAX_TOTAL_CONNECTIONS,
        )
        .expect("default inbound frame budgets must fit")
    }
}
/// Classified downstream byte owners spanning network dispatch, subscriber
/// backlogs, subscriber channels, and relay-worker queues.
#[derive(Clone, Debug)]
pub(crate) struct InboundDispatchByteBudgets {
    high: Arc<SharedByteBudget>,
    low: Arc<SharedByteBudget>,
}
impl InboundDispatchByteBudgets {
    pub(crate) fn new(
        high_max_bytes: usize,
        low_max_bytes: usize,
        safety_reserve_bytes: usize,
    ) -> Option<Self> {
        Some(Self {
            high: SharedByteBudget::new(high_max_bytes, safety_reserve_bytes)?,
            low: SharedByteBudget::new(low_max_bytes, 0)?,
        })
    }
    fn budget(&self, high: bool) -> Arc<SharedByteBudget> {
        if high {
            Arc::clone(&self.high)
        } else {
            Arc::clone(&self.low)
        }
    }
}
impl Default for InboundDispatchByteBudgets {
    fn default() -> Self {
        Self::new(
            iroha_config::parameters::defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_BYTES
                .get(),
            iroha_config::parameters::defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_BYTES
                .get(),
            crate::frame_queue_charge(
                iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_CONTROL.get(),
            )
            .expect("default safety dispatch charge must fit"),
        )
        .expect("default inbound dispatch budgets must fit")
    }
}
#[derive(Clone, Debug)]
struct InboundFrameRetention {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retains source custody until its final owner drops"
        )
    )]
    source: Arc<InboundFrameSourceLeases>,
    frame_queue_overhead_bytes: usize,
}
#[derive(Debug)]
struct InboundFrameSourceLeases {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "RAII leases retain the original physical backing")
    )]
    leases: Vec<SharedByteLease>,
    #[cfg(test)]
    retained_bytes: usize,
}
#[cfg(test)]
impl InboundFrameRetention {
    fn new(source: SharedByteLease, frame_queue_overhead_bytes: usize) -> Self {
        let retained_bytes = source.bytes;
        Self {
            source: Arc::new(InboundFrameSourceLeases {
                leases: vec![source],
                retained_bytes,
            }),
            frame_queue_overhead_bytes,
        }
    }
    fn retained_bytes(&self) -> usize {
        self.source.retained_bytes
    }
    fn extend(&mut self, source: SharedByteLease) -> Option<()> {
        let owned = Arc::get_mut(&mut self.source)?;
        let retained_bytes = owned.retained_bytes.checked_add(source.bytes)?;
        if let Some(existing) = owned
            .leases
            .iter_mut()
            .find(|existing| existing.same_owner(&source))
        {
            existing.merge(source).ok()?;
        } else {
            owned.leases.push(source);
        }
        debug_assert!(
            owned.leases.len() <= SOURCE_RETENTION_MAX_LEASES,
            "one frame may retain only the shared and PeerId source owners"
        );
        owned.retained_bytes = retained_bytes;
        Some(())
    }
}
#[derive(Debug)]
struct DispatchRetention {
    _byte_lease: SharedByteLease,
    budget: Arc<SharedByteBudget>,
    frame_queue_overhead_bytes: usize,
    safety: bool,
}
impl DispatchRetention {
    fn try_clone_for_payload(&self, payload_bytes: usize) -> Option<Self> {
        let bytes = payload_bytes.checked_add(self.frame_queue_overhead_bytes)?;
        Some(Self {
            _byte_lease: self.budget.try_reserve(bytes, self.safety)?,
            budget: Arc::clone(&self.budget),
            frame_queue_overhead_bytes: self.frame_queue_overhead_bytes,
            safety: self.safety,
        })
    }
}
#[derive(Debug)]
enum PeerMessageRetention {
    Granted(receive_credit::GrantRetention),
    Source(InboundFrameRetention),
    Dispatch(DispatchRetention),
}
/// Ownership that follows one admitted post through the complete stream-write
/// pipeline.
///
/// The optional completion sender is deliberately inseparable from the byte
/// lease.  Dropping any intermediate owner closes the corresponding receiver;
/// the only successful completion path is [`Self::acknowledge_flush`], which is
/// called after the complete socket batch has been written and flushed.
///
/// This is an at-least-once boundary, not a remote-consumption acknowledgement:
/// the remote may observe a complete write even when replacement or teardown
/// closes the local acknowledgement before flush completes. Callers therefore
/// retry on closure, and downstream semantic consumers must be idempotent or
/// deduplicate authenticated message identities.
#[derive(Debug)]
struct OutboundPostOwnership {
    _byte_lease: Option<SharedByteLease>,
    _semantic_lease: Option<post_admission::Lease>,
    flush_ack: Option<oneshot::Sender<()>>,
    /// Declared last: it wakes the network actor only after the byte leases
    /// are released and the acknowledgement is sent or abandoned.
    flush_notice: Option<crate::network::WriterFlushNotice>,
}
impl OutboundPostOwnership {
    fn new(byte_lease: SharedByteLease, flush_ack: Option<oneshot::Sender<()>>) -> Self {
        Self {
            _byte_lease: Some(byte_lease),
            _semantic_lease: None,
            flush_ack,
            flush_notice: None,
        }
    }
    fn granted(lease: post_admission::Lease) -> Self {
        Self {
            _byte_lease: None,
            _semantic_lease: Some(lease),
            flush_ack: None,
            flush_notice: None,
        }
    }
    fn acknowledge_flush(mut self) {
        if let Some(flush_ack) = self.flush_ack.take() {
            let _ = flush_ack.send(());
        }
    }
    /// Release a post the writer never accepted without waking the actor:
    /// the refusing caller already retains the occurrence for its retry.
    fn release_refused(mut self) {
        if let Some(notice) = self.flush_notice.take() {
            notice.disarm();
        }
    }
}
impl From<SharedByteLease> for OutboundPostOwnership {
    fn from(byte_lease: SharedByteLease) -> Self {
        Self::new(byte_lease, None)
    }
}
struct RetainedPost<T> {
    message: Option<T>,
    ownership: OutboundPostOwnership,
}
impl<T> RetainedPost<T> {
    fn new(message: T, ownership: OutboundPostOwnership) -> Self {
        Self {
            message: Some(message),
            ownership,
        }
    }
    fn into_parts(self) -> (T, OutboundPostOwnership) {
        let Self {
            mut message,
            ownership,
        } = self;
        (
            message
                .take()
                .expect("retained post must be consumed exactly once"),
            ownership,
        )
    }
    #[cfg(test)]
    fn into_inner(self) -> T {
        self.into_parts().0
    }
    #[cfg(test)]
    fn into_inner_and_acknowledge_flush(self) -> T {
        let (message, ownership) = self.into_parts();
        ownership.acknowledge_flush();
        message
    }
}
#[cfg(test)]
mod shared_byte_budget_tests {
    use super::*;
    #[test]
    fn ordinary_cannot_consume_the_safety_reserve() {
        let budget = SharedByteBudget::new(10, 3).expect("valid budget geometry");
        let ordinary = budget
            .try_reserve(10, false)
            .expect("ordinary exact boundary");
        assert!(budget.try_reserve(1, false).is_none());
        let safety = budget
            .try_reserve(3, true)
            .expect("safety exact reserve boundary");
        assert!(budget.try_reserve(1, true).is_none());
        assert_eq!(
            budget.retained(),
            SharedRetainedBytes {
                total: 13,
                ordinary: 10,
            }
        );
        drop(ordinary);
        assert!(budget.try_reserve(10, false).is_some());
        drop(safety);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn frame_retention_coalesces_each_distinct_source_owner_without_reaccounting() {
        let shared = SharedByteBudget::new(2, 0).expect("shared source owner");
        let peer = SharedByteBudget::new(2, 0).expect("PeerId source owner");
        let first_shared = shared.try_reserve(1, false).expect("first shared chunk");
        let second_shared = shared.try_reserve(1, false).expect("second shared chunk");
        let first_peer = peer.try_reserve(1, false).expect("first peer chunk");
        let second_peer = peer.try_reserve(1, false).expect("second peer chunk");
        let waiting_budget = Arc::clone(&shared);
        let waiter = tokio::spawn(async move {
            waiting_budget
                .reserve(2, false)
                .await
                .expect("aggregate release must admit the queued waiter")
        });
        tokio::task::yield_now().await;
        assert_eq!(
            shared
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .ordinary_waiters
                .len(),
            1,
            "the replacement owner must be queued before leases coalesce"
        );
        let released = shared.released.notified();
        tokio::pin!(released);
        released.as_mut().enable();
        let mut retention = InboundFrameRetention::new(first_shared, 0);
        retention
            .extend(second_shared)
            .expect("same-owner chunk coalesces");
        tokio::select! {
            biased;
            () = released.as_mut() => panic!("coalescing must not signal a capacity release"),
            () = std::future::ready(()) => {}
        }
        assert!(
            !waiter.is_finished(),
            "a defused lease cannot advance a waiter before aggregate ownership drops"
        );
        retention
            .extend(first_peer)
            .expect("second owner is retained");
        retention
            .extend(second_peer)
            .expect("peer-owner chunk coalesces");
        assert_eq!(retention.source.leases.len(), SOURCE_RETENTION_MAX_LEASES);
        assert_eq!(retention.retained_bytes(), 4);
        assert_eq!(shared.retained_total(), 2);
        assert_eq!(peer.retained_total(), 2);
        drop(retention);
        released.as_mut().await;
        let resumed = waiter.await.expect("queued waiter task must complete");
        assert_eq!(shared.retained_total(), 2);
        assert_eq!(peer.retained_total(), 0);
        drop(resumed);
        assert_eq!(shared.retained_total(), 0);
    }
    #[tokio::test]
    async fn queued_waiter_prevents_barging_and_cancellation_releases_rank() {
        let budget = SharedByteBudget::new(1, 0).expect("valid budget geometry");
        let held = budget.try_reserve(1, false).expect("initial lease");
        let waiting_budget = Arc::clone(&budget);
        let waiter = tokio::spawn(async move { waiting_budget.reserve(1, false).await });
        tokio::task::yield_now().await;
        assert!(
            budget.try_reserve(0, false).is_none(),
            "a fresh producer must not barge ahead of the queued waiter"
        );
        waiter.abort();
        let _ = waiter.await;
        tokio::task::yield_now().await;
        assert!(budget.try_reserve(0, false).is_some());
        drop(held);
        assert!(budget.try_reserve(1, false).is_some());
    }
    #[tokio::test]
    async fn equal_class_waiters_are_served_fifo() {
        let budget = SharedByteBudget::new(1, 0).expect("valid budget geometry");
        let held = budget.try_reserve(1, false).expect("initial lease");
        let (first_release_tx, first_release_rx) = tokio::sync::oneshot::channel();
        let (first_ready_tx, first_ready_rx) = tokio::sync::oneshot::channel();
        let first_budget = Arc::clone(&budget);
        let first = tokio::spawn(async move {
            let lease = first_budget.reserve(1, false).await.expect("first lease");
            let _ = first_ready_tx.send(());
            let _ = first_release_rx.await;
            drop(lease);
        });
        tokio::task::yield_now().await;
        let second_budget = Arc::clone(&budget);
        let (second_ready_tx, mut second_ready_rx) = tokio::sync::oneshot::channel();
        let second = tokio::spawn(async move {
            let lease = second_budget.reserve(1, false).await.expect("second lease");
            let _ = second_ready_tx.send(());
            lease
        });
        tokio::task::yield_now().await;
        drop(held);
        first_ready_rx.await.expect("first waiter served");
        assert!(
            second_ready_rx.try_recv().is_err(),
            "second waiter must remain behind the first"
        );
        first_release_tx.send(()).expect("release first lease");
        second_ready_rx.await.expect("second waiter served");
        drop(second.await.expect("second waiter task"));
        first.await.expect("first waiter task");
    }
    #[tokio::test(flavor = "current_thread")]
    async fn exhausted_ticket_sequence_fails_closed_while_a_waiter_is_live() {
        let budget = SharedByteBudget::new(1, 0).expect("valid budget geometry");
        let held = budget.try_reserve(1, false).expect("initial lease");
        {
            let mut state = budget
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.next_ticket = u64::MAX - 1;
        }
        let waiting_budget = Arc::clone(&budget);
        let waiter = tokio::spawn(async move { waiting_budget.reserve(1, false).await });
        tokio::task::yield_now().await;
        {
            let state = budget
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(state.next_ticket, u64::MAX);
            assert_eq!(state.ordinary_waiters, VecDeque::from([u64::MAX - 1]));
        }
        assert!(
            budget.reserve(0, false).await.is_none(),
            "ticket exhaustion must not wrap into a live FIFO"
        );
        drop(held);
        drop(
            waiter
                .await
                .expect("waiter task must finish")
                .expect("pre-exhaustion waiter must retain its rank"),
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn exhausted_ticket_sequence_resets_only_after_all_waiters_leave() {
        let budget = SharedByteBudget::new(1, 1).expect("valid budget geometry");
        {
            let mut state = budget
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.next_ticket = u64::MAX;
        }
        let lease = budget
            .reserve(0, false)
            .await
            .expect("an empty FIFO permits a collision-free sequence reset");
        let state = budget
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(state.next_ticket, 1);
        assert!(state.ordinary_waiters.is_empty());
        assert!(state.safety_waiters.is_empty());
        drop(state);
        drop(lease);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn ordinary_waiter_prevents_safety_from_reborrowing_ordinary_capacity() {
        let budget = SharedByteBudget::new(1, 1).expect("valid budget geometry");
        let borrowed = budget
            .try_reserve(2, true)
            .expect("safety may borrow idle ordinary capacity");
        let waiting_budget = Arc::clone(&budget);
        let ordinary = tokio::spawn(async move {
            waiting_budget
                .reserve(1, false)
                .await
                .expect("ordinary waiter must eventually acquire its class capacity")
        });
        tokio::task::yield_now().await;
        assert_eq!(
            budget
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .ordinary_waiters
                .len(),
            1,
            "ordinary waiter must be registered before the adversarial reacquisition"
        );
        drop(borrowed);
        assert!(
            budget.try_reserve(2, true).is_none(),
            "sustained safety traffic must not immediately re-borrow capacity owed to an ordinary waiter"
        );
        let safety_reserve = budget
            .try_reserve(1, true)
            .expect("the additive safety reserve remains available");
        let ordinary_lease = tokio::time::timeout(Duration::from_secs(1), ordinary)
            .await
            .expect("safety reserve use must not starve the ordinary waiter")
            .expect("ordinary waiter task must not panic");
        assert_eq!(
            budget.retained(),
            SharedRetainedBytes {
                total: 2,
                ordinary: 1,
            }
        );
        drop((ordinary_lease, safety_reserve));
    }
    #[test]
    fn duplicate_sessions_share_one_authenticated_peer_reserve() {
        let budgets = InboundFrameByteBudgets::new(1, 1, 2, 2).expect("valid source geometry");
        assert!(budgets.install_protected_sources(HashSet::new()));
        let peer_id = random_node_peer_id();
        let first = budgets.high(&peer_id).expect("first peer reserve");
        let second = budgets.high(&peer_id).expect("duplicate peer reserve");
        let first_reserve = first.peer_reserve.as_ref().expect("peer reserve");
        let second_reserve = second.peer_reserve.as_ref().expect("peer reserve");
        assert!(Arc::ptr_eq(first_reserve, second_reserve));
        let _shared = budgets
            .high
            .try_reserve(1, false)
            .expect("fill shared source owner");
        let _peer = first
            .try_reserve(2)
            .expect("exact peer reserve remains available");
        assert!(
            second.try_reserve(1).is_none(),
            "a replacement session must not multiply one peer's reserve"
        );
        let other_peer = random_node_peer_id();
        assert!(
            budgets
                .high(&other_peer)
                .expect("second distinct reserve remains within the cap")
                .try_reserve(2)
                .is_some(),
            "a distinct authenticated peer has an independent progress reserve"
        );
    }
    #[test]
    fn authenticated_peer_reserve_registry_fails_closed_at_its_bound() {
        let budgets = InboundFrameByteBudgets::new(1, 1, 2, 1).expect("valid source geometry");
        assert!(budgets.install_protected_sources(HashSet::new()));
        let first_peer = random_node_peer_id();
        let second_peer = random_node_peer_id();
        let first = budgets.high(&first_peer).expect("first reserve");
        assert!(
            budgets.high(&first_peer).is_some(),
            "a duplicate session must reuse the existing bounded reserve"
        );
        assert!(
            budgets.high(&second_peer).is_none(),
            "a distinct authenticated peer must fail closed while every reserve slot is live"
        );
        drop(first);
        assert!(
            budgets.high(&second_peer).is_some(),
            "dropping the last strong owner must recycle its weak-registry slot"
        );
    }
    #[test]
    fn authenticated_source_count_registry_bounds_identity_churn_and_capacity_drift() {
        let budgets = InboundFrameByteBudgets::new(1, 1, 1, 1).expect("valid source geometry");
        assert!(budgets.install_protected_sources(HashSet::new()));
        let first_peer = random_node_peer_id();
        let second_peer = random_node_peer_id();
        let first = budgets
            .source_credits(&first_peer, 1)
            .expect("first count owner");
        let permit = first
            .try_acquire_high_for_test()
            .expect("first identity acquires its only high-lane credit");
        let duplicate = budgets
            .source_credits(&first_peer, 1)
            .expect("duplicate connection reuses the existing owner");
        assert!(
            duplicate.try_acquire_high_for_test().is_none(),
            "a duplicate connection must observe the already-consumed credit"
        );
        assert!(
            budgets.source_credits(&second_peer, 1).is_none(),
            "a distinct identity must fail closed while the sole registry slot is live"
        );
        assert!(
            budgets.source_credits(&first_peer, 2).is_none(),
            "a capacity mismatch must not replace a live identity owner"
        );
        let after_mismatch = budgets
            .source_credits(&first_peer, 1)
            .expect("the original owner survives a rejected capacity mismatch");
        assert!(after_mismatch.try_acquire_high_for_test().is_none());
        drop((first, duplicate, after_mismatch));
        assert!(
            budgets.source_credits(&second_peer, 1).is_none(),
            "the permit itself must keep the first identity's weak entry live"
        );
        drop(permit);
        let recycled = budgets
            .source_credits(&second_peer, 1)
            .expect("terminal ownership release lets weak-entry pruning recycle the slot");
        assert!(
            recycled.try_acquire_high_for_test().is_some(),
            "the recycled owner exposes its configured lane capacity"
        );
    }
    #[test]
    fn pending_protected_sources_reserve_released_owner_slots_from_identity_churn() {
        let budgets = InboundFrameByteBudgets::new(1, 1, 1, 1).expect("valid source geometry");
        let old_source = random_node_peer_id();
        let desired_source = random_node_peer_id();
        let observer = random_node_peer_id();
        assert!(budgets.install_protected_sources(HashSet::new()));
        let old_owner = budgets
            .source_credits(&old_source, 1)
            .expect("old source owns the sole live slot");
        assert!(budgets.install_protected_sources(HashSet::from([desired_source.clone()])));
        assert!(
            !budgets.protected_source_geometry_fits(),
            "the desired projection waits for the obsolete live owner"
        );
        assert!(
            budgets.source_credits(&old_source, 1).is_some(),
            "an existing owner reconnect is reused before cardinality checks"
        );
        assert!(budgets.source_credits(&desired_source, 1).is_none());
        assert!(
            budgets.source_credits(&observer, 1).is_none(),
            "observer churn cannot steal the virtually reserved slot"
        );
        drop(old_owner);
        assert!(budgets.protected_source_geometry_fits());
        assert!(budgets.source_credits(&desired_source, 1).is_some());
    }
    #[test]
    fn impossible_protected_projection_preserves_last_valid_authority() {
        let budgets = InboundFrameByteBudgets::new(1, 1, 1, 1).expect("valid source geometry");
        let protected = random_node_peer_id();
        let overflow = random_node_peer_id();
        let observer = random_node_peer_id();
        assert!(budgets.install_protected_sources(HashSet::from([protected.clone()])));
        assert!(!budgets.install_protected_sources(HashSet::from([protected.clone(), overflow,])));
        assert!(
            budgets.source_credits(&observer, 1).is_none(),
            "a rejected projection cannot erase the prior reservation"
        );
        assert!(budgets.source_credits(&protected, 1).is_some());
    }
    #[test]
    fn authenticated_source_byte_reserves_fail_closed_until_authority_is_installed() {
        let geometry = AuthenticatedSourceGeometry::new(1);
        let inbound = InboundFrameByteBudgets::new_with_source_geometry(1, 1, 1, geometry.clone())
            .expect("valid inbound source geometry");
        let outbound = OutboundPostByteBudgets::new_with_source_geometry(1, 1, 1, geometry.clone())
            .expect("valid outbound source geometry");
        let observer = random_node_peer_id();
        assert!(inbound.high(&observer).is_none());
        assert!(outbound.high(&observer).is_none());
        assert!(inbound.source_credits(&observer, 1).is_none());
        assert!(geometry.install_protected_sources(HashSet::new()));
        assert!(inbound.high(&observer).is_some());
        assert!(outbound.high(&observer).is_some());
        assert!(inbound.source_credits(&observer, 1).is_some());
    }
    #[test]
    fn inbound_only_obsolete_lease_defers_protected_source_until_drain() {
        let geometry = AuthenticatedSourceGeometry::new(1);
        let inbound = InboundFrameByteBudgets::new_with_source_geometry(1, 1, 2, geometry.clone())
            .expect("valid inbound source geometry");
        let old_source = random_node_peer_id();
        let desired_source = random_node_peer_id();
        assert!(geometry.install_protected_sources(HashSet::new()));
        let old_budget = inbound.high(&old_source).expect("old inbound owner");
        let old_lease = old_budget
            .try_reserve(2)
            .expect("retain only the old source's inbound progress reserve");
        drop(old_budget);
        assert!(geometry.install_protected_sources(HashSet::from([desired_source.clone()])));
        assert!(!geometry.protected_source_geometry_fits());
        assert!(inbound.high(&desired_source).is_none());
        assert!(inbound.source_credits(&desired_source, 1).is_none());
        drop(old_lease);
        assert!(geometry.protected_source_geometry_fits());
        assert!(inbound.high(&desired_source).is_some());
    }
    #[test]
    fn outbound_only_obsolete_lease_defers_protected_source_until_drain() {
        let geometry = AuthenticatedSourceGeometry::new(1);
        let outbound = OutboundPostByteBudgets::new_with_source_geometry(1, 1, 2, geometry.clone())
            .expect("valid outbound source geometry");
        let old_source = random_node_peer_id();
        let desired_source = random_node_peer_id();
        assert!(geometry.install_protected_sources(HashSet::new()));
        let old_budget = outbound.high(&old_source).expect("old outbound owner");
        let old_lease = old_budget
            .try_reserve(2, true)
            .expect("retain only the old source's outbound progress reserve");
        drop(old_budget);
        assert!(geometry.install_protected_sources(HashSet::from([desired_source.clone()])));
        assert!(!geometry.protected_source_geometry_fits());
        assert!(outbound.high(&desired_source).is_none());
        drop(old_lease);
        assert!(geometry.protected_source_geometry_fits());
        assert!(outbound.high(&desired_source).is_some());
    }
    #[test]
    fn shared_source_geometry_counts_all_owner_kinds_by_unique_peer_id() {
        let geometry = AuthenticatedSourceGeometry::new(1);
        let inbound = InboundFrameByteBudgets::new_with_source_geometry(1, 1, 1, geometry.clone())
            .expect("valid inbound source geometry");
        let outbound = OutboundPostByteBudgets::new_with_source_geometry(1, 1, 1, geometry.clone())
            .expect("valid outbound source geometry");
        let first = random_node_peer_id();
        let second = random_node_peer_id();
        assert!(geometry.install_protected_sources(HashSet::new()));
        let inbound_first = inbound.high(&first).expect("first inbound owner");
        let outbound_first = outbound
            .high(&first)
            .expect("same source may own an outbound reserve");
        let credits_first = inbound
            .source_credits(&first, 1)
            .expect("same source may own lane credits");
        assert!(inbound.high(&second).is_none());
        assert!(outbound.high(&second).is_none());
        assert!(inbound.source_credits(&second, 1).is_none());
        drop((inbound_first, outbound_first, credits_first));
        assert!(inbound.high(&second).is_some());
    }
    #[test]
    fn inbound_source_registry_geometry_overflow_fails_closed() {
        assert!(InboundFrameByteBudgets::new(0, 0, usize::MAX, 2).is_none());
        assert!(InboundFrameByteBudgets::new(usize::MAX, 1, 0, 0).is_none());
    }
    #[test]
    fn outbound_duplicate_sessions_share_one_peer_reserve_without_blocking_another_peer() {
        let budgets =
            OutboundPostByteBudgets::new(1, 1, 2, 2).expect("valid connected-outbound geometry");
        assert!(
            budgets
                .source_geometry
                .install_protected_sources(HashSet::new())
        );
        let first_peer = random_node_peer_id();
        let other_peer = random_node_peer_id();
        let first = budgets.high(&first_peer).expect("first peer reserve");
        let replacement = budgets.high(&first_peer).expect("replacement peer reserve");
        let other = budgets.high(&other_peer).expect("other peer reserve");
        assert!(Arc::ptr_eq(
            first.peer_reserve.as_ref().expect("first reserve"),
            replacement
                .peer_reserve
                .as_ref()
                .expect("replacement reserve")
        ));
        let _ordinary = first
            .try_reserve(1, false)
            .expect("saturate shared ordinary H");
        let _stalled_peer = first
            .try_reserve(2, true)
            .expect("first peer may fill exactly its R");
        assert!(
            replacement.try_reserve(1, true).is_none(),
            "a replacement must not multiply the stalled peer's reserve"
        );
        assert!(
            other.try_reserve(2, true).is_some(),
            "a stalled peer must not consume another authenticated peer's R"
        );
        assert!(
            other.try_reserve(1, false).is_none(),
            "ordinary traffic must never consume any peer reserve"
        );
    }
    #[test]
    fn outbound_peer_registry_and_process_geometry_fail_closed() {
        assert!(OutboundPostByteBudgets::new(0, 0, usize::MAX, 2).is_none());
        assert!(OutboundPostByteBudgets::new(usize::MAX, 1, 0, 0).is_none());
        let budgets = OutboundPostByteBudgets::new(1, 1, 1, 1)
            .expect("valid one-peer connected-outbound geometry");
        assert!(
            budgets
                .source_geometry
                .install_protected_sources(HashSet::new())
        );
        let first_peer = random_node_peer_id();
        let second_peer = random_node_peer_id();
        let first = budgets.high(&first_peer).expect("first reserve");
        assert!(budgets.high(&first_peer).is_some());
        assert!(budgets.high(&second_peer).is_none());
        drop(first);
        assert!(budgets.high(&second_peer).is_some());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn source_reservation_ignores_an_owner_too_small_for_the_request() {
        let shared = SharedByteBudget::new(2, 0).expect("shared owner");
        let peer_reserve = SharedByteBudget::new(1, 0).expect("peer reserve");
        let held = shared
            .try_reserve(2, false)
            .expect("saturate the only owner large enough for the request");
        let budget = InboundSourceByteBudget {
            shared: Arc::clone(&shared),
            peer_reserve: Some(peer_reserve),
            decode_scratch: SharedByteBudget::new(2, 0).expect("decode scratch owner"),
        };
        let mut waiting = Box::pin(budget.reserve(2));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), waiting.as_mut())
                .await
                .is_err(),
            "an undersized peer reserve must not turn temporary shared saturation into rejection"
        );
        drop(held);
        assert!(waiting.await.is_some());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn source_reservation_waits_on_peer_when_shared_owner_is_too_small() {
        let shared = SharedByteBudget::new(1, 0).expect("shared owner");
        let peer_reserve = SharedByteBudget::new(2, 0).expect("peer reserve");
        let held = peer_reserve
            .try_reserve(2, false)
            .expect("saturate the only owner large enough for the request");
        let budget = InboundSourceByteBudget {
            shared,
            peer_reserve: Some(Arc::clone(&peer_reserve)),
            decode_scratch: SharedByteBudget::new(2, 0).expect("decode scratch owner"),
        };
        let mut waiting = Box::pin(budget.reserve(2));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), waiting.as_mut())
                .await
                .is_err(),
            "an undersized shared owner must not turn temporary peer saturation into rejection"
        );
        drop(held);
        assert!(waiting.await.is_some());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn inbound_decode_scratch_is_process_wide_and_priority_separated() {
        let budgets =
            InboundFrameByteBudgets::new(4, 3, 0, 2).expect("valid inbound byte geometry");
        assert!(
            budgets
                .source_geometry
                .install_protected_sources(HashSet::new())
        );
        let first_peer = random_node_peer_id();
        let second_peer = random_node_peer_id();
        let first = budgets.high(&first_peer).expect("first high source");
        let second = budgets.high(&second_peer).expect("second high source");
        let held = first
            .reserve_decode_scratch(4)
            .await
            .expect("reserve entire high scratch pool");
        let mut waiting = Box::pin(second.reserve_decode_scratch(1));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), waiting.as_mut())
                .await
                .is_err(),
            "a second reader must not multiply the process-wide high scratch pool"
        );
        assert!(
            budgets.low().reserve_decode_scratch(3).await.is_some(),
            "low-priority decode scratch must have an independent bounded pool"
        );
        drop(held);
        assert!(waiting.await.is_some());
    }
}
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Mutex, OnceLock};
    /// Origin for a peer task spawn observed in tests.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SpawnPath {
        /// Outbound dialer (`connecting`).
        Connecting,
        /// Inbound accept (`connected_from`).
        ConnectedFrom,
    }
    static RECORDS: OnceLock<Mutex<Vec<(SpawnPath, usize)>>> = OnceLock::new();
    fn records() -> &'static Mutex<Vec<(SpawnPath, usize)>> {
        RECORDS.get_or_init(|| Mutex::new(Vec::new()))
    }
    /// Record a spawn observation for later assertions.
    pub fn record(path: SpawnPath, value: usize) {
        let mut guard = records().lock().expect("spawn record mutex poisoned");
        guard.push((path, value));
    }
    /// Snapshot the spawn observations accumulated so far.
    pub fn snapshot() -> Vec<(SpawnPath, usize)> {
        records()
            .lock()
            .expect("spawn record mutex poisoned")
            .clone()
    }
}
/// Per-peer outbound encrypted frame backlog limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutboundFrameQueueLimits {
    /// Maximum high-priority stream wire bytes retained by one peer actor.
    pub(crate) high_max_bytes: usize,
    /// Maximum low-priority stream wire bytes retained by one peer actor.
    pub(crate) low_max_bytes: usize,
    /// Protected reliable-progress bytes reserved per authenticated peer by the process-wide
    /// connected-post owner.
    pub(crate) progress_reserve_bytes: usize,
    /// Maximum high-priority encrypted frames retained by one peer actor.
    pub(crate) high_max_frames: usize,
    /// Maximum low-priority encrypted frames retained by one peer actor.
    pub(crate) low_max_frames: usize,
}
impl OutboundFrameQueueLimits {
    /// Build non-zero limits from configuration values.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(
        high_max_bytes: usize,
        low_max_bytes: usize,
        high_max_frames: usize,
        low_max_frames: usize,
    ) -> Self {
        Self {
            high_max_bytes: high_max_bytes.max(1),
            low_max_bytes: low_max_bytes.max(1),
            progress_reserve_bytes: 0,
            high_max_frames: high_max_frames.max(1),
            low_max_frames: low_max_frames.max(1),
        }
    }
    /// Build limits with one reliable-progress reserve per authenticated peer.
    #[must_use]
    pub(crate) fn new_with_progress_reserve(
        high_max_bytes: usize,
        low_max_bytes: usize,
        progress_reserve_bytes: usize,
        high_max_frames: usize,
        low_max_frames: usize,
    ) -> Self {
        Self {
            high_max_bytes: high_max_bytes.max(1),
            low_max_bytes: low_max_bytes.max(1),
            progress_reserve_bytes,
            high_max_frames: high_max_frames.max(1),
            low_max_frames: low_max_frames.max(1),
        }
    }
}
impl Default for OutboundFrameQueueLimits {
    fn default() -> Self {
        Self::new_with_progress_reserve(
            iroha_config::parameters::defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_BYTES
                .get(),
            iroha_config::parameters::defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_BYTES
                .get(),
            crate::frame_queue_charge(
                iroha_config::parameters::defaults::network::MAX_PLAINTEXT_FRAME_BYTES.get(),
            )
            .expect("default maximum progress-frame stream charge must fit usize"),
            iroha_config::parameters::defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_HIGH_FRAMES
                .get(),
            iroha_config::parameters::defaults::network::P2P_OUTBOUND_FRAME_QUEUE_MAX_LOW_FRAMES
                .get(),
        )
    }
}
pub mod handles {
    //! Module with functions to start peer actor and handle to interact with it.
    use super::{run::RunPeerArgs, *};
    use iroha_crypto::KeyPair;
    use iroha_logger::Instrument;
    use iroha_primitives::addr::SocketAddr;
    /// Start Peer in `state::Connecting` state
    #[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
    pub(crate) fn connecting<T: Pload + crate::network::message::ClassifyTopic, E: Enc>(
        peer_addr: SocketAddr,
        peer_id: iroha_model_base::peer::PeerId,
        our_public_address: SocketAddr,
        key_pair: Arc<KeyPair>,
        connection_id: ConnectionId,
        service_message_sender: mpsc::Sender<ServiceMessage<T>>,
        idle_timeout: Duration,
        dial_timeout: Duration,
        authentication_deadline: PreauthDeadline,
        network_id: iroha_data_model::NetworkId,
        consensus_caps: Option<crate::ConsensusHandshakeCaps>,
        confidential_caps: Option<crate::ConfidentialHandshakeCaps>,
        crypto_caps: Option<crate::CryptoHandshakeCaps>,
        soranet_handshake: Arc<SoranetHandshakeConfig>,
        post_capacity: usize,
        outbound_frame_queue_limits: OutboundFrameQueueLimits,
        outbound_post_byte_budgets: OutboundPostByteBudgets,
        inbound_frame_byte_budgets: InboundFrameByteBudgets,
        quic_enabled: bool,
        prefer_scion: bool,
        local_scion_supported: bool,
        trust_gossip: bool,
        max_frame_bytes: usize,
        relay_role: RelayRole,
        happy_eyeballs_stagger: Duration,
        tcp_nodelay: bool,
        tcp_keepalive: Option<Duration>,
        proxy_tls_verify: bool,
        proxy_tls_pinned_cert_der: Option<std::sync::Arc<[u8]>>,
        proxy_policy: crate::transport::ProxyPolicy,
        outbound_dial_policy: Arc<crate::dial_policy::OutboundDialPolicy>,
        quic_dialer: Option<crate::transport::QuicDialer>,
        quic_datagrams_enabled: bool,
        quic_datagram_max_payload_bytes: usize,
    ) -> tokio::task::JoinHandle<()> {
        #[cfg(test)]
        crate::peer::test_support::record(
            crate::peer::test_support::SpawnPath::Connecting,
            max_frame_bytes,
        );
        let peer = state::Connecting {
            peer_addr,
            peer_id,
            our_public_address,
            key_pair,
            connection_id,
            network_id,
            consensus_caps,
            confidential_caps,
            crypto_caps,
            soranet_handshake,
            quic_enabled,
            prefer_scion,
            local_scion_supported,
            trust_gossip,
            relay_role,
            dial_timeout,
            happy_eyeballs_stagger,
            tcp_nodelay,
            tcp_keepalive,
            proxy_tls_verify,
            proxy_tls_pinned_cert_der,
            proxy_policy,
            outbound_dial_policy,
            quic_dialer,
            quic_datagrams_enabled,
            quic_datagram_max_payload_bytes: quic_datagram_max_payload_bytes
                .min(max_frame_bytes)
                .min(crate::MAX_ENCRYPTED_FRAME_BYTES),
        };
        let peer = RunPeerArgs {
            peer,
            service_message_sender,
            idle_timeout,
            authentication_deadline,
            inbound_auth_completion: None,
            post_capacity,
            outbound_frame_queue_limits,
            outbound_post_byte_budgets,
            inbound_frame_byte_budgets,
            max_frame_bytes,
            quic_datagrams_enabled,
            quic_datagram_max_payload_bytes,
        };
        tokio::task::spawn(run::run::<T, E, _>(peer).in_current_span())
    }
    /// Start Peer in `state::ConnectedFrom` state
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn connected_from<T: Pload + crate::network::message::ClassifyTopic, E: Enc>(
        our_public_address: SocketAddr,
        key_pair: Arc<KeyPair>,
        soranet_transport_key_pair: Arc<KeyPair>,
        soranet_transport_certificate: Arc<LocalSoranetTransportCertificateV5>,
        connection: Connection,
        service_message_sender: mpsc::Sender<ServiceMessage<T>>,
        idle_timeout: Duration,
        inbound_auth_completion: InboundAuthCompletion,
        network_id: iroha_data_model::NetworkId,
        consensus_caps: Option<crate::ConsensusHandshakeCaps>,
        confidential_caps: Option<crate::ConfidentialHandshakeCaps>,
        crypto_caps: Option<crate::CryptoHandshakeCaps>,
        soranet_handshake: Arc<SoranetHandshakeConfig>,
        local_scion_supported: bool,
        post_capacity: usize,
        outbound_frame_queue_limits: OutboundFrameQueueLimits,
        outbound_post_byte_budgets: OutboundPostByteBudgets,
        inbound_frame_byte_budgets: InboundFrameByteBudgets,
        relay_role: RelayRole,
        trust_gossip: bool,
        max_frame_bytes: usize,
        quic_datagrams_enabled: bool,
        quic_datagram_max_payload_bytes: usize,
    ) -> tokio::task::JoinHandle<()> {
        #[cfg(test)]
        crate::peer::test_support::record(
            crate::peer::test_support::SpawnPath::ConnectedFrom,
            max_frame_bytes,
        );
        let peer = state::ConnectedFrom {
            our_public_address,
            key_pair,
            soranet_transport_key_pair,
            soranet_transport_certificate,
            connection,
            network_id,
            consensus_caps,
            confidential_caps,
            crypto_caps,
            soranet_handshake,
            local_scion_supported,
            trust_gossip,
            relay_role,
        };
        let peer = RunPeerArgs {
            peer,
            service_message_sender,
            idle_timeout,
            authentication_deadline: inbound_auth_completion.deadline(),
            inbound_auth_completion: Some(inbound_auth_completion),
            post_capacity,
            outbound_frame_queue_limits,
            outbound_post_byte_budgets,
            inbound_frame_byte_budgets,
            max_frame_bytes,
            quic_datagrams_enabled,
            quic_datagram_max_payload_bytes,
        };
        tokio::task::spawn(run::run::<T, E, _>(peer).in_current_span())
    }
    /// One FIFO sender per semantic class, independent of caller priority and Topic.
    pub(super) struct ClassSenders<T> {
        pub(super) classes:
            [post_channel::Sender<RetainedPost<T>>; crate::TransportAdmissionClass::COUNT],
    }
    pub(super) fn class_channels<T>(
        capacity: usize,
    ) -> (
        ClassSenders<T>,
        [post_channel::Receiver<RetainedPost<T>>; crate::TransportAdmissionClass::COUNT],
    ) {
        let pairs = std::array::from_fn::<_, { crate::TransportAdmissionClass::COUNT }, _>(|_| {
            post_channel::channel(capacity)
        });
        let (senders, receivers): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        (
            ClassSenders {
                classes: senders
                    .try_into()
                    .unwrap_or_else(|_| unreachable!("one pair per semantic class")),
            },
            receivers
                .try_into()
                .unwrap_or_else(|_| unreachable!("one pair per semantic class")),
        )
    }
    /// Post error reason for bounded per‑peer channels.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PostError {
        /// Per-topic bounded channel is full.
        Full,
        /// Peer task/channel closed.
        Closed,
    }
    /// A bounded post failure that returns ownership of the unsent message.
    pub(crate) enum RecoverPostError<T> {
        /// Per-topic channel or retained-byte owner is full.
        Full(T),
        /// Peer task/channel is closed.
        Closed(T),
    }
    impl<T> RecoverPostError<T> {
        pub(crate) fn kind(&self) -> PostError {
            match self {
                Self::Full(_) => PostError::Full,
                Self::Closed(_) => PostError::Closed,
            }
        }
        pub(crate) fn into_message(self) -> T {
            match self {
                Self::Full(message) | Self::Closed(message) => message,
            }
        }
    }
    /// Peer actor handle.
    pub struct PeerHandle<T: Pload> {
        pub(super) senders: ClassSenders<T>,
        /// Explicit cancellation for this exact authenticated transport tenure.
        ///
        /// Merely dropping the handle still lets the peer actor drain already-admitted
        /// frames.  Network lifecycle transitions call [`Self::request_termination`]
        /// when that connection has been replaced or must be disconnected, so a
        /// blocked socket cannot retain its byte-budget leases indefinitely.
        pub(super) termination_sender: watch::Sender<bool>,
        /// Mandatory pre-grant semantic source ownership, retained through flush.
        pub(super) post_admission: post_admission::Admission,
    }
    impl<T: Pload> PeerHandle<T> {
        /// Bind a logical actor fixture to this exact handle's cancellation watch.
        #[cfg(test)]
        pub(crate) fn termination_sender_for_test(&self) -> watch::Sender<bool> {
            self.termination_sender.clone()
        }
        /// Request prompt teardown of this exact transport tenure.
        pub(crate) fn request_termination(&self) {
            self.termination_sender.send_replace(true);
        }
        /// Post message `T` on Peer
        ///
        /// # Errors
        /// Fail if peer terminated
        pub fn post(&self, msg: T) -> Result<(), PostError>
        where
            T: crate::network::message::ClassifyTopic,
        {
            self.post_recover(msg).map_err(|error| error.kind())
        }
        /// Post a message, returning its ownership when bounded admission fails.
        ///
        /// Deferred-send retry paths use this entrypoint so a failed post never
        /// needs to clone a potentially large relay payload.
        pub(crate) fn post_recover(&self, msg: T) -> Result<(), RecoverPostError<T>>
        where
            T: crate::network::message::ClassifyTopic,
        {
            self.post_recover_inner(msg, None, None)
        }
        /// Post a message and return a completion receiver that becomes ready
        /// only after the peer writer has written and flushed the complete
        /// frame (or coalesced batch) containing it.
        ///
        /// Closing the connection, cancelling the writer, or encountering any
        /// encode/write/flush error drops the completion sender instead.  The
        /// network actor uses that closed receiver as the exact retry witness.
        /// A close can race after a complete socket write, so this API provides
        /// at-least-once delivery rather than exactly-once delivery: callers
        /// must retry, and downstream semantic consumers must be idempotent or
        /// deduplicate authenticated message identities.
        ///
        /// `notice` wakes the network actor once this exact occurrence settles
        /// (flushed or abandoned). A refused post never fires it.
        pub(crate) fn post_recover_with_flush_ack(
            &self,
            msg: T,
            notice: Option<crate::network::WriterFlushNotice>,
        ) -> Result<oneshot::Receiver<()>, RecoverPostError<T>>
        where
            T: crate::network::message::ClassifyTopic,
        {
            let (flush_ack, receiver) = oneshot::channel();
            self.post_recover_inner(msg, Some(flush_ack), notice)?;
            Ok(receiver)
        }
        fn post_recover_inner(
            &self,
            msg: T,
            flush_ack: Option<oneshot::Sender<()>>,
            notice: Option<crate::network::WriterFlushNotice>,
        ) -> Result<(), RecoverPostError<T>>
        where
            T: crate::network::message::ClassifyTopic,
        {
            let disarm = |notice: Option<crate::network::WriterFlushNotice>| {
                if let Some(notice) = notice {
                    notice.disarm();
                }
            };
            use tokio::sync::mpsc::error::TrySendError;
            let topic = msg.topic();
            let priority = msg.priority();
            let progress =
                crate::network::is_reliable_progress_route(topic, msg.subscriber_route());
            let sender = &self.senders.classes[msg.admission_class().index()];
            let plaintext_frame_bytes = match checked_data_message_wire_len(&msg) {
                Ok(bytes) => bytes,
                Err(error) => {
                    iroha_logger::warn!(?topic, %error, "Failed to count outbound peer post");
                    disarm(notice);
                    return Err(RecoverPostError::Full(msg));
                }
            };
            let Some(mut ownership) =
                self.post_admission
                    .reserve(msg.admission_class(), plaintext_frame_bytes, progress)
            else {
                iroha_logger::warn!(
                    ?topic,
                    ?priority,
                    plaintext_frame_bytes,
                    "Semantic outbound post byte admission is full"
                );
                disarm(notice);
                return Err(RecoverPostError::Full(msg));
            };
            ownership.flush_ack = flush_ack;
            ownership.flush_notice = notice;
            let retained = RetainedPost::new(msg, ownership);
            sender.try_send(retained).map_err(|error| match error {
                TrySendError::Full(retained) => {
                    let (message, ownership) = retained.into_parts();
                    ownership.release_refused();
                    RecoverPostError::Full(message)
                }
                TrySendError::Closed(retained) => {
                    let (message, ownership) = retained.into_parts();
                    ownership.release_refused();
                    RecoverPostError::Closed(message)
                }
            })
        }
    }
    /// Receiver set kept alive by network tests that need a synthetic peer handle.
    #[cfg(test)]
    pub(crate) struct TestPeerHandleReceivers<T: Pload> {
        termination_receiver: watch::Receiver<bool>,
        classes: [post_channel::Receiver<RetainedPost<T>>; crate::TransportAdmissionClass::COUNT],
    }
    #[cfg(test)]
    impl<T: Pload> TestPeerHandleReceivers<T> {
        pub(crate) fn termination_requested(&self) -> bool {
            *self.termination_receiver.borrow()
        }
        pub(crate) fn try_recv_consensus_safety(
            &mut self,
        ) -> Result<T, tokio::sync::mpsc::error::TryRecvError> {
            self.classes[crate::TransportAdmissionClass::Safety.index()]
                .try_recv()
                .map(RetainedPost::into_inner)
        }
        pub(crate) fn try_recv_consensus_and_acknowledge_flush(
            &mut self,
        ) -> Result<T, tokio::sync::mpsc::error::TryRecvError> {
            self.classes[crate::TransportAdmissionClass::Lane.index()]
                .try_recv()
                .map(RetainedPost::into_inner_and_acknowledge_flush)
        }
        pub(crate) fn try_recv_block_sync(
            &mut self,
        ) -> Result<T, tokio::sync::mpsc::error::TryRecvError> {
            self.classes[crate::TransportAdmissionClass::BlockSync.index()]
                .try_recv()
                .map(RetainedPost::into_inner)
        }
        pub(crate) fn try_recv_high_control(
            &mut self,
        ) -> Result<T, tokio::sync::mpsc::error::TryRecvError> {
            self.classes[crate::TransportAdmissionClass::Control.index()]
                .try_recv()
                .map(RetainedPost::into_inner)
        }
        pub(crate) fn try_recv_other(
            &mut self,
        ) -> Result<T, tokio::sync::mpsc::error::TryRecvError> {
            self.classes[crate::TransportAdmissionClass::Low.index()]
                .try_recv()
                .map(RetainedPost::into_inner)
        }
        pub(crate) fn try_recv_any(&mut self) -> Result<T, tokio::sync::mpsc::error::TryRecvError> {
            use tokio::sync::mpsc::error::TryRecvError;
            for receiver in &mut self.classes {
                match receiver.try_recv() {
                    Ok(message) => return Ok(message.into_inner()),
                    Err(TryRecvError::Empty) => {}
                    Err(error) => return Err(error),
                }
            }
            Err(TryRecvError::Empty)
        }
        pub(crate) fn try_recv_any_and_acknowledge_flush(
            &mut self,
        ) -> Result<T, tokio::sync::mpsc::error::TryRecvError> {
            use tokio::sync::mpsc::error::TryRecvError;
            for receiver in &mut self.classes {
                match receiver.try_recv() {
                    Ok(message) => return Ok(message.into_inner_and_acknowledge_flush()),
                    Err(TryRecvError::Empty) => {}
                    Err(error) => return Err(error),
                }
            }
            Err(TryRecvError::Empty)
        }
    }
    /// Explicit synthetic construction; production uses the admitted shared budgets.
    #[cfg(test)]
    pub(crate) fn test_peer_handle<T: Pload>(
        cap: usize,
    ) -> (PeerHandle<T>, TestPeerHandleReceivers<T>) {
        let (termination_sender, termination_receiver) = watch::channel(false);
        let (senders, classes) = class_channels(cap);
        (
            PeerHandle {
                senders,
                termination_sender,
                post_admission: post_admission::Admission::Synthetic {
                    high: OutboundHighByteBudget::shared_only(
                        SharedByteBudget::new(
                            OutboundFrameQueueLimits::default().high_max_bytes,
                            0,
                        )
                        .expect("test high budget"),
                    ),
                    low: SharedByteBudget::new(
                        OutboundFrameQueueLimits::default().low_max_bytes,
                        0,
                    )
                    .expect("test low budget"),
                    overhead: crate::frame_queue_charge(0).expect("test frame overhead"),
                },
            },
            TestPeerHandleReceivers {
                termination_receiver,
                classes,
            },
        )
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            Priority,
            network::message::{ClassifyTopic, Topic},
        };
        use norito::codec::{Decode, Encode};
        use tokio::sync::mpsc::error::TryRecvError;
        #[test]
        fn captured_original_test_payload_identities() {
            crate::frame_identity_tests::test_payload_identity::<ConsensusSafetyMsg>(
                "iroha_p2p::peer::handles::tests::ConsensusSafetyMsg",
            );
            crate::frame_identity_tests::test_payload_identity::<ConsensusChunkMsg>(
                "iroha_p2p::peer::handles::tests::ConsensusChunkMsg",
            );
            crate::frame_identity_tests::test_payload_identity::<ConsensusPayloadMsg>(
                "iroha_p2p::peer::handles::tests::ConsensusPayloadMsg",
            );
            crate::frame_identity_tests::test_payload_identity::<PriorityMsg>(
                "iroha_p2p::peer::handles::tests::PriorityMsg",
            );
            crate::frame_identity_tests::test_payload_identity::<BudgetRouteMsg>(
                "iroha_p2p::peer::handles::tests::BudgetRouteMsg",
            );
        }
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_p2p::peer::handles::tests::ConsensusSafetyMsg")]
        #[derive(Clone, Debug, Decode, Encode)]
        struct ConsensusSafetyMsg;
        impl<'a> norito::core::DecodeFromSlice<'a> for ConsensusSafetyMsg {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                norito::core::decode_field_canonical::<Self>(bytes)
            }
        }
        impl ClassifyTopic for ConsensusSafetyMsg {
            fn topic(&self) -> Topic {
                Topic::ConsensusSafety
            }
        }
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_p2p::peer::handles::tests::ConsensusChunkMsg")]
        #[derive(Clone, Debug, Decode, Encode)]
        struct ConsensusChunkMsg;
        impl<'a> norito::core::DecodeFromSlice<'a> for ConsensusChunkMsg {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                norito::core::decode_field_canonical::<Self>(bytes)
            }
        }
        impl ClassifyTopic for ConsensusChunkMsg {
            fn topic(&self) -> Topic {
                Topic::ConsensusChunk
            }
        }
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_p2p::peer::handles::tests::ConsensusPayloadMsg")]
        #[derive(Clone, Debug, Decode, Encode)]
        struct ConsensusPayloadMsg;
        impl<'a> norito::core::DecodeFromSlice<'a> for ConsensusPayloadMsg {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                norito::core::decode_field_canonical::<Self>(bytes)
            }
        }
        impl ClassifyTopic for ConsensusPayloadMsg {
            fn topic(&self) -> Topic {
                Topic::ConsensusPayload
            }
        }
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_p2p::peer::handles::tests::PriorityMsg")]
        #[derive(Clone, Debug, Decode, Encode)]
        struct PriorityMsg {
            priority: Priority,
        }
        impl<'a> norito::core::DecodeFromSlice<'a> for PriorityMsg {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                norito::core::decode_field_canonical::<Self>(bytes)
            }
        }
        impl ClassifyTopic for PriorityMsg {
            fn topic(&self) -> Topic {
                Topic::TxGossip
            }
            fn priority(&self) -> Priority {
                self.priority
            }
        }
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_p2p::peer::handles::tests::BudgetRouteMsg")]
        #[derive(Clone, Debug, Decode, Encode, PartialEq, Eq)]
        enum BudgetRouteMsg {
            Gossip,
            Chunk,
            GeneralControl,
        }
        impl<'a> norito::core::DecodeFromSlice<'a> for BudgetRouteMsg {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                norito::core::decode_field_canonical::<Self>(bytes)
            }
        }
        impl ClassifyTopic for BudgetRouteMsg {
            fn topic(&self) -> Topic {
                match self {
                    Self::Gossip => Topic::TxGossip,
                    Self::Chunk => Topic::ConsensusChunk,
                    Self::GeneralControl => Topic::Control,
                }
            }
            fn priority(&self) -> Priority {
                Priority::High
            }
        }
        #[test]
        fn consensus_safety_has_an_independent_bounded_peer_queue() {
            let (handle, mut receivers) = test_peer_handle(1);
            handle
                .post(ConsensusSafetyMsg)
                .expect("first safety message must enter its dedicated queue");
            assert_eq!(handle.post(ConsensusSafetyMsg), Err(PostError::Full));
            assert!(matches!(
                receivers.try_recv_high_control(),
                Err(TryRecvError::Empty)
            ));
            assert!(matches!(
                receivers.try_recv_consensus_safety(),
                Ok(ConsensusSafetyMsg)
            ));
        }
        #[test]
        fn consensus_chunk_routes_to_payload_queue() {
            let (handle, mut receivers) = test_peer_handle::<ConsensusChunkMsg>(1);
            handle
                .post(ConsensusChunkMsg)
                .expect("post preserves semantic classification");
            assert!(matches!(
                receivers.classes[crate::TransportAdmissionClass::Payload.index()]
                    .try_recv()
                    .map(RetainedPost::into_inner),
                Ok(ConsensusChunkMsg)
            ));
            for receiver in &mut receivers.classes {
                assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
            }
        }
        #[test]
        fn consensus_payload_routes_to_dedicated_high_queue() {
            let (handle, mut receivers) = test_peer_handle::<ConsensusPayloadMsg>(1);
            handle
                .post(ConsensusPayloadMsg)
                .expect("post preserves semantic classification");
            assert!(matches!(
                receivers.classes[crate::TransportAdmissionClass::Payload.index()]
                    .try_recv()
                    .map(RetainedPost::into_inner),
                Ok(ConsensusPayloadMsg)
            ));
            for receiver in &mut receivers.classes {
                assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
            }
        }
        #[test]
        fn caller_priority_cannot_move_tx_gossip_out_of_low_lane() {
            let (handle, mut receivers) = test_peer_handle::<PriorityMsg>(1);
            handle
                .post(PriorityMsg {
                    priority: Priority::High,
                })
                .expect("post preserves semantic classification");
            assert!(matches!(
                receivers.classes[crate::TransportAdmissionClass::Low.index()]
                    .try_recv()
                    .map(RetainedPost::into_inner),
                Ok(PriorityMsg {
                    priority: Priority::High
                })
            ));
            for receiver in &mut receivers.classes {
                assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
            }
        }
        #[test]
        fn high_priority_gossip_cannot_consume_the_peer_progress_reserve() {
            let (mut handle, mut receivers) = test_peer_handle::<BudgetRouteMsg>(1);
            let overhead = crate::frame_queue_charge(0).expect("test frame overhead");
            let gossip = BudgetRouteMsg::Gossip;
            let gossip_charge = checked_data_message_wire_len(&gossip)
                .expect("count gossip frame")
                .checked_add(overhead)
                .expect("gossip stream charge");
            let progress_charge = checked_data_message_wire_len(&BudgetRouteMsg::Chunk)
                .expect("count progress frame")
                .checked_add(overhead)
                .expect("progress stream charge");
            let shared = SharedByteBudget::new(gossip_charge, 0).expect("test shared budget");
            let held = shared
                .try_reserve(gossip_charge, false)
                .expect("saturate shared high budget");
            let peer_reserve =
                SharedByteBudget::new(progress_charge, 0).expect("test progress reserve");
            let post_admission::Admission::Synthetic { high, low, .. } = &mut handle.post_admission
            else {
                unreachable!()
            };
            *low = SharedByteBudget::new(gossip_charge, 0).unwrap();
            let held_low = low.try_reserve(gossip_charge, false).unwrap();
            *high = OutboundHighByteBudget {
                shared,
                peer_reserve: Some(peer_reserve),
            };
            assert_eq!(
                handle.post(gossip),
                Err(PostError::Full),
                "caller-selected high priority must not turn gossip into reliable progress"
            );
            handle
                .post(BudgetRouteMsg::Chunk)
                .expect("semantic progress must use the disjoint peer reserve");
            assert_eq!(receivers.try_recv_any(), Ok(BudgetRouteMsg::Chunk));
            drop((held, held_low));
        }
    }
}
mod run {
    //! Module with peer [`run`] function.
    use super::{
        handshake_flow::Handshake,
        state::{ConnectedFrom, Connecting, Ready},
        *,
    };
    use crate::Priority;
    use crate::network::message::{ClassifyTopic, Topic};
    use iroha_data_model::peer::Peer;
    use iroha_logger::prelude::*;
    use norito::codec::Decode;
    use tokio::time::Instant;
    fn frame_plaintext_cap_for<E: Enc>(max_frame_bytes: usize) -> usize {
        max_frame_bytes
            .min(crate::MAX_ENCRYPTED_FRAME_BYTES)
            .saturating_sub(core::mem::size_of::<aead::Nonce<E>>())
            .saturating_sub(core::mem::size_of::<aead::Tag<E>>())
    }
    fn checked_encoded_frame_len<T: Pload, E: Enc>(
        message: &T,
        max_frame_bytes: usize,
    ) -> Result<usize, Error> {
        let flags = ncore::default_encode_flags();
        let _guard = ncore::DecodeFlagsGuard::enter(flags);
        let encoded_len = ncore::encoded_frame_len(message)?;
        if encoded_len > frame_plaintext_cap_for::<E>(max_frame_bytes) {
            return Err(Error::FrameTooLarge);
        }
        Ok(encoded_len)
    }
    const PEER_TERMINATION_NOTIFY_TIMEOUT: Duration = Duration::from_secs(1);
    #[derive(Clone, Copy, Debug)]
    #[cfg(test)]
    enum InboundDispatchLane {
        Safety,
        High,
        Low,
    }
    struct PendingInbound<T: Pload> {
        message: PeerMessage<T>,
        topic: Topic,
        priority: Priority,
    }
    struct InboundDispatchWorkers(Vec<tokio::task::JoinHandle<()>>);
    impl InboundDispatchWorkers {
        fn abort(&self) {
            for worker in &self.0 {
                worker.abort();
            }
        }
        async fn shutdown(mut self) -> Result<(), Vec<tokio::task::JoinError>> {
            // The peer task closes every producer before entering this method.
            // Each worker therefore drains a finite, byte- and source-credit-
            // bounded connection queue into the network actor before exiting.
            // Aborting here would discard authenticated reliable progress that
            // was already admitted from the old transport tenure.
            let mut failures = Vec::new();
            for worker in self.0.drain(..) {
                if let Err(error) = worker.await {
                    iroha_logger::error!(
                        ?error,
                        "Inbound peer dispatch worker did not terminate cleanly"
                    );
                    failures.push(error);
                }
            }
            if failures.is_empty() {
                Ok(())
            } else {
                Err(failures)
            }
        }
    }
    impl Drop for InboundDispatchWorkers {
        fn drop(&mut self) {
            self.abort();
        }
    }
    /// Cancellation-safe owner for one peer task's authenticated delivery seam.
    ///
    /// Peer I/O tasks are independently abortable. Once the actor has accepted
    /// a connection, aborting or unwinding that task must still drain the
    /// finite reliable dispatch queues, close their producer fence, and publish
    /// exactly one termination notice for that connection. Cleanup runs in a
    /// detached task so cancellation of the peer I/O future cannot cancel the
    /// ownership handoff itself.
    struct PeerTaskTerminationGuard<T: Pload> {
        service_message_sender: Option<mpsc::Sender<ServiceMessage<T>>>,
        conn_id: ConnectionId,
        peer: Option<Peer>,
        delivery_drain: Option<Arc<InboundDeliveryDrain>>,
        dispatch_producers: Vec<mpsc::UnboundedSender<PendingInbound<T>>>,
        dispatch_workers: Option<InboundDispatchWorkers>,
        armed: bool,
    }
    impl<T: Pload> PeerTaskTerminationGuard<T> {
        fn new(
            service_message_sender: mpsc::Sender<ServiceMessage<T>>,
            conn_id: ConnectionId,
        ) -> Self {
            Self {
                service_message_sender: Some(service_message_sender),
                conn_id,
                peer: None,
                delivery_drain: None,
                dispatch_producers: Vec::new(),
                dispatch_workers: None,
                armed: true,
            }
        }
        fn set_peer(&mut self, peer: Peer) {
            self.peer = Some(peer);
        }
        fn set_delivery_drain(&mut self, delivery_drain: Arc<InboundDeliveryDrain>) {
            debug_assert!(self.delivery_drain.is_none());
            self.delivery_drain = Some(delivery_drain);
        }
        fn set_dispatch_workers(
            &mut self,
            dispatch_producers: Vec<mpsc::UnboundedSender<PendingInbound<T>>>,
            dispatch_workers: InboundDispatchWorkers,
        ) {
            debug_assert!(self.dispatch_workers.is_none());
            self.dispatch_producers = dispatch_producers;
            self.dispatch_workers = Some(dispatch_workers);
        }
        fn spawn_cleanup(&mut self) -> tokio::task::JoinHandle<()> {
            debug_assert!(self.armed, "peer termination cleanup is spawned once");
            let service_message_sender = self
                .service_message_sender
                .take()
                .expect("armed peer termination guard owns its service sender");
            let conn_id = self.conn_id;
            let peer = self.peer.take();
            let delivery_drain = self.delivery_drain.take();
            let dispatch_producers = core::mem::take(&mut self.dispatch_producers);
            let dispatch_workers = self.dispatch_workers.take();
            self.armed = false;
            tokio::spawn(async move {
                // The peer task's local producer handles are dropped when its
                // future exits. Drop the cleanup-owned clones before joining so
                // each worker observes a closed, finite queue and can transfer
                // every already-admitted item to the actor.
                drop(dispatch_producers);
                if let Some(dispatch_workers) = dispatch_workers
                    && let Err(failures) = dispatch_workers.shutdown().await
                {
                    iroha_logger::error!(
                        conn_id,
                        failures = failures.len(),
                        "Peer dispatch teardown failed closed after worker failure"
                    );
                }
                if let Some(delivery_drain) = delivery_drain {
                    // This producer fence is deliberately published only after
                    // every surviving worker has joined. Receiver-held guards
                    // remain independently charged until their terminal drop.
                    delivery_drain.close_producer();
                }
                iroha_logger::debug!(conn_id, "Peer is terminated.");
                if !notify_peer_terminated(
                    &service_message_sender,
                    Terminated { peer, conn_id },
                    PEER_TERMINATION_NOTIFY_TIMEOUT,
                )
                .await
                {
                    iroha_logger::warn!(
                        conn_id,
                        timeout = ?PEER_TERMINATION_NOTIFY_TIMEOUT,
                        "Network service queue did not accept peer termination notification before the bounded deadline"
                    );
                }
            })
        }
        async fn finish(mut self) {
            let cleanup = self.spawn_cleanup();
            if let Err(error) = cleanup.await {
                // The cleanup future contains no fallible application work. A
                // JoinError here is therefore an invariant failure, and must be
                // visible instead of silently converting into a leaked tenure.
                iroha_logger::error!(
                    conn_id = self.conn_id,
                    ?error,
                    "Peer termination cleanup task did not terminate cleanly"
                );
            }
        }
    }
    impl<T: Pload> Drop for PeerTaskTerminationGuard<T> {
        fn drop(&mut self) {
            if self.armed {
                // `run` is always polled inside Tokio. Detaching here is what
                // makes an isolated peer-task abort/unwind cancellation-safe.
                drop(self.spawn_cleanup());
            }
        }
    }
    #[cfg(test)]
    async fn run_inbound_dispatch_lane<T: Pload>(
        mut receiver: mpsc::UnboundedReceiver<PendingInbound<T>>,
        senders: PeerMessageSenders<T>,
        lane: InboundDispatchLane,
    ) {
        while let Some(mut pending) = receiver.recv().await {
            match senders
                .transfer_before_send(&mut pending.message, pending.topic, pending.priority, true)
                .await
            {
                InboundDispatchAdmission::Admitted => {}
                InboundDispatchAdmission::OverTopicCap { cap } => {
                    iroha_logger::error!(
                        peer = %pending.message.peer,
                        topic = ?pending.topic,
                        payload_bytes = pending.message.payload_bytes,
                        cap,
                        "Rejected an over-cap payload after pre-dispatch validation"
                    );
                    continue;
                }
                InboundDispatchAdmission::ByteBudgetFull => {
                    iroha_logger::error!(
                        peer = %pending.message.peer,
                        topic = ?pending.topic,
                        payload_bytes = pending.message.payload_bytes,
                        "A validated reliable payload cannot fit its dispatch byte budget"
                    );
                    continue;
                }
            }
            let result = match lane {
                InboundDispatchLane::Safety => senders.safety.send(pending.message).await,
                InboundDispatchLane::High => senders.high.send(pending.message).await,
                InboundDispatchLane::Low => senders.low.send(pending.message).await,
            };
            if result.is_err() {
                break;
            }
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum MalformedPayloadFrameReason {
        HeaderTruncated,
        MagicMismatch,
        VersionMismatch,
        SchemaMismatch,
        CompressionUnsupported,
        LengthMissing,
        LengthTooLarge,
        LengthOverflow,
        FrameTruncated,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct InboundTopicCapViolation {
        topic: Topic,
        framed_len: usize,
        cap: usize,
    }
    #[derive(Debug, thiserror::Error)]
    enum InboundDecodeError {
        #[error("invalid peer frame codec: {0}")]
        Codec(ncore::Error),
        #[error("peer frame exceeds its topic cap: {0:?}")]
        TopicCap(InboundTopicCapViolation),
    }

    const INBOUND_PING_BURST: u8 = 2;
    /// Remote Ping requests own this budget; correlated Pongs retire local probes.
    #[derive(Clone, Copy, Debug)]
    pub(super) struct InboundPingLimiter {
        tokens: u8,
        last_refill: Instant,
        refill_period: Duration,
    }
    impl InboundPingLimiter {
        pub(super) fn new(now: Instant, idle_timeout: Duration) -> Self {
            Self {
                tokens: INBOUND_PING_BURST,
                last_refill: now,
                refill_period: (idle_timeout / 2).max(Duration::from_nanos(1)),
            }
        }
        pub(super) fn admit_at(&mut self, now: Instant) -> bool {
            let elapsed = now.saturating_duration_since(self.last_refill);
            let whole_periods = elapsed.as_nanos() / self.refill_period.as_nanos();
            if whole_periods != 0 {
                let missing = INBOUND_PING_BURST.saturating_sub(self.tokens);
                let replenished = u8::try_from(whole_periods.min(u128::from(missing)))
                    .expect("remote Ping refill is bounded by its two-token burst");
                self.tokens = self.tokens.saturating_add(replenished);
                if replenished != 0 {
                    self.last_refill = self
                        .last_refill
                        .checked_add(self.refill_period.saturating_mul(u32::from(replenished)))
                        .unwrap_or(now);
                }
            }
            if self.tokens == 0 {
                return false;
            }
            if self.tokens == INBOUND_PING_BURST {
                // Time spent at capacity cannot become credit for a later burst.
                self.last_refill = now;
            }
            self.tokens -= 1;
            true
        }
    }

    async fn notify_peer_terminated<T: Pload>(
        service_message_sender: &mpsc::Sender<ServiceMessage<T>>,
        terminated: Terminated,
        timeout: Duration,
    ) -> bool {
        use tokio::sync::mpsc::error::TrySendError;
        let message = ServiceMessage::Terminated(terminated);
        match service_message_sender.try_send(message) {
            Ok(()) => true,
            Err(TrySendError::Closed(_)) => false,
            Err(TrySendError::Full(message)) => {
                let reserve = tokio::time::timeout(timeout, service_message_sender.reserve()).await;
                match reserve {
                    Ok(Ok(permit)) => {
                        permit.send(message);
                        true
                    }
                    Ok(Err(_)) => false,
                    Err(_) => {
                        // The peer task must finish in bounded time, but dropping
                        // this exact connection notice would leave conservative
                        // connection-cap accounting charged forever.  Retrying in
                        // a detached task preserves eventual delivery whenever the
                        // responsive network actor reopens capacity; channel
                        // closure still terminates the retry without a leak.
                        let service_message_sender = service_message_sender.clone();
                        tokio::spawn(async move {
                            let _ = service_message_sender.send(message).await;
                        });
                        false
                    }
                }
            }
        }
    }
    mod granted;
    /// Peer task.
    #[allow(clippy::too_many_lines)]
    #[log(skip_all, fields(connection = &peer.log_description(), conn_id = peer.connection_id(), peer, disambiguator))]
    pub(super) async fn run<T: Pload + ClassifyTopic, E: Enc, P: Entrypoint<E>>(
        RunPeerArgs {
            peer,
            service_message_sender,
            idle_timeout,
            authentication_deadline,
            inbound_auth_completion,
            post_capacity,
            outbound_frame_queue_limits,
            outbound_post_byte_budgets,
            inbound_frame_byte_budgets,
            max_frame_bytes,
            quic_datagrams_enabled,
            quic_datagram_max_payload_bytes,
        }: RunPeerArgs<T, P>,
    ) {
        granted::run::<T, E, P>(RunPeerArgs {
            peer,
            service_message_sender,
            idle_timeout,
            authentication_deadline,
            inbound_auth_completion,
            post_capacity,
            outbound_frame_queue_limits,
            outbound_post_byte_budgets,
            inbound_frame_byte_budgets,
            max_frame_bytes,
            quic_datagrams_enabled,
            quic_datagram_max_payload_bytes,
        })
        .await;
    }

    // Synthetic channel fixtures use Tokio receivers in place of owned post channels.
    /// Args to pass inside [`run`] function.
    pub(super) struct RunPeerArgs<T: Pload, P> {
        pub peer: P,
        pub service_message_sender: mpsc::Sender<ServiceMessage<T>>,
        pub idle_timeout: Duration,
        pub authentication_deadline: PreauthDeadline,
        pub inbound_auth_completion: Option<InboundAuthCompletion>,
        pub post_capacity: usize,
        pub outbound_frame_queue_limits: OutboundFrameQueueLimits,
        pub outbound_post_byte_budgets: OutboundPostByteBudgets,
        pub inbound_frame_byte_budgets: InboundFrameByteBudgets,
        pub max_frame_bytes: usize,
        pub quic_datagrams_enabled: bool,
        pub quic_datagram_max_payload_bytes: usize,
    }
    /// Trait for peer stages that might be used as starting point for peer's [`run`] function.
    pub(super) trait Entrypoint<E: Enc>: Handshake<E> + Send + 'static {
        fn connection_id(&self) -> ConnectionId;
        /// Debug description, used for logging
        fn log_description(&self) -> String;
    }
    impl<E: Enc> Entrypoint<E> for Connecting {
        fn connection_id(&self) -> ConnectionId {
            self.connection_id
        }
        fn log_description(&self) -> String {
            format!("outgoing to {}", self.peer_addr)
        }
    }
    impl<E: Enc> Entrypoint<E> for ConnectedFrom {
        fn connection_id(&self) -> ConnectionId {
            self.connection.id
        }
        fn log_description(&self) -> String {
            #[allow(clippy::option_if_let_else)]
            match self.connection.remote_addr {
                None => "incoming".to_owned(),
                Some(remote_addr) => {
                    // In case of incoming connection,
                    // only host will have some meaningful value.
                    // Port will have some random value chosen only for this connection.
                    format!("incoming from {}", remote_addr.ip())
                }
            }
        }
    }
    #[cfg(test)]
    pub fn assert_captured_p2p_message<T>(owner: &str, variant: &str, value: T)
    where
        T: Clone + ncore::NoritoSerialize + for<'de> ncore::NoritoDeserialize<'de>,
    {
        use crate::frame_identity_tests::shapes;
        shapes(owner, &format!("{variant}_data"), &Message::Data(value));
        shapes(owner, &format!("{variant}_ping"), &Message::<T>::Ping);
        shapes(owner, &format!("{variant}_pong"), &Message::<T>::Pong);
    }
    #[test]
    fn captured_original_p2p_scalar_message_frames() {
        assert_captured_p2p_message("message_u32", "scalar", 0x1234_5678_u32);
        assert_captured_p2p_message("message_u64", "scalar", 0x0123_4567_89ab_cdef_u64);
    }
    #[cfg(test)]
    mod admission_class_tests;
    #[cfg(test)]
    mod payload_codec_tests;
    /// Either message or ping
    #[derive(Encode, Decode, Clone, Debug)]
    #[norito(decode_from_slice)]
    enum Message<T> {
        Data(T),
        Ping,
        Pong,
    }
    fn inbound_data_message_field(payload: &[u8], flags: u8) -> Result<&[u8], ncore::Error> {
        let encoded_field = payload
            .get(core::mem::size_of::<u32>()..)
            .ok_or(ncore::Error::LengthMismatch)?;
        let (field_len, prefix_len) = ncore::read_len_from_slice_with_flags(encoded_field, flags)?;
        let field_end = prefix_len
            .checked_add(field_len)
            .ok_or(ncore::Error::LengthMismatch)?;
        if field_end != encoded_field.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        encoded_field
            .get(prefix_len..field_end)
            .ok_or(ncore::Error::LengthMismatch)
    }
    fn inbound_message_discriminant(payload: &[u8]) -> Result<u32, ncore::Error> {
        let bytes: [u8; core::mem::size_of::<u32>()] = payload
            .get(..core::mem::size_of::<u32>())
            .ok_or(ncore::Error::LengthMismatch)?
            .try_into()
            .map_err(|_| ncore::Error::LengthMismatch)?;
        Ok(u32::from_le_bytes(bytes))
    }
    impl<T: ClassifyTopic> ClassifyTopic for Message<T> {
        const HAS_INBOUND_DECODE_LIMITS: bool = T::HAS_INBOUND_DECODE_LIMITS;
        fn topic(&self) -> Topic {
            match self {
                Self::Data(payload) => payload.topic(),
                // Pings are internal to the peer and should not block other
                // traffic. Classify them as `Health` to keep them low-impact.
                Self::Ping | Self::Pong => Topic::Health,
            }
        }
        fn admission_class(&self) -> crate::network::message::TransportAdmissionClass {
            use crate::network::message::TransportAdmissionClass;
            match self {
                Self::Data(payload) => payload.admission_class(),
                Self::Ping | Self::Pong => TransportAdmissionClass::Low,
            }
        }
        fn inbound_admission_class(
            payload: &[u8],
            flags: u8,
        ) -> Result<crate::network::message::TransportAdmissionClass, ncore::Error> {
            use crate::network::message::TransportAdmissionClass;
            match inbound_message_discriminant(payload)? {
                0 => T::inbound_admission_class(inbound_data_message_field(payload, flags)?, flags),
                1 | 2 if payload.len() == core::mem::size_of::<u32>() => {
                    Ok(TransportAdmissionClass::Low)
                }
                1 | 2 => Err(ncore::Error::LengthMismatch),
                _ => Err(ncore::Error::Message(
                    "unknown inbound P2P message discriminant".to_owned(),
                )),
            }
        }
        fn subscriber_route(&self) -> crate::network::message::SubscriberRoute {
            match self {
                Self::Data(payload) => payload.subscriber_route(),
                Self::Ping | Self::Pong => crate::network::message::SubscriberRoute::General,
            }
        }
        fn inbound_topic(payload: &[u8], flags: u8) -> Result<Option<Topic>, ncore::Error> {
            match inbound_message_discriminant(payload)? {
                0 => T::inbound_topic(inbound_data_message_field(payload, flags)?, flags),
                1 | 2 if payload.len() == core::mem::size_of::<u32>() => Ok(Some(Topic::Health)),
                1 | 2 => Err(ncore::Error::LengthMismatch),
                _ => Err(ncore::Error::Message(
                    "unknown inbound P2P message discriminant".to_owned(),
                )),
            }
        }
        fn inbound_decode_limits(
            payload: &[u8],
            framed_len: usize,
            flags: u8,
        ) -> Result<Option<norito::DecodeLimits>, ncore::Error> {
            if !T::HAS_INBOUND_DECODE_LIMITS {
                return Ok(None);
            }
            if inbound_message_discriminant(payload)? != 0 {
                // Ping and pong have no attacker-controlled nested payload.
                // Unknown tags are rejected by the ordinary enum decoder.
                return Ok(None);
            }
            T::inbound_decode_limits(
                inbound_data_message_field(payload, flags)?,
                framed_len,
                flags,
            )
        }
    }
    impl<T: norito::NoritoSchema> norito::NoritoSchema for Message<T> {
        fn nominal_name() -> String {
            norito::schema::identity::generic_name(
                "iroha_p2p::peer::run::Message",
                &[T::nominal_name()],
            )
        }
    }
    fn norito_frame_prefix_len<T>() -> Option<usize> {
        let align = ncore::archived_payload_align::<T>();
        let padding = if align <= 1 {
            0
        } else {
            let remainder = ncore::Header::SIZE % align;
            if remainder == 0 {
                0
            } else {
                align.checked_sub(remainder)?
            }
        };
        ncore::Header::SIZE.checked_add(padding)
    }
    /// Count the complete Norito frame length of one P2P data envelope without
    /// allocating its serialized bytes.
    ///
    /// # Errors
    ///
    /// Returns the underlying serialization error or `LengthMismatch` when
    /// either the nested payload or outer frame length is not representable.
    pub fn checked_data_message_wire_len<T: ncore::NoritoSerialize>(
        payload: &T,
    ) -> Result<usize, ncore::Error> {
        let flags = ncore::default_encode_flags();
        let _guard = ncore::DecodeFlagsGuard::enter(flags);
        let payload_frame_len = ncore::encoded_frame_len(payload)?;
        let payload_len = payload_frame_len
            .checked_sub(norito_frame_prefix_len::<T>().ok_or(ncore::Error::LengthMismatch)?)
            .ok_or(ncore::Error::LengthMismatch)?;
        checked_data_message_wire_len_from_payload_len::<T>(payload_len)
            .ok_or(ncore::Error::LengthMismatch)
    }
    /// Return the complete Norito frame length of one P2P data envelope.
    ///
    /// Serialization or arithmetic failure maps to `usize::MAX`; admission
    /// paths must use [`checked_data_message_wire_len`] so this diagnostic
    /// sentinel can never be mistaken for an exact configured maximum.
    #[cfg(test)]
    pub fn data_message_wire_len<T: ncore::NoritoSerialize>(payload: &T) -> usize {
        checked_data_message_wire_len(payload).unwrap_or(usize::MAX)
    }
    #[cfg(any(test, feature = "test-fixtures"))]
    /// Materialize one data frame so tests can compare the allocation-free counter.
    pub fn materialized_data_message_wire_len<T: ncore::NoritoSerialize>(
        payload: T,
    ) -> Result<usize, ncore::Error> {
        ncore::to_bytes(&Message::Data(payload)).map(|bytes| bytes.len())
    }
    /// Return the complete Norito frame length of one P2P data envelope from
    /// the already-known bare encoded length of its payload.
    ///
    /// `T` is used only to preserve the alignment of the real outer frame. The
    /// data variant always length-delimits its generic payload, so its encoded
    /// size otherwise depends only on `payload_len`. Arithmetic overflow is
    /// represented as `None` for the fallible admission path.
    fn checked_data_message_wire_len_from_payload_len<T>(payload_len: usize) -> Option<usize> {
        let flags = ncore::default_encode_flags();
        let message_payload_len = core::mem::size_of::<u32>()
            .checked_add(ncore::len_prefix_len_with_flags(payload_len, flags))
            .and_then(|len| len.checked_add(payload_len))?;
        norito_frame_prefix_len::<Message<T>>()?.checked_add(message_payload_len)
    }
    /// Return the complete Norito frame length of one P2P data envelope from
    /// the already-known bare encoded length of its payload.
    pub fn data_message_wire_len_from_payload_len<T>(payload_len: usize) -> usize {
        checked_data_message_wire_len_from_payload_len::<T>(payload_len).unwrap_or(usize::MAX)
    }
    fn encode_wire_message<T: Pload>(msg: &T, out: &mut Vec<u8>) -> Result<(), ncore::Error> {
        let flags = ncore::default_encode_flags();
        let _guard = ncore::DecodeFlagsGuard::enter(flags);
        ncore::to_bytes_in(msg, out)
    }
    pub(super) fn receive_credit_encoded_len<T: Pload, E: Enc>(
        message: &T,
        max_plaintext: usize,
    ) -> Result<usize, Error> {
        let max_encrypted = super::receive_credit::record::encrypted_len::<E>(max_plaintext)?;
        checked_encoded_frame_len::<T, E>(message, max_encrypted)
    }
    pub(super) fn receive_credit_encode<T: Pload>(
        message: &T,
        output: &mut Vec<u8>,
    ) -> Result<(), Error> {
        encode_wire_message(message, output).map_err(Error::NoritoCodec)
    }
    fn copy_to_aligned_scratch<'a>(scratch: &'a mut Vec<u8>, src: &[u8], align: usize) -> &'a [u8] {
        debug_assert!(align.is_power_of_two());
        let len = src.len();
        if len == 0 || align <= 1 {
            scratch.clear();
            scratch.extend_from_slice(src);
            return scratch.as_slice();
        }
        let extra = align.saturating_sub(1);
        let needed = len.saturating_add(extra);
        if scratch.len() < needed {
            scratch.resize(needed, 0);
        }
        let base = scratch.as_ptr() as usize;
        let misalignment = base % align;
        let offset = if misalignment == 0 {
            0
        } else {
            align - misalignment
        };
        let end = offset.saturating_add(len);
        scratch[offset..end].copy_from_slice(src);
        &scratch[offset..end]
    }
    pub(super) fn receive_credit_decode<T: Pload + ClassifyTopic>(
        frame: &[u8],
        admitted: crate::TransportAdmissionClass,
        caps: crate::network::TopicFrameCaps,
    ) -> Result<T, Error> {
        let alignment = ncore::archived_payload_align::<T>();
        if !alignment.is_power_of_two() || alignment > super::receive_credit::ENVELOPE_BYTES {
            return Err(Error::Format);
        }
        let padding = (alignment - ncore::Header::SIZE % alignment) % alignment;
        let length =
            framed_message_len(frame, norito::schema::identity::frame_hash::<T>(), padding)
                .map_err(|_| Error::Format)?;
        if length != frame.len() {
            return Err(Error::Format);
        } // exactly one inner frame
        let flags = *frame.get(ncore::Header::SIZE - 1).ok_or(Error::Format)?;
        let payload = frame
            .get(ncore::Header::SIZE + padding..)
            .ok_or(Error::Format)?;
        if T::inbound_admission_class(payload, flags).map_err(Error::NoritoCodec)? != admitted {
            return Err(Error::Format);
        }
        let raw_topic = T::inbound_topic(payload, flags)
            .map_err(Error::NoritoCodec)?
            .ok_or(Error::Format)?;
        let limits = inbound_frame_decode_limits::<T>(frame, padding, caps).map_err(|error| {
            iroha_logger::debug!(%error, "Rejected grant-framed peer payload");
            Error::Format
        })?;
        // The credit reader places every decrypted payload at an aligned
        // address, so the archive is decoded in place. Only an unaligned
        // caller pays for one aligned scratch copy.
        let mut scratch = Vec::new();
        let aligned = if (frame.as_ptr() as usize).is_multiple_of(alignment) {
            frame
        } else {
            copy_to_aligned_scratch(&mut scratch, frame, alignment)
        };
        let decoded =
            decode_inbound_frame_with_limits::<T>(aligned, limits).map_err(Error::NoritoCodec)?;
        if decoded.admission_class() != admitted || decoded.topic() != raw_topic {
            return Err(Error::Format);
        }
        Ok(decoded)
    }
    fn inbound_frame_decode_limits<T: Pload + ClassifyTopic>(
        frame: &[u8],
        padding: usize,
        topic_frame_caps: crate::network::TopicFrameCaps,
    ) -> Result<Option<norito::DecodeLimits>, InboundDecodeError> {
        let payload_offset = ncore::Header::SIZE
            .checked_add(padding)
            .ok_or(InboundDecodeError::Codec(ncore::Error::LengthMismatch))?;
        let payload = frame
            .get(payload_offset..)
            .ok_or(InboundDecodeError::Codec(ncore::Error::LengthMismatch))?;
        let flags = *frame
            .get(ncore::Header::SIZE - 1)
            .ok_or(InboundDecodeError::Codec(ncore::Error::LengthMismatch))?;
        if let Some(topic) = T::inbound_topic(payload, flags).map_err(InboundDecodeError::Codec)? {
            let cap = topic_frame_caps.for_topic(topic);
            if frame.len() > cap {
                return Err(InboundDecodeError::TopicCap(InboundTopicCapViolation {
                    topic,
                    framed_len: frame.len(),
                    cap,
                }));
            }
        }
        if T::HAS_INBOUND_DECODE_LIMITS {
            T::inbound_decode_limits(payload, frame.len(), flags).map_err(InboundDecodeError::Codec)
        } else {
            Ok(None)
        }
    }
    fn decode_inbound_frame_with_limits<T: Pload>(
        frame: &[u8],
        limits: Option<norito::DecodeLimits>,
    ) -> Result<T, ncore::Error> {
        limits.map_or_else(
            || ncore::decode_from_bytes::<T>(frame),
            |limits| ncore::decode_from_bytes_with_limits::<T>(frame, limits),
        )
    }
    #[cfg(test)]
    fn decode_inbound_frame<T: Pload + ClassifyTopic>(
        frame: &[u8],
        padding: usize,
        topic_frame_caps: crate::network::TopicFrameCaps,
    ) -> Result<T, InboundDecodeError> {
        let limits = inbound_frame_decode_limits::<T>(frame, padding, topic_frame_caps)?;
        decode_inbound_frame_with_limits::<T>(frame, limits).map_err(InboundDecodeError::Codec)
    }
    fn framed_message_len(
        bytes: &[u8],
        expected_schema: [u8; 16],
        padding: usize,
    ) -> Result<usize, MalformedPayloadFrameReason> {
        const LEN_OFF: usize = 4 + 1 + 1 + 16 + 1;
        if bytes.len() < ncore::Header::SIZE {
            return Err(MalformedPayloadFrameReason::HeaderTruncated);
        }
        if bytes[..4] != ncore::MAGIC {
            return Err(MalformedPayloadFrameReason::MagicMismatch);
        }
        if bytes.get(4) != Some(&ncore::VERSION_MAJOR)
            || bytes.get(5) != Some(&ncore::VERSION_MINOR)
        {
            return Err(MalformedPayloadFrameReason::VersionMismatch);
        }
        // schema hash: bytes[6..22]
        let schema = bytes
            .get(6..22)
            .ok_or(MalformedPayloadFrameReason::HeaderTruncated)?;
        if schema != expected_schema.as_slice() {
            return Err(MalformedPayloadFrameReason::SchemaMismatch);
        }
        // compression: bytes[22]
        if bytes.get(22) != Some(&(ncore::Compression::None as u8)) {
            return Err(MalformedPayloadFrameReason::CompressionUnsupported);
        }
        // payload length u64 LE: bytes[23..31]
        let len_bytes = bytes
            .get(LEN_OFF..LEN_OFF + 8)
            .ok_or(MalformedPayloadFrameReason::LengthMissing)?;
        let mut b = [0u8; 8];
        b.copy_from_slice(len_bytes);
        let payload_len_u64 = u64::from_le_bytes(b);
        if payload_len_u64 > ncore::max_archive_len() {
            return Err(MalformedPayloadFrameReason::LengthTooLarge);
        }
        let payload_len = usize::try_from(payload_len_u64)
            .map_err(|_| MalformedPayloadFrameReason::LengthTooLarge)?;
        let total = ncore::Header::SIZE
            .checked_add(padding)
            .and_then(|x| x.checked_add(payload_len))
            .ok_or(MalformedPayloadFrameReason::LengthOverflow)?;
        if total > bytes.len() {
            return Err(MalformedPayloadFrameReason::FrameTruncated);
        }
        Ok(total)
    }
    #[cfg(test)]
    mod tests {
        #[test]
        fn aligned_decode_scratch_preserves_bytes_and_reuses_storage() {
            let mut scratch = Vec::new();
            for alignment in [1, 2, 4, 8, 16, 32, 64, 128] {
                for length in [0, 1, 7, 257, 1024, 3] {
                    let payload = (0..length)
                        .map(|index| u8::try_from(index % 251).unwrap())
                        .collect::<Vec<_>>();
                    let decoded = super::copy_to_aligned_scratch(&mut scratch, &payload, alignment);
                    assert_eq!(decoded, payload);
                    if !decoded.is_empty() {
                        assert_eq!((decoded.as_ptr() as usize) % alignment, 0);
                    }
                }
            }
        }

        use super::*;
        use crate::Priority;
        use iroha_crypto::encryption::ChaCha20Poly1305;
        use iroha_data_model::peer::Peer;
        use norito::codec::{Decode, Encode};
        use std::{sync::Arc, time::Duration};
        #[test]
        fn captured_original_test_payload_identities() {
            crate::frame_identity_tests::test_payload_identity::<Dummy>(
                "iroha_p2p::peer::run::tests::Dummy",
            );
            crate::frame_identity_tests::test_payload_identity::<Blob>(
                "iroha_p2p::peer::run::tests::Blob",
            );
            crate::frame_identity_tests::test_payload_identity::<GuardedBlob>(
                "iroha_p2p::peer::run::tests::GuardedBlob",
            );
            crate::frame_identity_tests::test_payload_identity::<PredecodeGuardedBlob>(
                "iroha_p2p::peer::run::tests::PredecodeGuardedBlob",
            );
            crate::frame_identity_tests::test_payload_identity::<RoutedMsg>(
                "iroha_p2p::peer::run::tests::RoutedMsg",
            );
        }
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_p2p::peer::run::tests::Dummy")]
        #[derive(Encode, Decode, Clone, Debug)]
        struct Dummy;
        impl ClassifyTopic for Dummy {}
        impl<'a> ncore::DecodeFromSlice<'a> for Dummy {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
                ncore::decode_field_canonical::<Self>(bytes)
            }
        }
        struct PendingHandshake;
        #[async_trait::async_trait]
        impl<E: Enc> Handshake<E> for PendingHandshake {
            async fn handshake(self) -> Result<Ready<E>, crate::Error> {
                std::future::pending().await
            }
        }
        impl<E: Enc> Entrypoint<E> for PendingHandshake {
            fn connection_id(&self) -> ConnectionId {
                73
            }
            fn log_description(&self) -> String {
                "controlled pending authentication".to_owned()
            }
        }
        #[tokio::test(start_paused = true)]
        async fn peer_run_authentication_deadline_precedes_long_idle_and_retires_exact_connection()
        {
            let (service_tx, mut service_rx) = mpsc::channel::<ServiceMessage<Dummy>>(2);
            let authentication_deadline = PreauthDeadline::from_now(Duration::from_secs(35))
                .expect("authentication deadline");
            let task = tokio::spawn(run::<Dummy, ChaCha20Poly1305, _>(RunPeerArgs {
                peer: PendingHandshake,
                service_message_sender: service_tx,
                idle_timeout: Duration::from_secs(300),
                authentication_deadline,
                inbound_auth_completion: None,
                post_capacity: 1,
                outbound_frame_queue_limits: OutboundFrameQueueLimits::new(1, 1, 1, 1),
                outbound_post_byte_budgets: OutboundPostByteBudgets::new(1, 1, 0, 1)
                    .expect("outbound budget"),
                inbound_frame_byte_budgets: InboundFrameByteBudgets::new(1, 1, 0, 1)
                    .expect("inbound budget"),
                max_frame_bytes: 1,
                quic_datagrams_enabled: false,
                quic_datagram_max_payload_bytes: 0,
            }));
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_secs(34)).await;
            assert!(
                !task.is_finished(),
                "authentication remains owned before its deadline"
            );
            assert!(service_rx.try_recv().is_err());
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("authentication must not wait for the 300-second idle timeout")
                .expect("peer task must exit without panic");
            assert!(
                matches!(
                    service_rx.recv().await,
                    Some(ServiceMessage::Terminated(Terminated {
                        peer: None,
                        conn_id: 73
                    }))
                ),
                "the expired unauthenticated tenure must publish its exact termination witness"
            );
            assert!(
                service_rx.try_recv().is_err(),
                "termination is published exactly once"
            );
        }
        #[test]
        fn authenticated_via_survives_clone_mapping_and_into_parts() {
            let transport = Peer::new(
                "127.0.0.1:17447".parse().expect("transport address"),
                random_node_key_pair().public_key().clone(),
            );
            let semantic_origin = Peer::new(
                "127.0.0.1:17448".parse().expect("semantic origin address"),
                random_node_key_pair().public_key().clone(),
            );
            let authenticated_via = transport.id().clone();
            let message = PeerMessage::new(transport, Dummy, 1);
            let cloned = message.try_clone_retained().expect("synthetic clone");
            assert_eq!(cloned.authenticated_via(), &authenticated_via);
            drop(cloned);
            let mapped = message.map_payload(semantic_origin.clone(), |payload| payload);
            assert_eq!(mapped.peer, semantic_origin);
            assert_eq!(mapped.authenticated_via(), &authenticated_via);
            let (origin, split_via, Dummy, payload_bytes, guard) = mapped.into_parts();
            assert_eq!(origin, semantic_origin);
            assert_eq!(split_via, authenticated_via);
            assert_eq!(guard.authenticated_via(), &split_via);
            assert_eq!(payload_bytes, 1);
        }
        #[tokio::test(flavor = "current_thread")]
        async fn retention_guard_keeps_dispatch_bytes_and_source_credit_until_terminal_drop() {
            let source_budget = SharedByteBudget::new(1, 0).expect("source owner");
            let source_lease = source_budget.try_reserve(1, false).expect("source lease");
            let transport = Peer::new(
                "127.0.0.1:17451".parse().expect("transport address"),
                random_node_key_pair().public_key().clone(),
            );
            let semantic_origin = Peer::new(
                "127.0.0.1:17452".parse().expect("semantic origin address"),
                random_node_key_pair().public_key().clone(),
            );
            let authenticated_via = transport.id().clone();
            let mut message = PeerMessage::from_inbound_frame(
                transport,
                Dummy,
                1,
                7,
                InboundFrameRetention::new(source_lease, 0),
            );
            let dispatch_budgets =
                InboundDispatchByteBudgets::new(1, 1, 0).expect("dispatch geometry");
            let high_budget = Arc::clone(&dispatch_budgets.high);
            assert!(
                message
                    .transfer_to_dispatch_budget(&dispatch_budgets, true, false, false)
                    .await
            );
            assert_eq!(source_budget.retained_total(), 0);
            assert_eq!(high_budget.retained_total(), 1);
            let source_credits = Arc::new(tokio::sync::Semaphore::new(1));
            let credit = Arc::clone(&source_credits)
                .try_acquire_owned()
                .expect("source credit");
            message.retain_authenticated_source_credit(credit);
            assert_eq!(source_credits.available_permits(), 0);
            let redundant_credits = Arc::new(tokio::sync::Semaphore::new(1));
            let redundant = Arc::clone(&redundant_credits)
                .try_acquire_owned()
                .expect("redundant downstream credit");
            message.retain_authenticated_source_credit(redundant);
            assert_eq!(
                redundant_credits.available_permits(),
                1,
                "a redundant count owner must be released immediately"
            );
            assert!(
                message.try_clone_retained().is_none(),
                "one exact source credit must never be cloned"
            );
            let mapped = message.map_payload(semantic_origin, |payload| payload);
            let (_origin, split_via, Dummy, _payload_bytes, guard) = mapped.into_parts();
            assert_eq!(split_via, authenticated_via);
            assert_eq!(guard.authenticated_via(), &authenticated_via);
            assert_eq!(high_budget.retained_total(), 1);
            assert_eq!(source_credits.available_permits(), 0);
            drop(guard);
            assert_eq!(high_budget.retained_total(), 0);
            assert_eq!(source_credits.available_permits(), 1);
        }
        #[tokio::test(flavor = "current_thread")]
        async fn consensus_and_consensus_lane_topics_share_authenticated_high_source_credit() {
            let (safety, _safety_rx) = mpsc::channel(1);
            let (high, _high_rx) = mpsc::channel(1);
            let (low, _low_rx) = mpsc::channel(1);
            let senders = PeerMessageSenders {
                payload: mpsc::channel(1).0,
                block_sync: mpsc::channel(1).0,
                control: mpsc::channel(1).0,
                safety,
                high,
                low,
                dispatch_budgets: InboundDispatchByteBudgets::default(),
                source_credits: AuthenticatedSourceCredits::new(1),
                topic_frame_caps: crate::network::TopicFrameCaps::uniform(1),
                delivery_drain: Arc::new(InboundDeliveryDrain::new()),
            };
            let peer = Peer::new(
                "127.0.0.1:17455".parse().expect("peer address"),
                random_node_key_pair().public_key().clone(),
            );
            let mut v2 = PeerMessage::new(peer.clone(), Dummy, 1);
            assert!(matches!(
                senders
                    .transfer_before_send(&mut v2, Topic::Consensus, Priority::High, false)
                    .await,
                InboundDispatchAdmission::Admitted
            ));
            for topic in [Topic::ConsensusPayload, Topic::ConsensusChunk] {
                let mut lane = PeerMessage::new(peer.clone(), Dummy, 1);
                assert!(matches!(
                    senders
                        .transfer_before_send(&mut lane, topic, Priority::High, false)
                        .await,
                    InboundDispatchAdmission::ByteBudgetFull
                ));
            }
            drop(v2);
            let mut lane = PeerMessage::new(peer, Dummy, 1);
            assert!(matches!(
                senders
                    .transfer_before_send(
                        &mut lane,
                        Topic::ConsensusPayload,
                        Priority::High,
                        false,
                    )
                    .await,
                InboundDispatchAdmission::Admitted
            ));
        }
        #[tokio::test(flavor = "current_thread")]
        async fn dispatch_worker_shutdown_drains_reliable_replaced_connection_to_actor() {
            let source_budget = SharedByteBudget::new(1, 0).expect("source owner");
            let source_lease = source_budget.try_reserve(1, false).expect("source lease");
            let peer = Peer::new(
                "127.0.0.1:17449".parse().expect("peer address"),
                random_node_key_pair().public_key().clone(),
            );
            let pending = PendingInbound {
                message: PeerMessage::from_inbound_frame(
                    peer.clone(),
                    RoutedMsg::ConsensusSafety(7),
                    1,
                    41,
                    InboundFrameRetention::new(source_lease, 0),
                ),
                topic: Topic::ConsensusSafety,
                priority: Priority::Low,
            };
            assert!(crate::network::is_reliable_progress_route(
                pending.topic,
                pending.message.payload.subscriber_route(),
            ));
            let dispatch_budgets =
                InboundDispatchByteBudgets::new(1, 1, 0).expect("dispatch owner geometry");
            let high_budget = Arc::clone(&dispatch_budgets.high);
            let (safety, mut safety_rx) = mpsc::channel(1);
            let (high, _high_rx) = mpsc::channel(1);
            let (low, _low_rx) = mpsc::channel(1);
            safety
                .send(PeerMessage::new(peer, RoutedMsg::ConsensusSafety(0), 0))
                .await
                .expect("fill the network-actor lane");
            let source_credits = AuthenticatedSourceCredits::new(1);
            let source_credit_probe = source_credits.clone();
            let senders = PeerMessageSenders {
                payload: mpsc::channel(1).0,
                block_sync: mpsc::channel(1).0,
                control: mpsc::channel(1).0,
                safety,
                high,
                low,
                dispatch_budgets,
                source_credits,
                topic_frame_caps: crate::network::TopicFrameCaps::uniform(1),
                delivery_drain: Arc::new(InboundDeliveryDrain::new()),
            };
            let (pending_tx, pending_rx) = mpsc::unbounded_channel();
            pending_tx
                .send(pending)
                .expect("queue source-retained item");
            let workers = InboundDispatchWorkers(vec![tokio::spawn(run_inbound_dispatch_lane(
                pending_rx,
                senders,
                InboundDispatchLane::Safety,
            ))]);
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if high_budget.retained_total() == 1
                        && source_credit_probe.available_safety_for_test() == 0
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("worker must reach the blocked network-actor send");
            assert_eq!(source_budget.retained_total(), 0);
            assert_eq!(high_budget.retained_total(), 1);
            assert_eq!(source_credit_probe.available_safety_for_test(), 0);
            drop(pending_tx);
            let shutdown = tokio::spawn(workers.shutdown());
            tokio::task::yield_now().await;
            assert!(
                !shutdown.is_finished(),
                "teardown must wait instead of aborting the blocked reliable delivery"
            );
            let blocker = safety_rx.recv().await.expect("remove actor-lane blocker");
            assert_eq!(blocker.payload, RoutedMsg::ConsensusSafety(0));
            drop(blocker);
            let delivered = tokio::time::timeout(Duration::from_secs(1), safety_rx.recv())
                .await
                .expect("released actor capacity must advance the replaced connection")
                .expect("replaced-connection reliable item reaches the actor");
            assert_eq!(delivered.payload, RoutedMsg::ConsensusSafety(7));
            assert_eq!(delivered.connection_id(), Some(41));
            assert!(
                delivered.try_clone_retained().is_none(),
                "one exact source owner must cross the connection replacement boundary"
            );
            tokio::time::timeout(Duration::from_secs(1), shutdown)
                .await
                .expect("finite closed connection queue must drain")
                .expect("dispatch worker shutdown task must not panic")
                .expect("dispatch workers must terminate cleanly");
            assert_eq!(
                source_credit_probe.available_safety_for_test(),
                0,
                "actor ownership retains the authenticated source credit"
            );
            assert_eq!(high_budget.retained_total(), 1);
            drop(delivered);
            assert_eq!(source_credit_probe.available_safety_for_test(), 1);
            assert_eq!(high_budget.retained_total(), 0);
            assert!(
                safety_rx.recv().await.is_none(),
                "the closed replaced connection must deliver the exact item only once"
            );
        }
        #[tokio::test(flavor = "current_thread")]
        async fn peer_task_abort_drains_queued_worker_then_notifies_exact_connection_once() {
            let source_budget = SharedByteBudget::new(1, 0).expect("source owner");
            let source_lease = source_budget.try_reserve(1, false).expect("source lease");
            let peer = Peer::new(
                "127.0.0.1:17461".parse().expect("peer address"),
                random_node_key_pair().public_key().clone(),
            );
            let conn_id = 61;
            let pending = PendingInbound {
                message: PeerMessage::from_inbound_frame(
                    peer.clone(),
                    RoutedMsg::ConsensusSafety(7),
                    1,
                    conn_id,
                    InboundFrameRetention::new(source_lease, 0),
                ),
                topic: Topic::ConsensusSafety,
                priority: Priority::Low,
            };
            let budgets = InboundDispatchByteBudgets::new(1, 1, 0).expect("dispatch geometry");
            let high_budget = Arc::clone(&budgets.high);
            let (safety, mut safety_rx) = mpsc::channel(1);
            let (high, _high_rx) = mpsc::channel(1);
            let (low, _low_rx) = mpsc::channel(1);
            safety
                .send(PeerMessage::new(
                    peer.clone(),
                    RoutedMsg::ConsensusSafety(0),
                    0,
                ))
                .await
                .expect("fill the network-actor lane");
            let source_credits = AuthenticatedSourceCredits::new(1);
            let source_credit_probe = source_credits.clone();
            let delivery_drain = Arc::new(InboundDeliveryDrain::new());
            let senders = PeerMessageSenders {
                payload: mpsc::channel(1).0,
                block_sync: mpsc::channel(1).0,
                control: mpsc::channel(1).0,
                safety,
                high,
                low,
                dispatch_budgets: budgets,
                source_credits,
                topic_frame_caps: crate::network::TopicFrameCaps::uniform(1),
                delivery_drain: Arc::clone(&delivery_drain),
            };
            let (pending_tx, pending_rx) = mpsc::unbounded_channel();
            let workers = InboundDispatchWorkers(vec![tokio::spawn(run_inbound_dispatch_lane(
                pending_rx,
                senders,
                InboundDispatchLane::Safety,
            ))]);
            let (service_tx, mut service_rx) = mpsc::channel::<ServiceMessage<RoutedMsg>>(2);
            let task_peer = peer.clone();
            let task_drain = Arc::clone(&delivery_drain);
            let peer_task = tokio::spawn(async move {
                let mut guard = PeerTaskTerminationGuard::new(service_tx, conn_id);
                guard.set_peer(task_peer);
                guard.set_delivery_drain(task_drain);
                guard.set_dispatch_workers(vec![pending_tx.clone()], workers);
                pending_tx
                    .send(pending)
                    .expect("queue authenticated reliable delivery");
                std::future::pending::<()>().await;
            });
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if high_budget.retained_total() == 1
                        && source_credit_probe.available_safety_for_test() == 0
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("worker must reach the blocked actor send");
            assert_eq!(source_budget.retained_total(), 0);
            assert!(!delivery_drain.is_complete());
            peer_task.abort();
            let cancellation = peer_task
                .await
                .expect_err("isolated peer task must observe the requested abort");
            assert!(cancellation.is_cancelled());
            tokio::task::yield_now().await;
            assert!(
                service_rx.try_recv().is_err(),
                "termination cannot overtake a queued reliable delivery"
            );
            assert!(
                !delivery_drain.is_complete(),
                "producer fence stays open while the queued worker is blocked"
            );
            let blocker = safety_rx.recv().await.expect("remove actor-lane blocker");
            assert_eq!(blocker.payload, RoutedMsg::ConsensusSafety(0));
            drop(blocker);
            let delivered = tokio::time::timeout(Duration::from_secs(1), safety_rx.recv())
                .await
                .expect("released actor capacity must drain the aborted peer task")
                .expect("queued reliable item reaches the actor");
            assert_eq!(delivered.payload, RoutedMsg::ConsensusSafety(7));
            assert_eq!(delivered.connection_id(), Some(conn_id));
            let terminated = tokio::time::timeout(Duration::from_secs(1), service_rx.recv())
                .await
                .expect("cleanup must notify the actor")
                .expect("service channel remains open");
            match terminated {
                ServiceMessage::Terminated(Terminated {
                    peer: Some(terminated_peer),
                    conn_id: terminated_conn_id,
                }) => {
                    assert_eq!(terminated_peer, peer);
                    assert_eq!(terminated_conn_id, conn_id);
                }
                _ => panic!("cleanup must publish the exact connection termination"),
            }
            assert!(
                !delivery_drain.is_complete(),
                "the actor-held delivery guard remains charged after producer close"
            );
            drop(delivered);
            tokio::time::timeout(Duration::from_secs(1), delivery_drain.wait_complete())
                .await
                .expect("terminal receiver drop must complete the delivery fence");
            assert!(
                !matches!(
                    tokio::time::timeout(Duration::from_millis(25), service_rx.recv()).await,
                    Ok(Some(_))
                ),
                "one aborted peer task publishes exactly one termination notice"
            );
        }
        #[tokio::test(flavor = "current_thread")]
        async fn peer_task_panic_closes_delivery_producer_and_notifies_exact_connection_once() {
            let peer = Peer::new(
                "127.0.0.1:17462".parse().expect("peer address"),
                random_node_key_pair().public_key().clone(),
            );
            let conn_id = 62;
            let delivery_drain = Arc::new(InboundDeliveryDrain::new());
            let task_peer = peer.clone();
            let task_drain = Arc::clone(&delivery_drain);
            let (service_tx, mut service_rx) = mpsc::channel::<ServiceMessage<Dummy>>(2);
            let peer_task = tokio::spawn(async move {
                let mut guard = PeerTaskTerminationGuard::new(service_tx, conn_id);
                guard.set_peer(task_peer);
                guard.set_delivery_drain(task_drain);
                panic!("synthetic isolated peer-task panic");
            });
            let panic = peer_task
                .await
                .expect_err("synthetic peer task must unwind");
            assert!(panic.is_panic());
            let terminated = tokio::time::timeout(Duration::from_secs(1), service_rx.recv())
                .await
                .expect("unwind cleanup must notify the actor")
                .expect("service channel remains open");
            match terminated {
                ServiceMessage::Terminated(Terminated {
                    peer: Some(terminated_peer),
                    conn_id: terminated_conn_id,
                }) => {
                    assert_eq!(terminated_peer, peer);
                    assert_eq!(terminated_conn_id, conn_id);
                }
                _ => panic!("unwind cleanup must publish the exact connection termination"),
            }
            assert!(delivery_drain.is_complete());
            assert!(
                !matches!(
                    tokio::time::timeout(Duration::from_millis(25), service_rx.recv()).await,
                    Ok(Some(_))
                ),
                "one unwinding peer task publishes exactly one termination notice"
            );
        }
        #[tokio::test(flavor = "current_thread")]
        async fn dispatch_worker_join_error_is_returned_after_fail_closed_teardown() {
            let workers = InboundDispatchWorkers(vec![tokio::spawn(async {
                panic!("synthetic dispatch worker panic");
            })]);
            let failures = workers
                .shutdown()
                .await
                .expect_err("worker panic must not be silently ignored");
            assert_eq!(failures.len(), 1);
            assert!(failures[0].is_panic());
        }
        #[tokio::test(flavor = "current_thread")]
        async fn closed_dispatch_target_releases_source_and_dispatch_ownership() {
            for lane in [InboundDispatchLane::High, InboundDispatchLane::Low] {
                let source_budget = SharedByteBudget::new(1, 0).expect("source owner");
                let source_lease = source_budget.try_reserve(1, false).expect("source lease");
                let peer = Peer::new(
                    "127.0.0.1:17450".parse().expect("peer address"),
                    random_node_key_pair().public_key().clone(),
                );
                let pending = PendingInbound {
                    message: PeerMessage::from_inbound_frame(
                        peer,
                        Dummy,
                        1,
                        1,
                        InboundFrameRetention::new(source_lease, 0),
                    ),
                    topic: if matches!(lane, InboundDispatchLane::Low) {
                        Topic::TxGossip
                    } else {
                        Topic::Control
                    },
                    priority: if matches!(lane, InboundDispatchLane::Low) {
                        Priority::Low
                    } else {
                        Priority::High
                    },
                };
                let dispatch_budgets =
                    InboundDispatchByteBudgets::new(1, 1, 0).expect("dispatch owner geometry");
                let dispatch_budget =
                    dispatch_budgets.budget(!matches!(lane, InboundDispatchLane::Low));
                let (safety, _safety_rx) = mpsc::channel(1);
                let (high, high_rx) = mpsc::channel(1);
                let (low, low_rx) = mpsc::channel(1);
                drop(high_rx);
                drop(low_rx);
                let senders = PeerMessageSenders {
                    payload: mpsc::channel(1).0,
                    block_sync: mpsc::channel(1).0,
                    control: mpsc::channel(1).0,
                    safety,
                    high,
                    low,
                    dispatch_budgets,
                    source_credits: AuthenticatedSourceCredits::new(1),
                    topic_frame_caps: crate::network::TopicFrameCaps::uniform(1),
                    delivery_drain: Arc::new(InboundDeliveryDrain::new()),
                };
                let (pending_tx, pending_rx) = mpsc::unbounded_channel();
                pending_tx
                    .send(pending)
                    .expect("queue source-retained item");
                drop(pending_tx);
                let worker = tokio::spawn(run_inbound_dispatch_lane(pending_rx, senders, lane));
                tokio::time::timeout(Duration::from_secs(1), worker)
                    .await
                    .expect("closed target must stop the worker")
                    .expect("dispatch worker must not panic");
                assert_eq!(source_budget.retained_total(), 0);
                assert_eq!(
                    dispatch_budget.retained_total(),
                    0,
                    "failed channel send must drop the transferred dispatch lease"
                );
            }
        }
        #[tokio::test(flavor = "current_thread")]
        async fn authenticated_source_credit_precedes_network_and_subscriber_backlogs() {
            let source_budget = SharedByteBudget::new(2, 0).expect("source owner");
            let first_source = source_budget
                .try_reserve(1, false)
                .expect("first source lease");
            let second_source = source_budget
                .try_reserve(1, false)
                .expect("second source lease");
            let peer = Peer::new(
                "127.0.0.1:17453".parse().expect("peer address"),
                random_node_key_pair().public_key().clone(),
            );
            let pending = |connection_id, source| PendingInbound {
                message: PeerMessage::from_inbound_frame(
                    peer.clone(),
                    Dummy,
                    1,
                    connection_id,
                    InboundFrameRetention::new(source, 0),
                ),
                topic: Topic::Control,
                priority: Priority::High,
            };
            let dispatch_budgets =
                InboundDispatchByteBudgets::new(2, 1, 0).expect("dispatch owner geometry");
            let high_budget = Arc::clone(&dispatch_budgets.high);
            let (safety, _safety_rx) = mpsc::channel(2);
            let (high, mut high_rx) = mpsc::channel(2);
            let (low, _low_rx) = mpsc::channel(2);
            let senders = PeerMessageSenders {
                payload: mpsc::channel(1).0,
                block_sync: mpsc::channel(1).0,
                control: mpsc::channel(1).0,
                safety,
                high,
                low,
                dispatch_budgets,
                source_credits: AuthenticatedSourceCredits::new(1),
                topic_frame_caps: crate::network::TopicFrameCaps::uniform(1),
                delivery_drain: Arc::new(InboundDeliveryDrain::new()),
            };
            let (pending_tx, pending_rx) = mpsc::unbounded_channel();
            pending_tx
                .send(pending(1, first_source))
                .expect("queue first source-owned item");
            pending_tx
                .send(pending(1, second_source))
                .expect("queue second source-owned item");
            let worker = tokio::spawn(run_inbound_dispatch_lane(
                pending_rx,
                senders,
                InboundDispatchLane::High,
            ));
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
            assert_eq!(
                high_rx.len(),
                1,
                "a source cannot fill an otherwise roomy network-actor channel"
            );
            assert_eq!(high_budget.retained_total(), 1);
            let first = high_rx.recv().await.expect("first item reaches the actor");
            assert!(
                first.try_clone_retained().is_none(),
                "the authenticated-source credit must already precede subscriber fan-out"
            );
            drop(first);
            let second = tokio::time::timeout(Duration::from_secs(1), high_rx.recv())
                .await
                .expect("releasing the first terminal guard must advance source rank")
                .expect("second source-owned item reaches the actor");
            assert_eq!(second.authenticated_via(), peer.id());
            drop(second);
            drop(pending_tx);
            worker.await.expect("dispatch worker must finish");
            assert_eq!(source_budget.retained_total(), 0);
            assert_eq!(high_budget.retained_total(), 0);
        }
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_p2p::peer::run::tests::Blob")]
        #[derive(Encode, Decode, Clone, Debug)]
        struct Blob(Vec<u8>);
        impl ClassifyTopic for Blob {}
        impl<'a> ncore::DecodeFromSlice<'a> for Blob {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
                ncore::decode_field_canonical::<Self>(bytes)
            }
        }
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_p2p::peer::run::tests::GuardedBlob")]
        #[derive(Encode, Decode, Clone, Debug)]
        struct GuardedBlob(Vec<u8>);
        impl ClassifyTopic for GuardedBlob {
            const HAS_INBOUND_DECODE_LIMITS: bool = true;
            fn inbound_decode_limits(
                _payload: &[u8],
                _framed_len: usize,
                _flags: u8,
            ) -> Result<Option<norito::DecodeLimits>, ncore::Error> {
                Ok(Some(norito::DecodeLimits::new(8, 1024, 16, 1024, 16)))
            }
        }
        impl<'a> ncore::DecodeFromSlice<'a> for GuardedBlob {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
                ncore::decode_field_canonical::<Self>(bytes)
            }
        }
        static PREDECODE_POLICY_CALLS: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_p2p::peer::run::tests::PredecodeGuardedBlob")]
        #[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
        struct PredecodeGuardedBlob(Vec<u8>);
        impl ClassifyTopic for PredecodeGuardedBlob {
            const HAS_INBOUND_DECODE_LIMITS: bool = true;
            fn topic(&self) -> Topic {
                Topic::ConsensusSafety
            }
            fn inbound_topic(payload: &[u8], _flags: u8) -> Result<Option<Topic>, ncore::Error> {
                if payload.is_empty() {
                    return Err(ncore::Error::LengthMismatch);
                }
                Ok(Some(Topic::ConsensusSafety))
            }
            fn inbound_decode_limits(
                _payload: &[u8],
                _framed_len: usize,
                _flags: u8,
            ) -> Result<Option<norito::DecodeLimits>, ncore::Error> {
                PREDECODE_POLICY_CALLS.fetch_add(1, Ordering::SeqCst);
                Ok(Some(norito::DecodeLimits::new(
                    1024,
                    1024 * 1024,
                    4096,
                    1024 * 1024,
                    64,
                )))
            }
        }
        impl<'a> ncore::DecodeFromSlice<'a> for PredecodeGuardedBlob {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
                ncore::decode_field_canonical::<Self>(bytes)
            }
        }
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = "iroha_p2p::peer::run::tests::RoutedMsg")]
        #[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
        enum RoutedMsg {
            ConsensusSafety(u8),
            Control(u8),
            Consensus(u8),
            ConsensusPayload(u8),
            ConsensusChunk(u8),
            HighOther(u8),
            TxGossip(u8),
        }
        impl ClassifyTopic for RoutedMsg {
            fn topic(&self) -> Topic {
                match self {
                    Self::ConsensusSafety(_) => Topic::ConsensusSafety,
                    Self::Control(_) => Topic::Control,
                    Self::Consensus(_) => Topic::Consensus,
                    Self::ConsensusPayload(_) => Topic::ConsensusPayload,
                    Self::ConsensusChunk(_) => Topic::ConsensusChunk,
                    Self::HighOther(_) => Topic::BlockSync,
                    Self::TxGossip(_) => Topic::TxGossip,
                }
            }
            fn priority(&self) -> Priority {
                if matches!(self, Self::HighOther(_)) {
                    Priority::High
                } else {
                    Priority::Low
                }
            }
        }
        impl<'a> ncore::DecodeFromSlice<'a> for RoutedMsg {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
                ncore::decode_field_canonical::<Self>(bytes)
            }
        }
        struct TestOutboundReceivers<T> {
            termination_receiver: watch::Receiver<bool>,
            _classes:
                [post_channel::Receiver<RetainedPost<T>>; crate::TransportAdmissionClass::COUNT],
        }
        impl<T> TestOutboundReceivers<T> {
            async fn drop_on_explicit_termination(mut self) {
                loop {
                    if *self.termination_receiver.borrow_and_update() {
                        return;
                    }
                    self.termination_receiver
                        .changed()
                        .await
                        .expect("explicit test termination");
                }
            }
        }
        fn test_outbound_mailbox_for_peer<T: Pload>(
            capacity: usize,
            budgets: &OutboundPostByteBudgets,
            peer_id: &PeerId,
        ) -> (handles::PeerHandle<T>, TestOutboundReceivers<T>) {
            if budgets.source_geometry.protected_sources().is_none() {
                assert!(
                    budgets
                        .source_geometry
                        .install_protected_sources(HashSet::new())
                );
            }
            let (senders, classes) = handles::class_channels(capacity);
            let (termination_sender, termination_receiver) = watch::channel(false);
            (
                handles::PeerHandle {
                    senders,
                    termination_sender,
                    post_admission: post_admission::Admission::Synthetic {
                        high: budgets
                            .high(peer_id)
                            .expect("test peer reserve must fit the configured peer bound"),
                        low: budgets.low(),
                        overhead: crate::frame_queue_charge(0)
                            .expect("default frame overhead must fit"),
                    },
                },
                TestOutboundReceivers {
                    termination_receiver,
                    _classes: classes,
                },
            )
        }
        fn routed_post_charge(message: &RoutedMsg) -> usize {
            crate::frame_queue_charge(
                checked_data_message_wire_len(message)
                    .expect("test routed message must have a countable wire length"),
            )
            .expect("test routed message stream charge must fit")
        }
        #[tokio::test(flavor = "current_thread")]
        async fn connected_outbound_owner_is_process_wide_and_isolates_peer_progress() {
            const ORDINARY_PEERS: usize = 8;
            let ordinary = RoutedMsg::Consensus(1);
            let safety = RoutedMsg::ConsensusSafety(2);
            let low = RoutedMsg::TxGossip(3);
            let high_other = RoutedMsg::HighOther(4);
            let ordinary_charge = routed_post_charge(&ordinary);
            let safety_charge = routed_post_charge(&safety);
            let low_charge = routed_post_charge(&low);
            let high_other_charge = routed_post_charge(&high_other);
            let progress_charge = ordinary_charge.max(safety_charge).max(high_other_charge);
            let ordinary_max = ordinary_charge
                .checked_mul(ORDINARY_PEERS)
                .expect("test ordinary geometry must fit");
            let budgets = OutboundPostByteBudgets::new(
                ordinary_max,
                low_charge,
                progress_charge,
                ORDINARY_PEERS + 1,
            )
            .expect("test aggregate geometry must fit");
            let mut handles = Vec::new();
            let mut receivers = Vec::new();
            let peer_ids = (0..=ORDINARY_PEERS)
                .map(|_| {
                    let key_pair = iroha_crypto::KeyPair::random_with_algorithm(
                        iroha_crypto::Algorithm::BlsNormal,
                    );
                    PeerId::from(key_pair.public_key().clone())
                })
                .collect::<Vec<_>>();
            for peer_id in &peer_ids {
                let (handle, receiver) =
                    test_outbound_mailbox_for_peer::<RoutedMsg>(2, &budgets, peer_id);
                handles.push(handle);
                receivers.push(receiver);
            }
            for handle in handles.iter().take(ORDINARY_PEERS) {
                handle
                    .post(ordinary.clone())
                    .expect("each exact aggregate share must fit across distinct peers");
            }
            assert_eq!(budgets.retained_high_ordinary(), ordinary_max);
            handles[ORDINARY_PEERS]
                .post(high_other.clone())
                .expect("high block-sync work must use this peer's progress reserve");
            assert_eq!(
                handles[ORDINARY_PEERS].post(ordinary.clone()),
                Err(handles::PostError::Full),
                "one peer cannot multiply its exact progress reserve"
            );
            handles[0]
                .post(safety.clone())
                .expect("a non-reader may pin only its own protected reserve");
            assert_eq!(
                budgets.retained_high_total(),
                ordinary_max + high_other_charge + safety_charge
            );
            handles[ORDINARY_PEERS]
                .post(low.clone())
                .expect("low traffic has an independent process-wide owner");
            assert_eq!(budgets.retained_low_total(), low_charge);
            assert_eq!(
                handles[0].post(low),
                Err(handles::PostError::Full),
                "low ownership must also be aggregate across peers"
            );
            let (replacement, _replacement_receivers) =
                test_outbound_mailbox_for_peer::<RoutedMsg>(2, &budgets, &peer_ids[ORDINARY_PEERS]);
            assert_eq!(
                replacement.post(high_other.clone()),
                Err(handles::PostError::Full),
                "a replacement session must share ownership with the draining predecessor"
            );
            let predecessor_handle = handles
                .pop()
                .expect("the predecessor handle is the final test connection");
            let predecessor_receivers = receivers
                .pop()
                .expect("the predecessor receivers are the final test connection");
            let teardown = tokio::spawn(predecessor_receivers.drop_on_explicit_termination());
            predecessor_handle.request_termination();
            drop(predecessor_handle);
            teardown
                .await
                .expect("explicit connection teardown must complete");
            replacement
                .post(high_other)
                .expect("replacement may proceed after explicit predecessor teardown releases R");
            assert_eq!(budgets.retained_high_ordinary(), ordinary_max);
            let extra_key_pair = random_node_key_pair();
            let extra_peer = PeerId::from(extra_key_pair.public_key().clone());
            assert!(
                budgets.high(&extra_peer).is_none(),
                "the peer-reserve registry must fail closed at the configured connection bound"
            );
        }
        fn framed_padding<T>() -> usize {
            let align = ncore::archived_payload_align::<T>();
            if align <= 1 {
                return 0;
            }
            let remainder = ncore::Header::SIZE % align;
            if remainder == 0 { 0 } else { align - remainder }
        }
        #[test]
        fn data_envelope_applies_nested_decode_limits_before_sequence_allocation() {
            let mut frame = Vec::new();
            encode_wire_message(&Message::Data(GuardedBlob(vec![7; 64])), &mut frame)
                .expect("encode guarded data envelope");
            let error = decode_inbound_frame::<Message<GuardedBlob>>(
                &frame,
                framed_padding::<Message<GuardedBlob>>(),
                crate::network::TopicFrameCaps::uniform(usize::MAX),
            )
            .expect_err("nested sequence above the policy must be rejected");
            assert!(matches!(
                error,
                InboundDecodeError::Codec(ncore::Error::SequenceLengthExceeded {
                    length: 64,
                    limit: 8
                })
            ));
        }
        #[test]
        fn payload_without_inbound_policy_retains_large_message_compatibility() {
            let mut frame = Vec::new();
            encode_wire_message(&Message::Data(Blob(vec![9; 64 * 1024])), &mut frame)
                .expect("encode unrestricted data envelope");
            let decoded = decode_inbound_frame::<Message<Blob>>(
                &frame,
                framed_padding::<Message<Blob>>(),
                crate::network::TopicFrameCaps::uniform(usize::MAX),
            )
            .expect("payloads without a policy keep the ordinary decode path");
            let Message::Data(Blob(bytes)) = decoded else {
                panic!("decoded the wrong P2P envelope variant");
            };
            assert_eq!(bytes.len(), 64 * 1024);
        }
        #[test]
        fn raw_message_wrapper_rejects_unknown_and_trailing_unit_layouts() {
            let flags = ncore::default_encode_flags();
            assert!(
                <Message<PredecodeGuardedBlob> as ClassifyTopic>::inbound_topic(
                    &99_u32.to_le_bytes(),
                    flags,
                )
                .is_err(),
                "an unknown outer message discriminant must fail closed"
            );
            let mut trailing_ping = 1_u32.to_le_bytes().to_vec();
            trailing_ping.push(0);
            assert!(
                <Message<PredecodeGuardedBlob> as ClassifyTopic>::inbound_topic(
                    &trailing_ping,
                    flags,
                )
                .is_err(),
                "unit variants must not hide trailing attacker bytes"
            );
        }
        #[test]
        fn message_decode_from_slice_roundtrip() {
            let message = Message::Data(Blob(vec![1u8, 2, 3]));
            let bytes = ncore::to_bytes(&message).expect("encode message");
            let view = ncore::from_bytes_view(&bytes).expect("message view");
            let decoded = view
                .decode_exact::<Message<Blob>>()
                .expect("decode from slice");
            match decoded {
                Message::Data(blob) => assert_eq!(blob.0, vec![1u8, 2, 3]),
                _ => panic!("expected data message"),
            }
        }
        #[tokio::test(flavor = "current_thread")]
        async fn termination_notification_waits_boundedly_for_service_capacity() {
            let (tx, mut rx) = mpsc::channel::<ServiceMessage<Dummy>>(1);
            tx.try_send(ServiceMessage::InboundCancelled(7))
                .expect("fill service queue");
            let notify = notify_peer_terminated(
                &tx,
                Terminated {
                    peer: None,
                    conn_id: 42,
                },
                Duration::from_millis(100),
            );
            let receive = async {
                assert!(matches!(
                    rx.recv().await,
                    Some(ServiceMessage::InboundCancelled(7))
                ));
                rx.recv().await
            };
            let (accepted, delivered) = tokio::join!(notify, receive);
            assert!(
                accepted,
                "capacity reopening must preserve termination delivery"
            );
            assert!(matches!(
                delivered,
                Some(ServiceMessage::Terminated(Terminated { conn_id: 42, .. }))
            ));
        }
        #[tokio::test(flavor = "current_thread")]
        async fn termination_notification_does_not_wait_forever_on_full_service_queue() {
            let (tx, mut rx) = mpsc::channel::<ServiceMessage<Dummy>>(1);
            tx.try_send(ServiceMessage::InboundCancelled(7))
                .expect("fill service queue");
            let accepted = tokio::time::timeout(
                Duration::from_millis(100),
                notify_peer_terminated(
                    &tx,
                    Terminated {
                        peer: None,
                        conn_id: 43,
                    },
                    Duration::from_millis(5),
                ),
            )
            .await
            .expect("termination notifier must obey its internal deadline");
            assert!(
                !accepted,
                "full service queue must fail closed at the deadline"
            );
            assert!(matches!(
                rx.recv().await,
                Some(ServiceMessage::InboundCancelled(7))
            ));
            assert!(
                matches!(
                    tokio::time::timeout(Duration::from_secs(1), rx.recv()).await,
                    Ok(Some(ServiceMessage::Terminated(Terminated {
                        conn_id: 43,
                        ..
                    })))
                ),
                "the bounded return must leave an eventual exact-connection delivery retry"
            );
        }
        #[test]
        fn inbound_health_limiter_allows_only_the_initial_burst() {
            let now = Instant::now();
            let mut limiter = InboundPingLimiter::new(now, Duration::from_secs(20));
            assert!(limiter.admit_at(now));
            assert!(limiter.admit_at(now));
            assert!(!limiter.admit_at(now));
        }
        #[test]
        fn inbound_health_limiter_refills_one_token_per_period_and_caps_credit() {
            let now = Instant::now();
            let period = Duration::from_secs(10);
            let mut limiter = InboundPingLimiter::new(now, period * 2);
            assert!(limiter.admit_at(now));
            assert!(limiter.admit_at(now));
            assert!(!limiter.admit_at(now));

            let one_period = now + period;
            assert!(limiter.admit_at(one_period));
            assert!(!limiter.admit_at(one_period));

            let fully_refilled = one_period + period * 20;
            assert!(limiter.admit_at(fully_refilled));
            assert!(limiter.admit_at(fully_refilled));
            assert!(!limiter.admit_at(fully_refilled));
        }
        #[test]
        fn inbound_ping_limiter_does_not_bank_time_at_capacity() {
            let now = Instant::now();
            let period = Duration::from_secs(10);
            let mut limiter = InboundPingLimiter::new(now, period * 2);
            let long_idle = now + period * 20;
            assert!(limiter.admit_at(long_idle));
            assert!(limiter.admit_at(long_idle));
            assert!(!limiter.admit_at(long_idle));
            assert!(!limiter.admit_at(long_idle + period / 2));
            assert!(limiter.admit_at(long_idle + period));
            assert!(!limiter.admit_at(long_idle + period));
        }
        #[test]
        fn sparse_read_tail_does_not_pin_a_maximum_frame_allocation() {
            let retained_cap = MAX_RETAINED_MESSAGE_BUFFER_CAP;
            let mut buffer = BytesMut::with_capacity(retained_cap * 2);
            buffer.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
            compact_sparse_bytes_to_cap(&mut buffer, retained_cap);
            assert_eq!(buffer.as_ref(), [0xAA, 0xBB, 0xCC]);
            assert!(buffer.capacity() <= retained_cap);
        }
    }
}
mod state {
    //! Module for peer stages.
    use super::{cryptographer::Cryptographer, *};
    use iroha_crypto::{KeyPair, PublicKey, Signature};
    use iroha_data_model::peer::Peer;
    use iroha_primitives::addr::SocketAddr;
    #[derive(Clone, Debug, Encode, Decode)]
    #[norito(decode_from_slice)]
    pub(super) struct HandshakeConfidentialDigest {
        vk_set_hash: Option<[u8; 32]>,
        poseidon_params_id: Option<u32>,
        pedersen_params_id: Option<u32>,
        conf_rules_version: Option<u32>,
        zk_policy_hash: Option<[u8; 32]>,
    }
    impl From<&crate::ConfidentialFeatureDigest> for HandshakeConfidentialDigest {
        fn from(digest: &crate::ConfidentialFeatureDigest) -> Self {
            Self {
                vk_set_hash: digest.vk_set_hash,
                poseidon_params_id: digest.poseidon_params_id,
                pedersen_params_id: digest.pedersen_params_id,
                conf_rules_version: digest.conf_rules_version,
                zk_policy_hash: digest.zk_policy_hash,
            }
        }
    }
    impl From<HandshakeConfidentialDigest> for crate::ConfidentialFeatureDigest {
        fn from(digest: HandshakeConfidentialDigest) -> Self {
            Self {
                vk_set_hash: digest.vk_set_hash,
                poseidon_params_id: digest.poseidon_params_id,
                pedersen_params_id: digest.pedersen_params_id,
                conf_rules_version: digest.conf_rules_version,
                zk_policy_hash: digest.zk_policy_hash,
            }
        }
    }
    #[derive(Clone, Copy, Debug, Encode, Decode)]
    pub(super) struct HandshakeConsensusMeta {
        pub(super) mode: Option<ConsensusMode>,
        pub(super) proto_version: Option<u32>,
        pub(super) consensus_fingerprint: Option<[u8; 32]>,
        pub(super) config: Option<ConsensusConfigCaps>,
    }
    #[derive(Clone, Debug, Encode, Decode)]
    pub(super) struct HandshakeConfidentialMeta {
        pub(super) enabled: Option<bool>,
        pub(super) assume_valid: Option<bool>,
        pub(super) verifier_backend: Option<String>,
        pub(super) features: Option<HandshakeConfidentialDigest>,
    }
    #[derive(Clone, Debug, Encode, Decode)]
    pub(super) struct HandshakeCryptoMeta {
        pub(super) sm_enabled: Option<bool>,
        pub(super) sm_openssl_preview: Option<bool>,
    }
    fn build_trust_meta(trust_gossip: bool, scion_supported: bool) -> HandshakeTrustMeta {
        HandshakeTrustMeta {
            trust_gossip,
            scion_supported,
        }
    }
    #[derive(Clone, Debug, Encode, Decode)]
    pub(super) struct HandshakeTrustMeta {
        pub(super) trust_gossip: bool,
        pub(super) scion_supported: bool,
    }
    #[derive(Clone, Debug, Encode, Decode)]
    pub(super) struct HandshakeHello {
        pub(super) network_id: iroha_data_model::NetworkId,
        pub(super) public_key: Vec<u8>,
        pub(super) signature: Vec<u8>,
        pub(super) addr: iroha_primitives::addr::SocketAddr,
        pub(super) relay: RelayRole,
        pub(super) consensus: HandshakeConsensusMeta,
        pub(super) confidential: HandshakeConfidentialMeta,
        pub(super) crypto: HandshakeCryptoMeta,
        pub(super) trust: HandshakeTrustMeta,
    }
    fn build_consensus_meta(caps: Option<&ConsensusHandshakeCaps>) -> HandshakeConsensusMeta {
        caps.map_or(
            HandshakeConsensusMeta {
                mode: None,
                proto_version: None,
                consensus_fingerprint: None,
                config: None,
            },
            |caps| HandshakeConsensusMeta {
                mode: Some(caps.mode),
                proto_version: Some(caps.proto_version),
                consensus_fingerprint: Some(caps.consensus_fingerprint),
                config: Some(caps.config),
            },
        )
    }
    fn build_confidential_meta(
        caps: Option<&crate::ConfidentialHandshakeCaps>,
    ) -> HandshakeConfidentialMeta {
        caps.map_or(
            HandshakeConfidentialMeta {
                enabled: None,
                assume_valid: None,
                verifier_backend: None,
                features: None,
            },
            |caps| HandshakeConfidentialMeta {
                enabled: Some(caps.enabled),
                assume_valid: Some(caps.assume_valid),
                verifier_backend: Some(caps.verifier_backend.clone()),
                features: caps
                    .features
                    .as_ref()
                    .map(HandshakeConfidentialDigest::from),
            },
        )
    }
    fn build_crypto_meta(caps: Option<&crate::CryptoHandshakeCaps>) -> HandshakeCryptoMeta {
        caps.map_or(
            HandshakeCryptoMeta {
                sm_enabled: None,
                sm_openssl_preview: None,
            },
            |caps| HandshakeCryptoMeta {
                sm_enabled: Some(caps.sm_enabled),
                sm_openssl_preview: Some(caps.sm_openssl_preview),
            },
        )
    }
    fn enforce_consensus_caps(
        caps: Option<&crate::ConsensusHandshakeCaps>,
        meta: &HandshakeConsensusMeta,
    ) -> Result<(), crate::Error> {
        if let Some(caps) = caps {
            let Some(mode) = meta.mode else {
                return Err(crate::Error::HandshakeConsensusMismatch {
                    reason: "missing consensus mode".to_string(),
                });
            };
            if mode != caps.mode {
                let reason = format!(
                    "consensus mode mismatch (expected {}, got {})",
                    caps.mode.tag(),
                    mode.tag()
                );
                iroha_logger::warn!(reason, "peer rejected due to consensus config mismatch");
                return Err(crate::Error::HandshakeConsensusMismatch { reason });
            }
            let Some(proto) = meta.proto_version else {
                return Err(crate::Error::HandshakeConsensusMismatch {
                    reason: "missing consensus proto version".to_string(),
                });
            };
            if proto != caps.proto_version {
                let reason = format!(
                    "proto version mismatch (expected {}, got {})",
                    caps.proto_version, proto
                );
                iroha_logger::warn!(reason, "peer rejected due to consensus config mismatch");
                return Err(crate::Error::HandshakeConsensusMismatch { reason });
            }
            let Some(fp) = meta.consensus_fingerprint else {
                return Err(crate::Error::HandshakeConsensusMismatch {
                    reason: "missing consensus fingerprint".to_string(),
                });
            };
            if fp != caps.consensus_fingerprint {
                let reason = format!(
                    "fingerprint mismatch (expected 0x{}, got 0x{})",
                    hex_bytes(&caps.consensus_fingerprint),
                    hex_bytes(&fp)
                );
                iroha_logger::warn!(reason, "peer rejected due to consensus config mismatch");
                return Err(crate::Error::HandshakeConsensusMismatch { reason });
            }
            let peer_config =
                meta.config
                    .as_ref()
                    .ok_or_else(|| crate::Error::HandshakeConsensusMismatch {
                        reason: "missing consensus runtime config".to_string(),
                    })?;
            if let Some(reason) = consensus_config_mismatch(&caps.config, peer_config) {
                iroha_logger::warn!(
                    ?peer_config,
                    expected=?caps.config,
                    %reason,
                    "peer rejected due to consensus config mismatch"
                );
                return Err(crate::Error::HandshakeConsensusMismatch { reason });
            }
        }
        Ok(())
    }
    pub(super) fn consensus_config_mismatch(
        expected: &ConsensusConfigCaps,
        got: &ConsensusConfigCaps,
    ) -> Option<String> {
        if expected.execution_policy_hash != got.execution_policy_hash {
            return Some(format!(
                "execution_policy_hash mismatch (expected 0x{}, got 0x{})",
                hex_bytes(&expected.execution_policy_hash),
                hex_bytes(&got.execution_policy_hash),
            ));
        }
        if expected.nexus_policy_digest != got.nexus_policy_digest {
            return Some(format!(
                "nexus_policy_digest mismatch (expected 0x{}, got 0x{})",
                hex_bytes(&expected.nexus_policy_digest),
                hex_bytes(&got.nexus_policy_digest),
            ));
        }
        if expected.native_config_fingerprint != got.native_config_fingerprint {
            return Some(format!(
                "native_config_fingerprint mismatch (expected 0x{}, got 0x{})",
                hex_bytes(&expected.native_config_fingerprint),
                hex_bytes(&got.native_config_fingerprint),
            ));
        }
        if expected.ivm_gas_schedule_hash != got.ivm_gas_schedule_hash {
            return Some(format!(
                "ivm_gas_schedule_hash mismatch (expected 0x{}, got 0x{})",
                hex_bytes(&expected.ivm_gas_schedule_hash),
                hex_bytes(&got.ivm_gas_schedule_hash),
            ));
        }
        None
    }
    pub(super) fn hex_bytes(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(&mut out, "{byte:02x}");
        }
        out
    }
    fn enforce_confidential_caps(
        caps: Option<&crate::ConfidentialHandshakeCaps>,
        meta: &HandshakeConfidentialMeta,
        _remote_addr: &iroha_primitives::addr::SocketAddr,
    ) -> Result<(), crate::Error> {
        let Some(caps) = caps else {
            return Ok(());
        };
        let HandshakeConfidentialMeta {
            enabled,
            assume_valid,
            verifier_backend,
            features,
        } = meta.clone();
        let enabled = enabled.ok_or(crate::Error::HandshakeConfidentialMismatch)?;
        let assume_valid = assume_valid.ok_or(crate::Error::HandshakeConfidentialMismatch)?;
        let backend = verifier_backend.ok_or(crate::Error::HandshakeConfidentialMismatch)?;
        let remote_features = features.map(crate::ConfidentialFeatureDigest::from);
        if enabled != caps.enabled
            || assume_valid != caps.assume_valid
            || backend != caps.verifier_backend
        {
            return Err(crate::Error::HandshakeConfidentialMismatch);
        }
        match (&caps.features, remote_features.as_ref()) {
            (Some(local), Some(remote)) if remote == local => {}
            (Some(_), Some(_) | None) => {
                return Err(crate::Error::HandshakeConfidentialMismatch);
            }
            (None, _) => {}
        }
        Ok(())
    }
    fn enforce_crypto_caps(
        caps: Option<&crate::CryptoHandshakeCaps>,
        meta: &HandshakeCryptoMeta,
        remote_addr: &iroha_primitives::addr::SocketAddr,
    ) -> Result<(), crate::Error> {
        let Some(caps) = caps else {
            return Ok(());
        };
        let HandshakeCryptoMeta {
            sm_enabled,
            sm_openssl_preview,
        } = meta.clone();
        match (sm_enabled, caps.require_sm_handshake_match) {
            (Some(remote_enabled), true) => {
                if remote_enabled != caps.sm_enabled {
                    return Err(crate::Error::HandshakeCryptoMismatch);
                }
            }
            (Some(remote_enabled), false) => {
                if remote_enabled != caps.sm_enabled {
                    iroha_logger::warn!(
                        %remote_enabled,
                        local_enabled = %caps.sm_enabled,
                        addr = ?remote_addr,
                        "Remote peer SM helper availability differs; permitted by configuration"
                    );
                }
            }
            (None, true) => return Err(crate::Error::HandshakeCryptoMismatch),
            (None, false) => {
                if caps.sm_enabled {
                    iroha_logger::warn!(
                        addr = ?remote_addr,
                        "Remote peer omitted SM helper capability flag; continuing due to permissive configuration"
                    );
                }
            }
        }
        match (sm_openssl_preview, caps.require_sm_openssl_preview_match) {
            (Some(remote_preview), true) => {
                if remote_preview != caps.sm_openssl_preview {
                    return Err(crate::Error::HandshakeCryptoMismatch);
                }
            }
            (Some(remote_preview), false) => {
                if remote_preview != caps.sm_openssl_preview {
                    iroha_logger::warn!(
                        %remote_preview,
                        local_preview = %caps.sm_openssl_preview,
                        addr = ?remote_addr,
                        "Remote peer OpenSSL preview flag differs; permitted by configuration"
                    );
                }
            }
            (None, true) => return Err(crate::Error::HandshakeCryptoMismatch),
            (None, false) => {
                if caps.sm_openssl_preview {
                    iroha_logger::warn!(
                        addr = ?remote_addr,
                        "Remote peer omitted OpenSSL preview capability; continuing due to permissive configuration"
                    );
                }
            }
        }
        Ok(())
    }
    #[derive(Encode)]
    struct HandshakeIdentityBindingV1 {
        session_binding: [u8; iroha_crypto::Hash::LENGTH],
        network_id: iroha_data_model::NetworkId,
        soranet_transport_binding: [u8; iroha_crypto::Hash::LENGTH],
        transport_binding: Option<[u8; iroha_crypto::Hash::LENGTH]>,
        public_key: Vec<u8>,
        advertised_addr: iroha_primitives::addr::SocketAddr,
        relay: RelayRole,
        consensus: HandshakeConsensusMeta,
        confidential: HandshakeConfidentialMeta,
        crypto: HandshakeCryptoMeta,
        trust: HandshakeTrustMeta,
    }
    pub(super) fn handshake_signature_payload<E: Enc>(
        cryptographer: &Cryptographer<E>,
        hello: &HandshakeHello,
        soranet_transport_binding: &[u8; iroha_crypto::Hash::LENGTH],
        transport_binding: Option<&[u8; iroha_crypto::Hash::LENGTH]>,
    ) -> Vec<u8> {
        const DOMAIN: &[u8] = b"iroha:p2p:identity-binding:v1|";
        let binding = HandshakeIdentityBindingV1 {
            session_binding: cryptographer.session_binding,
            network_id: hello.network_id,
            soranet_transport_binding: *soranet_transport_binding,
            transport_binding: transport_binding.copied(),
            public_key: hello.public_key.clone(),
            advertised_addr: hello.addr.clone(),
            relay: hello.relay,
            consensus: hello.consensus,
            confidential: hello.confidential.clone(),
            crypto: hello.crypto.clone(),
            trust: hello.trust.clone(),
        }
        .encode();
        let mut data = Vec::with_capacity(DOMAIN.len().saturating_add(binding.len()));
        data.extend_from_slice(DOMAIN);
        data.extend_from_slice(&binding);
        data
    }
    pub(super) fn encode_handshake_message<E: Enc>(
        cryptographer: &Cryptographer<E>,
        message: &HandshakeHello,
    ) -> Result<Vec<u8>, crate::Error> {
        let payload = message.encode();
        let mut encoded = Vec::with_capacity(payload.len().saturating_add(2));
        encoded.push(HANDSHAKE_HELLO_VERSION_PREFIX);
        encoded.push(HANDSHAKE_HELLO_VERSION);
        encoded.extend_from_slice(&payload);
        cryptographer.encrypt(&encoded)
    }
    pub(super) fn decode_handshake_message<E: Enc>(
        cryptographer: &Cryptographer<E>,
        payload: &[u8],
    ) -> Result<HandshakeHello, crate::Error> {
        let decrypted = cryptographer.decrypt(payload)?;
        let (&prefix, rest) = decrypted.split_first().ok_or(crate::Error::Format)?;
        if prefix != HANDSHAKE_HELLO_VERSION_PREFIX {
            return Err(crate::Error::Format);
        }
        let (&version, body) = rest.split_first().ok_or(crate::Error::Format)?;
        if version != HANDSHAKE_HELLO_VERSION {
            return Err(crate::Error::Format);
        }
        decode_handshake_body_with_limits(body, norito::canonical_decode_limits(body.len()))
    }
    pub(super) fn decode_handshake_body_with_limits(
        body: &[u8],
        limits: norito::DecodeLimits,
    ) -> Result<HandshakeHello, crate::Error> {
        let mut slice = body;
        Ok(norito::with_decode_limits(limits, || {
            DecodeAll::decode_all(&mut slice)
        })?)
    }
    /// Peer that is connecting. This is the initial stage of a new
    /// outgoing peer.
    #[allow(clippy::struct_excessive_bools)]
    pub(super) struct Connecting {
        pub peer_addr: SocketAddr,
        pub peer_id: iroha_model_base::peer::PeerId,
        pub our_public_address: SocketAddr,
        pub key_pair: Arc<KeyPair>,
        pub connection_id: ConnectionId,
        pub network_id: iroha_data_model::NetworkId,
        pub consensus_caps: Option<ConsensusHandshakeCaps>,
        pub confidential_caps: Option<crate::ConfidentialHandshakeCaps>,
        pub crypto_caps: Option<crate::CryptoHandshakeCaps>,
        pub soranet_handshake: Arc<SoranetHandshakeConfig>,
        pub quic_enabled: bool,
        pub prefer_scion: bool,
        pub local_scion_supported: bool,
        pub trust_gossip: bool,
        pub relay_role: RelayRole,
        pub dial_timeout: Duration,
        pub happy_eyeballs_stagger: Duration,
        pub tcp_nodelay: bool,
        pub tcp_keepalive: Option<Duration>,
        pub proxy_tls_verify: bool,
        pub proxy_tls_pinned_cert_der: Option<std::sync::Arc<[u8]>>,
        pub proxy_policy: crate::transport::ProxyPolicy,
        pub outbound_dial_policy: Arc<crate::dial_policy::OutboundDialPolicy>,
        pub quic_dialer: Option<crate::transport::QuicDialer>,
        pub quic_datagrams_enabled: bool,
        pub quic_datagram_max_payload_bytes: usize,
    }
    impl Connecting {
        #[cfg(any(feature = "quic", test))]
        fn record_raced_dial_error(
            current_error: &mut Option<crate::Error>,
            other_dial_failed: bool,
            error: crate::Error,
        ) -> Result<(), crate::Error> {
            if other_dial_failed {
                return Err(error);
            }
            *current_error = Some(error);
            Ok(())
        }
        #[allow(clippy::too_many_lines, clippy::single_match_else)]
        #[cfg_attr(not(feature = "quic"), allow(unused_variables))]
        pub(super) async fn connect_to(
            Self {
                peer_addr,
                peer_id,
                our_public_address,
                key_pair,
                connection_id,
                network_id,
                consensus_caps,
                confidential_caps,
                crypto_caps,
                soranet_handshake,
                quic_enabled,
                prefer_scion,
                local_scion_supported,
                trust_gossip,
                relay_role,
                dial_timeout,
                happy_eyeballs_stagger,
                tcp_nodelay,
                tcp_keepalive,
                proxy_tls_verify,
                proxy_tls_pinned_cert_der,
                proxy_policy,
                outbound_dial_policy,
                quic_dialer,
                quic_datagrams_enabled,
                quic_datagram_max_payload_bytes,
            }: Self,
        ) -> Result<ConnectedTo, crate::Error> {
            async fn dial_tls(
                peer_addr: &iroha_primitives::addr::SocketAddr,
                opts: &crate::transport::TcpConnectOptions,
                dial_timeout: Duration,
                connection_id: ConnectionId,
            ) -> Result<Connection, crate::Error> {
                let sni_host = match peer_addr {
                    iroha_primitives::addr::SocketAddr::Host(host) => host.host.as_ref(),
                    _ => "iroha-p2p",
                };
                let tls = tokio::time::timeout(dial_timeout, async {
                    let stream = crate::transport::connect(peer_addr, opts).await?;
                    match stream {
                        crate::transport::TcpConnectStream::Plain(tcp) => {
                            let tls = crate::transport::tls::connect_tls(sni_host, tcp).await?;
                            let transport_binding =
                                crate::transport::tls_peer_certificate_fingerprint(&tls)?;
                            let (read_half, write_half) = tokio::io::split(tls);
                            Ok::<_, std::io::Error>(Connection::from_split_with_binding(
                                connection_id,
                                read_half,
                                write_half,
                                transport_binding,
                            ))
                        }
                        crate::transport::TcpConnectStream::Tls(proxy_tls) => {
                            let tls =
                                crate::transport::tls::connect_tls(sni_host, proxy_tls).await?;
                            let transport_binding =
                                crate::transport::tls_peer_certificate_fingerprint(&tls)?;
                            let (read_half, write_half) = tokio::io::split(tls);
                            Ok::<_, std::io::Error>(Connection::from_split_with_binding(
                                connection_id,
                                read_half,
                                write_half,
                                transport_binding,
                            ))
                        }
                    }
                })
                .await;
                match tls {
                    Ok(Ok(conn)) => Ok(conn),
                    Ok(Err(error)) => Err(error.into()),
                    Err(_) => Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "tls dial timeout",
                    )
                    .into()),
                }
            }
            #[cfg(feature = "quic")]
            async fn dial_quic_like(
                peer_addr: &iroha_primitives::addr::SocketAddr,
                dialer: &crate::transport::QuicDialer,
                dial_timeout: Duration,
                connection_id: ConnectionId,
                quic_datagrams_enabled: bool,
                quic_datagram_max_payload_bytes: usize,
                outbound_dial_policy: &crate::dial_policy::OutboundDialPolicy,
            ) -> Result<Connection, crate::Error> {
                use tokio::time::Instant;
                const QUIC_SERVER_NAME: &str = "iroha-quic";
                let deadline = Instant::now() + dial_timeout;
                outbound_dial_policy.check_target(peer_addr)?;
                let targets: Vec<std::net::SocketAddr> = match peer_addr {
                    iroha_primitives::addr::SocketAddr::Ipv4(v4) => outbound_dial_policy
                        .check_resolved_targets(std::iter::once(std::net::SocketAddr::V4(
                            std::net::SocketAddrV4::new(v4.ip.into(), v4.port),
                        )))?,
                    iroha_primitives::addr::SocketAddr::Ipv6(v6) => outbound_dial_policy
                        .check_resolved_targets(std::iter::once(std::net::SocketAddr::V6(
                            std::net::SocketAddrV6::new(v6.ip.into(), v6.port, 0, 0),
                        )))?,
                    iroha_primitives::addr::SocketAddr::Host(host) => {
                        let lookup = tokio::time::timeout_at(
                            deadline,
                            tokio::net::lookup_host((host.host.as_ref(), host.port)),
                        )
                        .await
                        .map_err(|_| {
                            std::io::Error::new(std::io::ErrorKind::TimedOut, "dial timeout")
                        })??;
                        outbound_dial_policy.check_resolved_targets(lookup)?
                    }
                };
                let mut last_err: Option<std::io::Error> = None;
                for target in targets {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    let remaining = deadline - now;
                    let res = tokio::time::timeout(remaining, async {
                        let conn = dialer.connect(target, QUIC_SERVER_NAME).await?;
                        let datagram_ingress = quic_datagrams_enabled.then(|| {
                            QuicDatagramIngress::spawn(
                                &conn,
                                quic_datagram_max_payload_bytes,
                            )
                        });
                        let transport_binding =
                            crate::transport::quic_peer_certificate_fingerprint(&conn)?;
                        let remote = conn.remote_address();
                        let (send_hi, recv_hi) = conn
                            .open_bi()
                            .await
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                        let lo = tokio::time::timeout_at(deadline, conn.open_bi()).await;
                        let (send_low, recv_low) = match lo {
                            Ok(Ok((s, r))) => (Some(s), Some(r)),
                            Ok(Err(e)) => {
                                iroha_logger::debug!(%e, addr=%target, "QUIC low-priority stream open failed; continuing with single stream");
                                (None, None)
                            }
                            Err(_) => (None, None),
                        };
                        Ok::<_, std::io::Error>(Connection::from_quic(
                            connection_id,
                            conn,
                            send_hi,
                            recv_hi,
                            send_low,
                            recv_low,
                            datagram_ingress,
                            Some(remote),
                            transport_binding,
                        ))
                    })
                    .await;
                    match res {
                        Ok(Ok(conn)) => return Ok(conn),
                        Ok(Err(e)) => last_err = Some(e),
                        Err(_) => {
                            last_err = Some(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "dial timeout",
                            ))
                        }
                    }
                }
                Err(last_err
                    .unwrap_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::Other, "quic dial failed")
                    })
                    .into())
            }
            let tcp_opts = crate::transport::TcpConnectOptions {
                proxy: proxy_policy,
                proxy_tls_verify,
                proxy_tls_pinned_cert_der,
                tcp_nodelay,
                tcp_keepalive,
                outbound_dial_policy: Arc::clone(&outbound_dial_policy),
            };
            if prefer_scion {
                #[cfg(feature = "quic")]
                if let Some(dialer) = &quic_dialer {
                    match dial_quic_like(
                        &peer_addr,
                        dialer,
                        dial_timeout,
                        connection_id,
                        quic_datagrams_enabled,
                        quic_datagram_max_payload_bytes,
                        &outbound_dial_policy,
                    )
                    .await
                    {
                        Ok(connection) => {
                            crate::network::inc_scion_outbound();
                            return Ok(ConnectedTo {
                                our_public_address,
                                expected_peer_id: peer_id.clone(),
                                key_pair,
                                connection,
                                network_id,
                                consensus_caps,
                                confidential_caps,
                                crypto_caps,
                                soranet_handshake,
                                local_scion_supported,
                                trust_gossip,
                                relay_role,
                            });
                        }
                        Err(err) => {
                            iroha_logger::warn!(
                                %err,
                                peer=%peer_addr,
                                "SCION-preferred dial failed; continuing with the standard dial strategy"
                            );
                        }
                    }
                }
            }
            let tls_fut = dial_tls(&peer_addr, &tcp_opts, dial_timeout, connection_id);
            tokio::pin!(tls_fut);
            let connection_result: Result<Connection, crate::Error> = {
                #[cfg(feature = "quic")]
                {
                    if quic_enabled {
                        if let Some(dialer) = &quic_dialer {
                            let quic_fut = dial_quic_like(
                                &peer_addr,
                                dialer,
                                dial_timeout,
                                connection_id,
                                quic_datagrams_enabled,
                                quic_datagram_max_payload_bytes,
                                &outbound_dial_policy,
                            );
                            tokio::pin!(quic_fut);
                            // Phase 1: give QUIC a head start, but don't stall on blocked UDP.
                            let stagger = tokio::time::sleep(happy_eyeballs_stagger);
                            tokio::pin!(stagger);
                            tokio::select! {
                                res = &mut quic_fut => match res {
                                    Ok(conn) => Ok(conn),
                                    Err(e) => {
                                        iroha_logger::warn!(%e, addr=%peer_addr, "QUIC dial failed; falling back to TLS");
                                        tls_fut.await
                                    }
                                },
                                () = &mut stagger => {
                                    let mut quic_err: Option<crate::Error> = None;
                                    let mut tcp_err: Option<crate::Error> = None;
                                    loop {
                                        tokio::select! {
                                            res = &mut quic_fut, if quic_err.is_none() => match res {
                                                Ok(conn) => break Ok(conn),
                                                Err(e) => {
                                                    iroha_logger::debug!(%e, addr=%peer_addr, "QUIC dial failed while racing TCP-like");
                                                    if let Err(err) = Self::record_raced_dial_error(
                                                        &mut quic_err,
                                                        tcp_err.is_some(),
                                                        e,
                                                    ) {
                                                        break Err(err);
                                                    }
                                                }
                                            },
                                            res = &mut tls_fut, if tcp_err.is_none() => match res {
                                                Ok(conn) => break Ok(conn),
                                                Err(e) => {
                                                    iroha_logger::debug!(%e, addr=%peer_addr, "TLS dial failed while racing QUIC");
                                                    if let Err(err) = Self::record_raced_dial_error(
                                                        &mut tcp_err,
                                                        quic_err.is_some(),
                                                        e,
                                                    ) {
                                                        break Err(err);
                                                    }
                                                }
                                            },
                                            else => {
                                                break Err(tcp_err.or(quic_err).unwrap_or_else(|| {
                                                    std::io::Error::new(std::io::ErrorKind::Other, "dial failed").into()
                                                }));
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            tls_fut.await
                        }
                    } else {
                        tls_fut.await
                    }
                }
                #[cfg(not(feature = "quic"))]
                {
                    tls_fut.await
                }
            };
            let connection = match connection_result {
                Ok(conn) => conn,
                Err(err) => {
                    crate::network::inc_dns_resolution_fail();
                    return Err(err);
                }
            };
            Ok(ConnectedTo {
                our_public_address,
                expected_peer_id: peer_id,
                key_pair,
                connection,
                network_id,
                consensus_caps,
                confidential_caps,
                crypto_caps,
                soranet_handshake,
                local_scion_supported,
                trust_gossip,
                relay_role,
            })
        }
    }
    #[cfg(test)]
    mod dial_policy_tests {
        use super::*;
        use std::{sync::Arc, time::Duration};
        fn connecting_to(peer_addr: std::net::SocketAddr) -> Connecting {
            let our_public_address: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
            Connecting {
                peer_addr: peer_addr.into(),
                peer_id: random_node_peer_id(),
                our_public_address: our_public_address.into(),
                key_pair: Arc::new(KeyPair::random_with_algorithm(
                    iroha_crypto::Algorithm::BlsNormal,
                )),
                connection_id: 0,
                network_id: test_network_id("test-chain"),
                consensus_caps: None,
                confidential_caps: None,
                crypto_caps: None,
                soranet_handshake: Arc::new(SoranetHandshakeConfig::defaults()),
                quic_enabled: false,
                prefer_scion: false,
                local_scion_supported: true,
                trust_gossip: false,
                relay_role: RelayRole::Disabled,
                dial_timeout: Duration::from_millis(200),
                happy_eyeballs_stagger: Duration::from_millis(10),
                tcp_nodelay: true,
                tcp_keepalive: None,
                proxy_tls_verify: true,
                proxy_tls_pinned_cert_der: None,
                proxy_policy: crate::transport::ProxyPolicy::disabled(),
                outbound_dial_policy: Arc::new(crate::dial_policy::OutboundDialPolicy::default()),
                quic_dialer: None,
                quic_datagrams_enabled: false,
                quic_datagram_max_payload_bytes: 0,
            }
        }
        fn io_error(kind: std::io::ErrorKind, label: &'static str) -> crate::Error {
            std::io::Error::new(kind, label).into()
        }
        #[test]
        fn raced_dial_error_state_returns_second_failure() {
            let mut first_error = None;
            Connecting::record_raced_dial_error(
                &mut first_error,
                false,
                io_error(std::io::ErrorKind::TimedOut, "quic timeout"),
            )
            .expect("first failure should be recorded");
            assert!(matches!(
                first_error,
                Some(crate::Error::Io(err)) if err.kind() == std::io::ErrorKind::TimedOut
            ));
            let mut second_slot = None;
            let err = Connecting::record_raced_dial_error(
                &mut second_slot,
                true,
                io_error(std::io::ErrorKind::ConnectionRefused, "tcp refused"),
            )
            .expect_err("second failure should be returned");
            assert!(second_slot.is_none());
            assert!(matches!(
                err,
                crate::Error::Io(err) if err.kind() == std::io::ErrorKind::ConnectionRefused
            ));
        }
        #[tokio::test(flavor = "current_thread")]
        async fn scion_preference_uses_standard_strategy_when_unavailable() {
            let addr: std::net::SocketAddr = "127.0.0.1:1".parse().expect("addr");
            let mut connecting = connecting_to(addr);
            connecting.prefer_scion = true;
            let res = Connecting::connect_to(connecting).await;
            assert!(matches!(
                res,
                Err(crate::Error::Io(e))
                    if e.kind() != std::io::ErrorKind::InvalidInput
                        && e.kind() != std::io::ErrorKind::NotFound
            ));
        }
        #[tokio::test(flavor = "current_thread")]
        async fn tls_failure_never_falls_back_to_plain_tcp() {
            use tokio::net::TcpListener;
            let listener = match TcpListener::bind("127.0.0.1:0").await {
                Ok(listener) => listener,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
                Err(e) => panic!("listener bind failed: {e:?}"),
            };
            let addr = listener.local_addr().expect("local addr");
            let accept_task = tokio::spawn(async move {
                loop {
                    let (sock, _) = match listener.accept().await {
                        Ok(ok) => ok,
                        Err(_) => break,
                    };
                    tokio::spawn(async move {
                        let _sock = sock;
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    });
                }
            });
            let result = Connecting::connect_to(connecting_to(addr)).await;
            assert!(result.is_err(), "TLS failure must not fall back to TCP");
            accept_task.abort();
        }
    }
    /// Peer that is being connected to.
    pub(super) struct ConnectedTo {
        our_public_address: SocketAddr,
        expected_peer_id: iroha_model_base::peer::PeerId,
        key_pair: Arc<KeyPair>,
        connection: Connection,
        network_id: iroha_data_model::NetworkId,
        consensus_caps: Option<ConsensusHandshakeCaps>,
        confidential_caps: Option<crate::ConfidentialHandshakeCaps>,
        crypto_caps: Option<crate::CryptoHandshakeCaps>,
        soranet_handshake: Arc<SoranetHandshakeConfig>,
        local_scion_supported: bool,
        trust_gossip: bool,
        relay_role: RelayRole,
    }
    impl ConnectedTo {
        #[cfg(test)]
        pub(super) fn for_transport_delegation_test(
            our_public_address: SocketAddr,
            expected_peer_id: iroha_model_base::peer::PeerId,
            key_pair: Arc<KeyPair>,
            connection: Connection,
            network_id: iroha_data_model::NetworkId,
            soranet_handshake: Arc<SoranetHandshakeConfig>,
        ) -> Self {
            Self {
                our_public_address,
                expected_peer_id,
                key_pair,
                connection,
                network_id,
                consensus_caps: None,
                confidential_caps: None,
                crypto_caps: None,
                soranet_handshake,
                local_scion_supported: true,
                trust_gossip: true,
                relay_role: RelayRole::Disabled,
            }
        }
        #[allow(clippy::similar_names, clippy::too_many_lines)]
        pub(super) async fn send_client_hello<E: Enc>(
            Self {
                our_public_address,
                expected_peer_id,
                key_pair,
                mut connection,
                network_id,
                consensus_caps,
                confidential_caps,
                crypto_caps,
                soranet_handshake,
                local_scion_supported,
                trust_gossip,
                relay_role,
            }: Self,
        ) -> Result<SendKey<E>, crate::Error> {
            // Generate the connection challenge before any admission-puzzle or
            // KEM work. Failure to seed the CSPRNG fails the handshake closed.
            let mut rng = soranet_handshake_rng()?;
            let delegation_challenge = generate_soranet_transport_delegation_challenge(&mut rng)?;
            // Initiator sends v5, its fresh challenge, and its exact transport
            // observation. The responder authenticates all three before the
            // initiator releases any admission credential.
            if let Err(e) = write_client_pre_handshake_header(
                &mut connection.write,
                &delegation_challenge,
                connection.transport_binding,
            )
            .await
            {
                return Err(crate::Error::from(e));
            }
            if let Err(e) = read_and_verify_server_pre_handshake_header(&mut connection.read).await
            {
                if e.kind() == std::io::ErrorKind::InvalidData {
                    return Err(crate::Error::HandshakeBadPreface);
                }
                return Err(crate::Error::from(e));
            }
            let verified_transport_delegation = read_and_verify_soranet_transport_delegation_v5(
                &mut connection.read,
                &network_id,
                &expected_peer_id,
                &delegation_challenge,
                connection.transport_binding,
            )
            .await?;
            if connection.transport_binding.is_none() {
                return Err(Error::HandshakeSoranet(
                    "first-release SoraNet P2P requires TLS or QUIC channel binding".to_owned(),
                ));
            }
            let runtime_params = soranet_handshake.runtime_params();
            // The admission credential commits to the final serialized hello,
            // so build it once and send those exact bytes after the ticket.
            let (client_hello, client_state) = build_client_hello(&runtime_params, &mut rng)
                .map_err(|err| Error::HandshakeSoranet(err.to_string()))?;
            let admission_transcript =
                soranet_admission_transcript(&client_hello, &verified_transport_delegation.binding);
            let mut minted =
                mint_handshake_challenge(Arc::clone(&soranet_handshake), admission_transcript, rng)
                    .await?;
            let send_result =
                write_handshake_frame(&mut connection.write, &minted.credential).await;
            minted.clear_sensitive_bytes();
            send_result?;
            write_handshake_frame(&mut connection.write, &client_hello).await?;
            let relay_hello = read_handshake_frame(&mut connection.read).await?;
            let secrets = match client_handle_relay_hello(
                client_state,
                &relay_hello,
                &verified_transport_delegation.relay_authentication_verifier,
                &runtime_params,
            ) {
                Ok(success) => success,
                Err(HarnessError::Downgrade {
                    warnings,
                    telemetry,
                }) => {
                    let warning_messages = warnings
                        .iter()
                        .map(|w| w.message.clone())
                        .collect::<Vec<_>>();
                    if let Some(payload) = telemetry {
                        iroha_logger::warn!(
                            payload = %String::from_utf8_lossy(&payload),
                            "SoraNet handshake downgrade telemetry"
                        );
                    }
                    iroha_logger::warn!(
                        warnings = ?warning_messages,
                        "SoraNet handshake downgrade detected (outbound)"
                    );
                    let summary = if warning_messages.is_empty() {
                        "capability downgrade detected".to_string()
                    } else {
                        format!(
                            "capability downgrade detected: {}",
                            warning_messages.join("; ")
                        )
                    };
                    return Err(Error::HandshakeSoranet(summary));
                }
                Err(err) => return Err(Error::HandshakeSoranet(err.to_string())),
            };
            if !secrets.warnings.is_empty() {
                iroha_logger::warn!(
                    warnings = ?secrets
                        .warnings
                        .iter()
                        .map(|w| w.message.clone())
                        .collect::<Vec<_>>(),
                    "SoraNet handshake reported capability warnings"
                );
            }
            if let Some(payload) = secrets.telemetry_payload.as_ref() {
                iroha_logger::debug!(
                    payload = %String::from_utf8_lossy(payload),
                    "SoraNet handshake telemetry"
                );
            }
            let cryptographer = Cryptographer::new(&secrets.session_key)?;
            Ok(SendKey {
                our_public_address,
                expected_peer_id: Some(expected_peer_id),
                key_pair,
                connection,
                cryptographer,
                network_id,
                soranet_transport_binding: verified_transport_delegation.binding,
                consensus_caps,
                confidential_caps,
                crypto_caps,
                relay_role,
                local_scion_supported,
                trust_gossip,
            })
        }
    }
    /// Peer that is being connected from
    pub(super) struct ConnectedFrom {
        pub our_public_address: SocketAddr,
        pub key_pair: Arc<KeyPair>,
        pub soranet_transport_key_pair: Arc<KeyPair>,
        pub soranet_transport_certificate: Arc<LocalSoranetTransportCertificateV5>,
        pub connection: Connection,
        pub network_id: iroha_data_model::NetworkId,
        pub consensus_caps: Option<ConsensusHandshakeCaps>,
        pub confidential_caps: Option<crate::ConfidentialHandshakeCaps>,
        pub crypto_caps: Option<crate::CryptoHandshakeCaps>,
        pub soranet_handshake: Arc<SoranetHandshakeConfig>,
        pub local_scion_supported: bool,
        pub trust_gossip: bool,
        pub relay_role: RelayRole,
    }
    impl ConnectedFrom {
        #[allow(clippy::similar_names, clippy::too_many_lines)]
        pub(super) async fn read_client_hello<E: Enc>(
            Self {
                our_public_address,
                key_pair,
                soranet_transport_key_pair,
                soranet_transport_certificate,
                mut connection,
                network_id,
                consensus_caps,
                confidential_caps,
                crypto_caps,
                soranet_handshake,
                local_scion_supported,
                trust_gossip,
                relay_role,
            }: Self,
        ) -> Result<SendKey<E>, crate::Error> {
            let client_preface =
                match read_and_verify_client_pre_handshake_header(&mut connection.read).await {
                    Ok(preface) => preface,
                    Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                        return Err(crate::Error::HandshakeBadPreface);
                    }
                    Err(e) => return Err(crate::Error::from(e)),
                };
            let proof_transport_binding = connection
                .validate_client_transport_binding(client_preface.transport_binding)
                .map_err(|_| crate::Error::HandshakeBadPreface)?;
            if proof_transport_binding.is_none() {
                return Err(Error::HandshakeSoranet(
                    "first-release SoraNet P2P requires TLS or QUIC channel binding".to_owned(),
                ));
            }
            if let Err(e) = write_server_pre_handshake_header(&mut connection.write).await {
                return Err(crate::Error::from(e));
            }
            // The process-lifetime BLS certificate is cached at Network
            // startup. An unauthenticated connection therefore triggers only a
            // cheap Ed25519 proof over its nonce and exact transport binding.
            let local_transport_delegation = sign_soranet_transport_delegation_v5(
                &soranet_transport_certificate,
                &soranet_transport_key_pair,
                client_preface.challenge,
                proof_transport_binding,
            )?;
            write_soranet_transport_delegation_v5(
                &mut connection.write,
                &local_transport_delegation.canonical_signed_frame,
            )
            .await?;
            let runtime_params = soranet_handshake.runtime_params();
            let mut rng = soranet_handshake_rng()?;
            let ticket =
                SensitiveHandshakeFrame::from(read_handshake_frame(&mut connection.read).await?);
            // Buffering the bounded hello is cheap. Verify its admission
            // commitment before `process_client_hello` performs ML-KEM work.
            let client_hello = read_handshake_frame(&mut connection.read).await?;
            let admission_transcript =
                soranet_admission_transcript(&client_hello, &local_transport_delegation.binding);
            verify_handshake_challenge(
                Arc::clone(&soranet_handshake),
                ticket,
                admission_transcript,
            )
            .await?;
            let (relay_hello, secrets) = match process_client_hello(
                &client_hello,
                &runtime_params,
                &soranet_transport_certificate.relay_authentication_signer,
                &mut rng,
            ) {
                Ok(success) => success,
                Err(HarnessError::Downgrade {
                    warnings,
                    telemetry,
                }) => {
                    let warning_messages = warnings
                        .iter()
                        .map(|w| w.message.clone())
                        .collect::<Vec<_>>();
                    if let Some(payload) = telemetry {
                        iroha_logger::warn!(
                            payload = %String::from_utf8_lossy(&payload),
                            "SoraNet handshake downgrade telemetry"
                        );
                    }
                    iroha_logger::warn!(
                        warnings = ?warning_messages,
                        "SoraNet handshake downgrade detected (inbound)"
                    );
                    let summary = if warning_messages.is_empty() {
                        "capability downgrade detected".to_string()
                    } else {
                        format!(
                            "capability downgrade detected: {}",
                            warning_messages.join("; ")
                        )
                    };
                    return Err(Error::HandshakeSoranet(summary));
                }
                Err(err) => return Err(Error::HandshakeSoranet(err.to_string())),
            };
            write_handshake_frame(&mut connection.write, &relay_hello).await?;
            if !secrets.warnings.is_empty() {
                iroha_logger::warn!(
                    warnings = ?secrets
                        .warnings
                        .iter()
                        .map(|w| w.message.clone())
                        .collect::<Vec<_>>(),
                    "SoraNet handshake reported capability warnings"
                );
            }
            if let Some(payload) = secrets.telemetry_payload.as_ref() {
                iroha_logger::debug!(
                    payload = %String::from_utf8_lossy(payload),
                    "SoraNet handshake telemetry"
                );
            }
            let cryptographer = Cryptographer::new(&secrets.session_key)?;
            Ok(SendKey {
                our_public_address,
                expected_peer_id: None,
                key_pair,
                connection,
                cryptographer,
                network_id,
                soranet_transport_binding: local_transport_delegation.binding,
                consensus_caps,
                confidential_caps,
                crypto_caps,
                relay_role,
                local_scion_supported,
                trust_gossip,
            })
        }
    }
    #[cfg(test)]
    pub(super) struct SendKeyInit<E: Enc> {
        pub(super) our_public_address: SocketAddr,
        pub(super) expected_peer_id: Option<iroha_model_base::peer::PeerId>,
        pub(super) key_pair: KeyPair,
        pub(super) connection: Connection,
        pub(super) cryptographer: Cryptographer<E>,
        pub(super) network_id: iroha_data_model::NetworkId,
        pub(super) soranet_transport_binding: [u8; iroha_crypto::Hash::LENGTH],
        pub(super) consensus_caps: Option<ConsensusHandshakeCaps>,
        pub(super) confidential_caps: Option<crate::ConfidentialHandshakeCaps>,
        pub(super) crypto_caps: Option<crate::CryptoHandshakeCaps>,
        pub(super) relay_role: RelayRole,
        pub(super) local_scion_supported: bool,
        pub(super) trust_gossip: bool,
    }
    /// Peer that needs to send key.
    pub(super) struct SendKey<E: Enc> {
        pub(super) our_public_address: SocketAddr,
        pub(super) expected_peer_id: Option<iroha_model_base::peer::PeerId>,
        pub(super) key_pair: Arc<KeyPair>,
        pub(super) connection: Connection,
        pub(super) cryptographer: Cryptographer<E>,
        pub(super) network_id: iroha_data_model::NetworkId,
        pub(super) soranet_transport_binding: [u8; iroha_crypto::Hash::LENGTH],
        pub(super) consensus_caps: Option<ConsensusHandshakeCaps>,
        pub(super) confidential_caps: Option<crate::ConfidentialHandshakeCaps>,
        pub(super) crypto_caps: Option<crate::CryptoHandshakeCaps>,
        pub(super) relay_role: RelayRole,
        pub(super) local_scion_supported: bool,
        pub(super) trust_gossip: bool,
    }
    impl<E: Enc> SendKey<E> {
        #[cfg(test)]
        pub(super) fn new(init: SendKeyInit<E>) -> Self {
            let SendKeyInit {
                our_public_address,
                expected_peer_id,
                key_pair,
                connection,
                cryptographer,
                network_id,
                soranet_transport_binding,
                consensus_caps,
                confidential_caps,
                crypto_caps,
                relay_role,
                local_scion_supported,
                trust_gossip,
            } = init;
            Self {
                our_public_address,
                expected_peer_id,
                key_pair: Arc::new(key_pair),
                connection,
                cryptographer,
                network_id,
                soranet_transport_binding,
                consensus_caps,
                confidential_caps,
                crypto_caps,
                relay_role,
                local_scion_supported,
                trust_gossip,
            }
        }
        pub(super) async fn send_our_public_key(
            Self {
                our_public_address,
                expected_peer_id,
                key_pair,
                mut connection,
                cryptographer,
                network_id,
                soranet_transport_binding,
                consensus_caps,
                confidential_caps,
                crypto_caps,
                relay_role,
                local_scion_supported,
                trust_gossip,
            }: Self,
        ) -> Result<GetKey<E>, crate::Error> {
            let write_half = &mut connection.write;
            let our_addr = our_public_address;
            let (alg, pk_bytes) = key_pair.public_key().to_bytes();
            if alg != iroha_crypto::Algorithm::BlsNormal {
                return Err(crate::Error::HandshakeNodeAlgorithmMismatch { found: alg });
            }
            let mut hello = HandshakeHello {
                network_id,
                public_key: pk_bytes.to_vec(),
                signature: Vec::new(),
                addr: our_addr,
                relay: relay_role,
                consensus: build_consensus_meta(consensus_caps.as_ref()),
                confidential: build_confidential_meta(confidential_caps.as_ref()),
                crypto: build_crypto_meta(crypto_caps.as_ref()),
                trust: build_trust_meta(trust_gossip, local_scion_supported),
            };
            let payload = handshake_signature_payload::<E>(
                &cryptographer,
                &hello,
                &soranet_transport_binding,
                connection.transport_binding.as_ref(),
            );
            hello.signature = Signature::try_new(key_pair.private_key(), &payload)?
                .payload()
                .to_vec();
            let encrypted = encode_handshake_message(&cryptographer, &hello)?;
            // Handshake messages can exceed 255 bytes once they include the
            // peer's public address and additional metadata. Encode the
            // payload length as a two-byte big-endian integer to support
            // larger messages.
            #[allow(clippy::cast_possible_truncation)]
            let size = u16::try_from(encrypted.len())
                .map_err(|_| crate::Error::HandshakeMessageTooLarge)?;
            let mut buf = Vec::<u8>::with_capacity(encrypted.len() + 2);
            buf.extend_from_slice(&size.to_be_bytes());
            buf.extend_from_slice(&encrypted);
            write_half.write_all(&buf).await?;
            write_half.flush().await?;
            Ok(GetKey {
                local_peer_id: key_pair.public_key().clone().into(),
                connection,
                expected_peer_id,
                cryptographer,
                network_id,
                soranet_transport_binding,
                consensus_caps,
                confidential_caps,
                crypto_caps,
                relay_role,
                local_scion_supported,
                trust_gossip,
            })
        }
    }
    /// Peer that needs to get key.
    pub struct GetKey<E: Enc> {
        pub(super) local_peer_id: PeerId,
        pub(super) connection: Connection,
        pub(super) expected_peer_id: Option<iroha_model_base::peer::PeerId>,
        pub(super) cryptographer: Cryptographer<E>,
        pub(super) network_id: iroha_data_model::NetworkId,
        pub(super) soranet_transport_binding: [u8; iroha_crypto::Hash::LENGTH],
        pub(super) consensus_caps: Option<ConsensusHandshakeCaps>,
        pub(super) confidential_caps: Option<crate::ConfidentialHandshakeCaps>,
        pub(super) crypto_caps: Option<crate::CryptoHandshakeCaps>,
        pub(super) relay_role: RelayRole,
        pub(super) local_scion_supported: bool,
        pub(super) trust_gossip: bool,
    }
    impl<E: Enc> GetKey<E> {
        /// Read the peer's public key
        pub(super) async fn read_their_public_key(
            Self {
                local_peer_id,
                mut connection,
                expected_peer_id,
                cryptographer,
                network_id,
                soranet_transport_binding,
                consensus_caps,
                confidential_caps,
                crypto_caps,
                relay_role: _relay_role,
                local_scion_supported: _local_scion_supported,
                trust_gossip,
            }: Self,
        ) -> Result<Ready<E>, crate::Error> {
            let read_half = &mut connection.read;
            // Read the length prefix encoded as a two-byte big-endian integer.
            let size = read_half.read_u16().await? as usize;
            // Reading public key
            let mut data = vec![0_u8; size];
            let _ = read_half.read_exact(&mut data).await?;
            let hello = decode_handshake_message(&cryptographer, data.as_slice())?;
            if hello.network_id != network_id {
                return Err(crate::Error::HandshakeNetworkMismatch {
                    expected: network_id,
                    found: hello.network_id,
                });
            }
            let payload = handshake_signature_payload::<E>(
                &cryptographer,
                &hello,
                &soranet_transport_binding,
                connection.transport_binding.as_ref(),
            );
            let (
                public_key,
                signature,
                remote_public_address,
                relay,
                consensus,
                confidential,
                crypto,
                trust_gossip_remote,
                scion_supported_remote,
            ) = {
                let HandshakeHello {
                    network_id: _,
                    public_key,
                    signature,
                    addr,
                    relay,
                    consensus,
                    confidential,
                    crypto,
                    trust,
                } = hello;
                (
                    public_key,
                    signature,
                    addr,
                    relay,
                    consensus,
                    confidential,
                    crypto,
                    trust.trust_gossip,
                    trust.scion_supported,
                )
            };
            let remote_pub_key =
                match PublicKey::from_bytes(iroha_crypto::Algorithm::BlsNormal, &public_key) {
                    Ok(pk) => pk,
                    Err(e) => return Err(crate::Error::from(iroha_crypto::error::Error::from(e))),
                };
            let signature = Signature::try_from_bytes(&signature)
                .map_err(iroha_crypto::error::Error::from)
                .map_err(crate::Error::Keys)?;
            signature.verify(&remote_pub_key, &payload)?;
            if let Some(expected_peer_id) = expected_peer_id {
                let found_peer_id = iroha_model_base::peer::PeerId::from(remote_pub_key.clone());
                if found_peer_id != expected_peer_id {
                    return Err(crate::Error::HandshakePeerMismatch {
                        expected: expected_peer_id,
                        found: found_peer_id,
                    });
                }
            }
            enforce_consensus_caps(consensus_caps.as_ref(), &consensus)?;
            enforce_confidential_caps(
                confidential_caps.as_ref(),
                &confidential,
                &remote_public_address,
            )?;
            enforce_crypto_caps(crypto_caps.as_ref(), &crypto, &remote_public_address)?;
            let peer = Peer::new(remote_public_address, remote_pub_key);
            let trust_gossip = trust_gossip && trust_gossip_remote;
            let scion_supported = scion_supported_remote;
            Ok(Ready {
                network_id,
                local_peer_id,
                peer,
                connection,
                cryptographer,
                relay_role: relay,
                scion_supported,
                trust_gossip,
            })
        }
    }
    /// Peer that is ready for communication after finishing the
    /// handshake process.
    pub(super) struct Ready<E: Enc> {
        pub network_id: iroha_data_model::NetworkId,
        pub local_peer_id: PeerId,
        pub peer: Peer,
        pub connection: Connection,
        pub cryptographer: Cryptographer<E>,
        pub relay_role: RelayRole,
        pub scion_supported: bool,
        pub trust_gossip: bool,
    }
    #[cfg(test)]
    mod tests {
        // Keep handshake-state tests at their stable libtest paths outside this production file.
        include!("peer_state_tests.rs");
        include!("peer_consensus_mode_test.rs");

        #[test]
        fn handshake_confidential_digest_slice_decoder_preserves_framed_options() {
            use norito::core::{DecodeFlagsGuard, DecodeFromSlice, header_flags};

            for flags in [0, header_flags::COMPACT_LEN] {
                let _flags = DecodeFlagsGuard::enter(flags);
                let frame = |body: &[u8]| {
                    let mut bytes = Vec::new();
                    norito::core::write_len_to_vec_with_flags(&mut bytes, body.len() as u64, flags);
                    bytes.extend_from_slice(body);
                    bytes
                };
                for digest in [
                    HandshakeConfidentialDigest {
                        vk_set_hash: None,
                        poseidon_params_id: None,
                        pedersen_params_id: None,
                        conf_rules_version: None,
                        zk_policy_hash: None,
                    },
                    HandshakeConfidentialDigest {
                        vk_set_hash: Some([0x51; 32]),
                        poseidon_params_id: Some(3),
                        pedersen_params_id: Some(5),
                        conf_rules_version: Some(7),
                        zk_policy_hash: Some([0x72; 32]),
                    },
                    HandshakeConfidentialDigest {
                        vk_set_hash: Some([0x63; 32]),
                        poseidon_params_id: None,
                        pedersen_params_id: Some(11),
                        conf_rules_version: None,
                        zk_policy_hash: None,
                    },
                ] {
                    let fields = (
                        digest.vk_set_hash,
                        digest.poseidon_params_id,
                        digest.pedersen_params_id,
                        digest.conf_rules_version,
                        digest.zk_policy_hash,
                    );
                    let mut wire = Vec::new();
                    norito::core::serialize_to_buffer(&digest, &mut wire).unwrap();
                    let mut expected = Vec::new();
                    let field_payloads: [&dyn norito::SerializePayload; 5] = [
                        &digest.vk_set_hash,
                        &digest.poseidon_params_id,
                        &digest.pedersen_params_id,
                        &digest.conf_rules_version,
                        &digest.zk_policy_hash,
                    ];
                    for value in field_payloads {
                        let mut payload = Vec::new();
                        norito::core::serialize_to_buffer(value, &mut payload).unwrap();
                        expected.extend_from_slice(&frame(&payload));
                    }
                    assert_eq!(wire, expected);
                    let (decoded, used) =
                        HandshakeConfidentialDigest::decode_from_slice(&wire).unwrap();
                    assert_eq!(used, wire.len());
                    assert_eq!(
                        (
                            decoded.vk_set_hash,
                            decoded.poseidon_params_id,
                            decoded.pedersen_params_id,
                            decoded.conf_rules_version,
                            decoded.zk_policy_hash
                        ),
                        fields
                    );
                    for end in 0..wire.len() {
                        assert!(
                            HandshakeConfidentialDigest::decode_from_slice(&wire[..end]).is_err()
                        );
                    }
                    let mut trailing = wire.clone();
                    trailing.push(9);
                    let (decoded, used) =
                        HandshakeConfidentialDigest::decode_from_slice(&trailing).unwrap();
                    assert_eq!(used, wire.len());
                    assert_eq!(
                        (
                            decoded.vk_set_hash,
                            decoded.poseidon_params_id,
                            decoded.pedersen_params_id,
                            decoded.conf_rules_version,
                            decoded.zk_policy_hash
                        ),
                        fields
                    );
                    assert!(
                        norito::core::decode_field_canonical::<HandshakeConfidentialDigest>(
                            &trailing
                        )
                        .is_err()
                    );
                    let (first_len, first_prefix) =
                        norito::core::read_len_from_slice_with_flags(&wire, flags).unwrap();
                    let rest = &wire[first_prefix + first_len..];
                    let mut raw_option = vec![1];
                    raw_option.extend_from_slice(&frame(&[0x51; 32]));
                    for malformed_option in [Vec::new(), vec![0, 0], raw_option] {
                        let mut malformed = frame(&malformed_option);
                        malformed.extend_from_slice(rest);
                        assert!(
                            HandshakeConfidentialDigest::decode_from_slice(&malformed).is_err()
                        );
                    }
                }
            }
        }
    }
}
include!("peer_tests.rs");
// handshake payload is encoded/decoded as a tuple to avoid extra type definitions
mod handshake_flow {
    //! Implementations of the handshake process.
    use super::{state::*, *};
    use async_trait::async_trait;
    #[async_trait]
    pub(super) trait Stage<E: Enc> {
        type NextStage;
        async fn advance_to_next_stage(self) -> Result<Self::NextStage, crate::Error>;
    }
    macro_rules! stage {
        ( $func:ident : $curstage:ty => $nextstage:ty ) => {
            stage!(@base self Self::$func(self).await ; $curstage => $nextstage);
        };
        ( $func:ident :: <$($generic_param:ident),+> : $curstage:ty => $nextstage:ty ) => {
            stage!(@base self Self::$func::<$($generic_param),+>(self).await ; $curstage => $nextstage);
        };
        // Internal case
        (@base $self:ident $call:expr ; $curstage:ty => $nextstage:ty ) => {
            #[async_trait]
            impl<E: Enc> Stage<E> for $curstage {
                type NextStage = $nextstage;
                async fn advance_to_next_stage(self) -> Result<Self::NextStage, crate::Error> {
                    // NOTE: Need this due to macro hygiene
                    let $self = self;
                    $call
                }
            }
        }
    }
    stage!(connect_to: Connecting => ConnectedTo);
    stage!(send_client_hello::<E>: ConnectedTo => SendKey<E>);
    stage!(read_client_hello::<E>: ConnectedFrom => SendKey<E>);
    stage!(send_our_public_key: SendKey<E> => GetKey<E>);
    stage!(read_their_public_key: GetKey<E> => Ready<E>);
    #[async_trait]
    pub(super) trait Handshake<E: Enc> {
        async fn handshake(self) -> Result<Ready<E>, crate::Error>;
    }
    macro_rules! impl_handshake {
        ( base_case $typ:ty ) => {
            // Base case, should be all states that lead to `Ready`
            #[async_trait]
            impl<E: Enc> Handshake<E> for $typ {
                #[inline]
                async fn handshake(self) -> Result<Ready<E>, crate::Error> {
                    <$typ as Stage<E>>::advance_to_next_stage(self).await
                }
            }
        };
        ( $typ:ty ) => {
            #[async_trait]
            impl<E: Enc> Handshake<E> for $typ {
                #[inline]
                async fn handshake(self) -> Result<Ready<E>, crate::Error> {
                    let next_stage = <$typ as Stage<E>>::advance_to_next_stage(self).await?;
                    <_ as Handshake<E>>::handshake(next_stage).await
                }
            }
        };
    }
    impl_handshake!(base_case GetKey<E>);
    impl_handshake!(SendKey<E>);
    impl_handshake!(ConnectedFrom);
    impl_handshake!(ConnectedTo);
    impl_handshake!(Connecting);
}
#[cfg(test)]
pub(crate) use run::data_message_wire_len;
#[cfg(any(test, feature = "test-fixtures"))]
pub(crate) use run::materialized_data_message_wire_len;
pub(crate) use run::{checked_data_message_wire_len, data_message_wire_len_from_payload_len};
pub mod message {
    //! Module for peer messages
    use super::*;
    use iroha_data_model::peer::Peer;
    /// Connection-local count of reliable deliveries which crossed a peer
    /// dispatch worker but have not yet left their final local consumer.
    ///
    /// The peer task closes the producer only after every dispatch worker has
    /// drained.  A network actor may therefore retire the connection's reply
    /// tenure only after both `producer_closed` and `in_flight == 0` hold.
    #[derive(Debug)]
    pub(crate) struct InboundDeliveryDrain {
        in_flight: AtomicUsize,
        producer_closed: AtomicBool,
        changed: Notify,
    }
    impl InboundDeliveryDrain {
        pub(crate) fn new() -> Self {
            Self {
                in_flight: AtomicUsize::new(0),
                producer_closed: AtomicBool::new(false),
                changed: Notify::new(),
            }
        }
        #[cfg(any(test, feature = "test-fixtures"))]
        pub(crate) fn completed_for_test() -> Arc<Self> {
            let drain = Arc::new(Self::new());
            drain.close_producer();
            drain
        }
        fn register(self: &Arc<Self>) -> Option<InboundDeliveryDrainGuard> {
            if self.producer_closed.load(Ordering::Acquire) {
                return None;
            }
            let mut current = self.in_flight.load(Ordering::Acquire);
            loop {
                let next = current.checked_add(1)?;
                match self.in_flight.compare_exchange_weak(
                    current,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(observed) => current = observed,
                }
            }
            if self.producer_closed.load(Ordering::Acquire) {
                let prior = self.in_flight.fetch_sub(1, Ordering::AcqRel);
                debug_assert!(prior > 0);
                if prior == 1 {
                    self.changed.notify_waiters();
                }
                return None;
            }
            Some(InboundDeliveryDrainGuard {
                owner: Arc::clone(self),
            })
        }
        pub(crate) fn close_producer(&self) {
            self.producer_closed.store(true, Ordering::Release);
            self.changed.notify_waiters();
        }
        pub(crate) fn is_complete(&self) -> bool {
            self.producer_closed.load(Ordering::Acquire)
                && self.in_flight.load(Ordering::Acquire) == 0
        }
        pub(crate) async fn wait_complete(&self) {
            loop {
                let changed = self.changed.notified();
                if self.is_complete() {
                    return;
                }
                changed.await;
            }
        }
    }
    struct InboundDeliveryDrainGuard {
        owner: Arc<InboundDeliveryDrain>,
    }
    impl Drop for InboundDeliveryDrainGuard {
        fn drop(&mut self) {
            let prior = self.owner.in_flight.fetch_sub(1, Ordering::AcqRel);
            debug_assert!(prior > 0, "delivery-drain ownership cannot underflow");
            if prior == 1 {
                self.owner.changed.notify_waiters();
            }
        }
    }
    /// Connection and Handshake was successful
    pub struct Connected<T: Pload> {
        /// Peer
        pub peer: Peer,
        /// Connection Id
        pub connection_id: ConnectionId,
        /// Handle for peer to send messages and terminate command
        pub ready_peer_handle: handles::PeerHandle<T>,
        /// Channel to send peer messages channel
        pub peer_message_sender: oneshot::Sender<PeerMessageSenders<T>>,
        /// Connection-local receiver-completion fence.
        pub(crate) delivery_drain: Arc<InboundDeliveryDrain>,
        /// Disambiguator of connection (equal for both peers)
        pub disambiguator: u64,
        /// Relay role advertised during handshake.
        pub relay_role: RelayRole,
        /// Whether the remote supports SCION transport preference.
        pub scion_supported: bool,
        /// Whether the remote supports trust gossip.
        pub trust_gossip: bool,
    }
    /// Isolated safety/high/low senders for inbound peer messages.
    #[derive(Clone)]
    pub struct PeerMessageSenders<T: Pload> {
        /// Sender for authoritative-consensus safety messages.
        pub safety: mpsc::Sender<PeerMessage<T>>,
        /// Sender for high-priority inbound peer messages.
        pub high: mpsc::Sender<PeerMessage<T>>,
        /// Sender for low-priority inbound peer messages.
        pub low: mpsc::Sender<PeerMessage<T>>,
        /// Ordinary body/chunk FIFO.
        pub(crate) payload: mpsc::Sender<PeerMessage<T>>,
        /// Reliable `BlockSync` FIFO charged to the low lane.
        pub(crate) block_sync: mpsc::Sender<PeerMessage<T>>,
        /// Ordinary application control FIFO.
        pub(crate) control: mpsc::Sender<PeerMessage<T>>,
        /// Classified downstream owner shared by every peer producer.
        pub(crate) dispatch_budgets: InboundDispatchByteBudgets,
        /// PeerId-keyed count owners, isolated by scheduling lane so stalled
        /// bulk work cannot consume safety service.
        pub(crate) source_credits: AuthenticatedSourceCredits,
        /// Plaintext frame caps enforced before actor-queue admission.
        pub(crate) topic_frame_caps: crate::network::TopicFrameCaps,
        /// Exact receiver-completion owner for this connection tenure.
        pub(crate) delivery_drain: Arc<InboundDeliveryDrain>,
    }
    /// Fair count ownership for one authenticated transport source.
    ///
    /// One instance is shared by every live or draining authenticated tenure
    /// for the same authenticated [`PeerId`]. The byte budgets remain
    /// authoritative for memory; these semaphores additionally prevent one
    /// identity's many small frames or rapid reconnects from monopolizing
    /// aggregate queue count.
    #[derive(Clone, Debug)]
    pub(crate) struct AuthenticatedSourceCredits {
        owner: Arc<AuthenticatedSourceCreditOwner>,
    }
    /// Opaque count ownership retained with one authenticated inbound message.
    #[derive(Debug)]
    pub(super) struct AuthenticatedSourceCreditGuard {
        _permit: OwnedSemaphorePermit,
        /// Retaining the aggregate owner is what lets the PeerId-keyed weak
        /// registry find and reuse it after a transport tenure exits.
        _owner: Option<AuthenticatedSourceCredits>,
    }
    impl AuthenticatedSourceCredits {
        pub(super) fn receive_capacity(&self) -> usize {
            self.owner.per_lane_capacity
        }
        pub(super) fn receive_partition(
            &self,
            geometry: [u8; 32],
            make: impl FnOnce() -> Result<receive_credit::SourcePartition, Error>,
        ) -> Result<Arc<receive_credit::SourcePartition>, Error> {
            let mut slot = self
                .owner
                .receive_partition
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(existing) = slot.as_ref() {
                if existing.geometry != geometry {
                    return Err(Error::Format);
                }
                return Ok(Arc::clone(existing));
            }
            let created = Arc::new(make()?);
            if created.geometry != geometry {
                return Err(Error::Format);
            }
            *slot = Some(Arc::clone(&created));
            Ok(created)
        }
        pub(super) fn try_receive_count(
            &self,
            class: crate::TransportAdmissionClass,
        ) -> Option<AuthenticatedSourceCreditGuard> {
            let owner = match class {
                crate::TransportAdmissionClass::Safety => &self.owner.safety,
                class if class.is_low() => &self.owner.low,
                _ => &self.owner.high,
            };
            Some(AuthenticatedSourceCreditGuard {
                _permit: Arc::clone(owner).try_acquire_owned().ok()?,
                _owner: Some(self.clone()),
            })
        }
        #[cfg(any(test, feature = "test-fixtures"))]
        pub(crate) fn new(per_lane_capacity: usize) -> Self {
            Self {
                owner: Arc::new(AuthenticatedSourceCreditOwner::new(per_lane_capacity)),
            }
        }
        pub(super) fn from_owner(owner: Arc<AuthenticatedSourceCreditOwner>) -> Self {
            Self { owner }
        }
        #[cfg(test)]
        /// Acquire one high-lane permit without entering the dispatch worker.
        pub(super) fn try_acquire_high_for_test(&self) -> Option<AuthenticatedSourceCreditGuard> {
            let permit = Arc::clone(&self.owner.high).try_acquire_owned().ok()?;
            Some(AuthenticatedSourceCreditGuard {
                _permit: permit,
                _owner: Some(self.clone()),
            })
        }
        #[cfg(test)]
        /// Report currently available safety-lane credits for ownership tests.
        pub(super) fn available_safety_for_test(&self) -> usize {
            self.owner.safety.available_permits()
        }
        async fn acquire(
            &self,
            safety: bool,
            high: bool,
            wait: bool,
        ) -> Option<AuthenticatedSourceCreditGuard> {
            let credits = if safety {
                &self.owner.safety
            } else if high {
                &self.owner.high
            } else {
                &self.owner.low
            };
            let permit = if wait {
                Arc::clone(credits).acquire_owned().await.ok()
            } else {
                Arc::clone(credits).try_acquire_owned().ok()
            }?;
            Some(AuthenticatedSourceCreditGuard {
                _permit: permit,
                _owner: Some(self.clone()),
            })
        }
    }
    pub(super) enum InboundDispatchAdmission {
        Admitted,
        OverTopicCap { cap: usize },
        ByteBudgetFull,
    }
    impl<T: Pload> PeerMessageSenders<T> {
        pub(super) async fn transfer_before_send(
            &self,
            message: &mut PeerMessage<T>,
            topic: crate::network::message::Topic,
            priority: crate::network::message::Priority,
            wait: bool,
        ) -> InboundDispatchAdmission {
            let cap = self.topic_frame_caps.for_topic(topic);
            if message.payload_bytes > cap {
                return InboundDispatchAdmission::OverTopicCap { cap };
            }
            if matches!(message.retention, Some(PeerMessageRetention::Granted(_))) {
                // The unforgeable grant already owns both dispatch bytes and
                // its exact count. Its final notifier runs after both release.
                message.attach_delivery_drain(&self.delivery_drain);
                return InboundDispatchAdmission::Admitted;
            }
            let safety = matches!(topic, crate::network::message::Topic::ConsensusSafety);
            let high = matches!(
                topic,
                crate::network::message::Topic::ConsensusSafety
                    | crate::network::message::Topic::Consensus
                    | crate::network::message::Topic::ConsensusPayload
                    | crate::network::message::Topic::ConsensusChunk
                    | crate::network::message::Topic::Control
            ) || matches!(priority, crate::network::message::Priority::High);
            if message.source_credit.is_none() {
                let Some(credit) = self.source_credits.acquire(safety, high, wait).await else {
                    return InboundDispatchAdmission::ByteBudgetFull;
                };
                let attached = message.retain_source_credit_guard(credit);
                debug_assert!(
                    attached,
                    "a peer dispatch message acquires one source credit exactly once"
                );
            }
            if message
                .transfer_to_dispatch_budget(&self.dispatch_budgets, high, safety, wait)
                .await
            {
                message.attach_delivery_drain(&self.delivery_drain);
                InboundDispatchAdmission::Admitted
            } else {
                InboundDispatchAdmission::ByteBudgetFull
            }
        }
        #[cfg(test)]
        pub(crate) async fn transfer_before_send_for_test(
            &self,
            message: &mut PeerMessage<T>,
            topic: crate::network::message::Topic,
            priority: crate::network::message::Priority,
        ) -> bool {
            matches!(
                self.transfer_before_send(message, topic, priority, false)
                    .await,
                InboundDispatchAdmission::Admitted
            )
        }
    }
    /// Messages received from Peer along with their encoded size (in bytes).
    ///
    /// Runtime-delivered messages carry a private byte lease from authenticated
    /// frame admission through subscriber and relay-worker processing.
    pub struct PeerMessage<T: Pload> {
        /// Semantic origin of this payload.
        ///
        /// For a direct connection this is the authenticated transport peer. A
        /// trusted relay may preserve a different protocol origin here; resource
        /// accounting must use [`Self::authenticated_via`] instead.
        pub peer: Peer,
        /// Fully decoded payload content.
        pub payload: T,
        /// Size of the payload on the wire (Norito-encoded) in bytes.
        pub payload_bytes: usize,
        /// Authenticated transport identity that delivered the frame.
        ///
        /// Unlike `peer`, payload mapping through a trusted relay never rewrites
        /// this identity. It is therefore the stable key for source-isolated
        /// queue, byte, and rate ownership.
        authenticated_via: PeerId,
        /// Exact authenticated transport tenure that delivered the frame.
        /// Synthetic producers leave this unset.
        pub(crate) connection_id: Option<ConnectionId>,
        /// Exact authenticated return route minted by the network actor after
        /// relay validation. Synthetic messages carry no route.
        reply_route: Option<crate::network::NetworkReplyRoute>,
        retention: Option<PeerMessageRetention>,
        source_credit: Option<AuthenticatedSourceCreditGuard>,
        delivery_drain: Option<InboundDeliveryDrainGuard>,
    }
    /// Opaque ownership guard for the retained bytes behind a [`PeerMessage`].
    ///
    /// Consumers that move the payload into an asynchronous operation must keep
    /// this guard alive until that operation finishes. Dropping it releases the
    /// corresponding inbound byte-budget reservation and any attached
    /// authenticated-source queue credit.
    pub struct PeerMessageRetentionGuard {
        retention: Option<PeerMessageRetention>,
        authenticated_via: PeerId,
        _source_credit: Option<AuthenticatedSourceCreditGuard>,
        _delivery_drain: Option<InboundDeliveryDrainGuard>,
    }
    impl<T: Pload> PeerMessage<T> {
        /// Exact class carried by a consumed grant; absent only for non-grant producers.
        pub(crate) fn granted_admission_class(&self) -> Option<crate::TransportAdmissionClass> {
            match &self.retention {
                Some(PeerMessageRetention::Granted(retention)) => Some(retention.class),
                _ => None,
            }
        }
        /// Construct an unretained message for synthetic producers and tests.
        #[must_use]
        pub fn new(peer: Peer, payload: T, payload_bytes: usize) -> Self {
            let authenticated_via = peer.id().clone();
            Self {
                peer,
                payload,
                payload_bytes,
                authenticated_via,
                connection_id: None,
                reply_route: None,
                retention: None,
                source_credit: None,
                delivery_drain: None,
            }
        }
        #[cfg(test)]
        pub(crate) fn new_for_connection(
            peer: Peer,
            payload: T,
            payload_bytes: usize,
            connection_id: ConnectionId,
        ) -> Self {
            let authenticated_via = peer.id().clone();
            Self {
                peer,
                payload,
                payload_bytes,
                authenticated_via,
                connection_id: Some(connection_id),
                reply_route: None,
                retention: None,
                source_credit: None,
                delivery_drain: None,
            }
        }
        #[cfg(test)]
        pub(crate) fn new_dispatch_retained_for_test(
            peer: Peer,
            payload: T,
            payload_bytes: usize,
            budget: Arc<SharedByteBudget>,
        ) -> Self {
            let byte_lease = budget
                .try_reserve(payload_bytes, false)
                .expect("test dispatch retention must fit its supplied budget");
            let authenticated_via = peer.id().clone();
            Self {
                peer,
                payload,
                payload_bytes,
                authenticated_via,
                connection_id: None,
                reply_route: None,
                retention: Some(PeerMessageRetention::Dispatch(DispatchRetention {
                    _byte_lease: byte_lease,
                    budget,
                    frame_queue_overhead_bytes: 0,
                    safety: false,
                })),
                source_credit: None,
                delivery_drain: None,
            }
        }
        /// Return the authenticated transport peer that delivered this frame.
        ///
        /// This identity remains unchanged when a relay maps the semantic
        /// [`Self::peer`] origin and must be used for resource isolation.
        pub fn authenticated_via(&self) -> &PeerId {
            &self.authenticated_via
        }
        /// Return the authenticated transport tenure, when this message
        /// came from a live peer transport rather than a synthetic producer.
        pub(crate) const fn connection_id(&self) -> Option<ConnectionId> {
            self.connection_id
        }
        /// Return the exact authenticated route on which a protocol reply may
        /// be sent, when this message originated from a live P2P connection.
        #[must_use]
        pub fn reply_route(&self) -> Option<&crate::network::NetworkReplyRoute> {
            self.reply_route.as_ref()
        }
        pub(crate) fn set_reply_route(&mut self, route: crate::network::NetworkReplyRoute) {
            self.reply_route = Some(route);
        }
        /// Reattach a previously minted route after a bounded local hold/release boundary.
        ///
        /// The route remains unforgeable and is accepted only when its semantic
        /// target matches this message's protocol origin. Its authenticated
        /// delivery identity is restored from the opaque route rather than from
        /// the semantic origin supplied by the local rehydration boundary.
        ///
        /// # Errors
        ///
        /// Returns the route unchanged when this message already owns a reply
        /// capability, the candidate belongs to another semantic origin, or its
        /// authenticated connection tenure is no longer active.
        pub fn reattach_reply_route(
            &mut self,
            route: crate::network::NetworkReplyRoute,
        ) -> Result<(), crate::network::NetworkReplyRoute> {
            if self.reply_route.is_some()
                || route.semantic_target() != self.peer.id()
                || !route.is_active()
            {
                return Err(route);
            }
            self.authenticated_via = route.authenticated_via().clone();
            self.reply_route = Some(route);
            Ok(())
        }
        /// Split the message while preserving its byte-budget ownership.
        ///
        /// The returned guard must remain in scope for as long as the moved
        /// payload remains queued or is being processed. Consumers which may
        /// produce a protocol reply must use [`Self::into_parts_with_reply_route`]
        /// so the authenticated return route is not discarded.
        #[must_use]
        pub fn into_parts(self) -> (Peer, PeerId, T, usize, PeerMessageRetentionGuard) {
            let (peer, authenticated_via, payload, payload_bytes, _reply_route, guard) =
                self.into_parts_with_reply_route();
            (peer, authenticated_via, payload, payload_bytes, guard)
        }
        /// Split the message while preserving both byte ownership and the
        /// exact authenticated return route.
        #[must_use]
        pub fn into_parts_with_reply_route(
            self,
        ) -> (
            Peer,
            PeerId,
            T,
            usize,
            Option<crate::network::NetworkReplyRoute>,
            PeerMessageRetentionGuard,
        ) {
            let Self {
                peer,
                payload,
                payload_bytes,
                authenticated_via,
                connection_id: _,
                reply_route,
                retention,
                source_credit,
                delivery_drain,
            } = self;
            (
                peer,
                authenticated_via.clone(),
                payload,
                payload_bytes,
                reply_route,
                PeerMessageRetentionGuard {
                    retention,
                    authenticated_via,
                    _source_credit: source_credit,
                    _delivery_drain: delivery_drain,
                },
            )
        }
        pub(super) fn from_receive_grant(
            peer: Peer,
            payload: T,
            payload_bytes: usize,
            connection_id: ConnectionId,
            retention: receive_credit::GrantRetention,
        ) -> Self {
            let authenticated_via = peer.id().clone();
            Self {
                peer,
                payload,
                payload_bytes,
                authenticated_via,
                connection_id: Some(connection_id),
                reply_route: None,
                retention: Some(PeerMessageRetention::Granted(retention)),
                source_credit: None,
                delivery_drain: None,
            }
        }
        #[cfg(test)]
        pub(super) fn from_inbound_frame(
            peer: Peer,
            payload: T,
            payload_bytes: usize,
            connection_id: ConnectionId,
            frame: InboundFrameRetention,
        ) -> Self {
            let authenticated_via = peer.id().clone();
            Self {
                peer,
                payload,
                payload_bytes,
                authenticated_via,
                connection_id: Some(connection_id),
                reply_route: None,
                retention: Some(PeerMessageRetention::Source(frame)),
                source_credit: None,
                delivery_drain: None,
            }
        }
        /// Attach one authenticated-source queue credit to this exact message.
        ///
        /// The credit follows payload mapping and is released only when the
        /// final [`PeerMessageRetentionGuard`] is dropped. Attaching a second
        /// credit is idempotent: the redundant permit is released immediately,
        /// leaving the earlier upstream owner authoritative.
        pub fn retain_authenticated_source_credit(&mut self, credit: OwnedSemaphorePermit) {
            let _ = self.retain_source_credit_guard(AuthenticatedSourceCreditGuard {
                _permit: credit,
                _owner: None,
            });
        }
        fn retain_source_credit_guard(&mut self, credit: AuthenticatedSourceCreditGuard) -> bool {
            if self.source_credit.is_some() {
                drop(credit);
                return false;
            }
            self.source_credit = Some(credit);
            true
        }
        fn attach_delivery_drain(&mut self, owner: &Arc<InboundDeliveryDrain>) {
            if self.delivery_drain.is_some() {
                return;
            }
            self.delivery_drain = Some(
                owner
                    .register()
                    .expect("dispatch worker cannot enqueue after closing its delivery drain"),
            );
        }
        pub(crate) async fn transfer_to_dispatch_budget(
            &mut self,
            budgets: &InboundDispatchByteBudgets,
            high: bool,
            safety: bool,
            wait: bool,
        ) -> bool {
            let Some(retention) = self.retention.take() else {
                return true;
            };
            let PeerMessageRetention::Source(source) = retention else {
                self.retention = Some(retention);
                return true;
            };
            let Some(bytes) = self
                .payload_bytes
                .checked_add(source.frame_queue_overhead_bytes)
            else {
                self.retention = Some(PeerMessageRetention::Source(source));
                return false;
            };
            let budget = budgets.budget(high);
            let byte_lease = if wait {
                budget.reserve(bytes, safety).await
            } else {
                budget.try_reserve(bytes, safety)
            };
            let Some(byte_lease) = byte_lease else {
                self.retention = Some(PeerMessageRetention::Source(source));
                return false;
            };
            self.retention = Some(PeerMessageRetention::Dispatch(DispatchRetention {
                _byte_lease: byte_lease,
                budget,
                frame_queue_overhead_bytes: source.frame_queue_overhead_bytes,
                safety,
            }));
            true
        }
        pub(crate) fn try_clone_retained(&self) -> Option<Self> {
            // A source credit represents one exact downstream owner and cannot
            // be cloned. Fan-out happens before the application attaches it.
            if self.source_credit.is_some() {
                return None;
            }
            let retention = match &self.retention {
                Some(PeerMessageRetention::Dispatch(retention)) => {
                    Some(PeerMessageRetention::Dispatch(
                        retention.try_clone_for_payload(self.payload_bytes)?,
                    ))
                }
                Some(PeerMessageRetention::Source(_) | PeerMessageRetention::Granted(_)) => {
                    return None;
                }
                None => None,
            };
            Some(Self {
                peer: self.peer.clone(),
                payload: self.payload.clone(),
                payload_bytes: self.payload_bytes,
                authenticated_via: self.authenticated_via.clone(),
                connection_id: self.connection_id,
                reply_route: self.reply_route.clone(),
                retention,
                source_credit: None,
                delivery_drain: None,
            })
        }
        pub(crate) fn map_payload<U: Pload>(
            self,
            peer: Peer,
            map: impl FnOnce(T) -> U,
        ) -> PeerMessage<U> {
            PeerMessage {
                peer,
                payload: map(self.payload),
                payload_bytes: self.payload_bytes,
                authenticated_via: self.authenticated_via,
                connection_id: self.connection_id,
                reply_route: self.reply_route,
                retention: self.retention,
                source_credit: self.source_credit,
                delivery_drain: self.delivery_drain,
            }
        }
    }
    impl PeerMessageRetentionGuard {
        /// Return the class authorized by the consumed, pre-reserved data grant.
        /// Synthetic messages have no grant. This never reclassifies from caller priority.
        pub fn granted_admission_class(&self) -> Option<crate::TransportAdmissionClass> {
            match &self.retention {
                Some(PeerMessageRetention::Granted(retention)) => Some(retention.class),
                _ => None,
            }
        }
        /// Return the authenticated transport source whose ownership this guard retains.
        pub fn authenticated_via(&self) -> &PeerId {
            &self.authenticated_via
        }
    }
    /// Peer faced error or `Terminate` message, send to indicate that it is terminated
    pub struct Terminated {
        /// Peer
        pub peer: Option<Peer>,
        /// Connection Id
        pub conn_id: ConnectionId,
    }
    /// Verified identity offered to the central connection owner before reader binding.
    /// It does not publish an online/application session. Exact configured-hub
    /// identity proof remains a separate decision of the network owner.
    pub struct Authenticated {
        /// Exact identity and address verified by the handshake.
        pub(crate) peer: Peer,
        /// Existing listener/dial connection reservation.
        pub(crate) connection_id: ConnectionId,
        /// Complete session hash covered by the peer identity signature.
        pub(crate) session: [u8; iroha_crypto::Hash::LENGTH],
        /// Authenticated role used only for the existing configured hub proof.
        pub(crate) relay_role: RelayRole,
        /// Same cancellation watch used throughout negotiation and active I/O.
        pub(crate) cancel: tokio::sync::watch::Sender<bool>,
        /// Exclusive reader permission, issued only after predecessor release.
        pub(crate) reply: tokio::sync::oneshot::Sender<super::tenure::ReaderPermit>,
    }
    /// Messages sent by peer during connection process
    pub enum ServiceMessage<T: Pload> {
        /// Authenticated identity awaits the central exclusive reader permission.
        Authenticated(Authenticated),
        /// Connection and Handshake was successful
        Connected(Connected<T>),
        /// Peer faced error or `Terminate` message, send to indicate that it is terminated
        Terminated(Terminated),
        /// Every reliable local delivery from a terminated connection has
        /// left its final receiver, so its reply tenure may now retire.
        ReplyRouteDeliveryDrained(ConnectionId),
        /// Ask the network actor if an inbound connection should be accepted,
        /// applying caps and per-IP throttle identically to TLS/QUIC accepts.
        /// If accepted, the network actor should insert the `conn_id` into
        /// `incoming_pending` and reply `true`.
        InboundAsk {
            /// Temporary connection id
            conn_id: ConnectionId,
            /// Remote socket address reported by transport
            remote_addr: std::net::SocketAddr,
            /// Reply whether to accept (true) or drop (false)
            reply: tokio::sync::oneshot::Sender<bool>,
        },
        /// Release a pre-authentication slot whose accepted transport failed or
        /// whose handoff future was cancelled before a peer actor took ownership.
        InboundCancelled(ConnectionId),
    }
}
mod cryptographer {
    use super::*;
    use iroha_crypto::{SessionKey, encryption::SymmetricEncryptor};
    /// Peer's cryptographic primitives
    #[derive(Clone)]
    pub struct Cryptographer<E: Enc> {
        /// Diagnostic prefix derived from the session binding.
        pub disambiguator: u64,
        /// Full domain-separated hash of the negotiated session key.
        ///
        /// Long-term peer identity signatures bind this complete value. The
        /// compact disambiguator is diagnostic; arbitration orders this full value.
        pub session_binding: [u8; iroha_crypto::Hash::LENGTH],
        /// Encryptor created from session key, that we got by Diffie-Hellman scheme
        pub encryptor: SymmetricEncryptor<E>,
    }
    impl<E: Enc> Cryptographer<E> {
        fn session_binding(key_bytes: &[u8]) -> [u8; iroha_crypto::Hash::LENGTH] {
            const DOMAIN: &[u8] = b"iroha:p2p:session-binding:v1|";
            let mut preimage = Vec::with_capacity(DOMAIN.len().saturating_add(key_bytes.len()));
            preimage.extend_from_slice(DOMAIN);
            preimage.extend_from_slice(key_bytes);
            iroha_crypto::Hash::new(&preimage).into()
        }
        fn disambiguator(session_binding: &[u8; iroha_crypto::Hash::LENGTH]) -> u64 {
            const COMPACT_LEN: usize = core::mem::size_of::<u64>();
            let mut compact = [0_u8; COMPACT_LEN];
            compact.copy_from_slice(&session_binding[..COMPACT_LEN]);
            u64::from_be_bytes(compact)
        }
        /// Construct from raw key bytes for deterministic unit fixtures.
        #[cfg(test)]
        pub fn new_with_raw_key_bytes(key_bytes: &[u8]) -> Result<Self, Error> {
            let session_binding = Self::session_binding(key_bytes);
            let disambiguator = Self::disambiguator(&session_binding);
            let encryptor = SymmetricEncryptor::<E>::new_with_key(key_bytes)?;
            Ok(Self {
                disambiguator,
                session_binding,
                encryptor,
            })
        }
        /// Decrypt bytes.
        ///
        /// # Errors
        /// Forwards [`SymmetricEncryptor::decrypt_easy`] error
        pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
            self.encryptor
                .decrypt_easy(DEFAULT_AAD.as_ref(), data)
                .map_err(Into::into)
        }

        /// Encrypt bytes.
        ///
        /// # Errors
        /// Forwards [`SymmetricEncryptor::decrypt_easy`] error
        pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
            self.encryptor
                .encrypt_easy(DEFAULT_AAD.as_ref(), data)
                .map_err(Into::into)
        }
        /// Derives shared key from local private key and remote public key.
        pub fn new(shared_key: &SessionKey) -> Result<Self, Error> {
            let session_binding = Self::session_binding(shared_key.payload());
            let disambiguator = Self::disambiguator(&session_binding);
            let encryptor = SymmetricEncryptor::<E>::new_from_session_key(shared_key)?;
            Ok(Self {
                disambiguator,
                session_binding,
                encryptor,
            })
        }
    }
}
/// An identification for peer connections.
pub type ConnectionId = u64;
/// Hash-sized binding for authenticated transport sessions.
pub type TransportBinding = [u8; iroha_crypto::Hash::LENGTH];
/// Authenticated P2P connection assembled by the crate's TLS or QUIC transports.
pub(crate) struct Connection {
    /// A unique connection id
    pub(crate) id: ConnectionId,
    /// Reader half of the stream
    pub(crate) read: Box<dyn AsyncRead + Send + Unpin>,
    /// Writer half of the stream
    pub(crate) write: Box<dyn AsyncWrite + Send + Unpin>,
    /// Optional low-priority reader half (e.g., second QUIC stream).
    pub(crate) read_low: Option<Box<dyn AsyncRead + Send + Unpin>>,
    /// Optional low-priority writer half (e.g., second QUIC stream).
    pub(crate) write_low: Option<Box<dyn AsyncWrite + Send + Unpin>>,
    /// QUIC connection handle (only set when the underlying transport is QUIC).
    pub(crate) quic: Option<crate::transport::QuicConnection>,
    /// Eager DATAGRAM drain started before application authentication.
    #[cfg(feature = "quic")]
    pub(crate) quic_datagrams: Option<QuicDatagramIngress>,
    /// Remote addr, for logging purpose.
    pub(crate) remote_addr: Option<SocketAddr>,
    /// Listener-observed TLS/QUIC channel binding; mandatory outside negative-path tests.
    pub(crate) transport_binding: Option<TransportBinding>,
}
impl Connection {
    /// Instantiate an intentionally unbound connection for negative-path tests.
    #[cfg(test)]
    pub(crate) fn from_split<R, W>(id: ConnectionId, read: R, write: W) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        Self {
            id,
            read: Box::new(read),
            write: Box::new(write),
            read_low: None,
            write_low: None,
            quic: None,
            #[cfg(feature = "quic")]
            quic_datagrams: None,
            remote_addr: None,
            transport_binding: None,
        }
    }
    /// Instantiate a TLS connection with its mandatory certificate binding.
    pub(crate) fn from_split_with_binding<R, W>(
        id: ConnectionId,
        read: R,
        write: W,
        transport_binding: TransportBinding,
    ) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        Connection {
            id,
            read: Box::new(read),
            write: Box::new(write),
            read_low: None,
            write_low: None,
            quic: None,
            #[cfg(feature = "quic")]
            quic_datagrams: None,
            remote_addr: None,
            transport_binding: Some(transport_binding),
        }
    }
    fn validate_client_transport_binding(
        &self,
        claimed: Option<TransportBinding>,
    ) -> std::io::Result<Option<TransportBinding>> {
        if claimed != self.transport_binding {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "client-observed transport binding does not match the accepted transport",
            ));
        }
        Ok(self.transport_binding)
    }
    /// Instantiate connection from QUIC streams.
    #[cfg(feature = "quic")]
    pub(crate) fn from_quic(
        id: ConnectionId,
        quic: quinn::Connection,
        send_hi: quinn::SendStream,
        recv_hi: quinn::RecvStream,
        send_low: Option<quinn::SendStream>,
        recv_low: Option<quinn::RecvStream>,
        quic_datagrams: Option<QuicDatagramIngress>,
        remote_addr: Option<SocketAddr>,
        transport_binding: TransportBinding,
    ) -> Self {
        Connection {
            id,
            read: Box::new(recv_hi),
            write: Box::new(send_hi),
            read_low: recv_low.map(|s| {
                let boxed: Box<dyn AsyncRead + Send + Unpin> = Box::new(s);
                boxed
            }),
            write_low: send_low.map(|s| {
                let boxed: Box<dyn AsyncWrite + Send + Unpin> = Box::new(s);
                boxed
            }),
            quic: Some(quic),
            quic_datagrams,
            remote_addr,
            transport_binding: Some(transport_binding),
        }
    }
}

#[cfg(test)]
pub(crate) use run::assert_captured_p2p_message;
