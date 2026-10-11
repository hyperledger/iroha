//! Bounded native HTTP reads for independently authenticated finality verification.
//!
//! Endpoint selection never establishes trust. The SDK authenticates each response's request,
//! network and signer; [`super::finality::FinalityVerifier`] separately verifies its contiguous
//! chain and committee. Credentials stay in the caller's immutable per-endpoint SDK contexts.

use std::{
    collections::BTreeMap,
    num::NonZeroU64,
    time::{Duration, Instant},
};

use iroha::client::{BridgeFinalityAttestationTipMismatch, Client};
use iroha_crypto::Algorithm;
use iroha_data_model::{NetworkId, sumeragi_finality::SumeragiFinalityProof};
use iroha_model_base::peer::PeerId;

use super::finality::{FinalityAttestation, FinalitySource, MAX_OBSERVATION_PEERS};

const MAX_CONCURRENT_PEERS: usize = 8;
const PER_PEER_BUDGET: Duration = Duration::from_secs(5);
const MAX_TIP_ATTEMPTS: usize = 4;

/// A closed transport error that never includes server bodies, URLs or credentials.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum HttpFinalityError {
    /// Endpoint policy, network, peer roster or challenge is invalid.
    #[error("invalid finality HTTP context: {0}")]
    Invalid(&'static str),
    /// The operation or selected peer's bounded read budget expired.
    #[error("finality HTTP deadline expired")]
    Deadline,
    /// The authenticated committee member has no selected endpoint.
    #[error("no finality endpoint for the selected committee member")]
    MissingPeer,
    /// SDK transport, codec or exact request authentication failed.
    #[error("native finality HTTP read failed")]
    Read,
    /// The node's applied/consensus tips did not settle within the finite attempt budget.
    #[error("finality tip changed throughout the bounded observation")]
    MovingTip,
    /// A bounded read worker failed internally.
    #[error("finality HTTP worker failed")]
    Worker,
}

/// Untrusted proof retrieval plus bounded concurrent reads of selected committee members.
/// Construct a new source for each observation deadline. Retain the verifier separately.
pub struct HttpFinalitySource {
    proof_clients: Vec<Client>,
    peers: BTreeMap<PeerId, Client>,
    initial_height: NonZeroU64,
    deadline: Instant,
}

impl HttpFinalitySource {
    /// Bind already configured SDK clients to one independently selected network.
    /// HTTPS is required except for numeric loopback development endpoints. Each client's
    /// explicit credential stays at that endpoint; this constructor never retargets a client.
    /// The initial height is only a retry hint, normally the retained checkpoint height.
    ///
    /// # Errors
    /// Rejects mixed networks, insecure remote endpoints, duplicate peers, unbounded endpoint
    /// collections, non-BLS identities or an elapsed observation deadline before any HTTP read.
    pub fn new(
        network_id: NetworkId,
        initial_height: NonZeroU64,
        proof_clients: Vec<Client>,
        peer_clients: Vec<(PeerId, Client)>,
        deadline: Instant,
    ) -> Result<Self, HttpFinalityError> {
        ensure_deadline(deadline)?;
        if proof_clients.is_empty()
            || proof_clients.len() > MAX_OBSERVATION_PEERS
            || peer_clients.is_empty()
            || peer_clients.len() > MAX_OBSERVATION_PEERS
        {
            return Err(HttpFinalityError::Invalid("endpoint count"));
        }
        for client in proof_clients
            .iter()
            .chain(peer_clients.iter().map(|(_, client)| client))
        {
            if *client.network_id() != network_id {
                return Err(HttpFinalityError::Invalid("network identity"));
            }
            validate_endpoint(client.endpoint())?;
        }
        let mut peers = BTreeMap::new();
        for (peer, client) in peer_clients {
            if peer.public_key().try_algorithm().ok() != Some(Algorithm::BlsNormal)
                || peers.insert(peer, client).is_some()
            {
                return Err(HttpFinalityError::Invalid("committee endpoint identity"));
            }
        }
        Ok(Self {
            proof_clients,
            peers,
            initial_height,
            deadline,
        })
    }
}

impl FinalitySource for HttpFinalitySource {
    type Error = HttpFinalityError;

    fn finality_proof(&self, height: NonZeroU64) -> Result<SumeragiFinalityProof, Self::Error> {
        for client in &self.proof_clients {
            ensure_deadline(self.deadline)?;
            let bounded =
                client.with_request_deadline(self.deadline.min(Instant::now() + PER_PEER_BUDGET));
            if let Ok(proof) = bounded.get_sumeragi_finality_proof(height) {
                ensure_deadline(self.deadline)?;
                return Ok(proof);
            }
        }
        ensure_deadline(self.deadline)?;
        Err(HttpFinalityError::Read)
    }

    fn latest_attestation(
        &self,
        peer: &PeerId,
        challenge: &[u8; 32],
    ) -> Result<FinalityAttestation, Self::Error> {
        if *challenge == [0; 32] {
            return Err(HttpFinalityError::Invalid("zero challenge"));
        }
        ensure_deadline(self.deadline)?;
        let deadline = self.deadline.min(Instant::now() + PER_PEER_BUDGET);
        let client = self
            .peers
            .get(peer)
            .ok_or(HttpFinalityError::MissingPeer)?
            .with_request_deadline(deadline);
        read_tip(self.initial_height, deadline, |height| {
            client
                .get_sumeragi_finality_attestation(height, *challenge, peer)
                .map(FinalityAttestation::Authenticated)
                .map_err(|error| {
                    match error.downcast_ref::<BridgeFinalityAttestationTipMismatch>() {
                        Some(progress) => TipRead::Progress(progress.response().applied_height),
                        None => TipRead::Failed,
                    }
                })
        })
    }

    fn latest_attestations(
        &self,
        peers: &[PeerId],
        challenge: &[u8; 32],
    ) -> Vec<Result<FinalityAttestation, Self::Error>> {
        if peers.len() > MAX_OBSERVATION_PEERS {
            return peers
                .iter()
                .map(|_| Err(HttpFinalityError::Invalid("peer batch count")))
                .collect();
        }
        if norito::core::decode_limits_active() {
            // The SDK decodes and verifies each response synchronously. Keep an enclosing
            // caller's cumulative admission and peer order on its original thread.
            return peers
                .iter()
                .map(|peer| self.latest_attestation(peer, challenge))
                .collect();
        }
        // Batches bound native threads and open requests. All joins finish before returning;
        // no detached task or retry can outlive the shared operation deadline.
        concurrent_reads(peers, |peer| self.latest_attestation(peer, challenge))
    }
}

fn validate_endpoint(url: &url::Url) -> Result<(), HttpFinalityError> {
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if url.host().is_none()
        || (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with('/')
    {
        return Err(HttpFinalityError::Invalid("endpoint policy"));
    }
    Ok(())
}

fn ensure_deadline(deadline: Instant) -> Result<(), HttpFinalityError> {
    if Instant::now() >= deadline {
        Err(HttpFinalityError::Deadline)
    } else {
        Ok(())
    }
}

enum TipRead {
    Progress(u64),
    Failed,
}

fn read_tip<T>(
    mut height: NonZeroU64,
    deadline: Instant,
    mut read: impl FnMut(NonZeroU64) -> Result<T, TipRead>,
) -> Result<T, HttpFinalityError> {
    for _ in 0..MAX_TIP_ATTEMPTS {
        ensure_deadline(deadline)?;
        let result = read(height);
        ensure_deadline(deadline)?;
        match result {
            Ok(value) => return Ok(value),
            Err(TipRead::Progress(applied)) => {
                height = NonZeroU64::new(applied).ok_or(HttpFinalityError::Read)?;
            }
            Err(TipRead::Failed) => return Err(HttpFinalityError::Read),
        }
    }
    Err(HttpFinalityError::MovingTip)
}

fn concurrent_reads<T: Sync, R: Send>(
    values: &[T],
    read: impl Fn(&T) -> Result<R, HttpFinalityError> + Sync,
) -> Vec<Result<R, HttpFinalityError>> {
    let mut output = Vec::with_capacity(values.len());
    for batch in values.chunks(MAX_CONCURRENT_PEERS) {
        output.extend(std::thread::scope(|scope| {
            let handles = batch
                .iter()
                .map(|value| {
                    let read = &read;
                    std::thread::Builder::new()
                        .name("finality-read".into())
                        .spawn_scoped(scope, move || read(value))
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| match handle {
                    Ok(handle) => handle.join().unwrap_or(Err(HttpFinalityError::Worker)),
                    Err(_) => Err(HttpFinalityError::Worker),
                })
                .collect::<Vec<_>>()
        }));
    }
    output
}

#[cfg(test)]
mod tests;
