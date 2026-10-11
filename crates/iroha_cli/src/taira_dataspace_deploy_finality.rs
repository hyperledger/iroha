//! Deployment completion under an independently selected genesis and four validator identities.
use super::*;
use iroha_crypto::{Hash, HashOf, PublicKey};
use iroha_data_model::{
    block::BlockHeader,
    sns::NameStatus,
    sumeragi_finality::{
        FinalityValidator, SumeragiFinalityAttestation, SumeragiFinalityProof,
        SumeragiFinalityVerifier,
    },
};
use iroha_model_base::peer::PeerId;
use norito::codec::Encode as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
};

#[path = "taira_authenticated_height.rs"]
pub(crate) mod authenticated_height;

#[path = "taira_dataspace_deploy_authority_replay.rs"]
mod authority_replay;
pub(super) use authority_replay::OriginalCompletion;

const MAX_NEW_PROOFS: usize = 128;
const VERIFICATION_PEERS: usize = 4;

/// Run one read-only job per selected validator and join every job before returning.
/// Results and errors follow the configured peer order, independently of scheduling.
fn read_four_peers<T: Sync, R: Send>(
    inputs: &[T],
    discriminant: u16,
    read: impl Fn(usize, &T) -> Result<R> + Sync,
) -> Result<Vec<R>> {
    require(
        inputs.len() == VERIFICATION_PEERS,
        "verification requires exactly four peer read jobs",
    )?;
    std::thread::scope(|scope| {
        let read = &read;
        let handles = inputs
            .iter()
            .enumerate()
            .map(|(index, input)| {
                std::thread::Builder::new()
                    .name(format!("dpn-finality-peer-{index}"))
                    .spawn_scoped(scope, move || {
                        // Account JSON codecs use a thread-local profile, not inherited state.
                        let _profile =
                            iroha_data_model::account::address::ChainDiscriminantGuard::enter(
                                discriminant,
                            );
                        read(index, input)
                    })
            })
            .collect::<Vec<_>>();
        // Collect all joined results first: short-circuiting here could abandon a panicked
        // scoped worker and lose the deterministic first peer error.
        let results = handles
            .into_iter()
            .enumerate()
            .map(|(index, handle)| {
                let result = match handle {
                    Ok(handle) => handle
                        .join()
                        .unwrap_or_else(|_| Err(eyre!("validator read worker panicked"))),
                    Err(error) => Err(error.into()),
                };
                result.wrap_err_with(|| format!("validator {} verification failed", index + 1))
            })
            .collect::<Vec<_>>();
        results.into_iter().collect()
    })
}

/// Select read transport independently of the immutable validator authority and signed plan.
pub(super) fn verification_origins(trust: &TrustV1, overrides: &[String]) -> Result<Vec<String>> {
    require(
        overrides.is_empty() || overrides.len() == VERIFICATION_PEERS,
        "verification routes require exactly four URLs in trusted peer order",
    )?;
    let origins = if overrides.is_empty() {
        trust
            .peers
            .iter()
            .map(|peer| peer.torii_origin.clone())
            .collect()
    } else {
        overrides.to_vec()
    };
    require(
        origins.len() == VERIFICATION_PEERS,
        "verification requires four peer routes",
    )?;
    let mut unique = BTreeSet::new();
    for origin in &origins {
        let url: url::Url = origin.parse()?;
        require(
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.as_str() == origin
                && unique.insert(origin.clone()),
            "verification requires four distinct canonical credential-free peer URLs",
        )?;
    }
    Ok(origins)
}

fn peer_clients<C: RunContext>(
    context: &C,
    trust: &TrustV1,
    overrides: &[String],
) -> Result<Vec<Client>> {
    require(
        context.config().chain == trust.chain
            && context.config().account_chain_discriminant == trust.account_chain_discriminant,
        "runtime chain identity differs from the selected public trust profile",
    )?;
    verification_origins(trust, overrides)?
        .iter()
        .map(|origin| {
            let mut config = context.config().clone();
            config.torii_api_url = origin.parse()?;
            let mut builder = Client::builder(config);
            builder.operator_key_pair = context.operator_key_pair().cloned();
            builder.build().map_err(Into::into)
        })
        .collect()
}

/// Public target profile selected independently of the server's proof responses.
#[derive(Debug, Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(crate) struct TrustV1 {
    /// Explicit network-operator pin; chain IDs are not encoded in signed genesis.
    pub(crate) chain: iroha_model_base::chain::ChainId,
    /// Explicit address-format pin selected with the network profile.
    pub(crate) account_chain_discriminant: u16,
    pub(crate) genesis_public_key: PublicKey,
    pub(crate) genesis_signed_wire_hex: String,
    pub(crate) peers: Vec<PeerV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(crate) struct PeerV1 {
    pub(crate) torii_origin: String,
    pub(crate) peer_id: PeerId,
    pub(crate) node_fingerprint: Hash,
    pub(crate) build_fingerprint: Hash,
    pub(crate) config_fingerprint: Hash,
}

struct Authority {
    chain: iroha_model_base::chain::ChainId,
    network: NetworkId,
    genesis: HashOf<BlockHeader>,
    trusted_genesis: iroha_data_model::block::SignedBlock,
    validators: Vec<FinalityValidator>,
}

impl TrustV1 {
    pub(super) fn validate(&self, network: NetworkId) -> Result<()> {
        self.authority(network).map(|_| ())
    }

    fn authority(&self, network: NetworkId) -> Result<Authority> {
        require(
            self.account_chain_discriminant != 0,
            "public trust profile account_chain_discriminant must be nonzero",
        )?;
        require(
            self.genesis_signed_wire_hex.len() <= MAX_BYTES,
            "public genesis exceeds the deployment profile bound",
        )?;
        let wire = hex::decode(&self.genesis_signed_wire_hex)?;
        require(
            hex::encode(&wire) == self.genesis_signed_wire_hex,
            "public genesis wire must use canonical lowercase hexadecimal",
        )?;
        let (hash, metadata) =
            iroha_core::release_identity::genesis_identity(&wire, &self.genesis_public_key)?;
        let genesis = HashOf::<BlockHeader>::from_untyped_unchecked(hash);
        require(
            NetworkId::from_genesis_hash(genesis) == network
                && metadata.mode
                    == iroha_data_model::parameter::system::SumeragiConsensusMode::Npos,
            "public signed genesis differs from the independently selected network",
        )?;
        let block = iroha_genesis::decode_signed_genesis(&wire)?;
        let validators = iroha_genesis::signed_genesis_validator_pops(&block)?;
        require(
            validators.len() == 4 && self.peers.len() == 4,
            "dataspace deployment verification currently requires exactly four genesis validators",
        )?;
        let validators: BTreeMap<_, _> = validators
            .into_iter()
            .map(|(key, pop)| (PeerId::new(key), pop))
            .collect();
        validate_peer_selection(&self.peers, &validators)?;
        Ok(Authority {
            chain: self.chain.clone(),
            network,
            genesis,
            trusted_genesis: block,
            validators: validators
                .into_iter()
                .map(|(peer, proof_of_possession)| FinalityValidator {
                    public_key: peer.public_key().clone(),
                    proof_of_possession,
                })
                .collect(),
        })
    }
}

fn validate_peer_selection(
    selected: &[PeerV1],
    validators: &BTreeMap<PeerId, Vec<u8>>,
) -> Result<()> {
    require(
        selected.len() == VERIFICATION_PEERS && validators.len() == VERIFICATION_PEERS,
        "verification requires exactly four authenticated genesis peers",
    )?;
    let mut peers = BTreeSet::new();
    for peer in selected {
        let origin: url::Url = peer.torii_origin.parse()?;
        require(
            matches!(origin.scheme(), "http" | "https")
                && origin.host_str().is_some()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.as_str() == peer.torii_origin,
            "validator endpoint must be a canonical credential-free Torii URL",
        )?;
        require(
            peers.insert(peer.peer_id.clone())
                && validators.contains_key(&peer.peer_id)
                && Hash::new(peer.peer_id.encode()) == peer.node_fingerprint,
            "validator profile must bind four distinct genesis peers and their selected endpoints",
        )?;
    }
    Ok(())
}

impl Authority {
    fn roster(&self, proof: &SumeragiFinalityProof) -> Result<()> {
        require(
            proof.committee == self.validators,
            "proof differs from the independently authenticated four-validator genesis roster",
        )
    }

    fn verifier(&self) -> Result<SumeragiFinalityVerifier> {
        Ok(SumeragiFinalityVerifier::new(
            &self.trusted_genesis,
            self.chain.as_str(),
            self.validators.clone(),
        )?)
    }

    fn anchor(&self, proof: &SumeragiFinalityProof) -> Result<SumeragiFinalityVerifier> {
        require(
            proof.block_header.height().get() == 1 && proof.block_header.hash() == self.genesis,
            "finality anchor differs from the selected signed genesis",
        )?;
        self.roster(proof)?;
        let mut verifier = self.verifier()?;
        verifier.verify(proof)?;
        Ok(verifier)
    }
}

fn validate_attestation(
    authority: &Authority,
    peer: &PeerV1,
    challenge: [u8; 32],
    attestation: &SumeragiFinalityAttestation,
) -> Result<()> {
    attestation.verify()?;
    let body = &attestation.body;
    require(
        body.challenge == challenge
            && body.node_id == peer.peer_id
            && body.node_fingerprint == peer.node_fingerprint
            && body.build_fingerprint == peer.build_fingerprint
            && body.config_fingerprint == peer.config_fingerprint
            && body.network_id == authority.network
            && body.genesis_block_hash == authority.genesis,
        "attested node, build, configuration, challenge or genesis differs from the target profile",
    )?;
    let verifier = authority.anchor(&body.genesis_finality_proof)?;
    require(
        body.status.instance == verifier.instance().0,
        "attested consensus instance differs from selected genesis and chain",
    )?;
    authority.roster(&body.finality_proof)
}

const PREFLIGHT_DIRECTORY: &str = "preflight-finality";

/// Chain evidence binds the owner definition and selected trust, excluding only the fee cap.
/// The cache never authorizes spending; the exact current definition and plan do that.
#[derive(Debug, Clone, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PreflightBinding {
    purpose: String,
    definition_sha256: String,
    network_id: NetworkId,
    trust_sha256: String,
}

impl PreflightBinding {
    fn expected(parent: &Journal) -> Result<Self> {
        let (definition_sha256, network_id, trust_sha256) = definition::preflight_identity(parent)?;
        Ok(Self {
            purpose: "iroha.dataspace-preflight-finality.v1".into(),
            definition_sha256,
            network_id,
            trust_sha256,
        })
    }
}

fn proof_file_height(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("proof-")?.strip_suffix(".json")?;
    if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().filter(|height| *height > 0)
}

fn preflight_staging_name(name: &str) -> bool {
    let Some((name, suffix)) = name
        .strip_prefix(".staging-")
        .and_then(|name| name.rsplit_once('-'))
    else {
        return false;
    };
    (name == "binding.json" || proof_file_height(name).is_some())
        && suffix.len() == 32
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The child never admits signatures, dispatch claims, plans or completion evidence.
#[cfg(unix)]
fn validate_preflight_contents(child: &Journal, expected: &PreflightBinding) -> Result<bool> {
    child.revalidate()?;
    let binding = child.optional_json::<PreflightBinding>("binding.json")?;
    if let Some(binding) = &binding {
        require(
            binding == expected,
            "preflight proof cache belongs to another definition or trust",
        )?;
    }
    let mut heights = BTreeSet::new();
    for entry in fs::read_dir(&child.path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| eyre!("invalid preflight proof filename"))?;
        private_metadata(&fs::symlink_metadata(entry.path())?, false)?;
        if let Some(height) = proof_file_height(name) {
            require(
                binding.is_some(),
                "preflight proofs lost their retained definition/trust binding",
            )?;
            heights.insert(height);
        } else {
            require(
                name == "lock" || name == "binding.json" || preflight_staging_name(name),
                "preflight proof cache contains evidence outside its read-only purpose",
            )?;
        }
    }
    for (index, height) in heights.into_iter().enumerate() {
        require(
            height
                == u64::try_from(index)?
                    .checked_add(1)
                    .ok_or_else(|| eyre!("proof height overflow"))?,
            "preflight proof cache has a missing or reordered height",
        )?;
    }
    child.revalidate()?;
    Ok(binding.is_some())
}

#[cfg(not(unix))]
fn validate_preflight_contents(_: &Journal, _: &PreflightBinding) -> Result<bool> {
    eyre::bail!("durable preflight proofs require Unix filesystem custody")
}

#[cfg(unix)]
fn open_preflight_child(parent: &Journal, create: bool) -> Result<Journal> {
    parent.revalidate()?;
    let path = parent.path.join(PREFLIGHT_DIRECTORY);
    let child = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            private_metadata(&metadata, true)?;
            if fs::read_dir(&path)?.next().is_none() {
                // A crash can leave mkdir durable before the first lock is created.
                // Only a truly empty child has no lock or proof custody to lose.
                // open_unpublished independently rejects evidence before a new lock.
                Journal::open_unpublished(&path)?
            } else {
                Journal::open(&path, false)?
            }
        }
        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
            Journal::open(&path, true)?
        }
        Err(error) => return Err(error.into()),
    };
    parent.revalidate()?;
    Ok(child)
}

#[cfg(not(unix))]
fn open_preflight_child(_: &Journal, _: bool) -> Result<Journal> {
    eyre::bail!("durable preflight proofs require Unix filesystem custody")
}

/// Used only while validating an otherwise unsigned outer journal.
pub(super) fn validate_preflight_cache(parent: &Journal) -> Result<()> {
    parent.revalidate()?;
    let expected = PreflightBinding::expected(parent)?;
    let child = open_preflight_child(parent, false)?;
    validate_preflight_contents(&child, &expected)?;
    parent.revalidate()
}

/// Invocation-owned verified prefix; disk proofs are reauthenticated on a new invocation.
/// The child journal is opened only while reading proofs, under the held operation lock.
pub(super) struct Preflight<'a> {
    parent: &'a Journal,
    binding: PreflightBinding,
    trust: TrustV1,
    authority: Authority,
    prefix: ProofPrefix,
    deadline: Instant,
}

impl<'a> Preflight<'a> {
    pub(super) fn new(
        parent: &'a Journal,
        trust: &TrustV1,
        network: NetworkId,
        deadline: Instant,
    ) -> Result<Self> {
        require_operation_budget(deadline, "opening preflight proof cache")?;
        parent.revalidate()?;
        let binding = PreflightBinding::expected(parent)?;
        require(
            binding.network_id == network && binding.trust_sha256 == digest(&json::to_vec(trust)?),
            "preflight trust differs from the retained dataspace definition",
        )?;
        let child = open_preflight_child(parent, true)?;
        if !validate_preflight_contents(&child, &binding)? {
            child.install_json("binding.json", &binding)?;
        }
        let authority = trust.authority(network)?;
        parent.revalidate()?;
        require_operation_budget(deadline, "opened preflight proof cache")?;
        Ok(Self {
            parent,
            binding,
            trust: trust.clone(),
            authority,
            prefix: ProofPrefix::default(),
            deadline,
        })
    }

    fn revalidate(&self, child: &Journal) -> Result<()> {
        self.parent.revalidate()?;
        require(
            PreflightBinding::expected(self.parent)? == self.binding,
            "dataspace definition changed while synchronizing preflight proofs",
        )?;
        require(
            validate_preflight_contents(child, &self.binding)?,
            "preflight proof cache lost its definition/trust binding",
        )
    }

    /// Complete bounded proof batches automatically while this invocation has time.
    fn synchronize_until(
        &mut self,
        child: &Journal,
        tip: &SumeragiFinalityProof,
        genesis: &SumeragiFinalityProof,
        batch_size: usize,
        mut fetch: impl FnMut(
            NonZeroU64,
            &mut SumeragiFinalityVerifier,
        ) -> Result<SumeragiFinalityProof>,
    ) -> Result<()> {
        let result: Result<()> = (|| {
            loop {
                self.revalidate(child)?;
                let complete = self.prefix.synchronize(
                    &self.authority,
                    child,
                    tip,
                    genesis,
                    self.deadline,
                    batch_size,
                    &mut fetch,
                )?;
                self.revalidate(child)?;
                if complete {
                    return Ok(());
                }
                eprintln!(
                    "[dataspace] preflight finality: verified {}/{}; continuing",
                    self.prefix.proofs.len(),
                    tip.block_header.height().get(),
                );
            }
        })();
        result.wrap_err_with(|| format!(
            "preflight finality synchronization stopped after retaining {} authenticated heights toward {}; rerun the same command with the same definition, trust and state to resume",
            self.prefix.proofs.len(), tip.block_header.height().get(),
        ))
    }

    /// Prove public verification routes, exact peer identities and live key eligibility.
    pub(super) fn verify<C: RunContext>(&mut self, context: &C) -> Result<()> {
        let child = Journal::open(&self.parent.path.join(PREFLIGHT_DIRECTORY), false)?;
        self.revalidate(&child)?;
        let challenge: [u8; 32] = rand::random();
        require(challenge != [0; 32], "random finality challenge is zero")?;
        let clients = peer_clients(context, &self.trust, &[])?
            .into_iter()
            .map(|client| client.with_request_deadline(self.deadline))
            .collect::<Vec<_>>();
        let discriminant = context.config().account_chain_discriminant;
        let tips = read_four_peers(&clients, discriminant, |index, client| {
            require_operation_budget(self.deadline, "reading preflight finality tip")?;
            let peer = &self.trust.peers[index];
            let height = NonZeroU64::new(client.get_sumeragi_status()?.committed_height)
                .ok_or_else(|| eyre!("validator has no durable tip"))?;
            let attestation = client
                .get_sumeragi_finality_attestation(height, challenge, &peer.peer_id)?
                .into_attestation();
            validate_attestation(&self.authority, peer, challenge, &attestation)?;
            Ok(attestation)
        })?;
        let (source_index, source_tip) = tips
            .iter()
            .enumerate()
            .max_by_key(|(_, tip)| tip.body.finality_proof.block_header.height())
            .ok_or_else(|| eyre!("missing preflight validator tips"))?;
        self.synchronize_until(
            &child,
            &source_tip.body.finality_proof,
            &source_tip.body.genesis_finality_proof,
            MAX_NEW_PROOFS,
            |height, trial| {
                clients[source_index]
                    .get_next_sumeragi_finality_proof(height, trial)
                    .map_err(Into::into)
            },
        )?;
        let verifier = self
            .prefix
            .verifier
            .as_ref()
            .ok_or_else(|| eyre!("missing preflight verifier"))?;
        read_four_peers(&clients, discriminant, |index, client| {
            require_operation_budget(self.deadline, "verifying preflight peer state")?;
            let attestation = &tips[index];
            let height = attestation.body.finality_proof.block_header.height().get();
            let genesis = self
                .prefix
                .proofs
                .get(&1)
                .ok_or_else(|| eyre!("missing preflight genesis"))?;
            let tip = self
                .prefix
                .proofs
                .get(&height)
                .ok_or_else(|| eyre!("peer tip absent from verified preflight prefix"))?;
            verifier.verify_same_decision(genesis, &attestation.body.genesis_finality_proof)?;
            verifier.verify_same_decision(tip, &attestation.body.finality_proof)?;
            read_committee_snapshot(client, &self.authority, height)?;
            client.get_lane_lifecycle_status()?.validate()?;
            require_operation_budget(self.deadline, "completed preflight finality")
        })?;
        self.revalidate(&child)
    }
}

/// Check the exact Committee role at both heights the runtime transition will require.
/// These operator observations can reject an ineligible parent before signing; the
/// executor still authenticates eligibility at the actual committed transition height.
fn validate_committee_snapshot(
    authority: &Authority,
    records: &[iroha_data_model::consensus::ConsensusKeyRecord],
    tip_height: u64,
) -> Result<()> {
    use iroha_data_model::consensus::ConsensusKeyRole;
    require(
        tip_height > 0,
        "committee preflight requires a durable parent tip",
    )?;
    let manifest_activation = tip_height
        .checked_add(2)
        .ok_or_else(|| eyre!("committee manifest activation height overflow"))?;
    let native_activation = tip_height
        .checked_add(3)
        .ok_or_else(|| eyre!("native committee activation height overflow"))?;
    for validator in &authority.validators {
        for height in [manifest_activation, native_activation] {
            let eligible = records.iter().any(|record| {
                record.id.role == ConsensusKeyRole::Committee
                    && record.public_key == validator.public_key
                    && record.is_live_at(height, 0, 0)
                    && record.pop.as_deref() == Some(validator.proof_of_possession.as_slice())
                    && iroha_crypto::bls_normal_pop_verify(
                        &record.public_key,
                        record.pop.as_deref().unwrap_or_default(),
                    )
                    .is_ok()
            });
            require(
                eligible,
                &format!(
                    "selected parent validator {} has no matching live Committee key and genesis PoP in the bounded operator snapshot at height {height}; the parent operator must register or activate its Committee credential before deployment (a Validator key alone is insufficient; older records may be outside the snapshot)",
                    validator.public_key
                ),
            )?;
        }
    }
    Ok(())
}

fn observe_committee_snapshot(
    authority: &Authority,
    authenticated_lower_bound: u64,
    mut tip: impl FnMut() -> Result<u64>,
    mut keys: impl FnMut() -> Result<Vec<iroha_data_model::consensus::ConsensusKeyRecord>>,
) -> Result<()> {
    let mut lower_bound = authenticated_lower_bound.max(1);
    // Each request inherits the operation deadline. Only observed head movement
    // permits another attempt; credential, transport and decoding errors stay final.
    for _ in 0..3 {
        let before = tip()?;
        require(
            before >= lower_bound,
            "parent tip regressed behind authenticated Committee preflight evidence",
        )?;
        let records = keys()?;
        let after = tip()?;
        require(
            after >= before,
            "parent tip regressed during Committee credential preflight",
        )?;
        if after == before {
            return validate_committee_snapshot(authority, &records, after);
        }
        lower_bound = after;
    }
    eyre::bail!(
        "parent tip kept advancing during Committee credential preflight; retry before signing"
    )
}

fn read_committee_snapshot(
    client: &Client,
    authority: &Authority,
    minimum_height: u64,
) -> Result<()> {
    observe_committee_snapshot(
        authority,
        minimum_height,
        || Ok(client.get_sumeragi_status()?.committed_height),
        || client.get_sumeragi_consensus_keys(),
    )
}

/// Recheck the primary endpoint immediately before preparing the unsigned catalog phase.
pub(super) fn committee_preflight(client: &Client, manifest: &ManifestV1) -> Result<()> {
    let authority = manifest.finality.authority(manifest.network_id)?;
    read_committee_snapshot(client, &authority, 1)
}

#[derive(JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PeerReceipt {
    peer_id: PeerId,
    height: u64,
    block_hash: HashOf<BlockHeader>,
    attestation: SumeragiFinalityAttestation,
    transactions: Vec<PhaseObservationV1>,
    carriers: Vec<CarrierReceipt>,
    native_lane: iroha_data_model::sumeragi_lanes::SumeragiLaneStatus,
}

#[derive(JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct CarrierReceipt {
    height: u64,
    file: String,
    wire_sha256: String,
}

#[derive(JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct CompletionV1 {
    schema_version: u8,
    operation_id: String,
    intent_sha256: String,
    network_id: NetworkId,
    challenge: [u8; 32],
    peers: Vec<PeerReceipt>,
    verification_origins: Vec<String>,
}

fn verify_native_lane(
    plan: &PlanV1,
    client: &Client,
    peer: &PeerId,
    catalog_height: u64,
    verified_height: u64,
) -> Result<PeerRead<iroha_data_model::sumeragi_lanes::SumeragiLaneStatus>> {
    use iroha_data_model::sumeragi_lanes::SumeragiLanePolicy;
    let parameters = client.get_parameters()?;
    let policy = parameters
        .custom
        .get(&SumeragiLanePolicy::parameter_id())
        .and_then(SumeragiLanePolicy::from_custom_parameter)
        .ok_or_else(|| eyre!("deployed dataspace has no native lane policy"))?
        .map_err(|error| eyre!(error))?;
    let lanes = client.get_sumeragi_lanes()?;
    verify_native_lane_snapshot(
        &plan.manifest,
        &policy,
        lanes,
        peer,
        catalog_height,
        verified_height,
    )
}

fn verify_native_lane_snapshot(
    manifest: &ManifestV1,
    policy: &iroha_data_model::sumeragi_lanes::SumeragiLanePolicy,
    lanes: Vec<iroha_data_model::sumeragi_lanes::SumeragiLaneStatus>,
    peer: &PeerId,
    catalog_height: u64,
    verified_height: u64,
) -> Result<PeerRead<iroha_data_model::sumeragi_lanes::SumeragiLaneStatus>> {
    use iroha_data_model::sumeragi_lanes::SumeragiLaneMember;
    policy.validate()?;
    let genesis = iroha_genesis::decode_signed_genesis(&hex::decode(
        &manifest.finality.genesis_signed_wire_hex,
    )?)?;
    let committee: Vec<_> = iroha_genesis::signed_genesis_validator_pops(&genesis)?
        .into_iter()
        .map(|(key, pop)| SumeragiLaneMember {
            peer: PeerId::new(key),
            pop,
        })
        .collect();
    let fixed = policy
        .fixed_lane(manifest.lane.id)
        .ok_or_else(|| eyre!("deployed dataspace is absent from native fixed lanes"))?;
    require(
        fixed.dataspace == manifest.lane.dataspace_id && fixed.committee == committee,
        "native lane policy changed the dataspace or selected validator committee",
    )?;
    let mut matches = lanes
        .into_iter()
        .filter(|lane| lane.record.lane == manifest.lane.id);
    let Some(lane) = matches.next() else {
        return Ok(PeerRead::Pending);
    };
    require(
        matches.next().is_none(),
        "native lane status repeats the deployment lane",
    )?;
    let record = &lane.record;
    require(
        record.dataspace == manifest.lane.dataspace_id
            && record.committee == committee
            && record.created_at == catalog_height
            && record.active_from
                == catalog_height
                    .checked_add(2)
                    .ok_or_else(|| eyre!("activation height overflow"))?
            && record.closing.is_none()
            && record.incarnation != [0; 32]
            && record.anchor_freshness != 0,
        "native dataspace lane is closed or differs from its committed activation",
    )?;
    // Each incarnation pins its own parameters. Later governance changes the policy
    // for future lanes, and must not invalidate a still-running existing incarnation.
    iroha_core::sumeragi::lanes::lane_height_config(record)
        .map_err(|error| eyre!("invalid committed dataspace lane parameters: {error}"))?;
    if !record.admits_anchor(verified_height) || lane.instance.is_none() {
        return Ok(PeerRead::Pending);
    }
    let expected_instance = iroha_core::sumeragi::lanes::lane_instance(
        &iroha_core::sumeragi::crypto::BlsCrypto::new(),
        &manifest.network_id,
        &manifest.finality.chain.to_string(),
        record,
    );
    require(
        lane.instance
            .as_ref()
            .is_some_and(|status| status.instance == expected_instance.0),
        "validator is running another dataspace lane instance",
    )?;
    require(
        lane.instance.as_ref().is_some_and(|status| {
            !status.is_halted()
                && status.is_signing()
                && status.signer.as_ref() == Some(peer.public_key())
        }),
        "dataspace lane instance is halted or not signing as its selected validator",
    )?;
    Ok(PeerRead::Verified(lane))
}

fn namespace_matches(plan: &PlanV1, client: &Client) -> Result<()> {
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    for ensure in &plan.manifest.alias_request.intents {
        let (namespace, name) = match &ensure.intent {
            AliasIntentV1::Dataspace(value) => (
                SnsNamespacePath::Dataspace,
                value.dataspace.canonical_text(),
            ),
            AliasIntentV1::AccountAlias(value) => {
                (SnsNamespacePath::AccountAlias, value.alias.canonical_text())
            }
            _ => eyre::bail!("unexpected namespace intent"),
        };
        let record = client
            .sns()
            .get_name_optional(namespace, &name)?
            .ok_or_else(|| eyre!("paid namespace record is absent"))?;
        require(
            record.name_hash == record.selector.name_hash()
                && record.owner == plan.manifest.owner
                && record.status == NameStatus::Active
                && record.expires_at_ms > now
                && record.ownership_generation == 1,
            "paid namespace is missing, expired, transferred or owned by another account",
        )?;
        if let AliasIntentV1::Dataspace(_) = &ensure.intent {
            let mapped = if let Some(value) = record
                .metadata
                .get(iroha_core::sns::SNS_DATASPACE_ID_METADATA_KEY)
            {
                iroha_model_base::topology::DataSpaceId::new(json::from_str::<u64>(value.get())?)
            } else {
                iroha_model_base::topology::DataSpaceId::from_hash(&record.name_hash)
            };
            require(
                mapped == plan.manifest.dataspace.descriptor.id,
                "paid namespace maps to another physical dataspace",
            )?;
        }
        if let AliasIntentV1::AccountAlias(intent) = &ensure.intent {
            let resolved = client
                .resolve_account_alias_authenticated(&intent.alias.canonical_name)?
                .ok_or_else(|| eyre!("committed account alias does not resolve"))?;
            require(
                resolved.account_id() == &intent.target_account
                    && resolved.alias() == &intent.alias.canonical_name,
                "account alias resolves to another canonical account",
            )?;
            let selector = iroha::client::AccountAliasesByAccountRequestV1::try_new(
                &intent.target_account,
                Some(intent.alias.canonical_name.dataspace.as_ref()),
                None,
            )?;
            let aliases = client
                .list_account_aliases_authenticated(&selector)?
                .ok_or_else(|| eyre!("committed account alias index is absent"))?;
            let expected_primary =
                intent.role == iroha_data_model::alias_setup::AccountAliasRoleV1::Primary;
            require(
                aliases.items().iter().any(|row| {
                    row.alias() == &intent.alias.canonical_name
                        && row.is_primary() == expected_primary
                }),
                "account alias primary role differs from intent",
            )?;
        }
    }
    Ok(())
}

struct VerifiedPeer {
    receipt: PeerReceipt,
    // At most one bounded canonical wire per retained phase height.
    wires: BTreeMap<u64, Vec<u8>>,
}

/// Compare all freshly authenticated carrier bytes before the coordinator publishes any.
fn consistent_carriers<'a>(
    peers: impl IntoIterator<Item = &'a BTreeMap<u64, Vec<u8>>>,
) -> Result<BTreeMap<u64, &'a [u8]>> {
    let mut carriers = BTreeMap::new();
    for peer in peers {
        for (&height, wire) in peer {
            if let Some(existing) = carriers.insert(height, wire.as_slice()) {
                require(
                    existing == wire,
                    "validators returned different canonical carrier bytes",
                )?;
            }
        }
    }
    Ok(carriers)
}

/// A successful read may prove that a peer needs a fresh snapshot; this is not an error.
/// Keeping progress outside `Err` prevents it from hiding a fixed failure on another peer.
enum PeerRead<T> {
    Verified(T),
    Pending,
}

/// Only the SDK's exact request-bound tip mismatch admits a fresh snapshot.
/// Classify inside each worker so a pending peer cannot hide another peer's error.
fn peer_attestation_progress<T>(read: Result<T>) -> Result<PeerRead<T>> {
    match read {
        Ok(value) => Ok(PeerRead::Verified(value)),
        Err(error) => {
            if let Some(progress) =
                error.downcast_ref::<iroha::client::BridgeFinalityAttestationTipMismatch>()
            {
                eprintln!(
                    "dataspace deploy: validator {} finality pending: {progress}",
                    progress.response().node_id
                );
                Ok(PeerRead::Pending)
            } else {
                Err(error)
            }
        }
    }
}

fn peer_carrier_progress(
    state: &str,
    hash: &str,
    global: &Option<PipelineTransactionStatusResponse>,
    peer: &Option<PipelineTransactionStatusResponse>,
    captured_tip: u64,
) -> Result<PeerRead<u64>> {
    // Validate both supplied responses before interpreting absence or a pending state.
    let carrier = matching_applied_height(hash, global, peer)?;
    match state {
        "pending" => {
            require(
                carrier.is_none(),
                "pending observation already has an Applied carrier",
            )?;
            Ok(PeerRead::Pending)
        }
        "applied_verification_pending" => {
            let carrier = carrier.ok_or_else(|| eyre!("missing exact carrier height"))?;
            if carrier > captured_tip {
                Ok(PeerRead::Pending)
            } else {
                Ok(PeerRead::Verified(carrier))
            }
        }
        _ => Err(eyre!(
            "one validator has not applied the exact retained deployment transaction"
        )),
    }
}

struct PeerVerification<'a> {
    authority: &'a Authority,
    plan: &'a PlanV1,
    prepared: &'a [(PreparedV1, SignedTransaction)],
    proofs: &'a BTreeMap<u64, SumeragiFinalityProof>,
    verifier: &'a SumeragiFinalityVerifier,
    challenge: [u8; 32],
    deadline: std::time::Instant,
}

fn verify_peer_state(
    client: &Client,
    peer: &PeerV1,
    before: &SumeragiFinalityAttestation,
    verification: &PeerVerification<'_>,
) -> Result<PeerRead<Box<VerifiedPeer>>> {
    let &PeerVerification {
        authority,
        plan,
        prepared,
        proofs,
        verifier,
        challenge,
        deadline,
    } = verification;
    require_operation_budget(deadline, "verifying validator state")?;
    let genesis = proofs
        .get(&1)
        .ok_or_else(|| eyre!("missing authenticated deployment genesis proof"))?;
    verifier
        .verify_same_decision(genesis, &before.body.genesis_finality_proof)
        .wrap_err("peer genesis differs from the independently verified successor chain")?;
    let height = before.body.finality_proof.block_header.height();
    let retained = proofs
        .get(&height.get())
        .ok_or_else(|| eyre!("peer durable tip is absent from the verified successor chain"))?;
    verifier
        .verify_same_decision(retained, &before.body.finality_proof)
        .wrap_err("peer durable tip differs from the independently verified successor chain")?;
    let mut transactions = Vec::new();
    let mut carriers = Vec::new();
    let mut wires = BTreeMap::new();
    for (prepared, transaction) in prepared {
        require_operation_budget(deadline, "verifying retained transaction carrier")?;
        let observed = observe(client, prepared, transaction)?;
        let carrier_height = match peer_carrier_progress(
            &observed.state,
            &prepared.transaction_hash,
            &observed.global_status,
            &observed.peer_status,
            height.get(),
        )? {
            PeerRead::Verified(height) => height,
            PeerRead::Pending => {
                require_operation_budget(deadline, "validator deployment state is pending")?;
                return Ok(PeerRead::Pending);
            }
        };
        let proof = proofs
            .get(&carrier_height)
            .ok_or_else(|| eyre!("transaction carrier is ahead of the verified peer tip"))?;
        let committed = &observed
            .committed
            .as_ref()
            .ok_or_else(|| eyre!("missing committed transaction"))?
            .transaction;
        require(
            committed.block_hash() == &proof.block_header.hash(),
            "transaction carrier differs from authenticated finality",
        )?;
        let certified = verifier.verify_same_decision(proof, proof)?;
        certified.verify_committed_transaction(&authority.network, committed)?;
        let wire = certified.canonical_executed_wire()?;
        carriers.push(CarrierReceipt {
            height: carrier_height,
            file: format!("carrier-{carrier_height:020}.nrt"),
            wire_sha256: digest(&wire),
        });
        if let Some(existing) = wires.get(&carrier_height) {
            require(
                existing == &wire,
                "verified phases returned different canonical carrier bytes",
            )?;
        } else {
            wires.insert(carrier_height, wire);
        }
        require_operation_budget(deadline, "verified retained transaction carrier")?;
        transactions.push(observed);
    }
    physical_matches(plan, client)?;
    let catalog_height = transactions
        .iter()
        .find(|observation| observation.phase == "catalog")
        .and_then(|observation| observation.global_status.as_ref())
        .and_then(|status| status.status.block_height)
        .ok_or_else(|| eyre!("catalog transaction has no authenticated applied height"))?;
    let native_lane =
        match verify_native_lane(plan, client, &peer.peer_id, catalog_height, height.get())? {
            PeerRead::Verified(lane) => lane,
            PeerRead::Pending => return Ok(PeerRead::Pending),
        };
    require(
        bootstrap_present(plan, client)?,
        "one validator omits the exact bootstrap grant",
    )?;
    namespace_matches(plan, client)?;
    let after = match peer_attestation_progress(client.get_sumeragi_finality_attestation(
        height,
        challenge,
        &peer.peer_id,
    ))? {
        PeerRead::Verified(attestation) => attestation.into_attestation(),
        PeerRead::Pending => {
            require_operation_budget(deadline, "validator finality tip is changing")?;
            return Ok(PeerRead::Pending);
        }
    };
    validate_attestation(authority, peer, challenge, &after)?;
    verifier
        .verify_same_decision(genesis, &after.body.genesis_finality_proof)
        .wrap_err("validator genesis changed while reading deployment state")?;
    verifier
        .verify_same_decision(retained, &after.body.finality_proof)
        .wrap_err("validator tip changed while reading deployment state; rerun status")?;
    require_operation_budget(deadline, "verified validator state")?;
    Ok(PeerRead::Verified(Box::new(VerifiedPeer {
        receipt: PeerReceipt {
            peer_id: peer.peer_id.clone(),
            height: height.get(),
            block_hash: after.body.finality_proof.block_header.hash(),
            attestation: after,
            transactions,
            carriers,
            native_lane,
        },
        wires,
    })))
}

#[derive(Default)]
struct ProofPrefix {
    proofs: BTreeMap<u64, SumeragiFinalityProof>,
    verifier: Option<SumeragiFinalityVerifier>,
    #[cfg(test)]
    authenticated_rows: usize,
}

impl ProofPrefix {
    /// Recheck immutable disk custody, then authenticate and durably publish only
    /// previously unseen contiguous successors. Lower tips never rewind this owner.
    #[allow(clippy::too_many_arguments)]
    fn synchronize(
        &mut self,
        authority: &Authority,
        journal: &Journal,
        source_tip: &SumeragiFinalityProof,
        source_genesis: &SumeragiFinalityProof,
        deadline: std::time::Instant,
        new_proof_budget: usize,
        mut fetch: impl FnMut(
            NonZeroU64,
            &mut SumeragiFinalityVerifier,
        ) -> Result<SumeragiFinalityProof>,
    ) -> Result<bool> {
        require(
            (1..=MAX_NEW_PROOFS).contains(&new_proof_budget),
            "finality proof batch budget must remain within the native bound",
        )?;
        let mut new_proofs = 0_usize;
        for next in 1..=source_tip.block_header.height().get() {
            require_operation_budget(deadline, "synchronizing authenticated finality proofs")?;
            let name = format!("proof-{next:020}.json");
            let cached: Option<SumeragiFinalityProof> = journal.optional_json(&name)?;
            if let Some(retained) = self.proofs.get(&next) {
                // Re-read through Journal custody and canonical-JSON checks on every attempt.
                // Only exact immutable evidence may reuse this invocation's authentication.
                require(
                    cached.as_ref() == Some(retained),
                    "retained proof cache changed after authentication",
                )?;
                require_operation_budget(deadline, "revalidated authenticated proof custody")?;
                continue;
            }
            let fresh = cached.is_none();
            let mut verified_successor = None;
            let proof = if let Some(proof) = cached {
                proof
            } else {
                if new_proofs == new_proof_budget {
                    return Ok(false);
                }
                new_proofs += 1;
                if next == 1 {
                    source_genesis.clone()
                } else {
                    let mut trial = self
                        .verifier
                        .clone()
                        .ok_or_else(|| eyre!("missing genesis verifier"))?;
                    let proof = fetch(NonZeroU64::new(next).unwrap(), &mut trial)?;
                    verified_successor = Some(trial);
                    proof
                }
            };
            require(
                proof.block_header.height().get() == next,
                "retained proof cache has a missing or reordered height",
            )?;
            authority.roster(&proof)?;
            let advanced = if next == 1 {
                authority.anchor(&proof)?
            } else if let Some(advanced) = verified_successor {
                // The native reader already verified this exact successor. Admit its advanced
                // verifier only after the same requested-height and independent-roster checks.
                advanced
            } else {
                let mut trial = self
                    .verifier
                    .clone()
                    .ok_or_else(|| eyre!("missing genesis verifier"))?;
                trial.verify(&proof)?;
                trial
            };
            self.publish_verified(journal, proof, advanced, fresh, deadline)?;
        }
        require_operation_budget(deadline, "verified authenticated finality chain")?;
        Ok(true)
    }

    /// Commit an already authenticated trial only after durable publication and budget checks.
    fn publish_verified(
        &mut self,
        journal: &Journal,
        proof: SumeragiFinalityProof,
        advanced: SumeragiFinalityVerifier,
        fresh: bool,
        deadline: std::time::Instant,
    ) -> Result<()> {
        #[cfg(test)]
        {
            self.authenticated_rows += 1;
        }
        require_operation_budget(deadline, "verified authenticated finality proof")?;
        let height = proof.block_header.height().get();
        if fresh {
            journal.install_json(&format!("proof-{height:020}.json"), &proof)?;
        }
        require_operation_budget(deadline, "published authenticated finality proof")?;
        // Failed verification, publication or deadline checks never advance retained state.
        self.proofs.insert(height, proof);
        self.verifier = Some(advanced);
        Ok(())
    }
}

/// Invocation-owned finality prefix under one immutable plan and held Journal lock.
/// A fresh invocation starts empty and independently authenticates every disk proof.
pub(super) struct Completion<'a> {
    plan: &'a PlanV1,
    journal: &'a Journal,
    authority: Authority,
    prefix: ProofPrefix,
    deadline: std::time::Instant,
    verification_origins: Vec<String>,
    runtime_update: Option<&'a runtime_update::Verified>,
}

impl<'a> Completion<'a> {
    pub(super) fn new(
        plan: &'a PlanV1,
        journal: &'a Journal,
        deadline: std::time::Instant,
        origins: &[String],
        runtime_update: Option<&'a runtime_update::Verified>,
    ) -> Result<Self> {
        require_operation_budget(deadline, "starting finality verification")?;
        let authority = plan.manifest.finality.authority(plan.manifest.network_id)?;
        require_operation_budget(deadline, "authenticated deployment trust")?;
        journal.revalidate()?;
        Ok(Self {
            plan,
            journal,
            authority,
            prefix: ProofPrefix::default(),
            deadline,
            verification_origins: verification_origins(&plan.manifest.finality, origins)?,
            runtime_update,
        })
    }

    /// Read fresh peer state and challenge attestations on every attempt; only the
    /// unchanged contiguous proof prefix can reuse authentication within this invocation.
    pub(super) fn complete<C: RunContext>(
        &mut self,
        context: &C,
        report: &mut ReportV1,
    ) -> Result<()> {
        complete(context, self, report)
    }
}

/// Read-only finality synchronization and fresh observations from all four validators.
/// The caller alone advances the authenticated proof chain and publishes journal evidence.
fn complete<C: RunContext>(
    context: &C,
    completion: &mut Completion<'_>,
    report: &mut ReportV1,
) -> Result<()> {
    let plan = completion.plan;
    let journal = completion.journal;
    let authority = &completion.authority;
    let deadline = completion.deadline;
    require_operation_budget(deadline, "starting finality verification")?;
    require(
        report.verification.transactions.len() == PHASES.len()
            && report
                .verification
                .transactions
                .iter()
                .all(|phase| phase.state == "applied_verification_pending"),
        "completion requires all three retained phases to be applied",
    )?;
    if let Some(update) = completion.runtime_update {
        update.revalidate()?;
    }
    let trust = completion
        .runtime_update
        .map(|update| &update.trust)
        .unwrap_or(&plan.manifest.finality);
    let challenge: [u8; 32] = rand::random();
    require(challenge != [0; 32], "random finality challenge is zero")?;
    let clients = peer_clients(context, trust, &completion.verification_origins)?
        .into_iter()
        .map(|client| client.with_request_deadline(deadline))
        .collect::<Vec<_>>();
    let discriminant = context.config().account_chain_discriminant;
    let tips = read_four_peers(&clients, discriminant, |index, client| {
        require_operation_budget(deadline, "reading validator finality tip")?;
        let peer = &trust.peers[index];
        let height = NonZeroU64::new(client.get_sumeragi_status()?.committed_height)
            .ok_or_else(|| eyre!("validator has no durable tip"))?;
        let before = match peer_attestation_progress(client.get_sumeragi_finality_attestation(
            height,
            challenge,
            &peer.peer_id,
        ))? {
            PeerRead::Verified(attestation) => attestation.into_attestation(),
            PeerRead::Pending => {
                require_operation_budget(deadline, "validator finality tip is changing")?;
                return Ok(PeerRead::Pending);
            }
        };
        validate_attestation(authority, peer, challenge, &before)?;
        require_operation_budget(deadline, "verified validator finality tip")?;
        Ok(PeerRead::Verified(before))
    })?;
    require_operation_budget(deadline, "read validator finality tips")?;
    let Some(tips) = tips
        .into_iter()
        .map(|peer| match peer {
            PeerRead::Verified(value) => Some(value),
            PeerRead::Pending => None,
        })
        .collect::<Option<Vec<_>>>()
    else {
        report.state = "verification_peer_pending".into();
        return Ok(());
    };
    let (source_index, source_tip) = tips
        .iter()
        .enumerate()
        .max_by_key(|(_, tip)| tip.body.finality_proof.block_header.height())
        .ok_or_else(|| eyre!("missing validator tips"))?;
    let source = &clients[source_index];
    if !completion.prefix.synchronize(
        authority,
        journal,
        &source_tip.body.finality_proof,
        &source_tip.body.genesis_finality_proof,
        deadline,
        MAX_NEW_PROOFS,
        |height, trial| {
            source
                .get_next_sumeragi_finality_proof(height, trial)
                .map_err(Into::into)
        },
    )? {
        report.state = "verification_sync_pending".into();
        return Ok(());
    }
    if let Some(update) = completion.runtime_update {
        update.retained_tip_claims()?.verify_authenticated_prefix(
            &completion.prefix.proofs,
            tips.iter()
                .map(|tip| tip.body.finality_proof.block_header.height().get()),
        )?;
    }
    let prepared = PHASES
        .iter()
        .map(|phase| {
            require_operation_budget(deadline, "verifying retained deployment transaction")?;
            let prepared: PreparedV1 = journal.read_json(&format!("{phase}.prepared.json"))?;
            let transaction = prepared.verify(plan, phase)?;
            Ok((prepared, transaction))
        })
        .collect::<Result<Vec<_>>>()?;
    // A previous completion receipt never replaces fresh peer state or the new challenge.
    let verification = PeerVerification {
        authority,
        plan,
        prepared: &prepared,
        proofs: &completion.prefix.proofs,
        verifier: completion
            .prefix
            .verifier
            .as_ref()
            .ok_or_else(|| eyre!("missing verified finality prefix"))?,
        challenge,
        deadline,
    };
    let verified = read_four_peers(&clients, discriminant, |index, client| {
        verify_peer_state(client, &trust.peers[index], &tips[index], &verification)
    })?;
    require_operation_budget(deadline, "verified all validator states")?;
    let Some(verified) = verified
        .into_iter()
        .map(|peer| match peer {
            PeerRead::Verified(value) => Some(value),
            PeerRead::Pending => None,
        })
        .collect::<Option<Vec<_>>>()
    else {
        report.state = "verification_peer_pending".into();
        return Ok(());
    };
    let carriers = consistent_carriers(verified.iter().map(|peer| &peer.wires))?;
    let maximum =
        iroha_data_model::block::proofs::AUTHENTICATED_BLOCK_PROOFS_MAX_BLOCK_WIRE_BYTES_V1;
    for (height, wire) in carriers {
        require_operation_budget(deadline, "publishing verified carrier evidence")?;
        let file = format!("carrier-{height:020}.nrt");
        if let Some(existing) = journal.read_optional_bounded(&file, maximum)? {
            require(
                existing == wire,
                "verified carrier bytes differ from retained evidence",
            )?;
        } else {
            journal.install_bounded(&file, wire, maximum)?;
        }
    }
    let receipts = verified
        .into_iter()
        .map(|peer| peer.receipt)
        .collect::<Vec<_>>();
    require(
        receipts.len() == VERIFICATION_PEERS,
        "four validator receipts are required",
    )?;
    let runtime_update = completion.runtime_update;
    let completion = CompletionV1 {
        schema_version: 1,
        operation_id: plan.operation_id.clone(),
        intent_sha256: plan.intent_sha256.clone(),
        network_id: plan.manifest.network_id,
        challenge,
        peers: receipts,
        verification_origins: completion.verification_origins.clone(),
    };
    let receipt_name = format!("completion-{}.json", hex::encode(challenge));
    require_operation_budget(deadline, "publishing completion receipt")?;
    if let Some(update) = runtime_update {
        update.revalidate()?;
        let trust_file = format!("verification-trust-{}.json", hex::encode(challenge));
        journal.install_json(&trust_file, &update.trust)?;
        let mut value = json::to_value(&completion)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| eyre!("completion must be an object"))?;
        object.insert("schema_version".into(), norito::json!(2));
        object.insert("runtime_update".into(), update.receipt.clone());
        object.insert("verification_trust_file".into(), norito::json!(trust_file));
        journal.install_json(&receipt_name, &value)?;
    } else {
        journal.install_json(&receipt_name, &completion)?;
    }
    require_operation_budget(deadline, "published completion receipt")?;
    report.completion_receipt = Some(receipt_name);
    report.deployment_complete = true;
    report.state = "completed".into();
    Ok(())
}

#[cfg(test)]
pub(super) fn test_trust() -> TrustV1 {
    let (block, key) = crate::taira_public_reset::deployment_genesis_fixture();
    let validators = iroha_genesis::signed_genesis_validator_pops(&block).unwrap();
    TrustV1 {
        chain: "fc56984b-2be7-431d-840e-21514d1883f0".into(),
        account_chain_discriminant: 369,
        genesis_public_key: key.public_key().clone(),
        genesis_signed_wire_hex: hex::encode(block.encode_wire().unwrap()),
        peers: validators
            .into_keys()
            .enumerate()
            .map(|(index, key)| {
                let peer_id = PeerId::new(key);
                PeerV1 {
                    torii_origin: format!("http://127.0.0.1:{}/", 8080 + index),
                    node_fingerprint: Hash::new(peer_id.encode()),
                    peer_id,
                    build_fingerprint: Hash::new([1]),
                    config_fingerprint: Hash::new([2]),
                }
            })
            .collect(),
    }
}

#[cfg(test)]
pub(super) fn test_network_id() -> NetworkId {
    NetworkId::from_genesis_hash(
        crate::taira_public_reset::deployment_genesis_fixture()
            .0
            .hash(),
    )
}

#[cfg(test)]
#[path = "taira_dataspace_deploy_finality_tests.rs"]
mod tests;
