//! Fresh, four-peer committed-height evidence rooted in a native prepared genesis bundle.

use super::*;
use std::time::Instant;

/// A poll can report progress without authorizing an unauthenticated height.
pub(crate) enum HeightObservationV1 {
    Pending,
    Verified(VerifiedCommittedHeightV1),
}

/// Only this module can construct a height accepted by the bootstrap controller.
/// Its public evidence contains every immediate successor from the signed genesis.
#[derive(JsonSerialize)]
pub(crate) struct VerifiedCommittedHeightV1 {
    schema: String,
    network_id: NetworkId,
    genesis_block_hash: HashOf<BlockHeader>,
    committed_height: NonZeroU64,
    block_hash: HashOf<BlockHeader>,
    before_challenge: [u8; 32],
    after_challenge: [u8; 32],
    proofs: Vec<SumeragiFinalityProof>,
    peers: Vec<PeerHeightEvidenceV1>,
}

/// Untrusted retained bytes are deliberately separate from the verified capability.
#[derive(JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RetainedCommittedHeightV1 {
    schema: String,
    network_id: NetworkId,
    genesis_block_hash: HashOf<BlockHeader>,
    committed_height: NonZeroU64,
    block_hash: HashOf<BlockHeader>,
    before_challenge: [u8; 32],
    after_challenge: [u8; 32],
    proofs: Vec<SumeragiFinalityProof>,
    peers: Vec<PeerHeightEvidenceV1>,
}

impl VerifiedCommittedHeightV1 {
    #[cfg(test)]
    pub(crate) fn convergence_evidence_fixture(
        height: u64,
    ) -> (
        iroha_genesis::ValidatedGenesisBundle,
        Vec<PeerV1>,
        json::Value,
    ) {
        tests::convergence_evidence_fixture(height)
    }

    /// Reauthenticate retained evidence under independently selected genesis and peers.
    /// This proves the historical capture; callers must bind its journal/wave custody.
    pub(crate) fn validate_retained(
        genesis: &iroha_genesis::ValidatedGenesisBundle,
        chain: &str,
        peers: Vec<PeerV1>,
        value: json::Value,
    ) -> Result<Self> {
        let raw: RetainedCommittedHeightV1 = json::from_value(value)?;
        let mut observer = AuthenticatedHeightObserverV1::new(genesis, chain, peers)?;
        require(
            raw.schema == "iroha.taira.authenticated-committed-height.v1"
                && raw.network_id == observer.authority.network
                && raw.genesis_block_hash == observer.authority.genesis
                && raw.before_challenge != [0; 32]
                && raw.after_challenge != [0; 32]
                && raw.before_challenge != raw.after_challenge
                && raw.proofs.len() == usize::try_from(raw.committed_height.get())?
                && raw.peers.len() == VERIFICATION_PEERS,
            "retained height summary, challenges or complete proof prefix differs",
        )?;
        let mut verifier = observer.authority.verifier()?;
        for proof in &raw.proofs {
            observer.authority.roster(proof)?;
            verifier.verify(proof)?;
        }
        require(
            raw.proofs
                .last()
                .is_some_and(|proof| proof.block_header.hash() == raw.block_hash),
            "retained block hash differs from the authenticated tip",
        )?;
        observer.verifier = Some(verifier);
        observer.proofs = raw.proofs;
        for (index, evidence) in raw.peers.iter().enumerate() {
            require(
                evidence.peer == observer.peers[index],
                "retained selected peer identity differs",
            )?;
            for (attestation, challenge) in [
                (&evidence.before, raw.before_challenge),
                (&evidence.after, raw.after_challenge),
            ] {
                validate_attestation(&observer.authority, &evidence.peer, challenge, attestation)?;
                require(
                    attestation.body.finality_proof.block_header.height() == raw.committed_height,
                    "retained peer capture did not converge on the selected height",
                )?;
                observer.require_chain_tip(attestation)?;
            }
        }
        Ok(Self {
            schema: raw.schema,
            network_id: raw.network_id,
            genesis_block_hash: raw.genesis_block_hash,
            committed_height: raw.committed_height,
            block_hash: raw.block_hash,
            before_challenge: raw.before_challenge,
            after_challenge: raw.after_challenge,
            proofs: observer.proofs,
            peers: raw.peers,
        })
    }

    pub(crate) fn block_hash(&self) -> HashOf<BlockHeader> {
        self.block_hash
    }

    pub(crate) fn committed_height(&self) -> NonZeroU64 {
        self.committed_height
    }

    /// Reauthenticate a carrier from the retained complete chain under selected genesis.
    pub(crate) fn verified_proof_at(
        &self,
        genesis: &iroha_genesis::ValidatedGenesisBundle,
        height: NonZeroU64,
    ) -> Result<iroha_data_model::sumeragi_finality::VerifiedSumeragiBlock> {
        require(
            self.genesis_block_hash == genesis.expected_hash(),
            "carrier genesis differs",
        )?;
        let validators = genesis
            .validator_pops()
            .iter()
            .map(|(public_key, proof_of_possession)| FinalityValidator {
                public_key: public_key.clone(),
                proof_of_possession: proof_of_possession.clone(),
            })
            .collect();
        let mut verifier = SumeragiFinalityVerifier::new(
            genesis.block(),
            "fc56984b-2be7-431d-840e-21514d1883f0",
            validators,
        )?;
        for proof in &self.proofs {
            let verified = verifier.verify(proof)?;
            if proof.block_header.height() == height {
                return Ok(verified);
            }
        }
        Err(eyre!("carrier is absent from the authenticated prefix"))
    }

    /// Retrieve only a proof admitted into this observation's contiguous prefix.
    pub(crate) fn proof_at(&self, height: NonZeroU64) -> Option<&SumeragiFinalityProof> {
        self.proofs.get(usize::try_from(height.get() - 1).ok()?)
    }
}

#[derive(JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PeerHeightEvidenceV1 {
    peer: PeerV1,
    before: SumeragiFinalityAttestation,
    after: SumeragiFinalityAttestation,
}

/// A verified chain is retained only in memory; every emitted height requires new peer reads.
pub(crate) struct AuthenticatedHeightObserverV1 {
    authority: Authority,
    peers: Vec<PeerV1>,
    verifier: Option<SumeragiFinalityVerifier>,
    proofs: Vec<SumeragiFinalityProof>,
    emitted_height: u64,
}

trait HeightReads: Sync {
    fn transport_pending(&self, _: &eyre::Report) -> bool {
        false
    }
    fn tip(&self, peer: usize) -> Result<u64>;
    fn attest(
        &self,
        peer: usize,
        height: NonZeroU64,
        challenge: [u8; 32],
        identity: &PeerId,
    ) -> Result<SumeragiFinalityAttestation>;
    fn next_proof(
        &self,
        peer: usize,
        height: NonZeroU64,
        verifier: &mut SumeragiFinalityVerifier,
    ) -> Result<SumeragiFinalityProof>;
}

struct NativeReads {
    clients: [Client; VERIFICATION_PEERS],
}

impl HeightReads for NativeReads {
    fn tip(&self, peer: usize) -> Result<u64> {
        Ok(self.clients[peer].get_sumeragi_status()?.committed_height)
    }

    fn attest(
        &self,
        peer: usize,
        height: NonZeroU64,
        challenge: [u8; 32],
        identity: &PeerId,
    ) -> Result<SumeragiFinalityAttestation> {
        self.clients[peer]
            .get_sumeragi_finality_attestation(height, challenge, identity)
            .map(|attestation| attestation.into_attestation())
    }

    fn next_proof(
        &self,
        peer: usize,
        height: NonZeroU64,
        verifier: &mut SumeragiFinalityVerifier,
    ) -> Result<SumeragiFinalityProof> {
        self.clients[peer].get_next_sumeragi_finality_proof(height, verifier)
    }
}

impl AuthenticatedHeightObserverV1 {
    /// The opaque bundle can only be obtained through native signed-manifest validation.
    pub(crate) fn new(
        genesis: &iroha_genesis::ValidatedGenesisBundle,
        chain: &str,
        peers: Vec<PeerV1>,
    ) -> Result<Self> {
        require(
            genesis.consensus_metadata().mode
                == iroha_data_model::parameter::system::SumeragiConsensusMode::Npos,
            "authenticated height requires the prepared NPoS genesis",
        )?;
        let validators = genesis
            .validator_pops()
            .iter()
            .map(|(key, pop)| (PeerId::new(key.clone()), pop.clone()))
            .collect::<BTreeMap<_, _>>();
        validate_peer_selection(&peers, &validators)?;
        Ok(Self {
            authority: Authority {
                chain: chain.parse()?,
                network: NetworkId::from_genesis_hash(genesis.expected_hash()),
                genesis: genesis.expected_hash(),
                trusted_genesis: genesis.block().clone(),
                validators: validators
                    .into_iter()
                    .map(|(peer, proof_of_possession)| FinalityValidator {
                        public_key: peer.public_key().clone(),
                        proof_of_possession,
                    })
                    .collect(),
            },
            peers,
            verifier: None,
            proofs: Vec::new(),
            emitted_height: 0,
        })
    }

    /// Observe one bounded turn using the caller's independently configured four native clients.
    pub(crate) fn observe(
        &mut self,
        clients: &[Client; VERIFICATION_PEERS],
        discriminant: u16,
        deadline: Instant,
    ) -> Result<HeightObservationV1> {
        require_operation_budget(deadline, "starting authenticated height observation")?;
        let readers = NativeReads {
            clients: std::array::from_fn(|index| clients[index].with_request_deadline(deadline)),
        };
        self.observe_with(
            &readers,
            discriminant,
            deadline,
            rand::random(),
            rand::random(),
        )
    }

    fn capture(
        &self,
        reads: &impl HeightReads,
        discriminant: u16,
        deadline: Instant,
        challenge: [u8; 32],
    ) -> Result<Vec<PeerRead<SumeragiFinalityAttestation>>> {
        read_four_peers(&self.peers, discriminant, |index, peer| {
            require_operation_budget(deadline, "reading authenticated validator height")?;
            let tip = match reads.tip(index) {
                Ok(tip) => tip,
                Err(error) if reads.transport_pending(&error) => return Ok(PeerRead::Pending),
                Err(error) => return Err(error),
            };
            let Some(height) = NonZeroU64::new(tip) else {
                return Ok(PeerRead::Pending);
            };
            require_operation_budget(deadline, "challenging validator finality")?;
            let attestation = match reads.attest(index, height, challenge, &peer.peer_id) {
                Ok(value) => value,
                Err(error)
                    if error
                        .downcast_ref::<iroha::client::BridgeFinalityAttestationTipMismatch>()
                        .is_some() =>
                {
                    require_operation_budget(deadline, "validator finality tip is moving")?;
                    return Ok(PeerRead::Pending);
                }
                Err(error) if reads.transport_pending(&error) => return Ok(PeerRead::Pending),
                Err(error) => return Err(error),
            };
            validate_attestation(&self.authority, peer, challenge, &attestation)?;
            require(
                attestation.body.finality_proof.block_header.height() == height,
                "attested proof differs from requested height",
            )?;
            // Certificate verification follows against the authenticated contiguous prefix.
            // The challenged identity alone never authorizes a height.
            require_operation_budget(deadline, "verified validator height attestation")?;
            Ok(PeerRead::Verified(attestation))
        })
    }

    fn observe_with(
        &mut self,
        reads: &impl HeightReads,
        discriminant: u16,
        deadline: Instant,
        before_challenge: [u8; 32],
        after_challenge: [u8; 32],
    ) -> Result<HeightObservationV1> {
        self.observe_with_policy(
            reads,
            discriminant,
            deadline,
            before_challenge,
            after_challenge,
            false,
        )
    }

    fn observe_with_policy(
        &mut self,
        reads: &impl HeightReads,
        discriminant: u16,
        deadline: Instant,
        before_challenge: [u8; 32],
        after_challenge: [u8; 32],
        repeat_current: bool,
    ) -> Result<HeightObservationV1> {
        require_operation_budget(deadline, "starting authenticated height observation")?;
        require(
            before_challenge != [0; 32]
                && after_challenge != [0; 32]
                && before_challenge != after_challenge,
            "height observation needs two distinct fresh challenges",
        )?;
        let before = self.capture(reads, discriminant, deadline, before_challenge)?;
        require_operation_budget(deadline, "captured validator height attestations")?;
        let Some((source_index, source)) = before
            .iter()
            .enumerate()
            .filter_map(|(index, read)| match read {
                PeerRead::Verified(value) => Some((index, value)),
                PeerRead::Pending => None,
            })
            .max_by_key(|(_, proof)| proof.body.finality_proof.block_header.height())
        else {
            return Ok(HeightObservationV1::Pending);
        };
        let target_height = source.body.finality_proof.block_header.height();
        // A disconnected suffix source must not hide a conflict in already authenticated history.
        if repeat_current {
            for read in &before {
                if let PeerRead::Verified(attestation) = read
                    && usize::try_from(attestation.body.finality_proof.block_header.height().get())?
                        <= self.proofs.len()
                {
                    self.require_chain_tip(attestation)?;
                }
            }
        }
        let mut new_proofs = 0;
        if !self.synchronize(reads, source_index, source, deadline, &mut new_proofs)? {
            return Ok(HeightObservationV1::Pending);
        }
        // Reject a conflicting proof before classifying any other peer as still progressing.
        for read in &before {
            if let PeerRead::Verified(attestation) = read {
                self.require_chain_tip(attestation)?;
            }
        }
        let Some(before) = before
            .into_iter()
            .map(|read| match read {
                PeerRead::Verified(value) => Some(value),
                PeerRead::Pending => None,
            })
            .collect::<Option<Vec<_>>>()
        else {
            return Ok(HeightObservationV1::Pending);
        };
        if before.iter().any(|attestation| {
            attestation.body.finality_proof.block_header.height() != target_height
        }) || target_height.get() < self.emitted_height
            || (!repeat_current && target_height.get() == self.emitted_height)
        {
            return Ok(HeightObservationV1::Pending);
        }
        let after = self.capture(reads, discriminant, deadline, after_challenge)?;
        require_operation_budget(deadline, "rechecked authenticated validator heights")?;
        if repeat_current {
            for read in &after {
                if let PeerRead::Verified(attestation) = read
                    && usize::try_from(attestation.body.finality_proof.block_header.height().get())?
                        <= self.proofs.len()
                {
                    self.require_chain_tip(attestation)?;
                }
            }
        }
        if let Some((index, tip)) = after
            .iter()
            .enumerate()
            .filter_map(|(index, read)| match read {
                PeerRead::Verified(value) => Some((index, value)),
                PeerRead::Pending => None,
            })
            .max_by_key(|(_, proof)| proof.body.finality_proof.block_header.height())
        {
            if !self.synchronize(reads, index, tip, deadline, &mut new_proofs)? {
                return Ok(HeightObservationV1::Pending);
            }
        }
        let mut pending = false;
        for read in &after {
            match read {
                PeerRead::Pending => pending = true,
                PeerRead::Verified(attestation) => {
                    let height = attestation.body.finality_proof.block_header.height();
                    self.require_chain_tip(attestation)?;
                    pending |= height != target_height;
                }
            }
        }
        if pending {
            return Ok(HeightObservationV1::Pending);
        }
        let peers = before
            .into_iter()
            .zip(after)
            .enumerate()
            .map(|(index, (before, after))| {
                let PeerRead::Verified(after) = after else {
                    unreachable!("pending captures returned above")
                };
                PeerHeightEvidenceV1 {
                    peer: self.peers[index].clone(),
                    before,
                    after,
                }
            })
            .collect();
        let proof = self
            .proofs
            .get(usize::try_from(target_height.get() - 1)?)
            .ok_or_else(|| eyre!("missing authenticated target proof"))?;
        let evidence = VerifiedCommittedHeightV1 {
            schema: "iroha.taira.authenticated-committed-height.v1".to_owned(),
            network_id: self.authority.network,
            genesis_block_hash: self.authority.genesis,
            committed_height: target_height,
            block_hash: proof.block_header.hash(),
            before_challenge,
            after_challenge,
            proofs: self.proofs[..usize::try_from(target_height.get())?].to_vec(),
            peers,
        };
        require_operation_budget(deadline, "publishing authenticated committed height")?;
        self.emitted_height = target_height.get();
        Ok(HeightObservationV1::Verified(evidence))
    }

    fn synchronize(
        &mut self,
        reads: &impl HeightReads,
        source_index: usize,
        source: &SumeragiFinalityAttestation,
        deadline: Instant,
        new_proofs: &mut usize,
    ) -> Result<bool> {
        let target_height = source.body.finality_proof.block_header.height();
        while u64::try_from(self.proofs.len())? < target_height.get() {
            require_operation_budget(deadline, "synchronizing authenticated height proof chain")?;
            if *new_proofs == MAX_NEW_PROOFS {
                return Ok(false);
            }
            let next = NonZeroU64::new(
                u64::try_from(self.proofs.len())?
                    .checked_add(1)
                    .ok_or_else(|| eyre!("authenticated proof height overflow"))?,
            )
            .unwrap();
            let (proof, advanced) = if next.get() == 1 {
                let proof = source.body.genesis_finality_proof.clone();
                let verifier = self.authority.anchor(&proof)?;
                (proof, verifier)
            } else {
                let mut verifier = self
                    .verifier
                    .clone()
                    .ok_or_else(|| eyre!("missing genesis verifier"))?;
                let proof = match reads.next_proof(source_index, next, &mut verifier) {
                    Ok(proof) => proof,
                    Err(error) if reads.transport_pending(&error) => return Ok(false),
                    Err(error) => return Err(error),
                };
                (proof, verifier)
            };
            require(
                proof.block_header.height() == next,
                "finality chain skipped or reordered a height",
            )?;
            self.authority.roster(&proof)?;
            require_operation_budget(deadline, "verified authenticated successor proof")?;
            self.verifier = Some(advanced);
            self.proofs.push(proof);
            *new_proofs += 1;
        }
        Ok(true)
    }

    fn require_chain_tip(&self, attestation: &SumeragiFinalityAttestation) -> Result<()> {
        let tip = &attestation.body.finality_proof;
        let genesis = self
            .proofs
            .first()
            .ok_or_else(|| eyre!("missing authenticated genesis proof"))?;
        let verifier = self
            .verifier
            .as_ref()
            .ok_or_else(|| eyre!("missing authenticated verifier"))?;
        verifier
            .verify_same_decision(genesis, &attestation.body.genesis_finality_proof)
            .wrap_err(
                "validator genesis proof conflicts with the authenticated contiguous chain",
            )?;
        let index = usize::try_from(tip.block_header.height().get() - 1)?;
        let retained = self
            .proofs
            .get(index)
            .ok_or_else(|| eyre!("missing authenticated chain tip"))?;
        verifier
            .verify_same_decision(retained, tip)
            .map(|_| ())
            .wrap_err("validator proof conflicts with the authenticated contiguous chain")
    }
}

#[cfg(test)]
#[path = "taira_authenticated_height_tests.rs"]
mod tests;
