//! Explicit recovery of an absent initial upload after every signed validity window closes.
//! This is a certified-history absence claim, never a fabricated transaction failure.
use super::*;
use iroha::data_model::{
    block::consensus::SumeragiRootScope,
    parameter::system::ConsensusMode,
    sumeragi_finality::{
        FinalityValidator, MAX_SIGNED_GENESIS_BYTES_V1, SumeragiFinalityProof,
        SumeragiFinalityVerifier, VerifiedSumeragiBlock, authenticated_genesis,
        consensus_configuration_fingerprint,
    },
};
use iroha_model_base::peer::PeerId;
use std::{collections::BTreeSet, io::Read as _, num::NonZeroU64};

const MARKER: &str = "validity-window-elapsed.json";
const ROOT: &str = "expiry-root.json";
const MAX_HEIGHT: u64 = 100_000;
const MAX_PROOF_BYTES: usize = 32 * 1024 * 1024;
const MAX_TOTAL_PROOF_BYTES: usize = 512 * 1024 * 1024;

/// Independent public pins supplied by the operator's authenticated runtime release.
#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RecoveryRoot {
    chain_id: String,
    network_id: NetworkId,
    genesis_hash: HashOf<BlockHeader>,
    signed_genesis_sha256: String,
    genesis_public_key: iroha_crypto::PublicKey,
    roster: Vec<String>,
    mode: String,
}

#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RetainedRoot {
    pins: RecoveryRoot,
    signed_genesis_hex: String,
}

impl RetainedRoot {
    fn authenticate(&self, record: &PlanRecord) -> Result<SumeragiFinalityVerifier> {
        if self.pins.network_id != record.preflight.network_id
            || self.pins.chain_id != record.preflight.chain_id
            || record.preflight.dataspace_id != DataSpaceId::UNIVERSAL
            || self.pins.chain_id.is_empty()
            || self.pins.chain_id.len() > 512
            || self.pins.chain_id.trim() != self.pins.chain_id
            || self.pins.chain_id.chars().any(char::is_control)
            || self.pins.network_id.into_genesis_hash() != self.pins.genesis_hash
        {
            return Err(eyre!(
                "expiry root differs from the selected Global deployment"
            ));
        }
        let digest = canonical_hex(&self.pins.signed_genesis_sha256, 32)?;
        let digest: [u8; 32] = digest
            .try_into()
            .map_err(|_| eyre!("invalid genesis SHA-256"))?;
        let wire = canonical_hex(&self.signed_genesis_hex, MAX_SIGNED_GENESIS_BYTES_V1)?;
        if digest == [0; 32] || iroha_crypto::sha256(&wire) != digest {
            return Err(eyre!(
                "public genesis differs from independently selected raw SHA-256"
            ));
        }
        // Same maintained native public-root composition used by Core PublicDomainRoot.
        // The original certified height-one bytes remain intact. Its result-only
        // certificate grants no execution authority and is never stripped/re-authored.
        let genesis = norito::core::with_decode_limits_scope(
            norito::canonical_decode_limits(wire.len()),
            || iroha::data_model::block::decode_framed_signed_block(&wire),
        )?;
        if !genesis.header().is_genesis()
            || genesis.encode_wire()? != wire
            || genesis.hash() != self.pins.genesis_hash
        {
            return Err(eyre!(
                "public genesis differs from independently selected header"
            ));
        }
        let (epoch, scope) = authenticated_genesis(&genesis)?.into_parts();
        let roster = self
            .pins
            .roster
            .iter()
            .map(|key| key.parse().map(PeerId::new))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mode = match self.pins.mode.as_str() {
            "permissioned" => ConsensusMode::Permissioned,
            "npos" => ConsensusMode::Npos,
            _ => return Err(eyre!("expiry root mode must be permissioned or npos")),
        };
        let actual_roster: Vec<_> = epoch
            .committee
            .iter()
            .map(|member| member.validator.clone())
            .collect();
        if scope != SumeragiRootScope::Global
            || epoch.network_id != self.pins.network_id
            || epoch.mode != mode
            || actual_roster != roster
            || genesis
                .external_transactions()
                .next()
                .and_then(|tx| tx.authority().try_signatory())
                != Some(&self.pins.genesis_public_key)
        {
            return Err(eyre!(
                "public genesis scope, committee, mode or signer differs from independent pins"
            ));
        }
        consensus_configuration_fingerprint(&genesis)?;
        let validators = epoch
            .committee
            .iter()
            .map(|member| FinalityValidator {
                public_key: member.validator.public_key().clone(),
                proof_of_possession: member.proof_of_possession.clone(),
            })
            .collect();
        let verifier = SumeragiFinalityVerifier::new(&genesis, &self.pins.chain_id, validators)?;
        verifier.initial_chain_parameters()?;
        if verifier.root_scope() != SumeragiRootScope::Global
            || verifier.authenticated_height().is_some()
        {
            return Err(eyre!(
                "public genesis did not create an unadvanced Global verifier"
            ));
        }
        Ok(verifier)
    }
}

#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RetainedProof {
    norito_hex: String,
    digest: String,
}
impl RetainedProof {
    fn capture(proof: &SumeragiFinalityProof) -> Result<Self> {
        let wire = norito::to_bytes(proof)?;
        if wire.len() > MAX_PROOF_BYTES {
            return Err(eyre!("expiry proof exceeds byte bound"));
        }
        Ok(Self {
            digest: Hash::new(&wire).to_string(),
            norito_hex: hex::encode(wire),
        })
    }
    fn decode(&self) -> Result<(SumeragiFinalityProof, usize)> {
        let wire = canonical_hex(&self.norito_hex, MAX_PROOF_BYTES)?;
        if Hash::new(&wire).to_string() != self.digest {
            return Err(eyre!("expiry proof digest differs"));
        }
        let proof: SumeragiFinalityProof = norito::core::with_decode_limits_scope(
            norito::canonical_decode_limits(wire.len()),
            || norito::decode_from_bytes(&wire),
        )?;
        if norito::to_bytes(&proof)? != wire {
            return Err(eyre!("expiry proof is not canonical Norito"));
        }
        Ok((proof, wire.len()))
    }
}

/// Append-only evidence that the original initial-upload plan is absent and cannot execute.
/// The retained original genesis and every contiguous proof are reauthenticated on inspection.
#[derive(
    Clone, Debug, PartialEq, Eq, norito::derive::JsonSerialize, norito::derive::JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct DeploymentValidityWindowElapsed {
    /// Exact original plan hash, including the original review and signed bytes.
    pub plan_digest: String,
    /// Exact retained independently pinned genesis-input record digest.
    pub root_digest: String,
    /// All original signed payload hashes, including never-attempted later stages.
    pub transaction_hashes: Vec<String>,
    /// Authorization-inclusive canonical wire digests in the same order.
    pub signed_wire_digests: Vec<String>,
    /// Latest signature-bound creation time plus TTL among all original stages.
    pub valid_until_ms: u64,
    /// Final certified Global height of the complete genesis-origin absence scan.
    pub finalized_height: u64,
    /// Exact certified final header hash.
    pub finalized_block_hash: String,
    /// Certified block creation time, strictly greater than every original expiry.
    pub finalized_time_ms: u64,
    /// Exact retained canonical proof-wire digest for every height, starting at one.
    pub proof_digests: Vec<String>,
}

fn canonical_hex(raw: &str, maximum: usize) -> Result<Vec<u8>> {
    if raw.is_empty() || raw.len() > maximum.saturating_mul(2) {
        return Err(eyre!("expiry hex exceeds byte bound"));
    }
    let bytes = hex::decode(raw)?;
    if hex::encode(&bytes) != raw {
        return Err(eyre!("expiry hex is not canonical"));
    }
    Ok(bytes)
}
fn digest<T: norito::json::JsonSerialize>(value: &T) -> Result<String> {
    Ok(Hash::new(norito::json::to_vec(value)?).to_string())
}
fn proof_name(height: u64) -> String {
    format!("expiry-proof-{height:010}.json")
}
fn signed_deadline(transaction: &SignedTransaction) -> Result<u64> {
    let ttl = transaction
        .time_to_live()
        .filter(|ttl| !ttl.is_zero())
        .ok_or_else(|| eyre!("expiry recovery requires a positive signed TTL"))?;
    let deadline = transaction
        .creation_time()
        .checked_add(ttl)
        .ok_or_else(|| eyre!("signed validity deadline overflow"))?;
    u64::try_from(deadline.as_millis()).map_err(Into::into)
}

struct Scan {
    verifier: SumeragiFinalityVerifier,
    network: NetworkId,
    chain: String,
    hashes: BTreeSet<HashOf<SignedTransaction>>,
    observed_height: u64,
    observed_hash: String,
    deadline: u64,
    bytes: usize,
    proof_digests: Vec<String>,
    previous_time_ms: Option<u64>,
}
impl Scan {
    fn new(record: &PlanRecord, root: &RetainedRoot) -> Result<Self> {
        let verifier = root.authenticate(record)?;
        if verifier.root_scope() != SumeragiRootScope::Global {
            return Err(eyre!("expiry recovery requires Global genesis"));
        }
        let transactions = record
            .transactions
            .iter()
            .map(decode_transaction)
            .collect::<Result<Vec<_>>>()?;
        let hashes = transactions
            .iter()
            .map(SignedTransaction::hash)
            .collect::<BTreeSet<_>>();
        if hashes.len() != transactions.len() {
            return Err(eyre!("expiry plan repeats a signed transaction hash"));
        }
        let deadline = transactions
            .iter()
            .map(signed_deadline)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .ok_or_else(|| eyre!("empty expiry recovery plan"))?;
        Ok(Self {
            verifier,
            network: record.preflight.network_id,
            chain: record.preflight.chain_id.clone(),
            hashes,
            observed_height: record.preflight.observed_block_height,
            observed_hash: record.preflight.observed_block_hash.clone(),
            deadline,
            bytes: 0,
            proof_digests: Vec::new(),
            previous_time_ms: None,
        })
    }
    fn accept(&mut self, retained: &RetainedProof) -> Result<VerifiedSumeragiBlock> {
        let (proof, size) = retained.decode()?;
        self.bytes = self
            .bytes
            .checked_add(size)
            .filter(|size| *size <= MAX_TOTAL_PROOF_BYTES)
            .ok_or_else(|| eyre!("expiry history exceeds retained byte bound"))?;
        let verified = self.verifier.verify(&proof)?;
        if self
            .previous_time_ms
            .is_some_and(|previous| verified.header().creation_time_ms <= previous)
        {
            return Err(eyre!(
                "expiry history block time does not strictly increase"
            ));
        }
        self.previous_time_ms = Some(verified.header().creation_time_ms);
        if verified.height() > 1 {
            verified.verify_global_scope(self.network, &self.chain)?;
        }
        if verified.height() == self.observed_height
            && verified.header().hash().to_string() != self.observed_hash
        {
            return Err(eyre!(
                "expiry history differs from original deployment observation"
            ));
        }
        if verified
            .block()
            .external_transactions()
            .any(|tx| self.hashes.contains(&tx.hash()))
        {
            return Err(eyre!(
                "an original deployment transaction exists in certified history; recover its outcome"
            ));
        }
        self.proof_digests.push(retained.digest.clone());
        self.verifier.retain_recent_decisions(3);
        Ok(verified)
    }
    fn finished(&self, tip: &VerifiedSumeragiBlock) -> bool {
        tip.height() > self.observed_height && tip.header().creation_time_ms > self.deadline
    }
    fn evidence(
        &self,
        record: &PlanRecord,
        root: &RetainedRoot,
        tip: &VerifiedSumeragiBlock,
    ) -> Result<DeploymentValidityWindowElapsed> {
        if !self.finished(tip) {
            return Err(eyre!(
                "certified history has not closed every signed validity window"
            ));
        }
        Ok(DeploymentValidityWindowElapsed {
            plan_digest: digest(record)?,
            root_digest: digest(root)?,
            transaction_hashes: record.preflight.transaction_hashes.clone(),
            signed_wire_digests: record
                .transactions
                .iter()
                .map(|tx| Ok(Hash::new(hex::decode(&tx.norito_hex)?).to_string()))
                .collect::<Result<Vec<_>>>()?,
            valid_until_ms: self.deadline,
            finalized_height: tip.height(),
            finalized_block_hash: tip.header().hash().to_string(),
            finalized_time_ms: tip.header().creation_time_ms,
            proof_digests: self.proof_digests.clone(),
        })
    }
}

fn require_initial_upload(record: &PlanRecord, journal: &Journal) -> Result<()> {
    if record.transactions.len() != 3 || record.transactions[0].name != "register_bytes_finalize" {
        return Err(eyre!(
            "expiry reconciliation supports only the single-chunk initial upload"
        ));
    }
    journal.require_expiry_recovery_entries(MAX_HEIGHT as usize + 5, None)?;
    let attempt: TransactionAttempt = journal.read("attempt-0000.json")?;
    if attempt.name != record.transactions[0].name || attempt.hash != record.transactions[0].hash {
        return Err(eyre!(
            "expiry reconciliation attempt differs from original plan"
        ));
    }
    Ok(())
}

pub(super) fn retained(
    record: &PlanRecord,
    journal: &Journal,
) -> DeploymentResult<Option<DeploymentValidityWindowElapsed>> {
    if !journal.exists(MARKER).map_err(DeploymentError::Journal)? {
        return Ok(None);
    }
    let result = (|| -> Result<DeploymentValidityWindowElapsed> {
        require_initial_upload(record, journal)?;
        let expected: DeploymentValidityWindowElapsed = journal.read(MARKER)?;
        if !(2..=MAX_HEIGHT).contains(&expected.finalized_height)
            || expected.proof_digests.len() != expected.finalized_height as usize
        {
            return Err(eyre!("invalid retained expiry history range"));
        }
        journal.require_expiry_recovery_entries(
            MAX_HEIGHT as usize + 5,
            Some(expected.finalized_height),
        )?;
        let root: RetainedRoot = journal.read(ROOT)?;
        let mut scan = Scan::new(record, &root)?;
        let mut last = None;
        for height in 1..=expected.finalized_height {
            let proof: RetainedProof = journal.read(&proof_name(height))?;
            last = Some(scan.accept(&proof)?);
        }
        let actual = scan.evidence(
            record,
            &root,
            &last.ok_or_else(|| eyre!("empty expiry history"))?,
        )?;
        if actual != expected {
            return Err(eyre!(
                "retained expiry evidence differs from original verified history"
            ));
        }
        Ok(actual)
    })();
    result.map(Some).map_err(DeploymentError::Journal)
}

fn require_global_absence(service: &DeploymentService, record: &PlanRecord) -> Result<()> {
    for step in &record.transactions {
        let transaction = decode_transaction(step)?;
        if service
            .client
            .client()
            .get_transaction_status_response_global(transaction.hash())?
            .is_some()
        {
            return Err(eyre!(
                "original deployment transaction has a status; resume native exact-hash recovery"
            ));
        }
    }
    Ok(())
}
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(eyre!("expiry public input exceeds byte bound"));
    }
    Ok(bytes)
}

impl DeploymentService {
    /// Retire only a single attempted initial upload whose entire signed plan is absent
    /// throughout certified Global history and whose signed validity windows have elapsed.
    ///
    /// `root_path` contains independent public pins from the authenticated operator release;
    /// `genesis_path` is its original framed signed genesis. Never derive pins from fetched proofs.
    /// This operation sends reads only, retains every original, and cannot emit an Applied receipt.
    /// `max_height` is an explicit finite scan ceiling, not evidence of the current ledger height.
    ///
    /// # Errors
    /// Rejects changed plans, later attempts, any execution evidence, foreign or incomplete
    /// history, observed transaction status, unelapsed TTLs, unsafe custody and transport errors.
    pub fn reconcile_initial_upload_expiry(
        &self,
        journal_dir: &Path,
        expected: &DeploymentPreflight,
        root_path: &Path,
        genesis_path: &Path,
        max_height: u64,
    ) -> DeploymentResult<DeploymentValidityWindowElapsed> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        let operation = (|| -> Result<DeploymentValidityWindowElapsed> {
            if !(2..=MAX_HEIGHT).contains(&max_height) {
                return Err(eyre!("expiry scan height must be 2..100000"));
            }
            let journal = Journal::open(journal_dir, false)?;
            let record: PlanRecord = journal.read("plan.json")?;
            self.validate_plan(&record)?;
            record.preflight.require_same_plan(expected)?;
            require_initial_upload(&record, &journal)?;
            let pins: RecoveryRoot =
                norito::json::from_slice(&read_bounded(root_path, 64 * 1024)?)?;
            let root = RetainedRoot {
                pins,
                signed_genesis_hex: hex::encode(read_bounded(
                    genesis_path,
                    MAX_SIGNED_GENESIS_BYTES_V1,
                )?),
            };
            let mut scan = Scan::new(&record, &root)?;
            self.client.refresh_capabilities()?;
            require_global_absence(self, &record)?;
            journal.put_exact(ROOT, &root)?;
            if let Some(evidence) = retained(&record, &journal)? {
                require_global_absence(self, &record)?;
                return Ok(evidence);
            }
            let mut height = 1;
            while height <= max_height {
                let name = proof_name(height);
                let batch = if journal.exists(&name)? {
                    vec![journal.read::<RetainedProof>(&name)?]
                } else {
                    // One native bounded interval; no fallback that multiplies its byte ceiling.
                    let end = max_height.min(height + 63);
                    self.client
                        .client()
                        .get_sumeragi_finality_interval(
                            NonZeroU64::new(height).ok_or_else(|| eyre!("zero expiry height"))?,
                            NonZeroU64::new(end).ok_or_else(|| eyre!("zero expiry height"))?,
                            SumeragiRootScope::Global,
                        )?
                        .iter()
                        .map(RetainedProof::capture)
                        .collect::<Result<Vec<_>>>()?
                };
                for proof in batch {
                    let tip = scan.accept(&proof)?;
                    journal.put_exact(&proof_name(height), &proof)?;
                    if scan.finished(&tip) {
                        require_global_absence(self, &record)?;
                        let evidence = scan.evidence(&record, &root, &tip)?;
                        journal.put_exact(MARKER, &evidence)?;
                        return Ok(evidence);
                    }
                    height += 1;
                }
            }
            Err(eyre!(
                "scan ceiling reached before certified validity windows elapsed; original journal remains pending"
            ))
        })();
        operation.map_err(DeploymentError::Journal)
    }
}

#[cfg(test)]
#[path = "expiry_tests.rs"]
mod tests;
