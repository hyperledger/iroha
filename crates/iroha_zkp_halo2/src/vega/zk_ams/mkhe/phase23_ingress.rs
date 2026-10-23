//! Full-roster commit/reveal freshness for encrypted ZK-AMS Phase II/III ingress.
//!
//! The release protocol admits exactly eight authenticated commitments before any reveal can be
//! opened. Every commitment and reveal is bound to the governed authentication-key roster, epoch,
//! phase, transcript, session, and canonical party slot. The public beacon absorbs the complete
//! ordered, signed transcript, so one honest reveal keeps it unpredictable until the reveal round.
//! This receipt supplies freshness only; it is not evidence that the encrypted Phase-II/III
//! equations were evaluated correctly.
use super::{
    ArtifactAuthentication, MKHE_VERSION_V1, ZkAmsMkheErrorV1, ZkAmsMkhePartyIdV1,
    active::{ZkAmsMkheActivePartySecretV1, ZkAmsMkheGovernedActiveRosterV1},
    manifest::{ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1, release_profile_v1},
    wire::ZkAmsMkheAuthenticationWireV1,
};
use crate::vega::{
    MaskedRelaxedRandomSourceV1,
    sponge::{Keccak256, shake256},
};
const COMMIT_TAG_V1: [u8; 4] = *b"ZAPC";
const REVEAL_TAG_V1: [u8; 4] = *b"ZAPR";
const RECEIPT_TAG_V1: [u8; 4] = *b"ZAPF";
const CONTEXT_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase23.freshness.context";
const COMMITMENT_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase23.freshness.commitment";
const COMMIT_STATEMENT_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase23.freshness.commit-statement";
const REVEAL_STATEMENT_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase23.freshness.reveal-statement";
const COMMIT_AUTHENTICATION_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.phase23.freshness.commit-authentication";
const REVEAL_AUTHENTICATION_DOMAIN_V1: &[u8] =
    b"iroha.zk-ams.v1.phase23.freshness.reveal-authentication";
const COMMIT_TRANSCRIPT_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase23.freshness.commit-transcript";
const REVEAL_TRANSCRIPT_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase23.freshness.reveal-transcript";
const PUBLIC_BEACON_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase23.freshness.public-beacon";
const RECEIPT_DIGEST_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase23.freshness.receipt";
const PUBLIC_CHALLENGE_DOMAIN_V1: &[u8] = b"iroha.zk-ams.v1.phase23.freshness.public-challenge";
const MAX_REVEAL_REJECTION_ATTEMPTS_V1: usize = 128;
const RELEASE_ROSTER_COUNT_U8_V1: u8 = 8;
const _: [(); 8] = [(); ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1];
const AUTHENTICATION_WIRE_BYTES_V1: usize = 1 + 32 + 33 + 65;
const CONTEXT_BINDING_WIRE_BYTES_V1: usize = 1 + 1 + 1 + 32 + 32 + 32 + 8 + 32 + 32;
/// Exact encoded size of one freshness commitment record.
pub const ZK_AMS_PHASE23_FRESHNESS_COMMIT_WIRE_BYTES_V1: usize =
    4 + CONTEXT_BINDING_WIRE_BYTES_V1 + 1 + 32 + 32 + AUTHENTICATION_WIRE_BYTES_V1;
/// Exact encoded size of one freshness reveal record.
pub const ZK_AMS_PHASE23_FRESHNESS_REVEAL_WIRE_BYTES_V1: usize =
    4 + CONTEXT_BINDING_WIRE_BYTES_V1 + 1 + 32 + 32 + 32 + AUTHENTICATION_WIRE_BYTES_V1;
const RECEIPT_CONTEXT_WIRE_BYTES_V1: usize = 4 + CONTEXT_BINDING_WIRE_BYTES_V1;
/// Exact encoded size of one self-contained eight-party freshness receipt.
pub const ZK_AMS_PHASE23_FRESHNESS_RECEIPT_WIRE_BYTES_V1: usize = RECEIPT_CONTEXT_WIRE_BYTES_V1
    + 1
    + ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 * ZK_AMS_PHASE23_FRESHNESS_COMMIT_WIRE_BYTES_V1
    + 1
    + ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 * ZK_AMS_PHASE23_FRESHNESS_REVEAL_WIRE_BYTES_V1
    + 32
    + 32;
/// Freshness receipts do not certify hidden encrypted party mask shares.
///
/// The public beacon is suitable only for transcript challenges and domain separation. Phase-II/III
/// ingress privacy remains fail-closed until a separate full-roster protocol proves independently
/// sampled encrypted mask shares and their aggregation.
pub const ZK_AMS_PHASE23_FRESHNESS_CERTIFIES_HIDDEN_MASK_SHARES_V1: bool = false;
/// Phase whose public session freshness beacon is certified by a receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ZkAmsPhase23FreshnessPhaseV1 {
    /// Phase II encrypted folding.
    PhaseIi = 2,
    /// Phase III encrypted folding and terminal preparation.
    PhaseIii = 3,
}
impl TryFrom<u8> for ZkAmsPhase23FreshnessPhaseV1 {
    type Error = ZkAmsMkheErrorV1;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(Self::PhaseIi),
            3 => Ok(Self::PhaseIii),
            _ => Err(ZkAmsMkheErrorV1::InvalidWireEncoding),
        }
    }
}
/// Protocol family for one domain-separated public challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ZkAmsPhase23PublicChallengeFamilyV1 {
    /// Public challenge for replicated-U and mask-share statements.
    MaskShareStatement = 1,
    /// Public challenge for collective-encryption statements and proofs.
    CollectiveEncryptionStatement = 2,
    /// Public Phase-II/III folding proof challenge.
    FoldProof = 3,
}
/// Exact semantic role of one derived public Phase-II/III challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ZkAmsPhase23PublicChallengeRoleV1 {
    /// Challenge binding the replicated-U public statement.
    ReplicatedUStatement = 1,
    /// Challenge binding an encrypted party mask-share proof.
    EncryptedMaskShareProof = 2,
    /// Challenge binding a collective-encryption statement.
    CollectiveEncryptionProof = 3,
    /// Challenge binding the Phase-II/III fold proof transcript.
    FoldProofTranscript = 4,
}
impl ZkAmsPhase23PublicChallengeFamilyV1 {
    fn admits(self, role: ZkAmsPhase23PublicChallengeRoleV1) -> bool {
        matches!(
            (self, role),
            (
                Self::MaskShareStatement,
                ZkAmsPhase23PublicChallengeRoleV1::ReplicatedUStatement
                    | ZkAmsPhase23PublicChallengeRoleV1::EncryptedMaskShareProof
            ) | (
                Self::CollectiveEncryptionStatement,
                ZkAmsPhase23PublicChallengeRoleV1::CollectiveEncryptionProof
            ) | (
                Self::FoldProof,
                ZkAmsPhase23PublicChallengeRoleV1::FoldProofTranscript
            )
        )
    }
}
/// Typed public challenge derived from a fully revealed freshness receipt.
///
/// The bytes are public transcript material. This type intentionally does not
/// implement a random-source adapter and must not be used for secrets, masks,
/// RLWE coins or errors, or prover blinding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsPhase23PublicChallengeV1 {
    phase: ZkAmsPhase23FreshnessPhaseV1,
    family: ZkAmsPhase23PublicChallengeFamilyV1,
    role: ZkAmsPhase23PublicChallengeRoleV1,
    record_index: u32,
    chunk_index: u32,
    slot_index: u32,
    bytes: [u8; 32],
}
impl ZkAmsPhase23PublicChallengeV1 {
    /// Phase bound into the public challenge.
    #[must_use]
    pub const fn phase(&self) -> ZkAmsPhase23FreshnessPhaseV1 {
        self.phase
    }
    /// Protocol family bound into the public challenge.
    #[must_use]
    pub const fn family(&self) -> ZkAmsPhase23PublicChallengeFamilyV1 {
        self.family
    }
    /// Semantic role bound into the public challenge.
    #[must_use]
    pub const fn role(&self) -> ZkAmsPhase23PublicChallengeRoleV1 {
        self.role
    }
    /// Record index bound into the public challenge.
    #[must_use]
    pub const fn record_index(&self) -> u32 {
        self.record_index
    }
    /// Packed chunk index bound into the public challenge.
    #[must_use]
    pub const fn chunk_index(&self) -> u32 {
        self.chunk_index
    }
    /// Logical slot index bound into the public challenge.
    #[must_use]
    pub const fn slot_index(&self) -> u32 {
        self.slot_index
    }
    /// Exact 256 public challenge bits.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.bytes
    }
}
/// Trusted, governed context for one exact Phase-II/III freshness ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsPhase23FreshnessContextV1 {
    phase: ZkAmsPhase23FreshnessPhaseV1,
    profile_digest: [u8; 32],
    roster_digest: [u8; 32],
    key_material_digest: [u8; 32],
    epoch: u64,
    transcript_digest: [u8; 32],
    session_digest: [u8; 32],
    parties: [ZkAmsMkhePartyIdV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
    authentication_public_keys: [[u8; 33]; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
}
impl ZkAmsPhase23FreshnessContextV1 {
    /// Bind one ceremony to a validated governed roster and unique session.
    pub fn new(
        roster: &ZkAmsMkheGovernedActiveRosterV1,
        phase: ZkAmsPhase23FreshnessPhaseV1,
        transcript_digest: [u8; 32],
        session_digest: [u8; 32],
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        roster.validate()?;
        if transcript_digest == [0; 32]
            || session_digest == [0; 32]
            || transcript_digest == session_digest
        {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        let parties = roster.participants().map(|participant| participant.party());
        let authentication_public_keys = roster
            .participants()
            .map(|participant| participant.authentication_public_key());
        let context = Self {
            phase,
            profile_digest: roster.profile_digest(),
            roster_digest: roster.roster_digest(),
            key_material_digest: roster.key_material_digest(),
            epoch: roster.epoch(),
            transcript_digest,
            session_digest,
            parties,
            authentication_public_keys,
        };
        context.validate()?;
        Ok(context)
    }
    /// Bound Phase II or Phase III identifier.
    #[must_use]
    pub const fn phase(&self) -> ZkAmsPhase23FreshnessPhaseV1 {
        self.phase
    }
    /// Frozen release-profile digest.
    #[must_use]
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }
    /// Exact governed roster digest.
    #[must_use]
    pub const fn roster_digest(&self) -> [u8; 32] {
        self.roster_digest
    }
    /// Nonzero governed key epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Bound higher-level Phase-II/III transcript digest.
    #[must_use]
    pub const fn transcript_digest(&self) -> [u8; 32] {
        self.transcript_digest
    }
    /// Unique freshness-session digest.
    #[must_use]
    pub const fn session_digest(&self) -> [u8; 32] {
        self.session_digest
    }
    fn validate(&self) -> Result<(), ZkAmsMkheErrorV1> {
        if self.profile_digest != release_profile_v1().digest()?
            || self.roster_digest == [0; 32]
            || self.key_material_digest == [0; 32]
            || self.epoch == 0
            || self.transcript_digest == [0; 32]
            || self.session_digest == [0; 32]
            || self.transcript_digest == self.session_digest
            || self.parties.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        for (party, public_key) in self
            .parties
            .iter()
            .zip(self.authentication_public_keys.iter())
        {
            if *party != ZkAmsMkhePartyIdV1::from_authentication_key(public_key)? {
                return Err(ZkAmsMkheErrorV1::InvalidAuthentication);
            }
        }
        Ok(())
    }
    fn digest(&self) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
        self.validate()?;
        let mut hash = Keccak256::new();
        hash.update(CONTEXT_DOMAIN_V1);
        update_context_hash(&mut hash, self);
        for (party, public_key) in self
            .parties
            .iter()
            .zip(self.authentication_public_keys.iter())
        {
            hash.update(&party.to_bytes());
            hash.update(public_key);
        }
        Ok(hash.finalize())
    }
    fn participant(
        &self,
        party_index: usize,
    ) -> Result<(ZkAmsMkhePartyIdV1, [u8; 33]), ZkAmsMkheErrorV1> {
        Ok((
            *self
                .parties
                .get(party_index)
                .ok_or(ZkAmsMkheErrorV1::InvalidPartySet)?,
            *self
                .authentication_public_keys
                .get(party_index)
                .ok_or(ZkAmsMkheErrorV1::InvalidPartySet)?,
        ))
    }
}
/// One canonical authenticated freshness commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsPhase23FreshnessCommitV1 {
    phase: ZkAmsPhase23FreshnessPhaseV1,
    profile_digest: [u8; 32],
    roster_digest: [u8; 32],
    key_material_digest: [u8; 32],
    epoch: u64,
    transcript_digest: [u8; 32],
    session_digest: [u8; 32],
    party_index: u8,
    party: ZkAmsMkhePartyIdV1,
    commitment: [u8; 32],
    authentication: ZkAmsMkheAuthenticationWireV1,
}
impl ZkAmsPhase23FreshnessCommitV1 {
    /// Canonical roster slot authenticated by this commitment.
    #[must_use]
    pub const fn party_index(&self) -> u8 {
        self.party_index
    }
    /// Authentication-key-derived governed party.
    #[must_use]
    pub const fn party(&self) -> ZkAmsMkhePartyIdV1 {
        self.party
    }
    /// Hiding commitment to the party's nonzero reveal.
    #[must_use]
    pub const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
    /// Encode one exact, verified commitment record.
    pub fn encode(
        &self,
        context: &ZkAmsPhase23FreshnessContextV1,
    ) -> Result<Vec<u8>, ZkAmsMkheErrorV1> {
        self.verify(context)?;
        Ok(self.encode_canonical())
    }
    /// Decode and authenticate one exact commitment under a trusted context.
    pub fn decode_exact(
        bytes: &[u8],
        context: &ZkAmsPhase23FreshnessContextV1,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        if bytes.len() != ZK_AMS_PHASE23_FRESHNESS_COMMIT_WIRE_BYTES_V1 {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        let mut decoder = FixedDecoder::new(bytes);
        decoder.expect(&COMMIT_TAG_V1)?;
        decode_and_expect_context(&mut decoder, context)?;
        let party_index = decoder.u8()?;
        let party = ZkAmsMkhePartyIdV1::new(decoder.array()?)?;
        let commitment = decoder.array()?;
        let authentication = decode_authentication(&mut decoder)?;
        decoder.finish()?;
        let value = Self {
            phase: context.phase,
            profile_digest: context.profile_digest,
            roster_digest: context.roster_digest,
            key_material_digest: context.key_material_digest,
            epoch: context.epoch,
            transcript_digest: context.transcript_digest,
            session_digest: context.session_digest,
            party_index,
            party,
            commitment,
            authentication,
        };
        value.verify(context)?;
        Ok(value)
    }
    fn verify(&self, context: &ZkAmsPhase23FreshnessContextV1) -> Result<(), ZkAmsMkheErrorV1> {
        context.validate()?;
        if !self.has_context(context) || self.commitment == [0; 32] {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        let index = usize::from(self.party_index);
        let (party, public_key) = context.participant(index)?;
        if self.party != party
            || self.authentication.party() != party
            || self.authentication.public_key() != public_key
        {
            return Err(ZkAmsMkheErrorV1::InvalidAuthentication);
        }
        verify_authentication(
            &self.authentication,
            COMMIT_AUTHENTICATION_DOMAIN_V1,
            self.statement_digest()?,
        )
    }
    fn has_context(&self, context: &ZkAmsPhase23FreshnessContextV1) -> bool {
        self.phase == context.phase
            && self.profile_digest == context.profile_digest
            && self.roster_digest == context.roster_digest
            && self.key_material_digest == context.key_material_digest
            && self.epoch == context.epoch
            && self.transcript_digest == context.transcript_digest
            && self.session_digest == context.session_digest
    }
    fn statement_digest(&self) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
        commit_statement_digest(
            self.phase,
            self.profile_digest,
            self.roster_digest,
            self.key_material_digest,
            self.epoch,
            self.transcript_digest,
            self.session_digest,
            self.party_index,
            self.party,
            self.commitment,
        )
    }
    fn encode_unsigned(&self) -> Vec<u8> {
        encode_commit_unsigned_fields(
            self.phase,
            self.profile_digest,
            self.roster_digest,
            self.key_material_digest,
            self.epoch,
            self.transcript_digest,
            self.session_digest,
            self.party_index,
            self.party,
            self.commitment,
        )
    }
    fn encode_canonical(&self) -> Vec<u8> {
        let mut bytes = self.encode_unsigned();
        encode_authentication(&mut bytes, &self.authentication);
        debug_assert_eq!(bytes.len(), ZK_AMS_PHASE23_FRESHNESS_COMMIT_WIRE_BYTES_V1);
        bytes
    }
}
struct SecretRevealV1([u8; 32]);
impl Drop for SecretRevealV1 {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
/// Opaque local reveal state returned with a commitment.
///
/// It is deliberately neither cloneable nor serializable and is redacted from debug output. A
/// signed reveal can be opened only against a fully verified exact commitment set.
pub struct ZkAmsPhase23PendingRevealV1 {
    context_digest: [u8; 32],
    commit_statement_digest: [u8; 32],
    party_index: u8,
    party: ZkAmsMkhePartyIdV1,
    commitment: [u8; 32],
    reveal: SecretRevealV1,
}
impl core::fmt::Debug for ZkAmsPhase23PendingRevealV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ZkAmsPhase23PendingRevealV1([REDACTED])")
    }
}
/// Commit one governed party's fresh nonzero reveal.
pub fn commit_zk_ams_phase23_freshness_v1<R: MaskedRelaxedRandomSourceV1>(
    context: &ZkAmsPhase23FreshnessContextV1,
    party_index: usize,
    secret: &ZkAmsMkheActivePartySecretV1,
    random: &mut R,
) -> Result<(ZkAmsPhase23FreshnessCommitV1, ZkAmsPhase23PendingRevealV1), ZkAmsMkheErrorV1> {
    context.validate()?;
    let (party, public_key) = context.participant(party_index)?;
    if secret.party()? != party || secret.public_key()? != public_key {
        return Err(ZkAmsMkheErrorV1::InvalidAuthentication);
    }
    let reveal = sample_nonzero_reveal(random)?;
    let party_index = u8::try_from(party_index).map_err(|_| ZkAmsMkheErrorV1::InvalidPartySet)?;
    let commitment = reveal_commitment(context, party_index, party, &reveal.0)?;
    let statement_digest = commit_statement_digest(
        context.phase,
        context.profile_digest,
        context.roster_digest,
        context.key_material_digest,
        context.epoch,
        context.transcript_digest,
        context.session_digest,
        party_index,
        party,
        commitment,
    )?;
    let authentication = authenticate(
        secret,
        COMMIT_AUTHENTICATION_DOMAIN_V1,
        statement_digest,
        random,
    )?;
    let commit = ZkAmsPhase23FreshnessCommitV1 {
        phase: context.phase,
        profile_digest: context.profile_digest,
        roster_digest: context.roster_digest,
        key_material_digest: context.key_material_digest,
        epoch: context.epoch,
        transcript_digest: context.transcript_digest,
        session_digest: context.session_digest,
        party_index,
        party,
        commitment,
        authentication,
    };
    commit.verify(context)?;
    let pending = ZkAmsPhase23PendingRevealV1 {
        context_digest: context.digest()?,
        commit_statement_digest: statement_digest,
        party_index,
        party,
        commitment,
        reveal,
    };
    Ok((commit, pending))
}
/// Exact canonical commitment set verified before reveal-round processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkAmsPhase23VerifiedCommitSetV1 {
    context: ZkAmsPhase23FreshnessContextV1,
    commits: [ZkAmsPhase23FreshnessCommitV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
    transcript_digest: [u8; 32],
}
impl ZkAmsPhase23VerifiedCommitSetV1 {
    /// Verify exactly eight commitments in governed roster order.
    pub fn verify_exact(
        context: &ZkAmsPhase23FreshnessContextV1,
        commits: &[ZkAmsPhase23FreshnessCommitV1],
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        context.validate()?;
        let commits: [ZkAmsPhase23FreshnessCommitV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1] = commits
            .try_into()
            .map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)?;
        for (index, commit) in commits.iter().enumerate() {
            if usize::from(commit.party_index) != index {
                return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
            }
            commit.verify(context)?;
        }
        let transcript_digest = commit_transcript_digest(context, &commits)?;
        Ok(Self {
            context: *context,
            commits,
            transcript_digest,
        })
    }
    /// Digest of the exact ordered signed commitment transcript.
    #[must_use]
    pub const fn transcript_digest(&self) -> [u8; 32] {
        self.transcript_digest
    }
}
/// One canonical authenticated freshness reveal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAmsPhase23FreshnessRevealV1 {
    phase: ZkAmsPhase23FreshnessPhaseV1,
    profile_digest: [u8; 32],
    roster_digest: [u8; 32],
    key_material_digest: [u8; 32],
    epoch: u64,
    transcript_digest: [u8; 32],
    session_digest: [u8; 32],
    party_index: u8,
    party: ZkAmsMkhePartyIdV1,
    commitment: [u8; 32],
    reveal: [u8; 32],
    authentication: ZkAmsMkheAuthenticationWireV1,
}
impl ZkAmsPhase23FreshnessRevealV1 {
    /// Canonical roster slot authenticated by this reveal.
    #[must_use]
    pub const fn party_index(&self) -> u8 {
        self.party_index
    }
    /// Encode one reveal only after the complete commitment set is verified.
    pub fn encode(
        &self,
        commits: &ZkAmsPhase23VerifiedCommitSetV1,
    ) -> Result<Vec<u8>, ZkAmsMkheErrorV1> {
        self.verify(commits)?;
        Ok(self.encode_canonical())
    }
    /// Decode and authenticate one reveal after all commitments are verified.
    pub fn decode_exact(
        bytes: &[u8],
        commits: &ZkAmsPhase23VerifiedCommitSetV1,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        if bytes.len() != ZK_AMS_PHASE23_FRESHNESS_REVEAL_WIRE_BYTES_V1 {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        let mut decoder = FixedDecoder::new(bytes);
        decoder.expect(&REVEAL_TAG_V1)?;
        decode_and_expect_context(&mut decoder, &commits.context)?;
        let party_index = decoder.u8()?;
        let party = ZkAmsMkhePartyIdV1::new(decoder.array()?)?;
        let commitment = decoder.array()?;
        let reveal = decoder.array()?;
        let authentication = decode_authentication(&mut decoder)?;
        decoder.finish()?;
        let value = Self {
            phase: commits.context.phase,
            profile_digest: commits.context.profile_digest,
            roster_digest: commits.context.roster_digest,
            key_material_digest: commits.context.key_material_digest,
            epoch: commits.context.epoch,
            transcript_digest: commits.context.transcript_digest,
            session_digest: commits.context.session_digest,
            party_index,
            party,
            commitment,
            reveal,
            authentication,
        };
        value.verify(commits)?;
        Ok(value)
    }
    fn verify(&self, commits: &ZkAmsPhase23VerifiedCommitSetV1) -> Result<(), ZkAmsMkheErrorV1> {
        let context = &commits.context;
        context.validate()?;
        if self.reveal == [0; 32]
            || self.phase != context.phase
            || self.profile_digest != context.profile_digest
            || self.roster_digest != context.roster_digest
            || self.key_material_digest != context.key_material_digest
            || self.epoch != context.epoch
            || self.transcript_digest != context.transcript_digest
            || self.session_digest != context.session_digest
        {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        let index = usize::from(self.party_index);
        let commit = commits
            .commits
            .get(index)
            .ok_or(ZkAmsMkheErrorV1::InvalidPhase23Fold)?;
        let (party, public_key) = context.participant(index)?;
        if self.party != party
            || self.party != commit.party
            || self.commitment != commit.commitment
            || self.authentication.party() != party
            || self.authentication.public_key() != public_key
            || reveal_commitment(context, self.party_index, self.party, &self.reveal)?
                != self.commitment
        {
            return Err(ZkAmsMkheErrorV1::InvalidAuthentication);
        }
        verify_authentication(
            &self.authentication,
            REVEAL_AUTHENTICATION_DOMAIN_V1,
            self.statement_digest()?,
        )
    }
    fn statement_digest(&self) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
        reveal_statement_digest(
            self.phase,
            self.profile_digest,
            self.roster_digest,
            self.key_material_digest,
            self.epoch,
            self.transcript_digest,
            self.session_digest,
            self.party_index,
            self.party,
            self.commitment,
            self.reveal,
        )
    }
    fn encode_unsigned(&self) -> Vec<u8> {
        encode_reveal_unsigned_fields(
            self.phase,
            self.profile_digest,
            self.roster_digest,
            self.key_material_digest,
            self.epoch,
            self.transcript_digest,
            self.session_digest,
            self.party_index,
            self.party,
            self.commitment,
            self.reveal,
        )
    }
    fn encode_canonical(&self) -> Vec<u8> {
        let mut bytes = self.encode_unsigned();
        encode_authentication(&mut bytes, &self.authentication);
        debug_assert_eq!(bytes.len(), ZK_AMS_PHASE23_FRESHNESS_REVEAL_WIRE_BYTES_V1);
        bytes
    }
}
/// Open and authenticate one reveal after every commitment is verified.
pub fn open_zk_ams_phase23_freshness_reveal_v1<R: MaskedRelaxedRandomSourceV1>(
    commits: &ZkAmsPhase23VerifiedCommitSetV1,
    pending: ZkAmsPhase23PendingRevealV1,
    secret: &ZkAmsMkheActivePartySecretV1,
    random: &mut R,
) -> Result<ZkAmsPhase23FreshnessRevealV1, ZkAmsMkheErrorV1> {
    let context = &commits.context;
    let index = usize::from(pending.party_index);
    let commit = commits
        .commits
        .get(index)
        .ok_or(ZkAmsMkheErrorV1::InvalidPhase23Fold)?;
    let (party, public_key) = context.participant(index)?;
    if pending.context_digest != context.digest()?
        || pending.commit_statement_digest != commit.statement_digest()?
        || pending.party != party
        || pending.commitment != commit.commitment
        || secret.party()? != party
        || secret.public_key()? != public_key
    {
        return Err(ZkAmsMkheErrorV1::InvalidAuthentication);
    }
    let reveal_bytes = pending.reveal.0;
    let statement_digest = reveal_statement_digest(
        context.phase,
        context.profile_digest,
        context.roster_digest,
        context.key_material_digest,
        context.epoch,
        context.transcript_digest,
        context.session_digest,
        pending.party_index,
        party,
        pending.commitment,
        reveal_bytes,
    )?;
    let authentication = authenticate(
        secret,
        REVEAL_AUTHENTICATION_DOMAIN_V1,
        statement_digest,
        random,
    )?;
    let reveal = ZkAmsPhase23FreshnessRevealV1 {
        phase: context.phase,
        profile_digest: context.profile_digest,
        roster_digest: context.roster_digest,
        key_material_digest: context.key_material_digest,
        epoch: context.epoch,
        transcript_digest: context.transcript_digest,
        session_digest: context.session_digest,
        party_index: pending.party_index,
        party,
        commitment: pending.commitment,
        reveal: reveal_bytes,
        authentication,
    };
    reveal.verify(commits)?;
    Ok(reveal)
}
/// Self-contained exact eight-party freshness transcript and public beacon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkAmsPhase23FreshnessReceiptV1 {
    context: ZkAmsPhase23FreshnessContextV1,
    commits: [ZkAmsPhase23FreshnessCommitV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
    reveals: [ZkAmsPhase23FreshnessRevealV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
    public_beacon: [u8; 32],
    receipt_digest: [u8; 32],
}
impl ZkAmsPhase23FreshnessReceiptV1 {
    /// Digest binding the context, every signed record, and the public beacon.
    #[must_use]
    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }
    /// Derive one domain-separated 256-bit public transcript challenge.
    ///
    /// This output is public after the reveal round. It must never be used as
    /// an RLWE encryption coin, an error-sampling seed, a secret mask, or a
    /// proof blinding nonce. Family/role combinations are closed and typed;
    /// record, chunk, and slot indices are absorbed independently.
    pub fn derive_public_challenge(
        &self,
        context: &ZkAmsPhase23FreshnessContextV1,
        family: ZkAmsPhase23PublicChallengeFamilyV1,
        role: ZkAmsPhase23PublicChallengeRoleV1,
        record_index: u32,
        chunk_index: u32,
        slot_index: u32,
    ) -> Result<ZkAmsPhase23PublicChallengeV1, ZkAmsMkheErrorV1> {
        self.validate(context)?;
        if !family.admits(role) {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        let mut frame = Vec::with_capacity(256);
        frame.extend_from_slice(PUBLIC_CHALLENGE_DOMAIN_V1);
        frame.push(MKHE_VERSION_V1);
        frame.push(context.phase as u8);
        frame.push(family as u8);
        frame.push(role as u8);
        frame.extend_from_slice(&context.digest()?);
        frame.extend_from_slice(&self.receipt_digest);
        frame.extend_from_slice(&self.public_beacon);
        frame.extend_from_slice(&record_index.to_be_bytes());
        frame.extend_from_slice(&chunk_index.to_be_bytes());
        frame.extend_from_slice(&slot_index.to_be_bytes());
        let bytes = shake256(&frame, 32)
            .try_into()
            .map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)?;
        Ok(ZkAmsPhase23PublicChallengeV1 {
            phase: context.phase,
            family,
            role,
            record_index,
            chunk_index,
            slot_index,
            bytes,
        })
    }
    /// Encode the complete exact-width transcript after revalidation.
    pub fn encode(
        &self,
        context: &ZkAmsPhase23FreshnessContextV1,
    ) -> Result<Vec<u8>, ZkAmsMkheErrorV1> {
        self.validate(context)?;
        Ok(self.encode_canonical())
    }
    /// Decode and verify a complete receipt under an independently trusted context.
    ///
    /// The decoder consumes and verifies all eight commitments before it reads
    /// the first reveal record.
    pub fn decode_exact(
        bytes: &[u8],
        context: &ZkAmsPhase23FreshnessContextV1,
    ) -> Result<Self, ZkAmsMkheErrorV1> {
        if bytes.len() != ZK_AMS_PHASE23_FRESHNESS_RECEIPT_WIRE_BYTES_V1 {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        let mut decoder = FixedDecoder::new(bytes);
        decoder.expect(&RECEIPT_TAG_V1)?;
        decode_and_expect_context(&mut decoder, context)?;
        decoder.expect_u8(RELEASE_ROSTER_COUNT_U8_V1)?;
        let mut commits = Vec::with_capacity(ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1);
        for _ in 0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 {
            commits.push(ZkAmsPhase23FreshnessCommitV1::decode_exact(
                decoder.take(ZK_AMS_PHASE23_FRESHNESS_COMMIT_WIRE_BYTES_V1)?,
                context,
            )?);
        }
        let verified = ZkAmsPhase23VerifiedCommitSetV1::verify_exact(context, &commits)?;
        decoder.expect_u8(RELEASE_ROSTER_COUNT_U8_V1)?;
        let mut reveals = Vec::with_capacity(ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1);
        for _ in 0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 {
            reveals.push(ZkAmsPhase23FreshnessRevealV1::decode_exact(
                decoder.take(ZK_AMS_PHASE23_FRESHNESS_REVEAL_WIRE_BYTES_V1)?,
                &verified,
            )?);
        }
        let public_beacon = decoder.array()?;
        let receipt_digest = decoder.array()?;
        decoder.finish()?;
        let receipt = Self {
            context: *context,
            commits: commits
                .try_into()
                .map_err(|_| ZkAmsMkheErrorV1::InvalidWireEncoding)?,
            reveals: reveals
                .try_into()
                .map_err(|_| ZkAmsMkheErrorV1::InvalidWireEncoding)?,
            public_beacon,
            receipt_digest,
        };
        receipt.validate(context)?;
        Ok(receipt)
    }
    fn validate(&self, context: &ZkAmsPhase23FreshnessContextV1) -> Result<(), ZkAmsMkheErrorV1> {
        if self.context != *context {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        let commits = ZkAmsPhase23VerifiedCommitSetV1::verify_exact(context, &self.commits)?;
        for (index, reveal) in self.reveals.iter().enumerate() {
            if usize::from(reveal.party_index) != index {
                return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
            }
            reveal.verify(&commits)?;
        }
        let expected_beacon = public_beacon(context, &self.commits, &self.reveals)?;
        if self.public_beacon != expected_beacon
            || self.receipt_digest
                != receipt_digest(context, &self.commits, &self.reveals, expected_beacon)?
        {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        Ok(())
    }
    fn encode_canonical(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ZK_AMS_PHASE23_FRESHNESS_RECEIPT_WIRE_BYTES_V1);
        bytes.extend_from_slice(&RECEIPT_TAG_V1);
        encode_context_binding(&mut bytes, &self.context);
        bytes.push(RELEASE_ROSTER_COUNT_U8_V1);
        for commit in &self.commits {
            bytes.extend_from_slice(&commit.encode_canonical());
        }
        bytes.push(RELEASE_ROSTER_COUNT_U8_V1);
        for reveal in &self.reveals {
            bytes.extend_from_slice(&reveal.encode_canonical());
        }
        bytes.extend_from_slice(&self.public_beacon);
        bytes.extend_from_slice(&self.receipt_digest);
        debug_assert_eq!(bytes.len(), ZK_AMS_PHASE23_FRESHNESS_RECEIPT_WIRE_BYTES_V1);
        bytes
    }
}
/// Verify all reveals and derive the sole final receipt and public beacon.
pub fn finalize_zk_ams_phase23_freshness_v1(
    commits: &ZkAmsPhase23VerifiedCommitSetV1,
    reveals: &[ZkAmsPhase23FreshnessRevealV1],
) -> Result<ZkAmsPhase23FreshnessReceiptV1, ZkAmsMkheErrorV1> {
    let reveals: [ZkAmsPhase23FreshnessRevealV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1] = reveals
        .try_into()
        .map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)?;
    for (index, reveal) in reveals.iter().enumerate() {
        if usize::from(reveal.party_index) != index {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
        reveal.verify(commits)?;
    }
    let public_beacon = public_beacon(&commits.context, &commits.commits, &reveals)?;
    let receipt_digest =
        receipt_digest(&commits.context, &commits.commits, &reveals, public_beacon)?;
    let receipt = ZkAmsPhase23FreshnessReceiptV1 {
        context: commits.context,
        commits: commits.commits,
        reveals,
        public_beacon,
        receipt_digest,
    };
    receipt.validate(&commits.context)?;
    Ok(receipt)
}
fn sample_nonzero_reveal<R: MaskedRelaxedRandomSourceV1>(
    random: &mut R,
) -> Result<SecretRevealV1, ZkAmsMkheErrorV1> {
    for _ in 0..MAX_REVEAL_REJECTION_ATTEMPTS_V1 {
        let mut reveal = SecretRevealV1([0; 32]);
        random
            .fill_bytes(&mut reveal.0)
            .map_err(|_| ZkAmsMkheErrorV1::RandomUnavailable)?;
        if reveal.0 != [0; 32] {
            return Ok(reveal);
        }
    }
    Err(ZkAmsMkheErrorV1::RandomUnavailable)
}
fn reveal_commitment(
    context: &ZkAmsPhase23FreshnessContextV1,
    party_index: u8,
    party: ZkAmsMkhePartyIdV1,
    reveal: &[u8; 32],
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    if *reveal == [0; 32] || usize::from(party_index) >= ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    let mut hash = Keccak256::new();
    hash.update(COMMITMENT_DOMAIN_V1);
    hash.update(&context.digest()?);
    hash.update(&[party_index]);
    hash.update(&party.to_bytes());
    hash.update(reveal);
    let commitment = hash.finalize();
    if commitment == [0; 32] {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    Ok(commitment)
}
#[allow(clippy::too_many_arguments)]
fn encode_commit_unsigned_fields(
    phase: ZkAmsPhase23FreshnessPhaseV1,
    profile_digest: [u8; 32],
    roster_digest: [u8; 32],
    key_material_digest: [u8; 32],
    epoch: u64,
    transcript_digest: [u8; 32],
    session_digest: [u8; 32],
    party_index: u8,
    party: ZkAmsMkhePartyIdV1,
    commitment: [u8; 32],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        ZK_AMS_PHASE23_FRESHNESS_COMMIT_WIRE_BYTES_V1 - AUTHENTICATION_WIRE_BYTES_V1,
    );
    bytes.extend_from_slice(&COMMIT_TAG_V1);
    encode_record_context(
        &mut bytes,
        phase,
        profile_digest,
        roster_digest,
        key_material_digest,
        epoch,
        transcript_digest,
        session_digest,
    );
    bytes.push(party_index);
    bytes.extend_from_slice(&party.to_bytes());
    bytes.extend_from_slice(&commitment);
    bytes
}
#[allow(clippy::too_many_arguments)]
fn commit_statement_digest(
    phase: ZkAmsPhase23FreshnessPhaseV1,
    profile_digest: [u8; 32],
    roster_digest: [u8; 32],
    key_material_digest: [u8; 32],
    epoch: u64,
    transcript_digest: [u8; 32],
    session_digest: [u8; 32],
    party_index: u8,
    party: ZkAmsMkhePartyIdV1,
    commitment: [u8; 32],
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut hash = Keccak256::new();
    hash.update(COMMIT_STATEMENT_DOMAIN_V1);
    hash.update(&encode_commit_unsigned_fields(
        phase,
        profile_digest,
        roster_digest,
        key_material_digest,
        epoch,
        transcript_digest,
        session_digest,
        party_index,
        party,
        commitment,
    ));
    let digest = hash.finalize();
    if digest == [0; 32] {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    Ok(digest)
}
#[allow(clippy::too_many_arguments)]
fn encode_reveal_unsigned_fields(
    phase: ZkAmsPhase23FreshnessPhaseV1,
    profile_digest: [u8; 32],
    roster_digest: [u8; 32],
    key_material_digest: [u8; 32],
    epoch: u64,
    transcript_digest: [u8; 32],
    session_digest: [u8; 32],
    party_index: u8,
    party: ZkAmsMkhePartyIdV1,
    commitment: [u8; 32],
    reveal: [u8; 32],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        ZK_AMS_PHASE23_FRESHNESS_REVEAL_WIRE_BYTES_V1 - AUTHENTICATION_WIRE_BYTES_V1,
    );
    bytes.extend_from_slice(&REVEAL_TAG_V1);
    encode_record_context(
        &mut bytes,
        phase,
        profile_digest,
        roster_digest,
        key_material_digest,
        epoch,
        transcript_digest,
        session_digest,
    );
    bytes.push(party_index);
    bytes.extend_from_slice(&party.to_bytes());
    bytes.extend_from_slice(&commitment);
    bytes.extend_from_slice(&reveal);
    bytes
}
#[allow(clippy::too_many_arguments)]
fn reveal_statement_digest(
    phase: ZkAmsPhase23FreshnessPhaseV1,
    profile_digest: [u8; 32],
    roster_digest: [u8; 32],
    key_material_digest: [u8; 32],
    epoch: u64,
    transcript_digest: [u8; 32],
    session_digest: [u8; 32],
    party_index: u8,
    party: ZkAmsMkhePartyIdV1,
    commitment: [u8; 32],
    reveal: [u8; 32],
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut hash = Keccak256::new();
    hash.update(REVEAL_STATEMENT_DOMAIN_V1);
    hash.update(&encode_reveal_unsigned_fields(
        phase,
        profile_digest,
        roster_digest,
        key_material_digest,
        epoch,
        transcript_digest,
        session_digest,
        party_index,
        party,
        commitment,
        reveal,
    ));
    let digest = hash.finalize();
    if digest == [0; 32] {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    Ok(digest)
}
fn authenticate<R: MaskedRelaxedRandomSourceV1>(
    secret: &ZkAmsMkheActivePartySecretV1,
    domain: &[u8],
    statement_digest: [u8; 32],
    random: &mut R,
) -> Result<ZkAmsMkheAuthenticationWireV1, ZkAmsMkheErrorV1> {
    let authentication = secret.authenticate_artifact(domain, statement_digest, random)?;
    ZkAmsMkheAuthenticationWireV1::new(
        authentication.party,
        authentication.public_key,
        authentication.signature,
    )
}
fn verify_authentication(
    authentication: &ZkAmsMkheAuthenticationWireV1,
    domain: &[u8],
    statement_digest: [u8; 32],
) -> Result<(), ZkAmsMkheErrorV1> {
    ArtifactAuthentication {
        version: MKHE_VERSION_V1,
        party: authentication.party(),
        public_key: authentication.public_key(),
        signature: authentication.signature(),
    }
    .verify(domain, statement_digest)
}
fn commit_transcript_digest(
    context: &ZkAmsPhase23FreshnessContextV1,
    commits: &[ZkAmsPhase23FreshnessCommitV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut hash = Keccak256::new();
    hash.update(COMMIT_TRANSCRIPT_DOMAIN_V1);
    hash.update(&context.digest()?);
    hash.update(&[RELEASE_ROSTER_COUNT_U8_V1]);
    for commit in commits {
        hash.update(&commit.encode_canonical());
    }
    Ok(hash.finalize())
}
fn reveal_transcript_digest(
    context: &ZkAmsPhase23FreshnessContextV1,
    reveals: &[ZkAmsPhase23FreshnessRevealV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut hash = Keccak256::new();
    hash.update(REVEAL_TRANSCRIPT_DOMAIN_V1);
    hash.update(&context.digest()?);
    hash.update(&[RELEASE_ROSTER_COUNT_U8_V1]);
    for reveal in reveals {
        hash.update(&reveal.encode_canonical());
    }
    Ok(hash.finalize())
}
fn public_beacon(
    context: &ZkAmsPhase23FreshnessContextV1,
    commits: &[ZkAmsPhase23FreshnessCommitV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
    reveals: &[ZkAmsPhase23FreshnessRevealV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut frame = Vec::with_capacity(ZK_AMS_PHASE23_FRESHNESS_RECEIPT_WIRE_BYTES_V1);
    frame.extend_from_slice(PUBLIC_BEACON_DOMAIN_V1);
    frame.extend_from_slice(&context.digest()?);
    frame.extend_from_slice(&commit_transcript_digest(context, commits)?);
    frame.extend_from_slice(&reveal_transcript_digest(context, reveals)?);
    frame.push(RELEASE_ROSTER_COUNT_U8_V1);
    for commit in commits {
        frame.extend_from_slice(&commit.encode_canonical());
    }
    for reveal in reveals {
        frame.extend_from_slice(&reveal.encode_canonical());
    }
    shake256(&frame, 32)
        .try_into()
        .map_err(|_| ZkAmsMkheErrorV1::InvalidPhase23Fold)
}
fn receipt_digest(
    context: &ZkAmsPhase23FreshnessContextV1,
    commits: &[ZkAmsPhase23FreshnessCommitV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
    reveals: &[ZkAmsPhase23FreshnessRevealV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1],
    public_beacon: [u8; 32],
) -> Result<[u8; 32], ZkAmsMkheErrorV1> {
    let mut hash = Keccak256::new();
    hash.update(RECEIPT_DIGEST_DOMAIN_V1);
    hash.update(&context.digest()?);
    hash.update(&commit_transcript_digest(context, commits)?);
    hash.update(&reveal_transcript_digest(context, reveals)?);
    hash.update(&public_beacon);
    for commit in commits {
        hash.update(&commit.encode_canonical());
    }
    for reveal in reveals {
        hash.update(&reveal.encode_canonical());
    }
    Ok(hash.finalize())
}
fn update_context_hash(hash: &mut Keccak256, context: &ZkAmsPhase23FreshnessContextV1) {
    hash.update(&[MKHE_VERSION_V1]);
    hash.update(&[context.phase as u8]);
    hash.update(&[RELEASE_ROSTER_COUNT_U8_V1]);
    hash.update(&context.profile_digest);
    hash.update(&context.roster_digest);
    hash.update(&context.key_material_digest);
    hash.update(&context.epoch.to_be_bytes());
    hash.update(&context.transcript_digest);
    hash.update(&context.session_digest);
}
#[allow(
    clippy::too_many_arguments,
    reason = "the canonical record prefix encodes each context axis independently"
)]
fn encode_record_context(
    bytes: &mut Vec<u8>,
    phase: ZkAmsPhase23FreshnessPhaseV1,
    profile_digest: [u8; 32],
    roster_digest: [u8; 32],
    key_material_digest: [u8; 32],
    epoch: u64,
    transcript_digest: [u8; 32],
    session_digest: [u8; 32],
) {
    bytes.push(MKHE_VERSION_V1);
    bytes.push(phase as u8);
    bytes.push(RELEASE_ROSTER_COUNT_U8_V1);
    bytes.extend_from_slice(&profile_digest);
    bytes.extend_from_slice(&roster_digest);
    bytes.extend_from_slice(&key_material_digest);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(&transcript_digest);
    bytes.extend_from_slice(&session_digest);
}
fn encode_context_binding(bytes: &mut Vec<u8>, context: &ZkAmsPhase23FreshnessContextV1) {
    encode_record_context(
        bytes,
        context.phase,
        context.profile_digest,
        context.roster_digest,
        context.key_material_digest,
        context.epoch,
        context.transcript_digest,
        context.session_digest,
    );
}
fn decode_and_expect_context(
    decoder: &mut FixedDecoder<'_>,
    context: &ZkAmsPhase23FreshnessContextV1,
) -> Result<(), ZkAmsMkheErrorV1> {
    context.validate()?;
    decoder.expect_u8(MKHE_VERSION_V1)?;
    if ZkAmsPhase23FreshnessPhaseV1::try_from(decoder.u8()?)? != context.phase {
        return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
    }
    decoder.expect_u8(RELEASE_ROSTER_COUNT_U8_V1)?;
    if decoder.array::<32>()? != context.profile_digest
        || decoder.array::<32>()? != context.roster_digest
        || decoder.array::<32>()? != context.key_material_digest
        || decoder.u64()? != context.epoch
        || decoder.array::<32>()? != context.transcript_digest
        || decoder.array::<32>()? != context.session_digest
    {
        return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
    }
    Ok(())
}
fn encode_authentication(bytes: &mut Vec<u8>, authentication: &ZkAmsMkheAuthenticationWireV1) {
    bytes.push(MKHE_VERSION_V1);
    bytes.extend_from_slice(&authentication.party().to_bytes());
    bytes.extend_from_slice(&authentication.public_key());
    bytes.extend_from_slice(&authentication.signature());
}
fn decode_authentication(
    decoder: &mut FixedDecoder<'_>,
) -> Result<ZkAmsMkheAuthenticationWireV1, ZkAmsMkheErrorV1> {
    decoder.expect_u8(MKHE_VERSION_V1)?;
    ZkAmsMkheAuthenticationWireV1::new(
        ZkAmsMkhePartyIdV1::new(decoder.array()?)?,
        decoder.array()?,
        decoder.array()?,
    )
}
struct FixedDecoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl<'a> FixedDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], ZkAmsMkheErrorV1> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(ZkAmsMkheErrorV1::InvalidWireEncoding)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(ZkAmsMkheErrorV1::InvalidWireEncoding)?;
        self.cursor = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ZkAmsMkheErrorV1> {
        self.take(N)?
            .try_into()
            .map_err(|_| ZkAmsMkheErrorV1::InvalidWireEncoding)
    }
    fn u8(&mut self) -> Result<u8, ZkAmsMkheErrorV1> {
        Ok(self.array::<1>()?[0])
    }
    fn u64(&mut self) -> Result<u64, ZkAmsMkheErrorV1> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn expect(&mut self, expected: &[u8]) -> Result<(), ZkAmsMkheErrorV1> {
        if self.take(expected.len())? != expected {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        Ok(())
    }
    fn expect_u8(&mut self, expected: u8) -> Result<(), ZkAmsMkheErrorV1> {
        if self.u8()? != expected {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        Ok(())
    }
    fn finish(self) -> Result<(), ZkAmsMkheErrorV1> {
        if self.cursor != self.bytes.len() {
            return Err(ZkAmsMkheErrorV1::InvalidWireEncoding);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vega::{
        MaskedRelaxedRandomErrorV1,
        sponge::{keccak256, shake256},
    };
    use hex_literal::hex;
    use std::sync::OnceLock;
    struct KatRandom {
        seed: Vec<u8>,
        counter: u64,
    }
    impl KatRandom {
        fn new(label: &[u8]) -> Self {
            Self {
                seed: label.to_vec(),
                counter: 0,
            }
        }
    }
    impl MaskedRelaxedRandomSourceV1 for KatRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
            let mut written = 0;
            while written < destination.len() {
                let mut frame = self.seed.clone();
                frame.extend_from_slice(&self.counter.to_be_bytes());
                let block = keccak256(&frame);
                let take = (destination.len() - written).min(block.len());
                destination[written..written + take].copy_from_slice(&block[..take]);
                written += take;
                self.counter = self.counter.wrapping_add(1);
            }
            Ok(())
        }
    }
    struct FailingRandom;
    impl MaskedRelaxedRandomSourceV1 for FailingRandom {
        fn fill_bytes(
            &mut self,
            _destination: &mut [u8],
        ) -> Result<(), MaskedRelaxedRandomErrorV1> {
            Err(MaskedRelaxedRandomErrorV1::Unavailable)
        }
    }
    struct ZeroRandom;
    impl MaskedRelaxedRandomSourceV1 for ZeroRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
            destination.fill(0);
            Ok(())
        }
    }
    struct NeverRandom;
    impl MaskedRelaxedRandomSourceV1 for NeverRandom {
        fn fill_bytes(
            &mut self,
            _destination: &mut [u8],
        ) -> Result<(), MaskedRelaxedRandomErrorV1> {
            panic!("invalid context or party must fail before randomness")
        }
    }
    struct Fixture {
        roster: ZkAmsMkheGovernedActiveRosterV1,
        secrets: Vec<ZkAmsMkheActivePartySecretV1>,
    }
    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| fixture_with_label(b"phase23-freshness.fixture", 0x2301))
    }
    fn other_fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| fixture_with_label(b"phase23-freshness.other-fixture", 0x2301))
    }
    fn fixture_with_label(label: &[u8], epoch: u64) -> Fixture {
        let mut random = KatRandom::new(label);
        let mut secrets = (0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1)
            .map(|_| ZkAmsMkheActivePartySecretV1::generate(&mut random).unwrap())
            .collect::<Vec<_>>();
        secrets.sort_by_key(|secret| secret.party().unwrap());
        let ordered: [&ZkAmsMkheActivePartySecretV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1] =
            std::array::from_fn(|index| &secrets[index]);
        let roster = ZkAmsMkheGovernedActiveRosterV1::new(epoch, ordered, &mut random).unwrap();
        Fixture { roster, secrets }
    }
    fn digest(label: &[u8]) -> [u8; 32] {
        keccak256(label)
    }
    fn freshness_context(
        fixture: &Fixture,
        phase: ZkAmsPhase23FreshnessPhaseV1,
        transcript_label: &[u8],
        session_label: &[u8],
    ) -> ZkAmsPhase23FreshnessContextV1 {
        ZkAmsPhase23FreshnessContextV1::new(
            &fixture.roster,
            phase,
            digest(transcript_label),
            digest(session_label),
        )
        .unwrap()
    }
    fn freshness_context_at_epoch(
        fixture: &Fixture,
        epoch: u64,
        phase: ZkAmsPhase23FreshnessPhaseV1,
        transcript_label: &[u8],
        session_label: &[u8],
    ) -> ZkAmsPhase23FreshnessContextV1 {
        let ordered: [&ZkAmsMkheActivePartySecretV1; ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1] =
            std::array::from_fn(|index| &fixture.secrets[index]);
        let mut random = KatRandom::new(b"phase23-freshness.changed-epoch-roster");
        let roster = ZkAmsMkheGovernedActiveRosterV1::new(epoch, ordered, &mut random).unwrap();
        ZkAmsPhase23FreshnessContextV1::new(
            &roster,
            phase,
            digest(transcript_label),
            digest(session_label),
        )
        .unwrap()
    }
    fn party_label(prefix: &[u8], party_index: usize, suffix: &[u8]) -> Vec<u8> {
        let mut label = prefix.to_vec();
        label.extend_from_slice(&(party_index as u32).to_be_bytes());
        label.extend_from_slice(suffix);
        label
    }
    fn commit_round(
        fixture: &Fixture,
        context: &ZkAmsPhase23FreshnessContextV1,
        label: &[u8],
        changed_party: Option<usize>,
    ) -> (
        Vec<ZkAmsPhase23FreshnessCommitV1>,
        Vec<ZkAmsPhase23PendingRevealV1>,
    ) {
        let mut commits = Vec::with_capacity(ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1);
        let mut pending = Vec::with_capacity(ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1);
        for (index, secret) in fixture.secrets.iter().enumerate() {
            let suffix = if changed_party == Some(index) {
                b".changed".as_slice()
            } else {
                b".base".as_slice()
            };
            let mut random = KatRandom::new(&party_label(label, index, suffix));
            let (commit, reveal) =
                commit_zk_ams_phase23_freshness_v1(context, index, secret, &mut random).unwrap();
            commits.push(commit);
            pending.push(reveal);
        }
        (commits, pending)
    }
    fn open_round(
        fixture: &Fixture,
        commits: &ZkAmsPhase23VerifiedCommitSetV1,
        pending: Vec<ZkAmsPhase23PendingRevealV1>,
        label: &[u8],
    ) -> Vec<ZkAmsPhase23FreshnessRevealV1> {
        pending
            .into_iter()
            .enumerate()
            .map(|(index, pending)| {
                let mut random = KatRandom::new(&party_label(label, index, b".open"));
                open_zk_ams_phase23_freshness_reveal_v1(
                    commits,
                    pending,
                    &fixture.secrets[index],
                    &mut random,
                )
                .unwrap()
            })
            .collect()
    }
    struct CompleteRound {
        commits: Vec<ZkAmsPhase23FreshnessCommitV1>,
        verified: ZkAmsPhase23VerifiedCommitSetV1,
        reveals: Vec<ZkAmsPhase23FreshnessRevealV1>,
        receipt: ZkAmsPhase23FreshnessReceiptV1,
    }
    fn complete_round(
        fixture: &Fixture,
        context: &ZkAmsPhase23FreshnessContextV1,
        label: &[u8],
        changed_party: Option<usize>,
    ) -> CompleteRound {
        let (commits, pending) = commit_round(fixture, context, label, changed_party);
        let verified = ZkAmsPhase23VerifiedCommitSetV1::verify_exact(context, &commits).unwrap();
        let reveals = open_round(fixture, &verified, pending, label);
        let receipt = finalize_zk_ams_phase23_freshness_v1(&verified, &reveals).unwrap();
        CompleteRound {
            commits,
            verified,
            reveals,
            receipt,
        }
    }
    fn forged_authentication(
        authentication: ZkAmsMkheAuthenticationWireV1,
    ) -> ZkAmsMkheAuthenticationWireV1 {
        let mut signature = authentication.signature();
        signature[64] ^= 1;
        ZkAmsMkheAuthenticationWireV1::new(
            authentication.party(),
            authentication.public_key(),
            signature,
        )
        .unwrap()
    }
    #[test]
    fn exact_width_roundtrip_and_ordered_kat() {
        assert_eq!(ZK_AMS_PHASE23_FRESHNESS_COMMIT_WIRE_BYTES_V1, 371);
        assert_eq!(ZK_AMS_PHASE23_FRESHNESS_REVEAL_WIRE_BYTES_V1, 403);
        assert_eq!(ZK_AMS_PHASE23_FRESHNESS_RECEIPT_WIRE_BYTES_V1, 6_433);
        const { assert!(!ZK_AMS_PHASE23_FRESHNESS_CERTIFIES_HIDDEN_MASK_SHARES_V1) };
        let fixture = fixture();
        let context = freshness_context(
            fixture,
            ZkAmsPhase23FreshnessPhaseV1::PhaseIi,
            b"phase23-freshness.kat.transcript",
            b"phase23-freshness.kat.session",
        );
        assert_eq!(context.phase(), ZkAmsPhase23FreshnessPhaseV1::PhaseIi);
        assert_eq!(context.profile_digest(), fixture.roster.profile_digest());
        assert_eq!(context.roster_digest(), fixture.roster.roster_digest());
        assert_eq!(context.epoch(), fixture.roster.epoch());
        assert_eq!(
            context.transcript_digest(),
            digest(b"phase23-freshness.kat.transcript")
        );
        assert_eq!(
            context.session_digest(),
            digest(b"phase23-freshness.kat.session")
        );
        let round = complete_round(fixture, &context, b"phase23-freshness.kat", None);
        assert_ne!(round.verified.transcript_digest(), [0; 32]);
        for (index, commit) in round.commits.iter().enumerate() {
            assert_eq!(usize::from(commit.party_index()), index);
            assert_eq!(commit.party(), fixture.roster.participants()[index].party());
            assert_ne!(commit.commitment(), [0; 32]);
            let bytes = commit.encode(&context).unwrap();
            assert_eq!(bytes.len(), ZK_AMS_PHASE23_FRESHNESS_COMMIT_WIRE_BYTES_V1);
            assert_eq!(
                ZkAmsPhase23FreshnessCommitV1::decode_exact(&bytes, &context).unwrap(),
                *commit
            );
        }
        for (index, reveal) in round.reveals.iter().enumerate() {
            assert_eq!(usize::from(reveal.party_index()), index);
            let bytes = reveal.encode(&round.verified).unwrap();
            assert_eq!(bytes.len(), ZK_AMS_PHASE23_FRESHNESS_REVEAL_WIRE_BYTES_V1);
            assert_eq!(
                ZkAmsPhase23FreshnessRevealV1::decode_exact(&bytes, &round.verified).unwrap(),
                *reveal
            );
        }
        let bytes = round.receipt.encode(&context).unwrap();
        assert_eq!(bytes.len(), ZK_AMS_PHASE23_FRESHNESS_RECEIPT_WIRE_BYTES_V1);
        assert_eq!(
            ZkAmsPhase23FreshnessReceiptV1::decode_exact(&bytes, &context).unwrap(),
            round.receipt
        );
        // The oracle duplicates the specified SHAKE transcript directly from
        // the fixed canonical records, independently of `public_beacon`.
        let mut oracle = Vec::new();
        oracle.extend_from_slice(PUBLIC_BEACON_DOMAIN_V1);
        oracle.extend_from_slice(&context.digest().unwrap());
        oracle.extend_from_slice(
            &commit_transcript_digest(&context, &round.commits.as_slice().try_into().unwrap())
                .unwrap(),
        );
        oracle.extend_from_slice(
            &reveal_transcript_digest(&context, &round.reveals.as_slice().try_into().unwrap())
                .unwrap(),
        );
        oracle.push(RELEASE_ROSTER_COUNT_U8_V1);
        for commit in &round.commits {
            oracle.extend_from_slice(&commit.encode(&context).unwrap());
        }
        for reveal in &round.reveals {
            oracle.extend_from_slice(&reveal.encode(&round.verified).unwrap());
        }
        let oracle_beacon: [u8; 32] = shake256(&oracle, 32).try_into().unwrap();
        assert_eq!(round.receipt.public_beacon, oracle_beacon);
        assert_eq!(
            oracle_beacon,
            hex!("053ac797d8743d758abd9cc78987b34a4684ccf8f2f9b8c58cda209a68f28c0d")
        );
        assert_eq!(
            round.receipt.receipt_digest(),
            hex!("4084283cdd0195d2f1495c7dd69dbeefc655f09b8cc067d0a1892490d570933e")
        );
        eprintln!(
            "freshness public beacon KAT: {}",
            hex::encode(oracle_beacon)
        );
        eprintln!(
            "freshness receipt digest KAT: {}",
            hex::encode(round.receipt.receipt_digest())
        );
    }
    #[test]
    fn commit_set_rejects_missing_duplicate_reordered_excess_splice_and_binding_mutations() {
        let fixture = fixture();
        let context = freshness_context(
            fixture,
            ZkAmsPhase23FreshnessPhaseV1::PhaseIi,
            b"phase23-freshness.commit-set.transcript",
            b"phase23-freshness.commit-set.session",
        );
        let (commits, _pending) =
            commit_round(fixture, &context, b"phase23-freshness.commit-set", None);
        assert!(ZkAmsPhase23VerifiedCommitSetV1::verify_exact(&context, &commits).is_ok());
        assert!(
            ZkAmsPhase23VerifiedCommitSetV1::verify_exact(
                &context,
                &commits[..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 - 1]
            )
            .is_err()
        );
        let mut excess = commits.clone();
        excess.push(commits[0]);
        assert!(ZkAmsPhase23VerifiedCommitSetV1::verify_exact(&context, &excess).is_err());
        let mut duplicate = commits.clone();
        duplicate[1] = duplicate[0];
        assert!(ZkAmsPhase23VerifiedCommitSetV1::verify_exact(&context, &duplicate).is_err());
        let mut reordered = commits.clone();
        reordered.swap(2, 3);
        assert!(ZkAmsPhase23VerifiedCommitSetV1::verify_exact(&context, &reordered).is_err());
        let other_context = freshness_context(
            fixture,
            ZkAmsPhase23FreshnessPhaseV1::PhaseIi,
            b"phase23-freshness.commit-set.transcript",
            b"phase23-freshness.commit-set.other-session",
        );
        let (other_commits, _) = commit_round(
            fixture,
            &other_context,
            b"phase23-freshness.commit-set.other",
            None,
        );
        let mut spliced = commits.clone();
        spliced[4] = other_commits[4];
        assert!(ZkAmsPhase23VerifiedCommitSetV1::verify_exact(&context, &spliced).is_err());
        for mutation in 0..10 {
            let mut changed = commits.clone();
            match mutation {
                0 => changed[0].phase = ZkAmsPhase23FreshnessPhaseV1::PhaseIii,
                1 => changed[0].profile_digest[0] ^= 1,
                2 => changed[0].roster_digest[0] ^= 1,
                3 => changed[0].key_material_digest[0] ^= 1,
                4 => changed[0].epoch += 1,
                5 => changed[0].transcript_digest[0] ^= 1,
                6 => changed[0].session_digest[0] ^= 1,
                7 => changed[0].party_index = 1,
                8 => changed[0].party = changed[1].party,
                9 => changed[0].commitment[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(
                ZkAmsPhase23VerifiedCommitSetV1::verify_exact(&context, &changed).is_err(),
                "commit mutation {mutation} must fail"
            );
        }
        let mut forged = commits.clone();
        forged[0].authentication = forged_authentication(forged[0].authentication);
        assert!(ZkAmsPhase23VerifiedCommitSetV1::verify_exact(&context, &forged).is_err());
        let mut invalid_context = context;
        invalid_context.profile_digest[0] ^= 1;
        assert!(ZkAmsPhase23VerifiedCommitSetV1::verify_exact(&invalid_context, &commits).is_err());
    }
    #[test]
    fn reveal_set_rejects_replay_mismatch_wrong_order_and_cross_domain_authentication() {
        let fixture = fixture();
        let context = freshness_context(
            fixture,
            ZkAmsPhase23FreshnessPhaseV1::PhaseIii,
            b"phase23-freshness.reveal-set.transcript",
            b"phase23-freshness.reveal-set.session",
        );
        let round = complete_round(fixture, &context, b"phase23-freshness.reveal-set", None);
        assert!(
            finalize_zk_ams_phase23_freshness_v1(
                &round.verified,
                &round.reveals[..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 - 1]
            )
            .is_err()
        );
        let mut excess = round.reveals.clone();
        excess.push(round.reveals[0]);
        assert!(finalize_zk_ams_phase23_freshness_v1(&round.verified, &excess).is_err());
        let mut duplicate = round.reveals.clone();
        duplicate[2] = duplicate[1];
        assert!(finalize_zk_ams_phase23_freshness_v1(&round.verified, &duplicate).is_err());
        let mut reordered = round.reveals.clone();
        reordered.swap(5, 6);
        assert!(finalize_zk_ams_phase23_freshness_v1(&round.verified, &reordered).is_err());
        for mutation in 0..11 {
            let mut changed = round.reveals.clone();
            match mutation {
                0 => changed[0].phase = ZkAmsPhase23FreshnessPhaseV1::PhaseIi,
                1 => changed[0].profile_digest[0] ^= 1,
                2 => changed[0].roster_digest[0] ^= 1,
                3 => changed[0].key_material_digest[0] ^= 1,
                4 => changed[0].epoch += 1,
                5 => changed[0].transcript_digest[0] ^= 1,
                6 => changed[0].session_digest[0] ^= 1,
                7 => changed[0].party_index = 1,
                8 => changed[0].party = changed[1].party,
                9 => changed[0].commitment[0] ^= 1,
                10 => changed[0].reveal[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(
                finalize_zk_ams_phase23_freshness_v1(&round.verified, &changed).is_err(),
                "reveal mutation {mutation} must fail"
            );
        }
        let mut zero = round.reveals.clone();
        zero[0].reveal = [0; 32];
        assert!(finalize_zk_ams_phase23_freshness_v1(&round.verified, &zero).is_err());
        let mut forged = round.reveals.clone();
        forged[0].authentication = forged_authentication(forged[0].authentication);
        assert!(finalize_zk_ams_phase23_freshness_v1(&round.verified, &forged).is_err());
        // A valid commitment signature cannot cross the distinct reveal domain.
        let mut cross_domain = round.reveals.clone();
        cross_domain[0].authentication = round.commits[0].authentication;
        assert!(finalize_zk_ams_phase23_freshness_v1(&round.verified, &cross_domain).is_err());
        let replay_context = freshness_context(
            fixture,
            ZkAmsPhase23FreshnessPhaseV1::PhaseIii,
            b"phase23-freshness.reveal-set.transcript",
            b"phase23-freshness.reveal-set.replay-session",
        );
        let replay_round = complete_round(
            fixture,
            &replay_context,
            b"phase23-freshness.reveal-set.replay",
            None,
        );
        let mut spliced = round.reveals.clone();
        spliced[3] = replay_round.reveals[3];
        assert!(finalize_zk_ams_phase23_freshness_v1(&round.verified, &spliced).is_err());
    }
    #[test]
    fn reveal_state_machine_and_random_failure_are_bounded_and_fail_closed() {
        let fixture = fixture();
        let context = freshness_context(
            fixture,
            ZkAmsPhase23FreshnessPhaseV1::PhaseIi,
            b"phase23-freshness.rng.transcript",
            b"phase23-freshness.rng.session",
        );
        assert_eq!(
            commit_zk_ams_phase23_freshness_v1(
                &context,
                0,
                &fixture.secrets[0],
                &mut FailingRandom
            )
            .unwrap_err(),
            ZkAmsMkheErrorV1::RandomUnavailable
        );
        assert_eq!(
            commit_zk_ams_phase23_freshness_v1(&context, 0, &fixture.secrets[0], &mut ZeroRandom)
                .unwrap_err(),
            ZkAmsMkheErrorV1::RandomUnavailable
        );
        assert_eq!(
            commit_zk_ams_phase23_freshness_v1(&context, 0, &fixture.secrets[1], &mut NeverRandom)
                .unwrap_err(),
            ZkAmsMkheErrorV1::InvalidAuthentication
        );
        let (commits, mut pending) =
            commit_round(fixture, &context, b"phase23-freshness.rng.round", None);
        // Seven commitments cannot construct the type required by every reveal API.
        assert!(ZkAmsPhase23VerifiedCommitSetV1::verify_exact(&context, &commits[..7]).is_err());
        let verified = ZkAmsPhase23VerifiedCommitSetV1::verify_exact(&context, &commits).unwrap();
        let first_pending = pending.remove(0);
        assert_eq!(
            open_zk_ams_phase23_freshness_reveal_v1(
                &verified,
                first_pending,
                &fixture.secrets[0],
                &mut ZeroRandom
            )
            .unwrap_err(),
            ZkAmsMkheErrorV1::RandomUnavailable
        );
        assert!(format!("{:?}", pending.remove(0)).contains("[REDACTED]"));
    }
    #[test]
    fn canonical_wire_rejects_truncation_trailing_counts_context_and_mutation() {
        let fixture = fixture();
        let context = freshness_context(
            fixture,
            ZkAmsPhase23FreshnessPhaseV1::PhaseIi,
            b"phase23-freshness.wire.transcript",
            b"phase23-freshness.wire.session",
        );
        let round = complete_round(fixture, &context, b"phase23-freshness.wire", None);
        let commit = round.commits[0].encode(&context).unwrap();
        let reveal = round.reveals[0].encode(&round.verified).unwrap();
        let receipt = round.receipt.encode(&context).unwrap();
        for length in 0..commit.len() {
            assert!(
                ZkAmsPhase23FreshnessCommitV1::decode_exact(&commit[..length], &context).is_err()
            );
        }
        let mut trailing = commit.clone();
        trailing.push(0);
        assert!(ZkAmsPhase23FreshnessCommitV1::decode_exact(&trailing, &context).is_err());
        for index in 0..commit.len() {
            let mut changed = commit.clone();
            changed[index] ^= 1;
            assert!(
                ZkAmsPhase23FreshnessCommitV1::decode_exact(&changed, &context).is_err(),
                "commit wire mutation {index} must fail"
            );
        }
        for length in 0..reveal.len() {
            assert!(
                ZkAmsPhase23FreshnessRevealV1::decode_exact(&reveal[..length], &round.verified)
                    .is_err()
            );
        }
        let mut trailing = reveal.clone();
        trailing.push(0);
        assert!(ZkAmsPhase23FreshnessRevealV1::decode_exact(&trailing, &round.verified).is_err());
        for index in 0..reveal.len() {
            let mut changed = reveal.clone();
            changed[index] ^= 1;
            assert!(
                ZkAmsPhase23FreshnessRevealV1::decode_exact(&changed, &round.verified).is_err(),
                "reveal wire mutation {index} must fail"
            );
        }
        for length in 0..receipt.len() {
            assert!(
                ZkAmsPhase23FreshnessReceiptV1::decode_exact(&receipt[..length], &context).is_err()
            );
        }
        let mut trailing = receipt.clone();
        trailing.push(0);
        assert!(ZkAmsPhase23FreshnessReceiptV1::decode_exact(&trailing, &context).is_err());
        let commit_count_offset = RECEIPT_CONTEXT_WIRE_BYTES_V1;
        let reveal_count_offset = commit_count_offset
            + 1
            + ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 * ZK_AMS_PHASE23_FRESHNESS_COMMIT_WIRE_BYTES_V1;
        for offset in [
            0,
            4,
            5,
            6,
            7,
            39,
            71,
            103,
            111,
            143,
            commit_count_offset,
            reveal_count_offset,
            receipt.len() - 64,
            receipt.len() - 1,
        ] {
            let mut changed = receipt.clone();
            changed[offset] ^= if offset == commit_count_offset || offset == reveal_count_offset {
                0xff
            } else {
                1
            };
            assert!(
                ZkAmsPhase23FreshnessReceiptV1::decode_exact(&changed, &context).is_err(),
                "receipt mutation at {offset} must fail"
            );
        }
        let wrong_session = freshness_context(
            fixture,
            ZkAmsPhase23FreshnessPhaseV1::PhaseIi,
            b"phase23-freshness.wire.transcript",
            b"phase23-freshness.wire.wrong-session",
        );
        assert!(ZkAmsPhase23FreshnessCommitV1::decode_exact(&commit, &wrong_session).is_err());
        assert!(ZkAmsPhase23FreshnessReceiptV1::decode_exact(&receipt, &wrong_session).is_err());
    }
    #[test]
    fn every_contribution_and_context_axis_changes_beacon_and_public_challenges_are_typed() {
        let fixture = fixture();
        let base_context = freshness_context(
            fixture,
            ZkAmsPhase23FreshnessPhaseV1::PhaseIi,
            b"phase23-freshness.axes.transcript",
            b"phase23-freshness.axes.session",
        );
        let base = complete_round(fixture, &base_context, b"phase23-freshness.axes", None);
        for party in 0..ZK_AMS_MKHE_RELEASE_ROSTER_SIZE_V1 {
            let changed = complete_round(
                fixture,
                &base_context,
                b"phase23-freshness.axes",
                Some(party),
            );
            assert_ne!(
                changed.receipt.public_beacon, base.receipt.public_beacon,
                "party {party} contribution must change the beacon"
            );
        }
        let contexts = [
            (
                freshness_context(
                    fixture,
                    ZkAmsPhase23FreshnessPhaseV1::PhaseIii,
                    b"phase23-freshness.axes.transcript",
                    b"phase23-freshness.axes.session",
                ),
                fixture,
            ),
            (
                freshness_context(
                    fixture,
                    ZkAmsPhase23FreshnessPhaseV1::PhaseIi,
                    b"phase23-freshness.axes.other-transcript",
                    b"phase23-freshness.axes.session",
                ),
                fixture,
            ),
            (
                freshness_context(
                    fixture,
                    ZkAmsPhase23FreshnessPhaseV1::PhaseIi,
                    b"phase23-freshness.axes.transcript",
                    b"phase23-freshness.axes.other-session",
                ),
                fixture,
            ),
            (
                freshness_context_at_epoch(
                    fixture,
                    0x2302,
                    ZkAmsPhase23FreshnessPhaseV1::PhaseIi,
                    b"phase23-freshness.axes.transcript",
                    b"phase23-freshness.axes.session",
                ),
                fixture,
            ),
            (
                freshness_context(
                    other_fixture(),
                    ZkAmsPhase23FreshnessPhaseV1::PhaseIi,
                    b"phase23-freshness.axes.transcript",
                    b"phase23-freshness.axes.session",
                ),
                other_fixture(),
            ),
        ];
        for (index, (changed_context, changed_fixture)) in contexts.iter().enumerate() {
            let changed = complete_round(
                changed_fixture,
                changed_context,
                b"phase23-freshness.axes",
                None,
            );
            assert_ne!(
                changed.receipt.public_beacon, base.receipt.public_beacon,
                "context axis {index} must change the beacon"
            );
        }
        let mut invalid_profile = base_context;
        invalid_profile.profile_digest[0] ^= 1;
        assert!(invalid_profile.digest().is_err());
        let args = (
            ZkAmsPhase23PublicChallengeFamilyV1::MaskShareStatement,
            ZkAmsPhase23PublicChallengeRoleV1::ReplicatedUStatement,
            9,
            4,
            2,
        );
        let challenge = base
            .receipt
            .derive_public_challenge(&base_context, args.0, args.1, args.2, args.3, args.4)
            .unwrap();
        assert_eq!(challenge.phase(), ZkAmsPhase23FreshnessPhaseV1::PhaseIi);
        assert_eq!(challenge.family(), args.0);
        assert_eq!(challenge.role(), args.1);
        assert_eq!(challenge.record_index(), args.2);
        assert_eq!(challenge.chunk_index(), args.3);
        assert_eq!(challenge.slot_index(), args.4);
        assert_ne!(challenge.to_bytes(), [0; 32]);
        for changed in [
            base.receipt
                .derive_public_challenge(
                    &base_context,
                    ZkAmsPhase23PublicChallengeFamilyV1::FoldProof,
                    ZkAmsPhase23PublicChallengeRoleV1::FoldProofTranscript,
                    args.2,
                    args.3,
                    args.4,
                )
                .unwrap(),
            base.receipt
                .derive_public_challenge(
                    &base_context,
                    ZkAmsPhase23PublicChallengeFamilyV1::CollectiveEncryptionStatement,
                    ZkAmsPhase23PublicChallengeRoleV1::CollectiveEncryptionProof,
                    args.2,
                    args.3,
                    args.4,
                )
                .unwrap(),
            base.receipt
                .derive_public_challenge(
                    &base_context,
                    ZkAmsPhase23PublicChallengeFamilyV1::MaskShareStatement,
                    ZkAmsPhase23PublicChallengeRoleV1::EncryptedMaskShareProof,
                    args.2,
                    args.3,
                    args.4,
                )
                .unwrap(),
            base.receipt
                .derive_public_challenge(&base_context, args.0, args.1, args.2 + 1, args.3, args.4)
                .unwrap(),
            base.receipt
                .derive_public_challenge(&base_context, args.0, args.1, args.2, args.3 + 1, args.4)
                .unwrap(),
            base.receipt
                .derive_public_challenge(&base_context, args.0, args.1, args.2, args.3, args.4 + 1)
                .unwrap(),
        ] {
            assert_ne!(changed.to_bytes(), challenge.to_bytes());
        }
        assert!(
            base.receipt
                .derive_public_challenge(
                    &base_context,
                    ZkAmsPhase23PublicChallengeFamilyV1::MaskShareStatement,
                    ZkAmsPhase23PublicChallengeRoleV1::CollectiveEncryptionProof,
                    0,
                    0,
                    0,
                )
                .is_err()
        );
        // The only derivation API is explicitly public-challenge typed, and the
        // capability gate confirms no hidden mask-share protocol is certified.
        const { assert!(!ZK_AMS_PHASE23_FRESHNESS_CERTIFIES_HIDDEN_MASK_SHARES_V1) };
    }
}
