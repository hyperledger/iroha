//! Timed-OVN ballot participation for seated SORA Parliament jurors.
//!
//! A Policy Jury (or Confirmation Jury) member takes part in a private
//! timed-OVN ballot in three steps, each an ordinary signed transaction from the
//! configured account:
//!
//! 1. `ballot register` registers the juror's timed-OVN keys while the ballot
//!    is in `Registration` (`RegisterBallotParticipant`).
//! 2. `ballot dropout` optionally withdraws after registration closes and
//!    before the survivor freeze (`RecordBallotDropout`). Every registered
//!    juror who does not drop out MUST cast, or the ballot fails; a juror who
//!    lost the key file can still drop out, because dropping out never reads it.
//! 3. `ballot cast` appends the juror's masked ballot to the corpus while the
//!    ballot is in `TimedCommitment` (`FreezeTimedOvnCorpus`).
//!
//! `ballot status` shows this account's part in the active hidden ballots of an
//! attempt (and whether a key file can cast them), and `ballot relay` submits
//! other jurors' published records. The trusted checkpoint is pinned from an
//! independently authenticated canonical `SumeragiFinalityCheckpoint` file.
//! Every page extends its native certified decision and retained committee schedule.
//! Invitation responses, public-finding
//! endorsements and absences are the sibling `iroha gov parliament
//! respond-invitation|endorse|record-absence` commands, and the threshold
//! opening is `iroha gov parliament finalize-opened-ballot`.
//!
//! **Secrets.** Registration and ballot secrets are derived from one 32-byte
//! root seed held in an owner-only key file (see `files`), never from argv or
//! the environment. The derivation is the deterministic keyed-BLAKE3 scheme of
//! the native wallet bridge (`connect_norito_bridge`), with the same domain
//! separators, so a seed produces byte-identical records in the CLI and in a
//! wallet, and a repeated command never produces a second, different record.
//! Before any ballot bytes exist, `cast` atomically locks its choice in a
//! seat-bound file next to the key file, so no run with that key file can build
//! a ballot with a different choice for the same seat.
//!
//! **Trust.** Every command that publishes a record derived from the seed
//! (`register`, `cast`) first authenticates the casting context with a
//! consensus casting proof that begins at the state file's trusted checkpoint,
//! replays the Core archive and requires it to rederive the authenticated
//! compact binding. `dropout` does the same when a state file is named and
//! otherwise uses the public inspection context; `relay` and `status` use the
//! public context (`status` compares a key file with the committed registration
//! locally and sends nothing derived from it). Core re-validates every
//! submitted transition at execution. Ballot progress (the accepted prefix)
//! comes from the attempt projection, which is not consensus-authenticated.
//!
//! **Ballot order.** Core accepts masked ballots only as a contiguous prefix in
//! canonical survivor order. `cast` therefore submits the juror's record when
//! the accepted prefix reaches the juror's survivor index, optionally waiting for
//! it, and can export the public record so that anyone can `relay` it later.
//!
//! Every command reads Torii through [`BallotSource`], which [`Client`]
//! implements; the command logic itself never opens a connection.

mod files;
#[cfg(test)]
mod tests;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use eyre::{Result, WrapErr as _, bail, eyre};
use iroha::{
    client::Client,
    data_model::{
        account::AccountId,
        governance::types::{
            BallotAttemptId, BallotAttemptStatusV1, GovernanceAttemptId, ParliamentBody,
            parliament_ballot_participant_hash_v1,
        },
        isi::InstructionBox,
    },
};
use iroha_core_timed_ovn::casting::PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1;
use iroha_core_timed_ovn::casting::ParliamentTimedOvnCastingContextArchiveV1;
use iroha_core_timed_ovn::casting::ParliamentTimedOvnCastingPhaseV1;
use iroha_core_timed_ovn::casting::ValidatedParliamentTimedOvnCastingContextArchiveV1;
use iroha_crypto::timed_ovn::{
    TimedOvnChoiceV1, TimedOvnCommittedRegistrationCacheV1, TimedOvnMaskedBallotV1,
    TimedOvnRegistrationSecretV1,
};
use iroha_data_model::governance::types::PARLIAMENT_TIMED_OVN_BALLOT_RECORD_BYTES_V1 as TIMED_OVN_BALLOT_RECORD_BYTES_V1;
use iroha_data_model::governance::types::PARLIAMENT_TIMED_OVN_REGISTRATION_RECORD_BYTES_V1 as TIMED_OVN_REGISTRATION_RECORD_BYTES_V1;
use iroha_data_model::{
    NetworkId,
    governance::types::PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1,
    isi::governance::{
        ParliamentFreezeTimedOvnCorpusV1, ParliamentLifecycleTransitionV1,
        ParliamentRecordBallotDropoutV1, ParliamentRegisterBallotParticipantV1,
    },
    parliament_casting::ParliamentTimedOvnCastingContextBindingV1,
    sumeragi_finality::SumeragiFinalityCheckpoint,
};
use iroha_torii_shared::parliament_api::{
    PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BASE64_BYTES_V1,
    ParliamentBodyStateProjectionV1, ParliamentTimedOvnCastingProofResponseV1,
    ParliamentTimedOvnProgressProjectionV1,
};
use norito::json::JsonSerialize;
use rand::{TryCryptoRng, TryRngCore};
use zeroize::Zeroizing;

use self::files::{BallotState, TimedOvnSeedV1};
use super::{member::member_transition, parse_ballot_attempt_id, parse_governance_attempt_id};
use crate::{CliOutputFormat, Run, RunContext, gov::shared::print_with_summary};

/// Registration-secret RNG domain, shared with the native wallet bridge.
const REGISTRATION_RNG_DOMAIN_V1: &[u8] =
    b"iroha.connect.parliament.timed-ovn.registration-rng.v1\0";
/// Ballot-proof RNG domain, shared with the native wallet bridge.
const BALLOT_RNG_DOMAIN_V1: &[u8] = b"iroha.connect.parliament.timed-ovn.ballot-rng.v1\0";
/// Counter-block domain of the keyed RNG, shared with the native wallet bridge.
const RNG_BLOCK_DOMAIN_V1: &[u8] = b"iroha.connect.parliament.timed-ovn.rng-block.v1\0";
/// Maximum casting-proof pages fetched by one command.
const MAX_CASTING_PROOF_PAGES: u32 = 4_096;
/// Interval between accepted-prefix polls while `cast --wait-secs` waits.
const CAST_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Longest `cast --wait-secs` budget (one day).
const MAX_CAST_WAIT_SECS: u64 = 86_400;
/// Maximum number of records one `relay` accepts from files.
const MAX_RELAY_RECORD_FILES: usize = 1_000;
const ARCHIVE_NESTING_LIMIT_V1: usize = 64;
const ARCHIVE_ALLOCATION_MULTIPLIER_V1: usize = 16;
const ARCHIVE_FIXED_ALLOCATION_ALLOWANCE_V1: usize = 64 * 1024;

/// A juror's choice in a timed-OVN ballot.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum BallotChoiceArg {
    /// Vote for the proposal (`Aye`).
    Approve,
    /// Vote against the proposal (`Nay`).
    Reject,
    /// Count toward turnout without approving or rejecting (`Abstain`).
    Abstain,
}

impl BallotChoiceArg {
    /// Stable lowercase label.
    fn label(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Abstain => "abstain",
        }
    }

    /// Parse a stable lowercase label.
    fn from_label(label: &str) -> Option<Self> {
        match label {
            "approve" => Some(Self::Approve),
            "reject" => Some(Self::Reject),
            "abstain" => Some(Self::Abstain),
            _ => None,
        }
    }

    /// The timed-OVN one-hot choice.
    fn timed_ovn_choice(self) -> TimedOvnChoiceV1 {
        match self {
            Self::Approve => TimedOvnChoiceV1::Aye,
            Self::Reject => TimedOvnChoiceV1::Nay,
            Self::Abstain => TimedOvnChoiceV1::Abstain,
        }
    }
}

/// Zeroizing counter-mode keyed-BLAKE3 PRF (the native wallet bridge scheme).
struct KeyedBlake3Rng {
    key: Zeroizing<[u8; 32]>,
    block: Zeroizing<[u8; 32]>,
    block_cursor: usize,
    next_counter: u64,
}

/// The keyed RNG exhausted its 64-bit block counter.
#[derive(Debug)]
struct DeterministicRngExhausted;

impl core::fmt::Display for DeterministicRngExhausted {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("timed-OVN deterministic RNG exhausted")
    }
}

impl std::error::Error for DeterministicRngExhausted {}

impl KeyedBlake3Rng {
    fn derive(root_seed: &[u8; 32], context: &[u8]) -> Self {
        Self {
            key: Zeroizing::new(*blake3::keyed_hash(root_seed, context).as_bytes()),
            block: Zeroizing::new([0_u8; 32]),
            block_cursor: 32,
            next_counter: 0,
        }
    }

    fn refill(&mut self) -> Result<(), DeterministicRngExhausted> {
        let counter = self.next_counter;
        self.next_counter = self
            .next_counter
            .checked_add(1)
            .ok_or(DeterministicRngExhausted)?;
        let mut hasher = blake3::Hasher::new_keyed(&self.key);
        hasher.update(RNG_BLOCK_DOMAIN_V1);
        hasher.update(&counter.to_be_bytes());
        self.block.copy_from_slice(hasher.finalize().as_bytes());
        self.block_cursor = 0;
        Ok(())
    }
}

impl TryRngCore for KeyedBlake3Rng {
    type Error = DeterministicRngExhausted;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, mut destination: &mut [u8]) -> Result<(), Self::Error> {
        while !destination.is_empty() {
            if self.block_cursor == self.block.len() {
                self.refill()?;
            }
            let copied = (self.block.len() - self.block_cursor).min(destination.len());
            destination[..copied]
                .copy_from_slice(&self.block[self.block_cursor..self.block_cursor + copied]);
            self.block_cursor += copied;
            destination = &mut destination[copied..];
        }
        Ok(())
    }
}

impl TryCryptoRng for KeyedBlake3Rng {}

fn registration_rng(
    seed: &TimedOvnSeedV1,
    session_digest: &[u8; 32],
    participant_hash: &[u8; 32],
) -> KeyedBlake3Rng {
    let mut context = Vec::with_capacity(REGISTRATION_RNG_DOMAIN_V1.len() + 64);
    context.extend_from_slice(REGISTRATION_RNG_DOMAIN_V1);
    context.extend_from_slice(session_digest);
    context.extend_from_slice(participant_hash);
    KeyedBlake3Rng::derive(seed.as_bytes(), &context)
}

fn ballot_rng(
    seed: &TimedOvnSeedV1,
    session_digest: &[u8; 32],
    participant_hash: &[u8; 32],
    survivor_root: &[u8; 32],
    release_identity_digest: &[u8; 32],
    choice: TimedOvnChoiceV1,
) -> KeyedBlake3Rng {
    let mut context = Vec::with_capacity(BALLOT_RNG_DOMAIN_V1.len() + 32 * 4 + 1);
    context.extend_from_slice(BALLOT_RNG_DOMAIN_V1);
    context.extend_from_slice(session_digest);
    context.extend_from_slice(participant_hash);
    context.extend_from_slice(survivor_root);
    context.extend_from_slice(release_identity_digest);
    context.push(choice as u8);
    KeyedBlake3Rng::derive(seed.as_bytes(), &context)
}

/// Decode and replay one canonical casting-context archive.
fn decode_casting_archive(
    bytes: &[u8],
) -> Result<ValidatedParliamentTimedOvnCastingContextArchiveV1> {
    if bytes.is_empty() || bytes.len() > PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1 {
        bail!("Parliament casting archive is empty or exceeds its V1 bound");
    }
    // The validated archive owns registration and survivor collections whose
    // decoded allocation can exceed the wire size; the 4 MiB archive ceiling
    // bounds this explicit allowance.
    let limits = norito::DecodeLimits::new(
        bytes.len(),
        bytes.len(),
        bytes.len(),
        bytes
            .len()
            .saturating_mul(ARCHIVE_ALLOCATION_MULTIPLIER_V1)
            .saturating_add(ARCHIVE_FIXED_ALLOCATION_ALLOWANCE_V1),
        ARCHIVE_NESTING_LIMIT_V1,
    );
    let archive: ParliamentTimedOvnCastingContextArchiveV1 =
        norito::decode_canonical_with_limits(bytes, limits)
            .map_err(|error| eyre!("Parliament casting archive is not canonical: {error}"))?;
    archive
        .validate_v1()
        .map_err(|error| eyre!("Parliament casting archive failed replay validation: {error}"))
}

/// Decode and replay the archive of a public (unauthenticated) casting context
/// served for `ballot_attempt_id`.
///
/// The archive must be bounded, canonical padded standard base64 and must name
/// the requested ballot. Only seed-free commands use this; Core re-validates
/// every submitted transition against committed state.
fn public_casting_archive(
    archive_norito_base64: &str,
    ballot_attempt_id: BallotAttemptId,
) -> Result<ValidatedParliamentTimedOvnCastingContextArchiveV1> {
    if archive_norito_base64.is_empty()
        || archive_norito_base64.len()
            > PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BASE64_BYTES_V1
    {
        bail!("Parliament casting archive is empty or exceeds its base64 bound");
    }
    let bytes = BASE64_STANDARD
        .decode(archive_norito_base64.as_bytes())
        .ok()
        .filter(|bytes| BASE64_STANDARD.encode(bytes) == archive_norito_base64)
        .ok_or_else(|| {
            eyre!("Parliament casting archive is not canonical padded standard base64")
        })?;
    let context = decode_casting_archive(&bytes)?;
    if archive_ballot_attempt_id(&context) != ballot_attempt_id {
        bail!("Parliament casting archive names a different ballot attempt");
    }
    Ok(context)
}

/// Committed attempt facts read from the attempt projection.
#[derive(Clone, Debug)]
struct AttemptSnapshot {
    /// Committed height of the projection.
    current_height: u64,
    /// Public lifecycle projection of every required body.
    body_states: Vec<ParliamentBodyStateProjectionV1>,
}

/// Torii reads made by the ballot commands.
///
/// [`Client`] is the production source; tests substitute scripted responses,
/// so the command logic is exercised without a network.
trait BallotSource {
    /// One consensus casting-proof page that begins at `checkpoint`.
    fn casting_proof_page(
        &self,
        ballot_attempt_id: BallotAttemptId,
        checkpoint: &SumeragiFinalityCheckpoint,
    ) -> Result<ParliamentTimedOvnCastingProofResponseV1>;

    /// The public (unauthenticated) casting context, decoded and replayed.
    fn public_casting_context(
        &self,
        ballot_attempt_id: BallotAttemptId,
    ) -> Result<ValidatedParliamentTimedOvnCastingContextArchiveV1>;

    /// The committed projection of one Parliament attempt.
    fn attempt(&self, governance_attempt_id: GovernanceAttemptId) -> Result<AttemptSnapshot>;
}

impl BallotSource for Client {
    fn casting_proof_page(
        &self,
        ballot_attempt_id: BallotAttemptId,
        checkpoint: &SumeragiFinalityCheckpoint,
    ) -> Result<ParliamentTimedOvnCastingProofResponseV1> {
        self.get_parliament_timed_ovn_casting_proof_page(ballot_attempt_id, checkpoint)
            .map(|(page, _checkpoint)| page)
            .wrap_err("failed to fetch the Parliament casting proof")
    }

    fn public_casting_context(
        &self,
        ballot_attempt_id: BallotAttemptId,
    ) -> Result<ValidatedParliamentTimedOvnCastingContextArchiveV1> {
        let response = self
            .get_parliament_timed_ovn_casting_context(ballot_attempt_id)
            .wrap_err("failed to read the Parliament casting context")?;
        public_casting_archive(&response.archive_norito_base64, ballot_attempt_id)
    }

    fn attempt(&self, governance_attempt_id: GovernanceAttemptId) -> Result<AttemptSnapshot> {
        let response = self
            .get_parliament_attempt(governance_attempt_id)
            .wrap_err("failed to read the Parliament attempt")?;
        Ok(AttemptSnapshot {
            current_height: response.current_height,
            body_states: response.body_states,
        })
    }
}

/// Outcome of authenticating one casting-proof page.
enum CastingPageOutcome {
    /// An intermediate page: promote the checkpoint and fetch the next page.
    Promote(SumeragiFinalityCheckpoint),
    /// The terminal page with its replayed, binding-matched archive.
    Terminal {
        checkpoint: SumeragiFinalityCheckpoint,
        context: Box<ValidatedParliamentTimedOvnCastingContextArchiveV1>,
        binding: Box<ParliamentTimedOvnCastingContextBindingV1>,
    },
}

/// Authenticate one casting-proof page against the trusted checkpoint.
///
/// The finality chain, witness and membership are verified before the archive
/// is decoded, and a terminal archive is accepted only when its replay
/// rederives the authenticated compact binding exactly.
fn authenticate_casting_page(
    page: &ParliamentTimedOvnCastingProofResponseV1,
    network_id: NetworkId,
    checkpoint: &SumeragiFinalityCheckpoint,
    ballot_attempt_id: BallotAttemptId,
) -> Result<CastingPageOutcome> {
    let (binding, evaluated) = page
        .verify_consensus_page_against(network_id, checkpoint, ballot_attempt_id)
        .map_err(|reason| eyre!("Parliament casting proof verification failed: {reason}"))?;
    if page.evaluated_block_height < checkpoint.height()
        || (page.more_available && page.evaluated_block_height == checkpoint.height())
    {
        bail!("Parliament casting proof page does not advance the trusted checkpoint");
    }
    match (page.more_available, binding) {
        (true, None) => Ok(CastingPageOutcome::Promote(evaluated)),
        (false, Some(binding)) => {
            let archive = page
                .casting_context_archive
                .as_deref()
                .ok_or_else(|| eyre!("terminal Parliament casting proof omitted its archive"))?;
            let context = decode_casting_archive(archive)?;
            if !context.matches_compact_binding_v1(binding) {
                bail!("Parliament casting archive does not rederive the authenticated binding");
            }
            Ok(CastingPageOutcome::Terminal {
                checkpoint: evaluated,
                context: Box::new(context),
                binding: Box::new(binding.clone()),
            })
        }
        _ => bail!("Parliament casting proof page has an inconsistent terminal shape"),
    }
}

/// Consensus-authenticated casting context.
struct AuthenticatedCastingContext {
    context: ValidatedParliamentTimedOvnCastingContextArchiveV1,
    binding: ParliamentTimedOvnCastingContextBindingV1,
}

/// Fetch casting-proof pages from the trusted checkpoint to the tip, durably
/// promoting the checkpoint after every authenticated page.
fn fetch_authenticated_casting_context<S: BallotSource>(
    source: &S,
    network_id: NetworkId,
    ballot_attempt_id: BallotAttemptId,
    state: &mut BallotState,
) -> Result<AuthenticatedCastingContext> {
    for _ in 0..MAX_CASTING_PROOF_PAGES {
        let checkpoint = state.checkpoint();
        let page = source.casting_proof_page(ballot_attempt_id, &checkpoint)?;
        match authenticate_casting_page(&page, network_id, &checkpoint, ballot_attempt_id)? {
            CastingPageOutcome::Promote(next) => state.promote(next)?,
            CastingPageOutcome::Terminal {
                checkpoint,
                context,
                binding,
            } => {
                state.promote(checkpoint)?;
                return Ok(AuthenticatedCastingContext {
                    context: *context,
                    binding: *binding,
                });
            }
        }
    }
    bail!("Parliament casting proof did not terminate within {MAX_CASTING_PROOF_PAGES} pages")
}

/// Canonical governance attempt named by a casting archive.
fn archive_governance_attempt_id(
    context: &ValidatedParliamentTimedOvnCastingContextArchiveV1,
) -> GovernanceAttemptId {
    GovernanceAttemptId::new(context.archive().session().governance_attempt_id)
}

/// Canonical ballot attempt named by a casting archive.
fn archive_ballot_attempt_id(
    context: &ValidatedParliamentTimedOvnCastingContextArchiveV1,
) -> BallotAttemptId {
    BallotAttemptId::new(context.archive().session().ballot_attempt_id)
}

/// A juror's canonical registration for one ballot attempt.
#[derive(Debug)]
struct RegistrationPlan {
    governance_attempt_id: GovernanceAttemptId,
    participant_hash: [u8; 32],
    record: Vec<u8>,
    already_registered: bool,
}

/// The committed registration record of `participant_hash`, if any, in a
/// replayed casting archive of any cast-capable phase.
fn committed_registration<'a>(
    context: &'a ValidatedParliamentTimedOvnCastingContextArchiveV1,
    participant_hash: &[u8; 32],
) -> Result<Option<&'a [u8]>> {
    let session = context.timed_ovn_session();
    let mut found = None;
    for record in context.archive().registration_records() {
        let committed =
            TimedOvnCommittedRegistrationCacheV1::from_committed_record(session, record)
                .map_err(|error| eyre!("committed registration record is malformed: {error}"))?;
        if committed.participant_hash() == participant_hash {
            if found.is_some() {
                bail!("the casting archive repeats a participant registration");
            }
            found = Some(record.as_slice());
        }
    }
    Ok(found)
}

/// Regenerate the registration record that `seed` produces for one participant.
///
/// The record depends only on the seed, the timed-OVN session and the
/// participant hash, so it is identical in every cast-capable phase.
fn seeded_registration_record(
    context: &ValidatedParliamentTimedOvnCastingContextArchiveV1,
    participant_hash: [u8; 32],
    seed: &TimedOvnSeedV1,
) -> Result<Vec<u8>> {
    let session = context.timed_ovn_session();
    let mut rng = registration_rng(seed, &session.digest(), &participant_hash);
    let (_secret, registration) =
        TimedOvnRegistrationSecretV1::generate_with_rng(session, participant_hash, &mut rng)
            .map_err(|error| eyre!("failed to build the timed-OVN registration: {error}"))?;
    let record = registration.to_bytes();
    if record.len() != TIMED_OVN_REGISTRATION_RECORD_BYTES_V1 {
        bail!("timed-OVN registration record has the wrong width");
    }
    Ok(record)
}

/// Rebuild the juror's registration record from the seed.
///
/// A committed registration of the same participant is accepted only when it
/// is byte-identical, which makes the command idempotent.
fn registration_from_seed(
    context: &ValidatedParliamentTimedOvnCastingContextArchiveV1,
    authority: &AccountId,
    seed: &TimedOvnSeedV1,
) -> Result<RegistrationPlan> {
    if context.archive().phase() != ParliamentTimedOvnCastingPhaseV1::Registered {
        bail!(
            "ballot registration is closed (casting phase {:?})",
            context.archive().phase()
        );
    }
    let participant_hash =
        parliament_ballot_participant_hash_v1(archive_ballot_attempt_id(context), authority);
    let record = seeded_registration_record(context, participant_hash, seed)?;
    let already_registered = match committed_registration(context, &participant_hash)? {
        Some(existing) if existing != record.as_slice() => bail!(
            "this account already registered different timed-OVN keys for the ballot; \
             the key file does not hold the seed that registered them"
        ),
        Some(_) => true,
        None => false,
    };
    Ok(RegistrationPlan {
        governance_attempt_id: archive_governance_attempt_id(context),
        participant_hash,
        record,
        already_registered,
    })
}

/// A juror's seat among the frozen survivors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SurvivorSeat {
    participant_hash: [u8; 32],
    index: u32,
    survivor_count: u32,
}

/// Locate the account among the frozen survivors of a `SurvivorsFrozen` archive.
fn survivor_seat(
    context: &ValidatedParliamentTimedOvnCastingContextArchiveV1,
    authority: &AccountId,
) -> Result<SurvivorSeat> {
    if context.archive().phase() != ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen {
        bail!(
            "the ballot does not accept ballots yet (casting phase {:?})",
            context.archive().phase()
        );
    }
    let survivors = context
        .archive()
        .survivor_participant_hashes()
        .ok_or_else(|| eyre!("frozen casting archive omits its survivors"))?;
    let participant_hash =
        parliament_ballot_participant_hash_v1(archive_ballot_attempt_id(context), authority);
    let index = survivors
        .iter()
        .position(|survivor| *survivor == participant_hash)
        .ok_or_else(|| {
            eyre!("this account is not a frozen survivor of the ballot (not registered or dropped out)")
        })?;
    Ok(SurvivorSeat {
        participant_hash,
        index: u32::try_from(index).map_err(|_| eyre!("survivor index exceeds u32"))?,
        survivor_count: u32::try_from(survivors.len())
            .map_err(|_| eyre!("survivor count exceeds u32"))?,
    })
}

/// Rebuild the juror's secret from the seed and cast one masked ballot.
///
/// The regenerated registration must equal the committed one, so a wrong key
/// file fails before any ballot exists.
fn ballot_from_seed(
    context: &ValidatedParliamentTimedOvnCastingContextArchiveV1,
    authority: &AccountId,
    seed: &TimedOvnSeedV1,
    choice: BallotChoiceArg,
) -> Result<Vec<u8>> {
    let seat = survivor_seat(context, authority)?;
    let prepared = context
        .prepared_attempt()
        .ok_or_else(|| eyre!("frozen casting archive has no prepared survivor roster"))?;
    let session = prepared.registration_roster().session();
    let mut rng = registration_rng(seed, &session.digest(), &seat.participant_hash);
    let (secret, regenerated) =
        TimedOvnRegistrationSecretV1::generate_with_rng(session, seat.participant_hash, &mut rng)
            .map_err(|error| eyre!("failed to rebuild the timed-OVN secret: {error}"))?;
    let committed = prepared
        .registration_roster()
        .registrations()
        .iter()
        .find(|registration| registration.participant_hash() == &seat.participant_hash)
        .ok_or_else(|| eyre!("the survivor has no committed registration"))?;
    if regenerated.to_bytes() != committed.to_bytes() {
        bail!("the key file does not hold the seed that registered this account for the ballot");
    }
    let survivors = prepared.survivor_roster();
    let timed_choice = choice.timed_ovn_choice();
    let mut rng = ballot_rng(
        seed,
        &session.digest(),
        &seat.participant_hash,
        survivors.survivor_root(),
        survivors.identity_digest(),
        timed_choice,
    );
    let ballot = secret
        .cast_ballot_with_rng(survivors, timed_choice, &mut rng)
        .map_err(|error| eyre!("failed to build the masked ballot: {error}"))?;
    let record = ballot.to_bytes();
    if record.len() != TIMED_OVN_BALLOT_RECORD_BYTES_V1 || u32::from(ballot.index()) != seat.index {
        bail!("masked ballot record has the wrong width or seat");
    }
    Ok(record)
}

/// What `cast` does with a built ballot given the accepted corpus prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CastSchedule {
    /// The survivor's ballot is already in the accepted prefix.
    AlreadyAccepted,
    /// The accepted prefix ends right before the survivor: submit now.
    SubmitNow,
    /// `missing` earlier survivors have not been accepted yet.
    Wait {
        /// Number of earlier survivors still missing.
        missing: u32,
    },
}

/// Decide the cast action for survivor `index` of `survivor_count`.
fn cast_schedule(accepted_prefix: u32, survivor_count: u32, index: u32) -> Result<CastSchedule> {
    if index >= survivor_count || accepted_prefix > survivor_count {
        bail!("ballot progress is inconsistent with the frozen survivor roster");
    }
    Ok(match accepted_prefix.cmp(&index) {
        core::cmp::Ordering::Greater => CastSchedule::AlreadyAccepted,
        core::cmp::Ordering::Equal => CastSchedule::SubmitNow,
        core::cmp::Ordering::Less => CastSchedule::Wait {
            missing: index - accepted_prefix,
        },
    })
}

/// Final step of `ballot cast`.
#[derive(Debug, PartialEq, Eq)]
enum CastOutcome {
    /// The seat's ballot is already in the accepted prefix; nothing is submitted.
    AlreadyAccepted {
        /// Accepted prefix observed when the ballot was found accepted.
        accepted_prefix: u32,
    },
    /// Submit this record as the next one-record corpus chunk.
    Submit(Vec<u8>),
}

/// Poll the accepted prefix until the seat may submit its ballot.
///
/// `build` locks the choice, builds the masked ballot and exports it. It runs
/// only once the seat's ballot is known not to be accepted yet, and at most once
/// however many polls follow, so a waiting cast exports its record before its
/// turn and every later poll reuses the same bytes. `wait` sleeps before the
/// next poll and returns `false` once the wait budget is spent.
fn drive_cast(
    seat: SurvivorSeat,
    mut read_progress: impl FnMut() -> Result<BallotProgress>,
    mut build: impl FnMut() -> Result<Vec<u8>>,
    mut wait: impl FnMut() -> bool,
) -> Result<CastOutcome> {
    let mut built: Option<Vec<u8>> = None;
    loop {
        let progress = read_progress()?;
        if progress.status != BallotAttemptStatusV1::TimedCommitment {
            bail!(
                "the ballot no longer accepts ballots (status {:?})",
                progress.status
            );
        }
        if progress
            .frozen_survivor_count
            .is_some_and(|count| count != seat.survivor_count)
        {
            bail!("ballot progress is inconsistent with the frozen survivor roster");
        }
        let accepted_prefix = progress
            .accepted_prefix
            .ok_or_else(|| eyre!("the ballot progress omits its accepted prefix"))?;
        let missing = match cast_schedule(accepted_prefix, seat.survivor_count, seat.index)? {
            CastSchedule::AlreadyAccepted => {
                return Ok(CastOutcome::AlreadyAccepted { accepted_prefix });
            }
            CastSchedule::SubmitNow => None,
            CastSchedule::Wait { missing } => Some(missing),
        };
        let record = match built.take() {
            Some(record) => record,
            None => build()?,
        };
        let Some(missing) = missing else {
            return Ok(CastOutcome::Submit(record));
        };
        built = Some(record);
        if !wait() {
            bail!(
                "{missing} earlier survivor(s) have not cast yet (accepted prefix \
                 {accepted_prefix}, this seat {}); rerun later, pass --wait-secs, or relay \
                 their records with `iroha gov parliament ballot relay`",
                seat.index
            );
        }
    }
}

/// Sleep until the next accepted-prefix poll, or return `false` once
/// `deadline` has passed. The last poll happens at the deadline.
fn wait_for_next_poll(deadline: Instant) -> bool {
    let now = Instant::now();
    if now >= deadline {
        return false;
    }
    std::thread::sleep(CAST_POLL_INTERVAL.min(deadline - now));
    true
}

/// Public progress of one active ballot, read from the attempt projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BallotProgress {
    body: ParliamentBody,
    status: BallotAttemptStatusV1,
    frozen_survivor_count: Option<u32>,
    accepted_prefix: Option<u32>,
}

/// Find the progress of `ballot_attempt_id` among the attempt's body states.
fn find_ballot_progress(
    body_states: &[ParliamentBodyStateProjectionV1],
    ballot_attempt_id: BallotAttemptId,
) -> Result<BallotProgress> {
    body_states
        .iter()
        .find_map(|state| {
            state
                .timed_ovn_progress
                .filter(|progress| progress.ballot_attempt_id == ballot_attempt_id)
                .map(|progress| BallotProgress {
                    body: state.body,
                    status: progress.status,
                    frozen_survivor_count: progress.frozen_survivor_count,
                    accepted_prefix: progress.accepted_ballot_prefix_count,
                })
        })
        .ok_or_else(|| eyre!("the ballot is not the active hidden ballot of any body"))
}

/// Read the public progress of one ballot from its attempt projection.
fn read_ballot_progress<S: BallotSource>(
    source: &S,
    governance_attempt_id: GovernanceAttemptId,
    ballot_attempt_id: BallotAttemptId,
) -> Result<BallotProgress> {
    let attempt = source.attempt(governance_attempt_id)?;
    find_ballot_progress(&attempt.body_states, ballot_attempt_id)
}

/// Verify public masked-ballot records against the frozen survivors and key
/// them by survivor index.
fn index_relay_records(
    context: &ValidatedParliamentTimedOvnCastingContextArchiveV1,
    records: Vec<Vec<u8>>,
) -> Result<BTreeMap<u32, Vec<u8>>> {
    let prepared = context
        .prepared_attempt()
        .ok_or_else(|| eyre!("the ballot does not accept ballots yet (survivors not frozen)"))?;
    let mut indexed = BTreeMap::new();
    for record in records {
        let ballot = TimedOvnMaskedBallotV1::from_bytes(prepared.survivor_roster(), &record)
            .map_err(|error| eyre!("ballot record does not verify for this ballot: {error}"))?;
        if ballot.to_bytes() != record {
            bail!("ballot record is not canonical");
        }
        match indexed.entry(u32::from(ballot.index())) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(record);
            }
            std::collections::btree_map::Entry::Occupied(slot) => {
                if *slot.get() != record {
                    bail!(
                        "two different ballot records claim survivor seat {}",
                        slot.key()
                    );
                }
            }
        }
    }
    Ok(indexed)
}

/// Select the contiguous chunk that starts at the accepted prefix.
fn relay_chunk(accepted_prefix: u32, records: &BTreeMap<u32, Vec<u8>>) -> Result<Vec<Vec<u8>>> {
    let mut chunk = Vec::new();
    let mut next = accepted_prefix;
    while chunk.len() < PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1 {
        let Some(record) = records.get(&next) else {
            break;
        };
        chunk.push(record.clone());
        next = next
            .checked_add(1)
            .ok_or_else(|| eyre!("survivor index overflow"))?;
    }
    if chunk.is_empty() {
        bail!(
            "no supplied record continues the accepted prefix at survivor seat {accepted_prefix}"
        );
    }
    Ok(chunk)
}

fn corpus_instruction(
    governance_attempt_id: GovernanceAttemptId,
    ballot_attempt_id: BallotAttemptId,
    ballot_records: Vec<Vec<u8>>,
) -> Result<InstructionBox> {
    member_transition(
        governance_attempt_id,
        ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(ParliamentFreezeTimedOvnCorpusV1 {
            ballot_attempt_id,
            ballot_records,
        }),
    )
}

/// Print a line only in text mode, so JSON output stays one document.
fn note<C: RunContext>(context: &mut C, line: impl core::fmt::Display) -> Result<()> {
    if matches!(context.output_format(), CliOutputFormat::Text) {
        context.println(line)?;
    }
    Ok(())
}

/// Ballot state file and the one-time initialization of its trust anchor.
#[derive(clap::Args, Debug)]
pub struct BallotStateArgs {
    /// Canonical native checkpoint state file [default: `<key-file>.state.nrt`].
    #[arg(long, value_name = "PATH")]
    pub state_file: Option<PathBuf>,
    /// Independently authenticated, owner-only canonical Sumeragi checkpoint; initializes new state.
    #[arg(long, value_name = "PATH")]
    pub trusted_checkpoint_file: Option<PathBuf>,
}

impl BallotStateArgs {
    /// Read the complete independently selected checkpoint, if supplied.
    fn init(&self) -> Result<Option<SumeragiFinalityCheckpoint>> {
        self.trusted_checkpoint_file
            .as_deref()
            .map(files::load_checkpoint)
            .transpose()
    }

    /// State-file path: `--state-file`, else the default next to `key_file`.
    fn path(&self, key_file: Option<&Path>) -> Option<PathBuf> {
        self.state_file
            .clone()
            .or_else(|| key_file.map(files::default_state_path))
    }

    /// Open (or initialize) the state file when one is named, directly or
    /// through the key file.
    fn open(&self, key_file: Option<&Path>, network_id: &NetworkId) -> Result<Option<BallotState>> {
        let init = self.init()?;
        match self.path(key_file) {
            Some(path) => BallotState::open(&path, *network_id.as_bytes(), init).map(Some),
            None if init.is_some() => bail!(
                "--trusted-checkpoint-file initializes a state file; name it with --state-file \
                 or --key-file"
            ),
            None => Ok(None),
        }
    }
}

/// Owner-only key and state files shared by the seed-bearing commands.
#[derive(clap::Args, Debug)]
pub struct BallotFilesArgs {
    /// Owner-only (mode 0600 or 0400) timed-OVN key file holding the root seed.
    #[arg(long, value_name = "PATH")]
    pub key_file: PathBuf,
    /// State file and trust-anchor initialization.
    #[command(flatten)]
    pub state: BallotStateArgs,
}

impl BallotFilesArgs {
    fn open_state(&self, network_id: &NetworkId) -> Result<BallotState> {
        self.state
            .open(Some(&self.key_file), network_id)?
            .ok_or_else(|| eyre!("the key file always names a ballot state file"))
    }
}

/// Register timed-OVN ballot keys for one ballot attempt.
#[derive(clap::Args, Debug)]
pub struct RegisterArgs {
    /// Canonical lowercase identifier of the ballot attempt in `Registration`.
    #[arg(long, value_parser = parse_ballot_attempt_id)]
    pub ballot_attempt_id: BallotAttemptId,
    /// Key file, state file and trust-anchor initialization.
    #[command(flatten)]
    pub files: BallotFilesArgs,
}

impl RegisterArgs {
    /// Register against `source`, creating the key file when absent.
    fn execute<C: RunContext, S: BallotSource>(self, context: &mut C, source: &S) -> Result<()> {
        let network_id = context.config().network_id;
        let authority = context.config().account.clone();
        // The trust anchor is checked first so that a missing checkpoint never
        // leaves a freshly generated key file behind.
        let mut state = self.files.open_state(&network_id)?;
        let (seed, created) = files::load_or_create_key_file(&self.files.key_file)?;
        let authenticated = fetch_authenticated_casting_context(
            source,
            network_id,
            self.ballot_attempt_id,
            &mut state,
        )?;
        let plan = registration_from_seed(&authenticated.context, &authority, &seed)?;
        if created {
            note(
                context,
                format!(
                    "generated a new timed-OVN key file at `{}`",
                    self.files.key_file.display()
                ),
            )?;
        }
        if plan.already_registered {
            let value = norito::json!({
                "ballot_attempt_id": (self.ballot_attempt_id.to_hex()),
                "governance_attempt_id": (plan.governance_attempt_id.to_hex()),
                "participant_hash": (hex::encode(plan.participant_hash)),
                "registered": true,
                "submitted": false,
                "registration_close_height": (authenticated.binding.registration_close_height),
            });
            return print_with_summary(
                context,
                Some(format!(
                    "already registered for ballot {} (participant_hash={}); registration closes at height {}",
                    self.ballot_attempt_id.to_hex(),
                    hex::encode(plan.participant_hash),
                    authenticated.binding.registration_close_height
                )),
                &value,
            );
        }
        note(
            context,
            format!(
                "registering participant_hash={} for ballot {} (registration closes at height {})",
                hex::encode(plan.participant_hash),
                self.ballot_attempt_id.to_hex(),
                authenticated.binding.registration_close_height
            ),
        )?;
        let instruction = member_transition(
            plan.governance_attempt_id,
            ParliamentLifecycleTransitionV1::RegisterBallotParticipant(
                ParliamentRegisterBallotParticipantV1 {
                    ballot_attempt_id: self.ballot_attempt_id,
                    registration_record: plan.record,
                },
            ),
        )?;
        context.finish(vec![instruction])
    }
}

impl Run for RegisterArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        self.execute(context, &client)
    }
}

/// Build and submit this juror's masked timed-OVN ballot.
#[derive(clap::Args, Debug)]
pub struct CastArgs {
    /// Canonical lowercase identifier of the ballot attempt in `TimedCommitment`.
    #[arg(long, value_parser = parse_ballot_attempt_id)]
    pub ballot_attempt_id: BallotAttemptId,
    /// The juror's choice. It is locked in `<key-file>.choice-<participant-hash>`
    /// before the ballot is built and can never change for this seat.
    #[arg(long, value_enum)]
    pub choice: BallotChoiceArg,
    /// Key file, state file and trust-anchor initialization.
    #[command(flatten)]
    pub files: BallotFilesArgs,
    /// Also write the public masked-ballot record (lowercase hex) to this file for `relay`.
    #[arg(long, value_name = "PATH")]
    pub record_out: Option<PathBuf>,
    /// Wait up to this many seconds (at most one day) for earlier survivors to be accepted.
    #[arg(
        long,
        default_value_t = 0,
        value_parser = clap::value_parser!(u64).range(0..=MAX_CAST_WAIT_SECS)
    )]
    pub wait_secs: u64,
}

impl CastArgs {
    /// Cast against `source`: lock the choice, build the ballot once and submit
    /// it when the accepted prefix reaches this seat.
    fn execute<C: RunContext, S: BallotSource>(self, context: &mut C, source: &S) -> Result<()> {
        let network_id = context.config().network_id;
        let authority = context.config().account.clone();
        let ballot_bytes = *self.ballot_attempt_id.as_bytes();
        let participant_hash =
            parliament_ballot_participant_hash_v1(self.ballot_attempt_id, &authority);
        // Fail fast on a conflicting lock; `lock_choice` below is authoritative.
        files::check_choice_lock(
            &self.files.key_file,
            &ballot_bytes,
            &participant_hash,
            self.choice,
        )?;
        let wait_budget = Duration::from_secs(self.wait_secs.min(MAX_CAST_WAIT_SECS));
        let seed = files::load_key_file(&self.files.key_file)?;
        let mut state = self.files.open_state(&network_id)?;
        let authenticated = fetch_authenticated_casting_context(
            source,
            network_id,
            self.ballot_attempt_id,
            &mut state,
        )?;
        let seat = survivor_seat(&authenticated.context, &authority)?;
        if seat.participant_hash != participant_hash {
            bail!("the authenticated casting context names a different ballot attempt");
        }
        let governance_attempt_id = archive_governance_attempt_id(&authenticated.context);
        let deadline = Instant::now() + wait_budget;
        let outcome = drive_cast(
            seat,
            || read_ballot_progress(source, governance_attempt_id, self.ballot_attempt_id),
            || {
                // Lock the choice durably before any ballot bytes exist.
                files::lock_choice(
                    &self.files.key_file,
                    &ballot_bytes,
                    &seat.participant_hash,
                    self.choice,
                )?;
                let record =
                    ballot_from_seed(&authenticated.context, &authority, &seed, self.choice)?;
                if let Some(path) = &self.record_out {
                    files::write_public_record(path, &record)?;
                }
                Ok(record)
            },
            || wait_for_next_poll(deadline),
        )?;
        match outcome {
            CastOutcome::AlreadyAccepted { accepted_prefix } => {
                let value = norito::json!({
                    "ballot_attempt_id": (self.ballot_attempt_id.to_hex()),
                    "survivor_index": (seat.index),
                    "survivor_count": (seat.survivor_count),
                    "accepted_ballot_prefix_count": (accepted_prefix),
                    "accepted": true,
                    "submitted": false,
                });
                print_with_summary(
                    context,
                    Some(format!(
                        "ballot already accepted for survivor seat {} of {} (accepted prefix {accepted_prefix})",
                        seat.index, seat.survivor_count
                    )),
                    &value,
                )
            }
            CastOutcome::Submit(record) => {
                note(
                    context,
                    format!(
                        "casting survivor seat {} of {} for ballot {}",
                        seat.index,
                        seat.survivor_count,
                        self.ballot_attempt_id.to_hex()
                    ),
                )?;
                let instruction = corpus_instruction(
                    governance_attempt_id,
                    self.ballot_attempt_id,
                    vec![record],
                )?;
                context.finish(vec![instruction])
            }
        }
    }
}

impl Run for CastArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        self.execute(context, &client)
    }
}

/// Record this juror's dropout from a registered ballot before the survivor freeze.
///
/// A registered juror who will not cast MUST drop out, or the ballot fails.
/// The key itself is never read, so a juror who lost the key file can still
/// drop out. When a state file is named (directly or through `--key-file`), the
/// precheck uses the consensus-authenticated casting context and promotes the
/// trusted checkpoint; otherwise it uses the public inspection context. Core
/// re-validates the dropout at execution either way.
#[derive(clap::Args, Debug)]
pub struct DropoutArgs {
    /// Canonical lowercase identifier of the ballot attempt in `SurvivorFreeze`.
    #[arg(long, value_parser = parse_ballot_attempt_id)]
    pub ballot_attempt_id: BallotAttemptId,
    /// Timed-OVN key file; only locates the default state file and is never read.
    #[arg(long, value_name = "PATH")]
    pub key_file: Option<PathBuf>,
    /// Optional state file and trust-anchor initialization.
    #[command(flatten)]
    pub state: BallotStateArgs,
}

/// Check that the account may record a dropout in this casting archive.
fn dropout_precheck(
    context: &ValidatedParliamentTimedOvnCastingContextArchiveV1,
    authority: &AccountId,
) -> Result<GovernanceAttemptId> {
    if context.archive().phase() != ParliamentTimedOvnCastingPhaseV1::RegistrationClosed {
        bail!(
            "dropouts are recorded only after registration closes and before the survivor \
             freeze (casting phase {:?})",
            context.archive().phase()
        );
    }
    let participant_hash =
        parliament_ballot_participant_hash_v1(archive_ballot_attempt_id(context), authority);
    if committed_registration(context, &participant_hash)?.is_none() {
        bail!("this account is not registered for the ballot");
    }
    Ok(archive_governance_attempt_id(context))
}

impl DropoutArgs {
    /// Precheck against `source` and submit the dropout.
    fn execute<C: RunContext, S: BallotSource>(self, context: &mut C, source: &S) -> Result<()> {
        let network_id = context.config().network_id;
        let authority = context.config().account.clone();
        let mut state = self.state.open(self.key_file.as_deref(), &network_id)?;
        let (archive, trust) = match state.as_mut() {
            Some(state) => (
                fetch_authenticated_casting_context(
                    source,
                    network_id,
                    self.ballot_attempt_id,
                    state,
                )?
                .context,
                "consensus-authenticated",
            ),
            None => (
                source.public_casting_context(self.ballot_attempt_id)?,
                "public",
            ),
        };
        let governance_attempt_id = dropout_precheck(&archive, &authority)?;
        note(
            context,
            format!(
                "recording the dropout from ballot {} (checked against the {trust} casting \
                 context at height {})",
                self.ballot_attempt_id.to_hex(),
                archive.archive().finalized_height()
            ),
        )?;
        let instruction = member_transition(
            governance_attempt_id,
            ParliamentLifecycleTransitionV1::RecordBallotDropout(ParliamentRecordBallotDropoutV1 {
                ballot_attempt_id: self.ballot_attempt_id,
            }),
        )?;
        context.finish(vec![instruction])
    }
}

impl Run for DropoutArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        self.execute(context, &client)
    }
}

/// Submit published masked-ballot records that continue the accepted prefix.
#[derive(clap::Args, Debug)]
pub struct RelayArgs {
    /// Canonical lowercase identifier of the ballot attempt in `TimedCommitment`.
    #[arg(long, value_parser = parse_ballot_attempt_id)]
    pub ballot_attempt_id: BallotAttemptId,
    /// Public masked-ballot record file written by `cast --record-out` (repeatable).
    #[arg(long = "record", value_name = "PATH", required = true)]
    pub records: Vec<PathBuf>,
}

impl RelayArgs {
    /// Verify the records against `source` and submit the next chunk.
    fn execute<C: RunContext, S: BallotSource>(self, context: &mut C, source: &S) -> Result<()> {
        let (count, accepted_prefix, instruction) =
            relay_instruction_from(source, self.ballot_attempt_id, &self.records)?;
        note(
            context,
            format!(
                "relaying {count} ballot record(s) from survivor seat {accepted_prefix} for ballot {}",
                self.ballot_attempt_id.to_hex()
            ),
        )?;
        context.finish(vec![instruction])
    }
}

fn relay_instruction_from<S: BallotSource>(
    source: &S,
    ballot_attempt_id: BallotAttemptId,
    record_paths: &[PathBuf],
) -> Result<(usize, u32, InstructionBox)> {
    if record_paths.len() > MAX_RELAY_RECORD_FILES {
        bail!("relay accepts at most {MAX_RELAY_RECORD_FILES} record files");
    }
    let records = record_paths
        .iter()
        .map(|path| files::read_public_record(path, TIMED_OVN_BALLOT_RECORD_BYTES_V1))
        .collect::<Result<Vec<_>>>()?;
    let archive = source.public_casting_context(ballot_attempt_id)?;
    let indexed = index_relay_records(&archive, records)?;
    let governance_attempt_id = archive_governance_attempt_id(&archive);
    let progress = read_ballot_progress(source, governance_attempt_id, ballot_attempt_id)?;
    if progress.status != BallotAttemptStatusV1::TimedCommitment {
        bail!(
            "the ballot no longer accepts ballots (status {:?})",
            progress.status
        );
    }
    let accepted_prefix = progress
        .accepted_prefix
        .ok_or_else(|| eyre!("the ballot progress omits its accepted prefix"))?;
    let chunk = relay_chunk(accepted_prefix, &indexed)?;
    let count = chunk.len();
    let instruction = corpus_instruction(governance_attempt_id, ballot_attempt_id, chunk)?;
    Ok((count, accepted_prefix, instruction))
}

impl Run for RelayArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        self.execute(context, &client)
    }
}

/// One active hidden ballot in `ballot status` output.
#[derive(Debug, JsonSerialize)]
struct BallotStatusEntryV1 {
    body: String,
    ballot_attempt_id: String,
    status: String,
    participant_hash: String,
    frozen_survivor_count: Option<u32>,
    accepted_ballot_prefix_count: Option<u32>,
    casting_phase: Option<String>,
    casting_context_height: Option<u64>,
    registered: Option<bool>,
    dropped_out: Option<bool>,
    survivor_index: Option<u32>,
    ballot_accepted: Option<bool>,
    key_file_matches_registration: Option<bool>,
    choice_lock: Option<String>,
    casting_context_error: Option<String>,
}

impl BallotStatusEntryV1 {
    /// Entry holding only the public progress facts of one ballot.
    fn new(
        body: ParliamentBody,
        progress: &ParliamentTimedOvnProgressProjectionV1,
        participant_hash: &[u8; 32],
    ) -> Self {
        Self {
            body: format!("{body:?}"),
            ballot_attempt_id: progress.ballot_attempt_id.to_hex(),
            status: format!("{:?}", progress.status),
            participant_hash: hex::encode(participant_hash),
            frozen_survivor_count: progress.frozen_survivor_count,
            accepted_ballot_prefix_count: progress.accepted_ballot_prefix_count,
            casting_phase: None,
            casting_context_height: None,
            registered: None,
            dropped_out: None,
            survivor_index: None,
            ballot_accepted: None,
            key_file_matches_registration: None,
            choice_lock: None,
            casting_context_error: None,
        }
    }

    /// One summary line for text output.
    fn summary(&self) -> String {
        fn show<T: ToString>(value: Option<T>) -> String {
            value.map_or_else(|| "-".to_owned(), |value| value.to_string())
        }
        format!(
            "{} ballot {} status={} registered={} dropped_out={} survivor_index={} \
             accepted_prefix={} ballot_accepted={} key_matches={} choice_lock={}",
            self.body,
            self.ballot_attempt_id,
            self.status,
            show(self.registered),
            show(self.dropped_out),
            show(self.survivor_index),
            show(self.accepted_ballot_prefix_count),
            show(self.ballot_accepted),
            show(self.key_file_matches_registration),
            show(self.choice_lock.as_deref()),
        )
    }
}

/// `ballot status` output document.
#[derive(Debug, JsonSerialize)]
struct BallotStatusV1 {
    governance_attempt_id: String,
    current_height: u64,
    account: String,
    key_file_present: Option<bool>,
    state_file_present: Option<bool>,
    trusted_checkpoint_height: Option<u64>,
    ballots: Vec<BallotStatusEntryV1>,
}

/// Fill this account's participation facts from a casting archive.
///
/// With a seed, also report whether the seed regenerates the account's
/// committed registration, that is, whether this key file can cast the ballot.
/// The comparison stays local; nothing derived from the seed is sent anywhere.
fn apply_participation(
    entry: &mut BallotStatusEntryV1,
    context: &ValidatedParliamentTimedOvnCastingContextArchiveV1,
    participant_hash: &[u8; 32],
    seed: Option<&TimedOvnSeedV1>,
) -> Result<()> {
    let archive = context.archive();
    entry.casting_phase = Some(format!("{:?}", archive.phase()));
    entry.casting_context_height = Some(archive.finalized_height());
    let committed = committed_registration(context, participant_hash)?;
    entry.registered = Some(committed.is_some());
    entry.key_file_matches_registration = match (seed, committed) {
        (Some(seed), Some(committed)) => Some(
            seeded_registration_record(context, *participant_hash, seed)?.as_slice() == committed,
        ),
        _ => None,
    };
    if let Some(survivors) = archive.survivor_participant_hashes() {
        let index = survivors
            .iter()
            .position(|survivor| survivor == participant_hash)
            .map(u32::try_from)
            .transpose()
            .map_err(|_| eyre!("survivor index exceeds u32"))?;
        entry.survivor_index = index;
        entry.dropped_out = Some(committed.is_some() && index.is_none());
        entry.ballot_accepted = match (index, entry.accepted_ballot_prefix_count) {
            (Some(index), Some(prefix)) => Some(prefix > index),
            _ => None,
        };
    }
    Ok(())
}

/// Juror-local files that `status` reads; it never creates or changes them.
#[derive(Debug, Default)]
struct LocalCustody {
    key_file: Option<PathBuf>,
    seed: Option<TimedOvnSeedV1>,
    key_file_present: Option<bool>,
    state: Option<BallotState>,
    state_file_present: Option<bool>,
}

impl LocalCustody {
    /// Read the named key and state files; an absent file is reported, not an error.
    fn read(
        key_file: Option<&Path>,
        state_file: Option<&Path>,
        network_id: &NetworkId,
    ) -> Result<Self> {
        let mut custody = Self {
            key_file: key_file.map(Path::to_path_buf),
            ..Self::default()
        };
        if let Some(path) = key_file {
            custody.seed = files::load_key_file_if_present(path)?;
            custody.key_file_present = Some(custody.seed.is_some());
        }
        let state_path = state_file
            .map(Path::to_path_buf)
            .or_else(|| key_file.map(files::default_state_path));
        if let Some(path) = state_path {
            custody.state = BallotState::load_if_present(&path, *network_id.as_bytes())?;
            custody.state_file_present = Some(custody.state.is_some());
        }
        Ok(custody)
    }

    /// Choice locked for one seat next to the key file, if a key file was named.
    fn choice_lock(
        &self,
        ballot_attempt_id: BallotAttemptId,
        participant_hash: &[u8; 32],
    ) -> Result<Option<String>> {
        let Some(key_file) = &self.key_file else {
            return Ok(None);
        };
        Ok(
            files::read_choice_lock(key_file, ballot_attempt_id.as_bytes(), participant_hash)?
                .map(|choice| choice.label().to_owned()),
        )
    }
}

/// Collect the status entries of every active hidden ballot in `body_states`,
/// optionally restricted to one ballot attempt.
fn status_entries(
    body_states: &[ParliamentBodyStateProjectionV1],
    wanted: Option<BallotAttemptId>,
    authority: &AccountId,
    custody: &LocalCustody,
    mut casting_context: impl FnMut(
        BallotAttemptId,
    ) -> Result<ValidatedParliamentTimedOvnCastingContextArchiveV1>,
) -> Result<Vec<BallotStatusEntryV1>> {
    let mut ballots = Vec::new();
    for state in body_states {
        let Some(progress) = state.timed_ovn_progress else {
            continue;
        };
        if wanted.is_some_and(|wanted| wanted != progress.ballot_attempt_id) {
            continue;
        }
        let participant_hash =
            parliament_ballot_participant_hash_v1(progress.ballot_attempt_id, authority);
        let mut entry = BallotStatusEntryV1::new(state.body, &progress, &participant_hash);
        entry.choice_lock = custody.choice_lock(progress.ballot_attempt_id, &participant_hash)?;
        if matches!(
            progress.status,
            BallotAttemptStatusV1::Registration
                | BallotAttemptStatusV1::SurvivorFreeze
                | BallotAttemptStatusV1::TimedCommitment
        ) {
            let participation = casting_context(progress.ballot_attempt_id).and_then(|archive| {
                apply_participation(
                    &mut entry,
                    &archive,
                    &participant_hash,
                    custody.seed.as_ref(),
                )
            });
            if let Err(error) = participation {
                entry.casting_context_error = Some(format!("{error:#}"));
            }
        }
        ballots.push(entry);
    }
    if ballots.is_empty() {
        bail!("the attempt has no matching active hidden ballot");
    }
    Ok(ballots)
}

/// Show this account's part in the active hidden ballots of one attempt.
///
/// Name the attempt, one ballot attempt, or both; a ballot attempt alone is
/// resolved to its attempt through the public casting context, which is served
/// only while the ballot takes registrations or ballots. With `--key-file` the
/// status also says whether that key file can cast (it regenerates the
/// account's committed registration) and shows the choice locked next to it,
/// and with a state file it shows the pinned checkpoint. All files are only
/// read, and a missing file is reported rather than created. Facts come from
/// the public inspection context and attempt projection, which are not
/// consensus-authenticated.
#[derive(clap::Args, Debug)]
#[command(group(
    clap::ArgGroup::new("status_scope")
        .required(true)
        .multiple(true)
        .args(["governance_attempt_id", "ballot_attempt_id"])
))]
pub struct StatusArgs {
    /// Canonical lowercase identifier of the Parliament attempt.
    #[arg(long, value_parser = parse_governance_attempt_id)]
    pub governance_attempt_id: Option<GovernanceAttemptId>,
    /// Restrict the output to one ballot attempt.
    #[arg(long, value_parser = parse_ballot_attempt_id)]
    pub ballot_attempt_id: Option<BallotAttemptId>,
    /// Timed-OVN key file to check against the committed registration (read only).
    #[arg(long, value_name = "PATH")]
    pub key_file: Option<PathBuf>,
    /// Ballot state file to report (read only) [default: `<key-file>.state.nrt`].
    #[arg(long, value_name = "PATH")]
    pub state_file: Option<PathBuf>,
}

impl StatusArgs {
    /// Read the status from `source` and the named local files.
    fn execute<C: RunContext, S: BallotSource>(self, context: &mut C, source: &S) -> Result<()> {
        let network_id = context.config().network_id;
        let authority = context.config().account.clone();
        let custody = LocalCustody::read(
            self.key_file.as_deref(),
            self.state_file.as_deref(),
            &network_id,
        )?;
        let governance_attempt_id = match (self.governance_attempt_id, self.ballot_attempt_id) {
            (Some(governance_attempt_id), _) => governance_attempt_id,
            (None, Some(ballot_attempt_id)) => source
                .public_casting_context(ballot_attempt_id)
                .map(|archive| archive_governance_attempt_id(&archive))
                .wrap_err(
                    "failed to resolve the ballot's Parliament attempt from its casting context \
                     (served only while the ballot takes registrations or ballots); pass \
                     --governance-attempt-id",
                )?,
            (None, None) => bail!("name --governance-attempt-id or --ballot-attempt-id"),
        };
        let attempt = source.attempt(governance_attempt_id)?;
        let ballots = status_entries(
            &attempt.body_states,
            self.ballot_attempt_id,
            &authority,
            &custody,
            |ballot_attempt_id| source.public_casting_context(ballot_attempt_id),
        )?;
        let summary = ballots
            .iter()
            .map(BallotStatusEntryV1::summary)
            .collect::<Vec<_>>()
            .join("\n");
        let document = BallotStatusV1 {
            governance_attempt_id: governance_attempt_id.to_hex(),
            current_height: attempt.current_height,
            account: authority.to_string(),
            key_file_present: custody.key_file_present,
            state_file_present: custody.state_file_present,
            trusted_checkpoint_height: custody
                .state
                .as_ref()
                .map(|state| state.checkpoint().height()),
            ballots,
        };
        let value =
            norito::json::to_value(&document).wrap_err("failed to render the ballot status")?;
        print_with_summary(context, Some(summary), &value)
    }
}

impl Run for StatusArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        self.execute(context, &client)
    }
}

/// Timed-OVN ballot participation commands.
#[derive(clap::Subcommand, Debug)]
pub enum BallotCommand {
    /// Register this juror's timed-OVN ballot keys (generates the key file when absent).
    Register(Box<RegisterArgs>),
    /// Build and submit this juror's masked ballot.
    Cast(Box<CastArgs>),
    /// Record this juror's dropout before the survivor freeze.
    Dropout(DropoutArgs),
    /// Submit published ballot records that continue the accepted prefix.
    Relay(RelayArgs),
    /// Show this account's part in the active hidden ballots of an attempt.
    Status(StatusArgs),
}

impl Run for BallotCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Self::Register(args) => args.run(context),
            Self::Cast(args) => args.run(context),
            Self::Dropout(args) => args.run(context),
            Self::Relay(args) => args.run(context),
            Self::Status(args) => args.run(context),
        }
    }
}
