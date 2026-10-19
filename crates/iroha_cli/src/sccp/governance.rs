//! `iroha sccp governance`: SCCP proposals to the SORA Parliament (`specs/sccp.md` §4.14.3).
//!
//! The Parliament is the only SCCP governance authority. `propose` builds an
//! `SccpGovernanceProposalV1` whose `base_revisions` are Taira's current per-subject revisions,
//! runs the static checks and submits `ProposeSccpRouteGovernance`; attempts and lifecycle
//! transitions are permissionless (`iroha gov parliament`).
//!
//! `drive` is the Parliament driver of §4.14.5 item 4. It has no discretion: it creates the
//! first attempt of every admissible open proposal, oldest first, and submits the five
//! permissionless manager intents advised by Core's attempt plan. Shared block-start work and
//! keepalives advance the clock. The driver has no ballot, exact-height or tick authority.
//! Several drivers are harmless: a duplicate transition fails and pays its fee.
//!
//! `show` returns the proposal body, current-revision verdict, deployment checks and attempts.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{Duration, Instant},
};

use eyre::{Result, WrapErr as _, eyre};
use iroha::{
    client::Client,
    data_model::{
        NetworkId,
        governance::types::{
            GovernanceAttemptId, GovernanceAttemptStatusV1, ProposalKind,
            SccpRouteGovernanceProposal,
        },
        isi::{
            InstructionBox,
            governance::{
                CreateParliamentGovernanceAttemptV1, ParliamentLifecycleTransitionV1,
                ProposeSccpRouteGovernance, SubmitParliamentLifecycleTransitionV1,
            },
        },
        sccp::governance::{
            SccpGovernanceActionV1, SccpGovernanceBaseRevisionV1, SccpGovernanceProposalV1,
        },
    },
};
use iroha_sccp::api::SccpGovernanceProposalStatusV1;
use iroha_torii_shared::parliament_api::ParliamentAttemptPlanResponseV1;

use crate::{Run, RunContext};

/// `iroha sccp governance` subcommands.
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Propose SCCP actions to the Parliament against Taira's current revisions.
    Propose(ProposeArgs),
    /// Show a proposal body, current-revision verdict, deployment checks and attempts.
    Show(ShowArgs),
    /// Show governance readiness from the current committed state.
    Readiness,
    /// Show Taira's nonzero per-subject governance revisions.
    Revisions,
    /// Run the Parliament driver: carry SCCP proposals through their Parliament attempts.
    Drive(DriveArgs),
}

/// Arguments of `iroha sccp governance show`.
#[derive(clap::Args, Debug)]
pub struct ShowArgs {
    /// Proposal content id (32-byte hexadecimal).
    pub content_id: String,
}

/// Arguments of `iroha sccp governance drive`.
#[derive(clap::Args, Debug)]
pub struct DriveArgs {
    /// Milliseconds between polls.
    #[arg(long, default_value_t = 500)]
    pub poll_interval_ms: u64,
    /// Retry still-needed intents after this interval even if the tip has not advanced.
    #[arg(long, default_value_t = 4_000)]
    pub retry_interval_ms: u64,
    /// Stop after this many polls; 0 runs until interrupted.
    #[arg(long, default_value_t = 0)]
    pub polls: u64,
}

/// One driver submission.
#[derive(Clone, Debug, PartialEq, Eq)]
enum DriveStep {
    /// Create the first attempt of an admissible proposal.
    CreateAttempt(Box<ProposalKind>),
    /// Permissionless manager intents advised for one candidate, in one transaction.
    Due(GovernanceAttemptId, Vec<ParliamentLifecycleTransitionV1>),
}

impl DriveStep {
    /// Candidate height used to expire this submission's retry suppression.
    fn candidate_height(observed_tip: u64) -> Option<u64> {
        observed_tip.checked_add(1)
    }

    /// Key remembered until candidate commitment or the bounded retry interval.
    fn key(&self) -> String {
        match self {
            Self::CreateAttempt(kind) => {
                format!("create:{}", hex::encode(kind.fingerprint()))
            }
            Self::Due(attempt, transitions) => format!(
                "due:{}:{}",
                attempt.to_hex(),
                transitions
                    .iter()
                    .map(|transition| hex::encode(transition.digest_v1()))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }
}

/// Admissible open proposals without an attempt, in canonical creation order.
fn proposals_to_attempt(proposals: &[SccpGovernanceProposalStatusV1]) -> Vec<ProposalKind> {
    let mut proposals: Vec<_> = proposals
        .iter()
        .filter(|proposal| proposal.admissible && proposal.latest_attempt.is_none())
        .collect();
    proposals.sort_by_key(|proposal| (proposal.created_height, *proposal.content_id.as_bytes()));
    proposals
        .into_iter()
        .map(|proposal| {
            ProposalKind::SccpRouteGovernance(SccpRouteGovernanceProposal {
                proposal: Box::new(proposal.proposal.clone()),
            })
        })
        .collect()
}

/// Manager intents are the only account-submitted lifecycle work of this driver (§4.14.5).
fn manager_intent(transition: &ParliamentLifecycleTransitionV1) -> bool {
    matches!(
        transition,
        ParliamentLifecycleTransitionV1::CompleteQualification
            | ParliamentLifecycleTransitionV1::RegisterInitialSortition
            | ParliamentLifecycleTransitionV1::RegisterSortitionRequest(_)
            | ParliamentLifecycleTransitionV1::AdvanceBodyPhase(_)
            | ParliamentLifecycleTransitionV1::EscalateRisk(_)
    )
}

/// Plan DATA is advice; exact-height and retired ballot actions never become driver instructions.
fn plan_steps(plan: &ParliamentAttemptPlanResponseV1) -> Vec<DriveStep> {
    let transitions: Vec<_> = plan
        .due
        .iter()
        .filter(|transition| manager_intent(transition))
        .cloned()
        .collect();
    if transitions.is_empty() {
        Vec::new()
    } else {
        vec![DriveStep::Due(plan.governance_attempt_id, transitions)]
    }
}

fn step_instructions(step: &DriveStep) -> Vec<InstructionBox> {
    match step {
        DriveStep::CreateAttempt(kind) => vec![
            CreateParliamentGovernanceAttemptV1 {
                proposal: kind.as_ref().clone(),
                attempt_sequence: 0,
            }
            .into(),
        ],
        DriveStep::Due(attempt, transitions) => transitions
            .iter()
            .map(|transition| {
                SubmitParliamentLifecycleTransitionV1 {
                    governance_attempt_id: *attempt,
                    transition: transition.clone(),
                }
                .into()
            })
            .collect(),
    }
}

/// Retry only after the candidate commits or a bounded local retry interval elapses.
/// A lost submit response cannot suppress a necessary intent forever on an idle chain.
fn retire_submissions(
    sent: &mut BTreeMap<String, (u64, Instant)>,
    tip: u64,
    now: Instant,
    retry: Duration,
) {
    sent.retain(|_, (candidate, submitted)| {
        tip < *candidate && now.saturating_duration_since(*submitted) < retry
    });
}

/// Observations cannot open an unavailable launch gate or silently switch chains.
fn validate_drive_source(
    network: NetworkId,
    observed: [u8; 32],
    binding_available: bool,
) -> Result<()> {
    if &observed != network.as_bytes() {
        return Err(eyre!(
            "the peer's network identity differs from the configured chain"
        ));
    }
    if !binding_available {
        return Err(eyre!(
            "the qualified Parliament ballot is unavailable; SCCP governance remains closed"
        ));
    }
    Ok(())
}

/// Run the Parliament driver until `args.polls` polls (0: until interrupted).
fn drive<C: RunContext>(context: &mut C, args: &DriveArgs) -> Result<()> {
    let client = super::blocking(context)?;
    let capabilities = client.sccp().capabilities()?;
    validate_drive_source(
        context.config().network_id,
        capabilities.network_id,
        capabilities.parliament_binding_ballot_available,
    )?;
    let parliament: Client = context.client_from_config()?;
    let poll_interval = Duration::from_millis(args.poll_interval_ms.max(100));
    let retry_interval = Duration::from_millis(args.retry_interval_ms.max(100));
    // Every retry re-reads the committed plan; a prior submit never grants authority.
    let mut sent: BTreeMap<String, (u64, Instant)> = BTreeMap::new();
    let mut polls = 0_u64;
    loop {
        polls = polls.saturating_add(1);
        let tip = client.status().get()?.blocks;
        retire_submissions(&mut sent, tip, Instant::now(), retry_interval);
        let proposals = client.sccp().governance_proposals()?;
        let mut steps: Vec<_> = proposals_to_attempt(&proposals)
            .into_iter()
            .map(|kind| DriveStep::CreateAttempt(Box::new(kind)))
            .collect();
        for attempt in proposals
            .iter()
            .filter_map(|proposal| proposal.latest_attempt)
        {
            if attempt.status != GovernanceAttemptStatusV1::Active {
                continue;
            }
            match parliament.get_parliament_attempt_plan(attempt.id) {
                Ok(plan) => steps.extend(plan_steps(&plan)),
                Err(error) => context.println(format_args!(
                    "plan of attempt {}: {error:#}",
                    attempt.id.to_hex()
                ))?,
            }
        }
        for step in steps {
            let key = step.key();
            if sent.contains_key(&key) {
                continue;
            }
            let candidate = DriveStep::candidate_height(tip)
                .ok_or_else(|| eyre!("committed height has no next native candidate"))?;
            sent.insert(key.clone(), (candidate, Instant::now()));
            let instructions = step_instructions(&step);
            context.println(format_args!("tip {tip}: {key}"))?;
            if let Err(error) = context.finish_unconfirmed(instructions) {
                // A failed transport response is ambiguous. Retain candidate suppression and
                // re-read the original committed plan before attempting the same intent again.
                context.println(format_args!("{key}: {error:#}"))?;
            }
        }
        if args.polls != 0 && polls >= args.polls {
            return Ok(());
        }
        std::thread::sleep(poll_interval);
    }
}

/// Arguments of `iroha sccp governance propose`.
#[derive(clap::Args, Debug)]
pub struct ProposeArgs {
    /// JSON file with the array of `SccpGovernanceActionV1` to apply in order.
    #[arg(long)]
    pub actions: PathBuf,
    /// Print the proposal instead of submitting it.
    #[arg(long)]
    pub dry_run: bool,
}

/// Build the proposal of `actions` under `network_id` with the current `revisions` (absent
/// subjects are at 0) and run every static check (§4.14.3 step 1).
///
/// # Errors
/// Returns the first failed static check.
pub fn build_proposal(
    network_id: NetworkId,
    revisions: &[SccpGovernanceBaseRevisionV1],
    actions: Vec<SccpGovernanceActionV1>,
) -> Result<SccpGovernanceProposalV1> {
    let mut proposal = SccpGovernanceProposalV1 {
        network_id,
        base_revisions: Vec::new(),
        actions,
    };
    proposal.base_revisions = proposal
        .subjects()
        .into_iter()
        .map(|subject| {
            let revision = revisions
                .iter()
                .find(|current| current.subject == subject)
                .map_or(0, |current| current.revision);
            (subject, revision).into()
        })
        .collect();
    proposal
        .validate_static(&network_id)
        .map_err(|error| eyre!("the proposal fails static validation: {error:?}"))?;
    Ok(proposal)
}

impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client = super::blocking(context)?;
        match self {
            Self::Show(args) => context.print_data(
                &client
                    .sccp()
                    .governance_proposal(&super::parse_word(&args.content_id)?)?,
            ),
            Self::Readiness => context.print_data(&client.sccp().governance_readiness()?),
            Self::Revisions => {
                let revisions = client.sccp().governance_revisions()?;
                context.print_data(&revisions)
            }
            Self::Drive(args) => drive(context, &args),
            Self::Propose(args) => {
                let text = std::fs::read_to_string(&args.actions)
                    .wrap_err_with(|| format!("read {}", args.actions.display()))?;
                let actions: Vec<SccpGovernanceActionV1> = norito::json::from_str(&text)
                    .map_err(|error| eyre!("actions file is not SCCP actions JSON: {error}"))?;
                let revisions = client.sccp().governance_revisions()?;
                let proposal = build_proposal(context.config().network_id, &revisions, actions)?;
                if args.dry_run {
                    return context.print_data(&proposal);
                }
                context.finish(vec![InstructionBox::from(ProposeSccpRouteGovernance {
                    proposal,
                })])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha::data_model::sccp::{
        governance::{SccpGovernanceSubjectV1, SccpSetParametersActionV1},
        params::SccpParametersV1,
    };

    fn network_id() -> NetworkId {
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new([3; 32]),
        ))
    }

    fn open_proposal(
        admissible: bool,
        latest_attempt: Option<iroha::data_model::governance::types::GovernanceAttemptV1>,
    ) -> SccpGovernanceProposalStatusV1 {
        let proposal = build_proposal(
            network_id(),
            &[],
            vec![SccpGovernanceActionV1::SetParameters(
                SccpSetParametersActionV1 {
                    next: SccpParametersV1::taira_default(),
                },
            )],
        )
        .expect("valid");
        SccpGovernanceProposalStatusV1 {
            content_id: iroha::data_model::governance::types::ProposalContentId::new([4; 32]),
            created_height: 7,
            proposal,
            admissible,
            latest_attempt,
        }
    }

    fn attempt(
        status: GovernanceAttemptStatusV1,
    ) -> iroha::data_model::governance::types::GovernanceAttemptV1 {
        let content = iroha::data_model::governance::types::ProposalContentId::new([4; 32]);
        iroha::data_model::governance::types::GovernanceAttemptV1 {
            id: GovernanceAttemptId::derive_v1(content, 0),
            proposal_content_id: content,
            sequence: 0,
            risk_tier: iroha::data_model::governance::types::RiskTierV1::Standard,
            stage: iroha::data_model::governance::types::GovernanceStageV1::Qualification,
            status,
        }
    }

    #[test]
    fn only_admissible_proposals_without_an_attempt_get_one() {
        let fresh = open_proposal(true, None);
        let stale = open_proposal(false, None);
        let running = open_proposal(true, Some(attempt(GovernanceAttemptStatusV1::Active)));
        let kinds = proposals_to_attempt(&[fresh.clone(), stale.clone(), running.clone()]);
        assert_eq!(kinds.len(), 1);
        assert_eq!(
            kinds[0],
            ProposalKind::SccpRouteGovernance(SccpRouteGovernanceProposal {
                proposal: Box::new(fresh.proposal.clone()),
            })
        );
    }

    #[test]
    fn queued_create_attempt_preserves_canonical_fingerprint_and_instruction() {
        let proposal = open_proposal(true, None);
        let kind = proposals_to_attempt(&[proposal])
            .pop()
            .expect("one proposal");
        let expected_key = format!("create:{}", hex::encode(kind.fingerprint()));
        let expected: InstructionBox = CreateParliamentGovernanceAttemptV1 {
            proposal: kind.clone(),
            attempt_sequence: 0,
        }
        .into();
        let step = DriveStep::CreateAttempt(Box::new(kind));
        assert_eq!(step.key(), expected_key);
        assert_eq!(step_instructions(&step), vec![expected]);
        assert_eq!(step.key(), expected_key);
    }

    #[test]
    fn driver_uses_manager_intents_without_exact_height_or_ballot_authority() {
        use iroha::data_model::{
            governance::types::BallotAttemptId,
            isi::governance::ParliamentCloseBallotRegistrationV1,
        };
        use iroha_torii_shared::parliament_api::ParliamentExactTransitionProjectionV1;
        let attempt_id = attempt(GovernanceAttemptStatusV1::Active).id;
        let ballot = BallotAttemptId::new([9; 32]);
        let retired = ParliamentLifecycleTransitionV1::CloseBallotRegistration(
            ParliamentCloseBallotRegistrationV1 {
                ballot_attempt_id: ballot,
            },
        );
        let mut plan = ParliamentAttemptPlanResponseV1 {
            version: 1,
            governance_attempt_id: attempt_id,
            current_height: 40,
            execution_height: 41,
            due: vec![
                ParliamentLifecycleTransitionV1::CompleteQualification,
                retired.clone(),
                ParliamentLifecycleTransitionV1::RegisterInitialSortition,
            ],
            exact: vec![ParliamentExactTransitionProjectionV1 {
                height: 41,
                transition: retired,
            }],
        };
        let steps = plan_steps(&plan);
        assert_eq!(
            steps,
            vec![DriveStep::Due(
                attempt_id,
                vec![
                    ParliamentLifecycleTransitionV1::CompleteQualification,
                    ParliamentLifecycleTransitionV1::RegisterInitialSortition
                ]
            )]
        );
        assert_eq!(step_instructions(&steps[0]).len(), 2);
        plan.due.clear();
        assert!(
            plan_steps(&plan).is_empty(),
            "clock and ballot work never creates driver transactions"
        );
    }

    #[test]
    fn retry_suppression_tracks_actual_native_candidate_boundaries() {
        let step = DriveStep::Due(
            attempt(GovernanceAttemptStatusV1::Active).id,
            vec![ParliamentLifecycleTransitionV1::CompleteQualification],
        );
        assert_eq!(DriveStep::candidate_height(40), Some(41));
        assert_eq!(DriveStep::candidate_height(u64::MAX), None);
        let now = Instant::now();
        let retry = Duration::from_secs(4);
        let mut sent =
            BTreeMap::from([(step.key(), (DriveStep::candidate_height(40).unwrap(), now))]);
        retire_submissions(&mut sent, 40, now, retry);
        assert_eq!(sent.len(), 1);
        let mut delayed = sent.clone();
        retire_submissions(&mut sent, 41, now, retry);
        assert!(
            sent.is_empty(),
            "a committed candidate allows re-reading and retrying remaining work"
        );
        retire_submissions(&mut delayed, 40, now + retry, retry);
        assert!(
            delayed.is_empty(),
            "an ambiguous submission must not stall an idle tip forever"
        );
    }

    #[test]
    fn proposal_driver_orders_original_creation_height_before_content_identity() {
        let mut late = open_proposal(true, None);
        late.created_height = 10;
        late.proposal.base_revisions[0].revision = 8;
        let early = open_proposal(true, None);
        let kinds = proposals_to_attempt(&[late, early.clone()]);
        assert_eq!(kinds.len(), 2);
        let ProposalKind::SccpRouteGovernance(first) = &kinds[0] else {
            panic!("SCCP proposal");
        };
        assert_eq!(*first.proposal, early.proposal);
    }

    #[test]
    fn driver_preserves_closed_binding_gate_and_configured_chain() {
        let network = network_id();
        assert!(validate_drive_source(network, *network.as_bytes(), true).is_ok());
        assert!(validate_drive_source(network, *network.as_bytes(), false).is_err());
        assert!(validate_drive_source(network, [0; 32], true).is_err());
    }

    #[test]
    fn driver_arguments_reject_retired_ballot_and_tick_modes() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Cli {
            #[command(subcommand)]
            command: Command,
        }
        assert!(Cli::try_parse_from(["governance", "readiness"]).is_ok());
        assert!(Cli::try_parse_from(["governance", "drive", "--polls", "1"]).is_ok());
        for option in ["--release-peer", "--relay-dir", "--tick-interval-ms"] {
            assert!(Cli::try_parse_from(["governance", "drive", option, "1"]).is_err());
        }
    }

    #[test]
    fn proposals_carry_current_revisions_of_their_subjects() {
        let actions = vec![SccpGovernanceActionV1::SetParameters(
            SccpSetParametersActionV1 {
                next: SccpParametersV1::taira_default(),
            },
        )];
        let revisions = vec![
            (SccpGovernanceSubjectV1::Parameters, 4).into(),
            (
                SccpGovernanceSubjectV1::LightClient(
                    iroha::data_model::bridge::SccpNetworkV1::TonMainnet,
                ),
                9,
            )
                .into(),
        ];
        let proposal = build_proposal(network_id(), &revisions, actions.clone()).expect("valid");
        assert_eq!(proposal.base_revisions.len(), 1);
        assert_eq!(proposal.base_revisions[0].revision, 4);
        let fresh = build_proposal(network_id(), &[], actions).expect("valid");
        assert_eq!(fresh.base_revisions[0].revision, 0);
        assert!(build_proposal(network_id(), &[], Vec::new()).is_err());
    }
}
