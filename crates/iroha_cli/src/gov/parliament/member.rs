//! Seated-member Parliament transitions signed by the configured citizen account.
//!
//! These commands cover the public-body phases of a Parliament attempt: an
//! invited citizen answers the invitation, a seated member endorses a public
//! finding or records their own absence from the attempt. Core derives the
//! member identity and assignment from the transaction authority, so none of
//! the commands can act for another citizen.

use eyre::{Result, eyre};
use iroha::data_model::{
    governance::types::{
        AssignmentId, BodyElectionAttemptId, BodyInstanceId, GovernanceAttemptId, ParliamentBody,
    },
    isi::InstructionBox,
};
use iroha_data_model::isi::governance::{
    ParliamentEndorsePublicFindingV1, ParliamentInvitationDecisionV1,
    ParliamentLifecycleTransitionV1, ParliamentRecordAttemptAbsenceV1,
    ParliamentRecordInvitationResponseV1, SubmitParliamentLifecycleTransitionV1,
};

use super::parse_governance_attempt_id;
use crate::{Run, RunContext};

/// Wrap one member transition and reject a structurally invalid payload locally.
pub(super) fn member_transition(
    governance_attempt_id: GovernanceAttemptId,
    transition: ParliamentLifecycleTransitionV1,
) -> Result<InstructionBox> {
    let instruction = SubmitParliamentLifecycleTransitionV1 {
        governance_attempt_id,
        transition,
    };
    instruction
        .validate_static()
        .map_err(|reason| eyre!("invalid Parliament transition: {reason}"))?;
    Ok(InstructionBox::from(instruction))
}

fn parse_nonzero_hash32<T: core::str::FromStr + AsRef<[u8; 32]>>(
    input: &str,
    label: &str,
) -> Result<T, String> {
    let id = input.parse::<T>().map_err(|_| {
        "must be exactly 64 lowercase hexadecimal characters without a prefix".to_owned()
    })?;
    if id.as_ref().iter().all(|byte| *byte == 0) {
        return Err(format!("must be a non-zero {label}"));
    }
    Ok(id)
}

fn parse_election_attempt_id(input: &str) -> Result<BodyElectionAttemptId, String> {
    parse_nonzero_hash32(input, "body election attempt id")
}

fn parse_body_instance_id(input: &str) -> Result<BodyInstanceId, String> {
    parse_nonzero_hash32(input, "body instance id")
}

fn parse_body(input: &str) -> Result<ParliamentBody, String> {
    norito::json::from_value(norito::json::Value::from(input)).map_err(|_| {
        format!("unknown Parliament body `{input}` (use a label such as `policy-jury`)")
    })
}

fn parse_result_root(input: &str) -> Result<[u8; 32], String> {
    if input.len() != 64
        || !input
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("must be exactly 64 lowercase hexadecimal characters".to_owned());
    }
    let mut root = [0_u8; 32];
    hex::decode_to_slice(input, &mut root).map_err(|_| "invalid hexadecimal".to_owned())?;
    if root.iter().all(|byte| *byte == 0) {
        return Err("must be a non-zero result root".to_owned());
    }
    Ok(root)
}

/// Invitation decision.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationDecisionArg {
    /// Accept the offered seat.
    Accept,
    /// Decline the offered seat.
    Decline,
}

/// Answer one ranked Parliament invitation addressed to the configured account.
#[derive(clap::Args, Debug)]
pub struct RespondInvitationArgs {
    /// Canonical lowercase identifier of the Parliament attempt.
    #[arg(long, value_parser = parse_governance_attempt_id)]
    pub governance_attempt_id: GovernanceAttemptId,
    /// Body election whose invitation is answered.
    #[arg(long, value_parser = parse_election_attempt_id)]
    pub election_attempt_id: BodyElectionAttemptId,
    /// Body label, for example `rules-committee` or `policy-jury`.
    #[arg(long, value_parser = parse_body)]
    pub body: ParliamentBody,
    /// Accept or decline the seat.
    #[arg(long, value_enum)]
    pub decision: InvitationDecisionArg,
}

impl RespondInvitationArgs {
    fn instruction(&self) -> Result<InstructionBox> {
        member_transition(
            self.governance_attempt_id,
            ParliamentLifecycleTransitionV1::RecordInvitationResponse(
                ParliamentRecordInvitationResponseV1 {
                    election_attempt_id: self.election_attempt_id,
                    body: self.body,
                    decision: match self.decision {
                        InvitationDecisionArg::Accept => ParliamentInvitationDecisionV1::Accept,
                        InvitationDecisionArg::Decline => ParliamentInvitationDecisionV1::Decline,
                    },
                },
            ),
        )
    }
}

impl Run for RespondInvitationArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let instruction = self.instruction()?;
        context.finish(vec![instruction])
    }
}

/// Endorse one public-finding result root as a seated member.
#[derive(clap::Args, Debug)]
pub struct EndorseArgs {
    /// Canonical lowercase identifier of the Parliament attempt.
    #[arg(long, value_parser = parse_governance_attempt_id)]
    pub governance_attempt_id: GovernanceAttemptId,
    /// Sealed body instance contributing the finding.
    #[arg(long, value_parser = parse_body_instance_id)]
    pub body_instance_id: BodyInstanceId,
    /// Root of the complete evidence, deliberation and dissent record (64 lowercase hex).
    #[arg(long, value_parser = parse_result_root)]
    pub result_root: [u8; 32],
}

impl EndorseArgs {
    fn instruction(&self) -> Result<InstructionBox> {
        member_transition(
            self.governance_attempt_id,
            ParliamentLifecycleTransitionV1::EndorsePublicFinding(
                ParliamentEndorsePublicFindingV1 {
                    body_instance_id: self.body_instance_id,
                    result_root: self.result_root,
                },
            ),
        )
    }
}

impl Run for EndorseArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let instruction = self.instruction()?;
        context.finish(vec![instruction])
    }
}

/// Record the configured member's own absence from one attempt.
///
/// The assignment is derived from the election attempt and the configured
/// account, so a member can only excuse themselves.
#[derive(clap::Args, Debug)]
pub struct RecordAbsenceArgs {
    /// Canonical lowercase identifier of the Parliament attempt.
    #[arg(long, value_parser = parse_governance_attempt_id)]
    pub governance_attempt_id: GovernanceAttemptId,
    /// Sealed body instance the member sits on.
    #[arg(long, value_parser = parse_body_instance_id)]
    pub body_instance_id: BodyInstanceId,
    /// Body election that seated the member.
    #[arg(long, value_parser = parse_election_attempt_id)]
    pub election_attempt_id: BodyElectionAttemptId,
}

impl RecordAbsenceArgs {
    fn instruction(
        &self,
        member: &iroha::data_model::account::AccountId,
    ) -> Result<InstructionBox> {
        member_transition(
            self.governance_attempt_id,
            ParliamentLifecycleTransitionV1::RecordAttemptAbsence(
                ParliamentRecordAttemptAbsenceV1 {
                    body_instance_id: self.body_instance_id,
                    assignment_id: AssignmentId::derive_v1(self.election_attempt_id, member),
                },
            ),
        )
    }
}

impl Run for RecordAbsenceArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let member = context.config().account.clone();
        let instruction = self.instruction(&member)?;
        context.finish(vec![instruction])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use iroha_crypto::{Algorithm, KeyPair};

    const ATTEMPT_HEX: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    const ELECTION_HEX: &str = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
    const BODY_HEX: &str = "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e";

    #[derive(clap::Parser, Debug)]
    struct Fixture {
        #[command(subcommand)]
        command: super::super::ParliamentCommand,
    }

    fn parse(args: &[&str]) -> Result<super::super::ParliamentCommand, clap::Error> {
        Fixture::try_parse_from(std::iter::once("parliament").chain(args.iter().copied()))
            .map(|fixture| fixture.command)
    }

    fn transition(instruction: &InstructionBox) -> &SubmitParliamentLifecycleTransitionV1 {
        instruction
            .as_any()
            .downcast_ref::<SubmitParliamentLifecycleTransitionV1>()
            .expect("lifecycle transition")
    }

    #[test]
    fn invitation_response_builds_the_member_transition() {
        let command = parse(&[
            "respond-invitation",
            "--governance-attempt-id",
            ATTEMPT_HEX,
            "--election-attempt-id",
            ELECTION_HEX,
            "--body",
            "policy-jury",
            "--decision",
            "decline",
        ])
        .expect("respond-invitation parses");
        let super::super::ParliamentCommand::RespondInvitation(args) = command else {
            panic!("expected respond-invitation")
        };
        let instruction = args.instruction().expect("instruction");
        let submitted = transition(&instruction);
        assert_eq!(submitted.governance_attempt_id.to_hex(), ATTEMPT_HEX);
        let ParliamentLifecycleTransitionV1::RecordInvitationResponse(payload) =
            &submitted.transition
        else {
            panic!("expected an invitation response")
        };
        assert_eq!(payload.body, ParliamentBody::PolicyJury);
        assert_eq!(payload.decision, ParliamentInvitationDecisionV1::Decline);
        assert_eq!(payload.election_attempt_id.to_hex(), ELECTION_HEX);

        assert!(
            parse(&[
                "respond-invitation",
                "--governance-attempt-id",
                ATTEMPT_HEX,
                "--election-attempt-id",
                ELECTION_HEX,
                "--body",
                "PolicyJury",
                "--decision",
                "accept",
            ])
            .is_err(),
            "body labels are the canonical hyphenated JSON labels"
        );
        assert!(
            parse(&[
                "respond-invitation",
                "--governance-attempt-id",
                ATTEMPT_HEX,
                "--election-attempt-id",
                ELECTION_HEX,
                "--body",
                "policy-jury",
            ])
            .is_err(),
            "the decision is explicit"
        );
    }

    #[test]
    fn endorsement_builds_the_member_transition() {
        let root = "ab".repeat(32);
        let command = parse(&[
            "endorse",
            "--governance-attempt-id",
            ATTEMPT_HEX,
            "--body-instance-id",
            BODY_HEX,
            "--result-root",
            &root,
        ])
        .expect("endorse parses");
        let super::super::ParliamentCommand::Endorse(args) = command else {
            panic!("expected endorse")
        };
        let instruction = args.instruction().expect("instruction");
        let ParliamentLifecycleTransitionV1::EndorsePublicFinding(payload) =
            &transition(&instruction).transition
        else {
            panic!("expected an endorsement")
        };
        assert_eq!(payload.result_root, [0xAB; 32]);
        assert_eq!(payload.body_instance_id.to_hex(), BODY_HEX);
        for invalid in ["AB".repeat(32), "00".repeat(32), "ab".repeat(31)] {
            assert!(
                parse(&[
                    "endorse",
                    "--governance-attempt-id",
                    ATTEMPT_HEX,
                    "--body-instance-id",
                    BODY_HEX,
                    "--result-root",
                    &invalid,
                ])
                .is_err(),
                "invalid root must fail: {invalid}"
            );
        }
        assert!(
            parse(&[
                "endorse",
                "--governance-attempt-id",
                ATTEMPT_HEX,
                "--body-instance-id",
                &"00".repeat(32),
                "--result-root",
                &root,
            ])
            .is_err()
        );
    }

    #[test]
    fn absence_derives_the_members_own_assignment() {
        let command = parse(&[
            "record-absence",
            "--governance-attempt-id",
            ATTEMPT_HEX,
            "--body-instance-id",
            BODY_HEX,
            "--election-attempt-id",
            ELECTION_HEX,
        ])
        .expect("record-absence parses");
        let super::super::ParliamentCommand::RecordAbsence(args) = command else {
            panic!("expected record-absence")
        };
        let member = iroha::data_model::account::AccountId::new(
            KeyPair::try_from_seed(vec![0x42; 32], Algorithm::Ed25519)
                .expect("member key")
                .public_key()
                .clone(),
        );
        let instruction = args.instruction(&member).expect("instruction");
        let ParliamentLifecycleTransitionV1::RecordAttemptAbsence(payload) =
            &transition(&instruction).transition
        else {
            panic!("expected an absence")
        };
        assert_eq!(
            payload.assignment_id,
            AssignmentId::derive_v1(args.election_attempt_id, &member)
        );
        assert_eq!(payload.body_instance_id.to_hex(), BODY_HEX);
    }

    #[test]
    fn member_commands_submit_their_transition_through_the_run_context() {
        use crate::Run as _;

        let member_key =
            KeyPair::try_from_seed(vec![0x43; 32], Algorithm::Ed25519).expect("member key");
        let member = iroha::data_model::account::AccountId::new(member_key.public_key().clone());
        let network_id = crate::fallback_config().network_id;
        let run = |args: &[&str]| {
            let mut context =
                super::super::test_context::CaptureContext::new(member_key.clone(), network_id);
            parse(args)
                .expect("member command parses")
                .run(&mut context)
                .expect("member command runs");
            assert!(context.printed.is_empty() && context.lines.is_empty());
            context.single_transition().clone()
        };
        let root = "cd".repeat(32);

        let response = run(&[
            "respond-invitation",
            "--governance-attempt-id",
            ATTEMPT_HEX,
            "--election-attempt-id",
            ELECTION_HEX,
            "--body",
            "confirmation-jury",
            "--decision",
            "accept",
        ]);
        assert_eq!(response.governance_attempt_id.to_hex(), ATTEMPT_HEX);
        let ParliamentLifecycleTransitionV1::RecordInvitationResponse(payload) =
            &response.transition
        else {
            panic!("expected an invitation response")
        };
        assert_eq!(payload.body, ParliamentBody::ConfirmationJury);
        assert_eq!(payload.decision, ParliamentInvitationDecisionV1::Accept);

        let endorsement = run(&[
            "endorse",
            "--governance-attempt-id",
            ATTEMPT_HEX,
            "--body-instance-id",
            BODY_HEX,
            "--result-root",
            &root,
        ]);
        let ParliamentLifecycleTransitionV1::EndorsePublicFinding(payload) =
            &endorsement.transition
        else {
            panic!("expected an endorsement")
        };
        assert_eq!(payload.result_root, [0xCD; 32]);

        let absence = run(&[
            "record-absence",
            "--governance-attempt-id",
            ATTEMPT_HEX,
            "--body-instance-id",
            BODY_HEX,
            "--election-attempt-id",
            ELECTION_HEX,
        ]);
        let ParliamentLifecycleTransitionV1::RecordAttemptAbsence(payload) = &absence.transition
        else {
            panic!("expected an absence")
        };
        assert_eq!(
            payload.assignment_id,
            AssignmentId::derive_v1(ELECTION_HEX.parse().expect("election attempt id"), &member),
            "the configured account excuses only itself"
        );
    }

    #[test]
    fn member_transition_rejects_an_inert_attempt() {
        assert!(
            member_transition(
                GovernanceAttemptId::new([0; 32]),
                ParliamentLifecycleTransitionV1::CompleteQualification,
            )
            .is_err()
        );
        assert!(
            member_transition(
                GovernanceAttemptId::new([1; 32]),
                ParliamentLifecycleTransitionV1::CompleteQualification,
            )
            .is_ok()
        );
    }
}
