//! Attempt-based SORA Parliament draft, read and member commands.

mod member;
#[cfg(test)]
mod test_context;

use super::shared::print_with_summary;
use crate::{Run, RunContext};
use eyre::{Result, WrapErr};
use iroha::{
    client::{
        Client, PARLIAMENT_API_VERSION_V1, ParliamentAttemptDraftRequestV1,
        ParliamentTransitionDraftRequestV1,
    },
    data_model::governance::types::{GovernanceAttemptId, ProposalKind},
};
use iroha_data_model::isi::governance::ParliamentLifecycleTransitionV1;

fn parse_governance_attempt_id(input: &str) -> Result<GovernanceAttemptId, String> {
    let id = input.parse::<GovernanceAttemptId>().map_err(|_| {
        "must be exactly 64 lowercase hexadecimal characters without a prefix".to_owned()
    })?;
    if id.as_bytes().iter().all(|byte| *byte == 0) {
        return Err("must be a non-zero governance attempt id".to_owned());
    }
    Ok(id)
}

/// Draft one canonical Parliament attempt creation for local signing.
#[derive(clap::Args, Debug)]
pub struct DraftAttemptArgs {
    /// JSON file containing one exact tagged `ProposalKind` value.
    #[arg(long, value_name = "PATH")]
    pub proposal_json: std::path::PathBuf,
    /// Zero-based retry sequence for the exact proposal content.
    #[arg(long, default_value_t = 0)]
    pub attempt_sequence: u32,
}

impl Run for DraftAttemptArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let bytes = std::fs::read(&self.proposal_json).wrap_err_with(|| {
            format!(
                "failed to read Parliament proposal JSON `{}`",
                self.proposal_json.display()
            )
        })?;
        let proposal: ProposalKind = norito::json::from_slice(&bytes)
            .wrap_err("failed to decode strict Parliament ProposalKind JSON")?;
        let request = ParliamentAttemptDraftRequestV1 {
            version: PARLIAMENT_API_VERSION_V1,
            proposal,
            attempt_sequence: self.attempt_sequence,
        };
        let client: Client = context.client_from_config()?;
        let response = client.post_parliament_attempt_draft(&request)?;
        let value = norito::json::to_value(&response)
            .wrap_err("failed to render Parliament attempt draft")?;
        print_with_summary(
            context,
            Some(format!(
                "governance_attempt_id={} proposal_content_id={} instructions=1",
                response.governance_attempt_id.to_hex(),
                response.proposal_content_id.to_hex()
            )),
            &value,
        )
    }
}

/// Draft one exact Parliament lifecycle transition for local signing.
#[derive(clap::Args, Debug)]
pub struct DraftTransitionArgs {
    /// Canonical lowercase identifier of the existing Parliament attempt.
    #[arg(long, value_parser = parse_governance_attempt_id)]
    pub governance_attempt_id: GovernanceAttemptId,
    /// JSON file containing one exact tagged lifecycle transition.
    #[arg(long, value_name = "PATH")]
    pub transition_json: std::path::PathBuf,
}

impl Run for DraftTransitionArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let bytes = std::fs::read(&self.transition_json).wrap_err_with(|| {
            format!(
                "failed to read Parliament transition JSON `{}`",
                self.transition_json.display()
            )
        })?;
        let transition: ParliamentLifecycleTransitionV1 = norito::json::from_slice(&bytes)
            .wrap_err("failed to decode strict Parliament lifecycle transition JSON")?;
        let request = ParliamentTransitionDraftRequestV1 {
            version: PARLIAMENT_API_VERSION_V1,
            governance_attempt_id: self.governance_attempt_id,
            transition,
        };
        request
            .validate_static()
            .map_err(|reason| eyre::eyre!(reason))?;
        let client: Client = context.client_from_config()?;
        let response = client.post_parliament_transition_draft(&request)?;
        let value = norito::json::to_value(&response)
            .wrap_err("failed to render Parliament transition draft")?;
        print_with_summary(
            context,
            Some(format!(
                "governance_attempt_id={} transition={:?} transition_digest={} instructions=1",
                response.governance_attempt_id.to_hex(),
                response.transition_kind,
                hex::encode(response.transition_digest)
            )),
            &value,
        )
    }
}

/// Read one exact canonical Parliament attempt.
#[derive(clap::Args, Debug)]
pub struct GetAttemptArgs {
    /// Canonical lowercase attempt identifier.
    #[arg(long, value_parser = parse_governance_attempt_id)]
    pub governance_attempt_id: GovernanceAttemptId,
}

impl Run for GetAttemptArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client: Client = context.client_from_config()?;
        let response = client.get_parliament_attempt(self.governance_attempt_id)?;
        let state_bytes = response.state_payload_hex.len() / 2;
        let value = norito::json::to_value(&response)
            .wrap_err("failed to render Parliament attempt read response")?;
        print_with_summary(
            context,
            Some(format!(
                "governance_attempt_id={} stage={:?} status={:?} height={} state_bytes={state_bytes}",
                response.attempt.id.to_hex(),
                response.attempt.stage,
                response.attempt.status,
                response.current_height
            )),
            &value,
        )
    }
}

/// Attempt-based Parliament commands.
#[derive(clap::Subcommand, Debug)]
pub enum ParliamentCommand {
    /// Draft one canonical attempt creation instruction.
    DraftAttempt(DraftAttemptArgs),
    /// Draft one exact lifecycle transition instruction.
    DraftTransition(DraftTransitionArgs),
    /// Read one exact committed attempt projection.
    GetAttempt(GetAttemptArgs),
    /// Accept or decline one Parliament invitation addressed to this account.
    RespondInvitation(member::RespondInvitationArgs),
    /// Endorse one public-finding result root as a seated member.
    Endorse(member::EndorseArgs),
    /// Record this member's own absence from one attempt.
    RecordAbsence(member::RecordAbsenceArgs),
}

impl Run for ParliamentCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Self::DraftAttempt(args) => args.run(context),
            Self::DraftTransition(args) => args.run(context),
            Self::GetAttempt(args) => args.run(context),
            Self::RespondInvitation(args) => args.run(context),
            Self::Endorse(args) => args.run(context),
            Self::RecordAbsence(args) => args.run(context),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempt_id_parser_is_exact_lowercase_nonzero_hex() {
        assert!(parse_governance_attempt_id(&"ab".repeat(32)).is_ok());
        for invalid in [
            "00".repeat(32),
            "AB".repeat(32),
            format!("0x{}", "ab".repeat(32)),
            "ab".repeat(31),
        ] {
            assert!(
                parse_governance_attempt_id(&invalid).is_err(),
                "invalid attempt id must fail: {invalid}"
            );
        }
    }

    #[test]
    fn proposal_input_rejects_a_request_wrapper_alias() {
        let invalid = norito::json!({
            "version": 1,
            "proposal": {},
            "attemptSequence": 0
        });
        assert!(norito::json::from_value::<ProposalKind>(invalid).is_err());
    }
}
