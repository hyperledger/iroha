//! Governance helpers (app API convenience). Build/submit governance transactions.
mod audit;
mod deploy;
pub(crate) mod parliament;
mod shared;
mod vote;
use crate::{Run, RunContext};
pub use audit::AuditDeployArgs;
pub use deploy::{
    DeployMetaArgs, ProposeDeployArgs, ProtectedApplyArgs, ProtectedGetArgs, ProtectedSetArgs,
};
use eyre::Result;
pub use parliament::ParliamentCommand;
pub(crate) use shared::parse_governance_selector_v1;
pub use vote::{
    LocksGetArgs, ProposalGetArgs, ReferendumGetArgs, TallyGetArgs, UnlockStatsArgs, VoteArgs,
};
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Deployment helpers (propose/meta/audit). Propose deployment of IVM bytecode.
    #[command(subcommand)]
    Deploy(DeployCommand),
    /// Submit a standalone referendum ballot; auto-detects its mode unless overridden.
    Vote(VoteArgs),
    /// Proposal helpers
    #[command(subcommand)]
    Proposal(ProposalCommand),
    /// Lock helpers
    #[command(subcommand)]
    Locks(LocksCommand),
    /// Unlock helpers (expired lock stats)
    #[command(subcommand)]
    Unlock(UnlockCommand),
    /// Referendum helpers
    #[command(subcommand)]
    Referendum(ReferendumCommand),
    /// Tally helpers
    #[command(subcommand)]
    Tally(TallyCommand),
    /// Protected namespace helpers
    #[command(subcommand)]
    Protected(ProtectedCommand),
    /// Attempt-based private SORA Parliament helpers.
    #[command(subcommand)]
    Parliament(ParliamentCommand),
}
impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Command::Deploy(cmd) => cmd.run(context),
            Command::Vote(args) => args.run(context),
            Command::Proposal(cmd) => cmd.run(context),
            Command::Locks(cmd) => cmd.run(context),
            Command::Unlock(cmd) => cmd.run(context),
            Command::Referendum(cmd) => cmd.run(context),
            Command::Tally(cmd) => cmd.run(context),
            Command::Protected(cmd) => cmd.run(context),
            Command::Parliament(cmd) => cmd.run(context),
        }
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum DeployCommand {
    /// Propose deployment of IVM bytecode by code/abi hash via governance (build-only; server returns instruction skeleton)
    Propose(ProposeDeployArgs),
    /// Build deploy metadata JSON for protected namespace admission
    Meta(DeployMetaArgs),
    /// Audit stored manifests against governance proposals and code storage
    Audit(AuditDeployArgs),
}
impl Run for DeployCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            DeployCommand::Propose(args) => args.run(context),
            DeployCommand::Meta(args) => args.run(context),
            DeployCommand::Audit(args) => args.run(context),
        }
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum ProposalCommand {
    /// Get a governance proposal by id (hex)
    Get(ProposalGetArgs),
}
impl Run for ProposalCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            ProposalCommand::Get(args) => args.run(context),
        }
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum LocksCommand {
    /// Get locks for a referendum id
    Get(LocksGetArgs),
}
impl Run for LocksCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            LocksCommand::Get(args) => args.run(context),
        }
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum ReferendumCommand {
    /// Get a referendum by id
    Get(ReferendumGetArgs),
}
impl Run for ReferendumCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            ReferendumCommand::Get(args) => args.run(context),
        }
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum TallyCommand {
    /// Get a tally snapshot by referendum id
    Get(TallyGetArgs),
}
impl Run for TallyCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            TallyCommand::Get(args) => args.run(context),
        }
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum UnlockCommand {
    /// Show governance unlock sweep stats (expired locks at current height)
    Stats(UnlockStatsArgs),
}
impl Run for UnlockCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            UnlockCommand::Stats(args) => args.run(context),
        }
    }
}
#[derive(clap::Subcommand, Debug)]
pub enum ProtectedCommand {
    /// Set protected namespaces (custom parameter `gov_protected_namespaces`)
    Set(ProtectedSetArgs),
    /// Apply protected namespaces on the server (requires API token if configured)
    Apply(ProtectedApplyArgs),
    /// Get protected namespaces (custom parameter `gov_protected_namespaces`)
    Get(ProtectedGetArgs),
}
impl Run for ProtectedCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            ProtectedCommand::Set(args) => args.run(context),
            ProtectedCommand::Apply(args) => args.run(context),
            ProtectedCommand::Get(args) => args.run(context),
        }
    }
}

#[cfg(test)]
mod cutover_tests {
    use super::Command;
    use clap::Parser as _;

    #[derive(clap::Parser, Debug)]
    struct GovernanceCommandFixture {
        #[command(subcommand)]
        command: Command,
    }

    #[test]
    fn proposal_backed_finalize_and_enact_commands_are_retired() {
        for command in ["finalize", "enact"] {
            let error = GovernanceCommandFixture::try_parse_from(["gov", command])
                .expect_err("legacy governance command must not parse");
            assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
        }
    }

    #[test]
    fn standalone_referendum_vote_command_remains_reachable() {
        GovernanceCommandFixture::try_parse_from([
            "gov",
            "vote",
            "--referendum-id",
            "standalone-ref",
        ])
        .expect("standalone referendum vote command must remain registered");
    }
}
