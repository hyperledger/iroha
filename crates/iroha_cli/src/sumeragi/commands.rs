use super::{evidence, status};
use crate::{Run, RunContext};
use clap::ValueEnum;
use eyre::Result;
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Show the consensus status snapshot (round, leader, proxy tail, lock view, heights)
    Status(StatusArgs),
    /// Show committed consensus lanes and this node's typed instance status
    Lanes(LanesArgs),
    /// Show non-authoritative pipeline, queue, election, and lane diagnostics
    Diagnostics(DiagnosticsArgs),
    /// Show on-chain Sumeragi parameters snapshot
    Params(ParamsArgs),
    /// Evidence audit helpers (list/count)
    #[command(subcommand)]
    Evidence(EvidenceCommand),
}
#[derive(clap::Subcommand, Debug)]
pub enum EvidenceCommand {
    /// List committed evidence audit entries
    List(EvidenceListArgs),
    /// Show evidence count
    Count(EvidenceCountArgs),
}
#[derive(clap::Args, Debug)]
pub struct StatusArgs {}
#[derive(clap::Args, Debug)]
pub struct LanesArgs {
    /// Override the configured gateway with an explicitly approved physical-peer Torii URL
    #[arg(long, value_name = "URL")]
    pub torii_url: Option<url::Url>,
}
#[derive(clap::Args, Debug)]
pub struct DiagnosticsArgs {}
#[derive(clap::Args, Debug)]
pub struct ParamsArgs {}
#[derive(clap::Args, Debug)]
pub struct EvidenceListArgs {
    /// Maximum number of entries to return (1 through 1000)
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub limit: Option<u32>,
    /// Offset into the evidence list (0 through 10000)
    #[arg(long, value_parser = clap::value_parser!(u32).range(..=10_000))]
    pub offset: Option<u32>,
    /// Filter by evidence kind
    #[arg(long, value_enum)]
    pub kind: Option<EvidenceKindArg>,
}
#[derive(clap::Args, Debug)]
pub struct EvidenceCountArgs {}
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum EvidenceKindArg {
    #[value(name = "NativeSumeragiEvidence")]
    NativeSumeragiEvidence,
}
impl EvidenceKindArg {
    /// Convert the CLI literal into the closed client query enum.
    pub const fn into_client(self) -> iroha::client::SumeragiEvidenceKind {
        match self {
            EvidenceKindArg::NativeSumeragiEvidence => {
                iroha::client::SumeragiEvidenceKind::NativeSumeragiEvidence
            }
        }
    }
}
impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Command::Status(args) => status::status(context, args),
            Command::Lanes(args) => status::lanes(context, args),
            Command::Diagnostics(args) => status::diagnostics(context, args),
            Command::Params(args) => status::params(context, args),
            Command::Evidence(cmd) => cmd.run(context),
        }
    }
}
impl Run for EvidenceCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            EvidenceCommand::List(args) => evidence::list(context, args),
            EvidenceCommand::Count(args) => evidence::count(context, args),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::{Command, EvidenceKindArg};
    use clap::{Parser as _, ValueEnum as _};

    #[derive(clap::Parser, Debug)]
    struct SumeragiCommandFixture {
        #[command(subcommand)]
        command: Command,
    }

    #[test]
    fn retired_operator_commands_do_not_parse() {
        for command in ["vrf-penalties", "vrf-epoch", "pacemaker"] {
            let error =
                SumeragiCommandFixture::try_parse_from(["sumeragi", command, "--epoch", "1"])
                    .expect_err("retired operator command must not parse");
            assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
        }
        assert!(SumeragiCommandFixture::try_parse_from(["sumeragi", "status"]).is_ok());
    }

    #[test]
    fn evidence_kind_filter_maps_to_the_current_wire_name() {
        let cases = [(
            EvidenceKindArg::NativeSumeragiEvidence,
            "NativeSumeragiEvidence",
        )];
        for (kind, expected) in cases {
            assert_eq!(kind.into_client().as_str(), expected);
            assert_eq!(
                kind.to_possible_value()
                    .expect("evidence kind must have a CLI value")
                    .get_name(),
                expected
            );
        }
    }

    #[test]
    fn evidence_pagination_arguments_enforce_the_server_bounds() {
        for args in [
            ["sumeragi", "evidence", "list", "--limit", "0"],
            ["sumeragi", "evidence", "list", "--limit", "1001"],
            ["sumeragi", "evidence", "list", "--offset", "10001"],
        ] {
            let error = SumeragiCommandFixture::try_parse_from(args)
                .expect_err("out-of-range evidence pagination must fail locally");
            assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
        }
        assert!(
            SumeragiCommandFixture::try_parse_from([
                "sumeragi", "evidence", "list", "--limit", "1000", "--offset", "10000",
            ])
            .is_ok()
        );
    }
}
