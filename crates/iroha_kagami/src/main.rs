//! Managed developer networks and contract deployment over shared Iroha services.
//! Native operator tools also generate genesis, keys, configuration and schema references.
#![allow(
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::items_after_test_module,
    clippy::struct_excessive_bools,
    clippy::cast_possible_truncation,
    clippy::match_same_arms,
    clippy::unnecessary_debug_formatting
)]
use clap::{Args as ClapArgs, Parser, Subcommand};
use color_eyre::eyre::WrapErr as _;
use iroha_genesis::init_instruction_registry;
use std::{
    io::{BufWriter, Write, stdout},
    process::ExitCode,
};
mod atomic_output;
mod client_configs;
mod codec;
mod crypto;
mod developer;
mod genesis;
mod kura;
/// Helpers for generating a multi-peer localnet (configs, scripts, genesis).
pub mod localnet;
mod network_bootstrap;
mod privacy_bootstrap;
mod schema;
use iroha_deploy::secret_toml;
mod secure_fs;
use iroha_deploy::shell;
mod swarm;
mod tui;
mod verify;
mod wizard;
/// Norito JSON derive macros available to Kagami modules.
pub mod json_macros {
    pub use norito::derive::{FastJson, FastJsonWrite, JsonDeserialize, JsonSerialize};
}
/// Outcome shorthand used throughout this crate
// TODO: Migrate Kagami CLI to `error_stack` once modules no longer depend on
// `color_eyre` convenience macros.
pub(crate) type Outcome = color_eyre::Result<()>;
/// Build-time source identity embedded for release artifact validation.
const BUILD_SOURCE_ID: Option<&str> = option_env!("IROHA_GIT_COMMIT_HASH");
const TOP_LEVEL_HELP: &str = concat!(
    "Common tasks:\n",
    "  kagami localnet up\n",
    "  kagami dataspace up acme --network taira\n",
    "  kagami contract deploy hello.ko\n",
    "  kagami package publish .\n",
    "  kagami context list\n",
    "  kagami wizard\n",
    "  kagami localnet generate --out-dir ./localnet\n",
    "  kagami docker --peers 4 --config-dir ./localnet --image hyperledger/iroha:dev --out-file docker-compose.yml\n",
    "  kagami keys --out-dir ./key-custody\n",
    "  kagami keys --algorithm bls_normal --pop --out-dir ./validator-custody\n",
    "  kagami advanced markdown-help\n",
);
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if let Some(status) = error.downcast_ref::<developer::PublicationExit>() {
                return ExitCode::from(status.0);
            }
            eprintln!("{error:?}");
            ExitCode::FAILURE
        }
    }
}
fn run() -> Outcome {
    let _ = std::hint::black_box(BUILD_SOURCE_ID);
    color_eyre::install()?;
    init_instruction_registry();
    let cli = Cli::parse();
    cli.ui.install();
    let mut writer = BufWriter::new(stdout());
    cli.command.run(&mut writer)
}
/// Trait to encapsulate common attributes of the commands and sub-commands.
trait RunArgs<T: Write> {
    /// Run the given command.
    ///
    /// # Errors
    /// if inner command fails.
    fn run(self, writer: &mut BufWriter<T>) -> Outcome;
}
#[derive(Parser)]
#[command(
    name = "kagami",
    version,
    author,
    about = "Start local networks, attach private dataspaces, and deploy Iroha contracts.",
    after_help = TOP_LEVEL_HELP
)]
struct Cli {
    #[command(flatten)]
    ui: tui::UiOptions,
    #[command(subcommand)]
    command: Command,
}
/// Managed developer workflows and native operator tools for Iroha.
#[derive(Subcommand)]
enum Command {
    /// Guided onboarding flow for staging a Sora Nexus observer configuration
    Wizard(wizard::Args),
    /// Start and manage a persistent localnet without supplying configuration
    #[command(subcommand)]
    Localnet(developer::LocalnetCommand),
    /// Run an owner-private local dataspace attached to an installed remote network
    #[command(subcommand)]
    Dataspace(developer::DataspaceCommand),
    /// Select and inspect managed developer environments
    #[command(subcommand)]
    Context(developer::ContextCommand),
    /// Build and deploy native IVM contracts in one invocation
    #[command(subcommand)]
    Contract(developer::ContractCommand),
    /// Publish native Musubi packages through an exact generated local environment
    #[command(subcommand)]
    Package(developer::PackageCommand),
    /// Internal native process-owner entry point
    #[command(name = "_managed-worker", hide = true)]
    ManagedWorker(developer::WorkerArgs),
    /// Generate validator-only Docker Compose from a prepared bundle or explicit dev seed
    Docker(swarm::Args),
    /// Generate cryptographic key pairs and optional validator Proofs-of-Possession
    Keys(Box<crypto::Args>),
    /// Commands related to genesis
    #[clap(subcommand)]
    Genesis(genesis::Args),
    /// Emit and validate fail-closed Taira exact-12 privacy bootstrap artifacts
    PrivacyBootstrap(privacy_bootstrap::Args),
    /// Verify a genesis manifest against a preset profile
    Verify(verify::Args),
    /// Advanced low-level helpers for codec conversion, schema generation, block inspection, and docs
    #[clap(subcommand)]
    Advanced(AdvancedCommand),
}
#[derive(Subcommand)]
enum AdvancedCommand {
    /// Prepare signed remote-network bootstrap and native installation authorities offline
    #[command(subcommand)]
    NetworkBootstrap(network_bootstrap::Command),
    /// Generate per-client CLI configs from a base client.toml
    #[command(name = "client-configs")]
    ClientConfigs(client_configs::Args),
    /// Commands related to Norito codec conversions
    Codec(codec::Args),
    /// Commands related to block inspection
    Kura(kura::Args),
    /// Output CLI documentation in Markdown format
    MarkdownHelp(MarkdownHelp),
    /// Generate the schema used for code generation in Iroha SDKs
    Schema(schema::Args),
}
impl<T: Write> RunArgs<T> for AdvancedCommand {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        match self {
            Self::NetworkBootstrap(args) => args.run(writer),
            Self::ClientConfigs(args) => args.run(writer),
            Self::Codec(args) => args.run(writer),
            Self::Kura(args) => args.run(writer),
            Self::MarkdownHelp(args) => args.run(writer),
            Self::Schema(args) => args.run(writer),
        }
    }
}
impl<T: Write> RunArgs<T> for Command {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        use Command::*;
        match self {
            Wizard(args) => args.run(writer),
            Localnet(args) => args.run(writer),
            Dataspace(args) => args.run(writer),
            Context(args) => args.run(writer),
            Contract(args) => args.run(writer),
            Package(args) => args.run(writer),
            ManagedWorker(args) => args.run(writer),
            Docker(args) => args.run(writer),
            Keys(args) => args.run(writer),
            Genesis(args) => args.run(writer),
            PrivacyBootstrap(args) => args.run(writer),
            Verify(args) => args.run(writer),
            Advanced(args) => args.run(writer),
        }
    }
}
#[derive(Debug, ClapArgs, Clone)]
struct MarkdownHelp;
impl<T: Write> RunArgs<T> for MarkdownHelp {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        let command_info = clap_markdown::help_markdown::<Cli>();
        writer.write_all(command_info.as_bytes())?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::{Cli, Parser};
    use clap::{CommandFactory, Error};
    fn parse(args: &str) -> Result<Cli, Error> {
        Cli::try_parse_from(args.split(' '))
    }
    #[test]
    fn verify_args() {
        Cli::command().debug_assert();
    }
    #[test]
    fn privacy_bootstrap_commands_require_complete_exact_v1_artifact_paths() {
        assert!(
            parse(
                "kagami privacy-bootstrap emit-taira-v1 \
                 --instructions-output ./privacy-instructions.json \
                 --report-output ./privacy-report.json"
            )
            .is_ok()
        );
        assert!(
            parse(
                "kagami privacy-bootstrap validate-taira-v1 \
                 --instructions ./privacy-instructions.json \
                 --report ./privacy-report.json"
            )
            .is_ok()
        );
        assert!(
            parse(
                "kagami privacy-bootstrap validate-taira-nevo-review-v1 \
                 --unsigned-genesis ./unsigned-genesis.template.json \
                 --review ./review.json"
            )
            .is_ok()
        );
        assert!(
            parse(
                "kagami privacy-bootstrap render-taira-release-v1 \
                 --activation-instructions ./privacy-instructions.json \
                 --activation-report ./privacy-report.json \
                 --broker-public-export ./broker-public.json \
                 --plan-template ./privacy-plan.staging.json \
                 --config-template ./config.staging.toml \
                 --genesis-template ./genesis.staging.template.json \
                 --nevo-review ./review.json \
                 --plan-output ./privacy-plan.release.json \
                 --config-output ./config.release.toml \
                 --genesis-output ./genesis.release.template.json \
                 --broker-public-output ./broker-public.verified.json"
            )
            .is_ok()
        );
        assert!(
            parse(
                "kagami privacy-bootstrap render-taira-release-v1 \
                 --activation-instructions ./privacy-instructions.json \
                 --activation-report ./privacy-report.json \
                 --broker-public-export ./broker-public.json"
            )
            .is_err(),
            "release composition without every staging input and fresh output must fail"
        );
        assert!(
            parse(
                "kagami privacy-bootstrap validate-taira-nevo-review-v1 \
                 --unsigned-genesis ./unsigned-genesis.template.json"
            )
            .is_err(),
            "NEVO validation without the review manifest must remain unavailable"
        );
        assert!(
            parse(
                "kagami privacy-bootstrap emit-taira-v1 \
                 --instructions-output ./privacy-instructions.json"
            )
            .is_err(),
            "emission without its digest inventory must remain unavailable"
        );
        assert!(
            parse("kagami privacy-bootstrap emit --output ./legacy.json").is_err(),
            "the first release has no compatibility command aliases"
        );
    }
    #[test]
    fn parser_rejects_retired_kagemusha_commands() {
        use clap::error::ErrorKind;

        for retired in [
            "kagami kagemusha derive-mint-finality-next-epoch-v1",
            "kagami kagemusha derive-mint-finality-epoch-schedule-v1",
            "kagami kagemusha authenticate-release-v1 \
             --manifest ./release.norito \
             --validation-receipt ./receipt.norito \
             --authority-policy ./policy.norito \
             --attestation ./attestation.norito",
            "kagami kagemusha prepare-mobile-bootstrap-v1",
            "kagami kagemusha",
        ] {
            let error = parse(retired)
                .err()
                .expect("the old KAGEMUSHA command family must remain deleted");
            assert_eq!(error.kind(), ErrorKind::InvalidSubcommand, "{retired}");
        }
    }
    #[test]
    fn docker_accepts_valid_flags() {
        assert!(
            parse(
                "kagami docker \
            -p 20 \
            -c ./config \
            -i hyperledger/iroha \
            -o sample.yml\
            -HF",
            )
            .is_ok()
        )
    }
    #[test]
    fn docker_cannot_mix_print_and_force() {
        assert!(
            parse(
                "kagami docker \
            -p 20 \
            -c ./config \
            -i hyperledger/iroha \
            -o sample.yml \
            -PF",
            )
            .is_err()
        )
    }
    #[test]
    fn docker_accepts_pull_image_mode() {
        assert!(
            parse(
                "kagami docker \
            -p 20 \
            -c ./config \
            -i hyperledger/iroha \
            -o sample.yml",
            )
            .is_ok()
        )
    }
    #[test]
    fn docker_accepts_build_mode() {
        assert!(
            parse(
                "kagami docker \
            -p 20 \
            -i hyperledger/iroha \
            -b . \
            -c ./config \
            -o sample.yml",
            )
            .is_ok()
        )
    }
    #[test]
    fn docker_requires_image() {
        assert!(
            parse(
                "kagami docker \
            -p 1 \
            -c ./ \
            -o test.yml",
            )
            .is_err()
        )
    }
    #[test]
    fn keys_requires_owner_only_custody_output() {
        assert!(parse("kagami keys --out-dir ./custody").is_ok());
        assert!(parse("kagami keys").is_err());
        assert!(parse("kagami keys --out-dir ./custody --compact").is_err());
        assert!(parse("kagami keys --out-dir ./custody --json").is_err());
        assert!(parse("kagami keys --out-dir ./custody --private-key deadbeef").is_err());
        assert!(parse("kagami keys --json --json-mh-prefixed").is_err());
    }
    #[test]
    fn genesis_sign_accepts_only_file_backed_private_keys() {
        assert!(
            parse("kagami genesis sign ./genesis.json --private-key-file ./genesis.private_key")
                .is_ok()
        );
        assert!(
            parse("kagami genesis sign ./genesis.json --private-key deadbeef").is_err(),
            "raw private-key argv input must remain retired"
        );
        assert!(
            parse("kagami genesis sign ./genesis.json --seed-hex 1111111111111111111111111111111111111111111111111111111111111111")
                .is_err(),
            "raw signing seeds must remain retired"
        );
        assert!(
            parse("kagami genesis sign ./genesis.json --private-key-file ./genesis.private_key --algorithm ed25519")
                .is_err(),
            "the canonical private-key record must be the only algorithm source"
        );
        assert!(
            parse("kagami genesis sign ./genesis.json --private-key-file ./genesis.private_key --consensus-mode npos")
                .is_err(),
            "the canonical manifest must be the only consensus-mode source"
        );
        assert!(parse("kagami genesis sign ./genesis.json").is_err());
    }
    #[test]
    fn advanced_subcommands_parse() {
        assert!(parse("kagami advanced codec list-types").is_ok());
        assert!(parse("kagami advanced schema").is_ok());
        assert!(parse("kagami advanced kura print ./store").is_ok());
        assert!(parse("kagami advanced markdown-help").is_ok());
        assert!(
            parse("kagami advanced client-configs --base-config ./client.toml --names alice")
                .is_ok()
        );
        assert!(
            parse(
                "kagami advanced client-configs --base-config ./client.toml --names alice --seed-hex 1111111111111111111111111111111111111111111111111111111111111111"
            )
            .is_ok()
        );
        assert!(
            parse(
                "kagami advanced client-configs --base-config ./client.toml --names alice --seed-prefix demo"
            )
            .is_err()
        );
    }
    #[test]
    fn removed_top_level_commands_fail() {
        assert!(parse("kagami advanced kura ./store print").is_err());
        assert!(parse("kagami advanced kura -f 1 ./store print").is_err());
        assert!(parse("kagami advanced kura ./store sidecar -H 1").is_err());
        assert!(parse("kagami crypto --algorithm ed25519").is_err());
        assert!(parse("kagami swarm -p 1 -c ./cfg -i hyperledger/iroha -o docker.yml").is_err());
        assert!(parse("kagami codec list-types").is_err());
        assert!(parse("kagami schema").is_err());
        assert!(parse("kagami kura ./store print").is_err());
        assert!(parse("kagami client-configs --base-config ./client.toml --names alice").is_err());
        assert!(parse("kagami markdown-help").is_err());
        assert!(parse("kagami genesis pop --algorithm bls_normal").is_err());
    }
    #[test]
    fn checked_in_markdown_help_matches_generated_help() {
        let generated = clap_markdown::help_markdown::<Cli>();
        let checked_in = include_str!("../CommandLineHelp.md");
        assert_eq!(generated, checked_in);
    }
}
