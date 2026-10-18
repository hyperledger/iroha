//! Typed arguments for local SoraFS artifact operations.

use super::*;

/// Options for the advert operation.
#[derive(clap::Args, Debug, Default)]
pub struct AdvertArgs {
    #[arg(long, value_parser = parse_path)]
    pub(super) input: Option<PathBuf>,
    #[arg(long, value_parser = OutputFormat::parse)]
    pub(super) format: Option<OutputFormat>,
    #[arg(long, value_parser = parse_path)]
    pub(super) telemetry_out: Option<PathBuf>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--now"))]
    pub(super) now: Option<u64>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--generated-at"))]
    pub(super) generated_at: Option<u64>,
}

/// Options for the admission operation.
#[derive(clap::Args, Debug, Default)]
pub struct AdmissionArgs {
    #[arg(long, value_parser = parse_path)]
    pub(super) input: Option<PathBuf>,
    #[arg(long, value_parser = parse_path, conflicts_with = "revocation")]
    pub(super) renewal: Option<PathBuf>,
    #[arg(long, value_parser = parse_path)]
    pub(super) revocation: Option<PathBuf>,
    #[arg(long, value_parser = OutputFormat::parse)]
    pub(super) format: Option<OutputFormat>,
    #[arg(long, value_parser = parse_path)]
    pub(super) telemetry_out: Option<PathBuf>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--generated-at"))]
    pub(super) generated_at: Option<u64>,
}

/// Options for the pdp operation.
#[derive(clap::Args, Debug, Default)]
pub struct PdpArgs {
    #[arg(long, value_parser = parse_path)]
    pub(super) commitment: Option<PathBuf>,
    #[arg(long, value_parser = parse_path)]
    pub(super) challenge: Option<PathBuf>,
    #[arg(long, value_parser = parse_path)]
    pub(super) proof: Option<PathBuf>,
    #[arg(long, value_parser = OutputFormat::parse)]
    pub(super) format: Option<OutputFormat>,
    #[arg(long, value_parser = parse_path)]
    pub(super) telemetry_out: Option<PathBuf>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--generated-at"))]
    pub(super) generated_at: Option<u64>,
}

/// Options for the por operation.
#[derive(clap::Args, Debug, Default)]
pub struct PorArgs {
    #[arg(long, value_parser = parse_path)]
    pub(super) challenge: Option<PathBuf>,
    #[arg(long, value_parser = parse_path)]
    pub(super) proof: Option<PathBuf>,
    #[arg(long, value_parser = OutputFormat::parse)]
    pub(super) format: Option<OutputFormat>,
    #[arg(long, value_parser = parse_path)]
    pub(super) telemetry_out: Option<PathBuf>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--generated-at"))]
    pub(super) generated_at: Option<u64>,
}

/// Options for the potr operation.
#[derive(clap::Args, Debug, Default)]
pub struct PotrArgs {
    #[arg(long, value_parser = parse_path)]
    pub(super) receipt: Option<PathBuf>,
    #[arg(long, value_parser = parse_profile)]
    pub(super) profile: Option<ProofStreamTier>,
    #[arg(long, value_parser = OutputFormat::parse)]
    pub(super) format: Option<OutputFormat>,
    #[arg(long, value_parser = parse_path)]
    pub(super) telemetry_out: Option<PathBuf>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--generated-at"))]
    pub(super) generated_at: Option<u64>,
}

/// Options for the pop operation.
#[derive(clap::Args, Debug, Default)]
pub struct PopArgs {
    #[arg(long, value_parser = parse_path)]
    pub(super) input: Option<PathBuf>,
    #[arg(long, value_parser = parse_pop_kind)]
    pub(super) kind: Option<PopValidationPayloadKindV1>,
    #[arg(long, value_parser = OutputFormat::parse)]
    pub(super) format: Option<OutputFormat>,
    #[arg(long, value_parser = parse_path)]
    pub(super) telemetry_out: Option<PathBuf>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--generated-at"))]
    pub(super) generated_at: Option<u64>,
}

/// Options for the repair operation.
#[derive(clap::Args, Debug, Default)]
pub struct RepairArgs {
    #[arg(long, value_parser = parse_path)]
    pub(super) input: Option<PathBuf>,
    #[arg(long, value_parser = parse_repair_kind)]
    pub(super) kind: Option<RepairValidationPayloadKindV1>,
    #[arg(long, value_parser = OutputFormat::parse)]
    pub(super) format: Option<OutputFormat>,
    #[arg(long, value_parser = parse_path)]
    pub(super) telemetry_out: Option<PathBuf>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--generated-at"))]
    pub(super) generated_at: Option<u64>,
}

/// Options for the hedging operation.
#[derive(clap::Args, Debug, Default)]
pub struct HedgingArgs {
    #[arg(long, value_parser = parse_path)]
    pub(super) input: Option<PathBuf>,
    #[arg(long, value_parser = parse_hedging_kind)]
    pub(super) kind: Option<HedgingValidationPayloadKindV1>,
    #[arg(long, value_parser = OutputFormat::parse)]
    pub(super) format: Option<OutputFormat>,
    #[arg(long, value_parser = parse_path)]
    pub(super) telemetry_out: Option<PathBuf>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--generated-at"))]
    pub(super) generated_at: Option<u64>,
}

/// Options for the orderbook operation.
#[derive(clap::Args, Debug, Default)]
pub struct OrderbookArgs {
    #[arg(long, value_parser = parse_path)]
    pub(super) input: Option<PathBuf>,
    #[arg(long, value_parser = parse_orderbook_kind)]
    pub(super) kind: Option<OrderbookValidationPayloadKindV1>,
    #[arg(long, value_parser = OutputFormat::parse)]
    pub(super) format: Option<OutputFormat>,
    #[arg(long, value_parser = parse_path)]
    pub(super) telemetry_out: Option<PathBuf>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--generated-at"))]
    pub(super) generated_at: Option<u64>,
}

/// Options for the bundle operation.
#[derive(clap::Args, Debug, Default)]
pub struct BundleArgs {
    #[arg(long, value_parser = parse_path)]
    pub(super) bundle: Option<PathBuf>,
    #[arg(long, value_parser = OutputFormat::parse)]
    pub(super) format: Option<OutputFormat>,
    #[arg(long, value_parser = parse_path)]
    pub(super) telemetry_out: Option<PathBuf>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--now"))]
    pub(super) now: Option<u64>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--generated-at"))]
    pub(super) generated_at: Option<u64>,
}

/// Options for the governance operation.
#[derive(clap::Args, Debug, Default)]
pub struct GovernanceArgs {
    #[arg(long, value_parser = parse_path)]
    pub(super) node: Option<PathBuf>,
    #[arg(skip)]
    pub(super) block: Option<PathBuf>,
    #[arg(long, value_parser = parse_path)]
    pub(super) head: Option<PathBuf>,
    #[arg(long = "block")]
    pub(super) blocks: Vec<PathBuf>,
    #[arg(long, value_parser = parse_nonempty_text)]
    pub(super) cid: Option<String>,
    #[arg(long, value_parser = OutputFormat::parse)]
    pub(super) format: Option<OutputFormat>,
    #[arg(long, value_parser = parse_path)]
    pub(super) telemetry_out: Option<PathBuf>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--generated-at"))]
    pub(super) generated_at: Option<u64>,
}

/// Options for the release-manifest operation.
#[derive(clap::Args, Debug, Default)]
pub struct ReleaseManifestArgs {
    #[arg(long, value_parser = parse_path)]
    pub(super) manifest: Option<PathBuf>,
    #[arg(long, value_parser = parse_path)]
    pub(super) public_key: Option<PathBuf>,
    #[arg(long, value_parser = parse_nonempty_text)]
    pub(super) public_key_fingerprint: Option<String>,
    #[arg(long, value_parser = parse_path)]
    pub(super) signature: Option<PathBuf>,
    #[arg(long, value_parser = parse_path)]
    pub(super) signing_seed: Option<PathBuf>,
    #[arg(long, value_parser = parse_path)]
    pub(super) signature_out: Option<PathBuf>,
    #[arg(long)]
    pub(super) development_local_signing: bool,
}

/// Options for the sign operation.
#[derive(clap::Args, Debug, Default)]
pub struct SignArgs {
    #[arg(long, value_parser = parse_sign_kind)]
    pub(super) kind: Option<SignKind>,
    #[arg(long, value_parser = parse_orderbook_sign_kind)]
    pub(super) payload_kind: Option<OrderbookValidationPayloadKindV1>,
    #[arg(long, value_parser = parse_path)]
    pub(super) input: Option<PathBuf>,
    #[arg(long, value_parser = parse_path)]
    pub(super) out: Option<PathBuf>,
    #[arg(long, value_parser = parse_nonempty_text)]
    pub(super) key_hex: Option<String>,
    #[arg(long, value_parser = parse_path)]
    pub(super) key: Option<PathBuf>,
    #[arg(long, value_parser = OutputFormat::parse)]
    pub(super) format: Option<OutputFormat>,
    #[arg(long, value_parser = parse_path)]
    pub(super) telemetry_out: Option<PathBuf>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--now"))]
    pub(super) now: Option<u64>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--generated-at"))]
    pub(super) generated_at: Option<u64>,
}

/// Options for the order operation.
#[derive(clap::Args, Debug, Default)]
pub struct OrderArgs {
    #[arg(long, value_parser = parse_path, conflicts_with = "signed_order")]
    pub(super) order: Option<PathBuf>,
    #[arg(skip)]
    pub(super) signed: bool,
    #[arg(long, value_parser = OutputFormat::parse)]
    pub(super) format: Option<OutputFormat>,
    #[arg(long, value_parser = parse_path)]
    pub(super) telemetry_out: Option<PathBuf>,
    #[arg(long, value_parser = |value: &str| parse_u64_flag(value, "--generated-at"))]
    pub(super) generated_at: Option<u64>,
    #[arg(long, value_parser = parse_path, conflicts_with = "order")]
    pub(super) signed_order: Option<PathBuf>,
}

impl OrderArgs {
    pub(super) fn normalize(mut self) -> Self {
        if let Some(path) = self.signed_order.take() {
            self.order = Some(path);
            self.signed = true;
        }
        self
    }
}
impl GovernanceArgs {
    pub(super) fn normalize(mut self) -> Self {
        if self.head.is_none() && !self.blocks.is_empty() {
            self.block = Some(self.blocks.remove(0));
        }
        self
    }
}
fn parse_path(value: &str) -> Result<PathBuf, CliError> {
    parse_nonempty_text(value).map(PathBuf::from)
}
pub(super) fn parse_nonempty_text(value: &str) -> Result<String, CliError> {
    if value.is_empty() {
        return Err(CliError::Config("option requires a value".to_owned()));
    }
    Ok(value.to_owned())
}
