//! Reconciliation status and bounded authenticated forged-mint proof submissions.

use super::*;
use iroha::data_model::{
    isi::sccp::ProveSccpForgedMintV1,
    sccp::{inbound::SCCP_SOURCE_PROOF_MAX_BYTES_V1, reconciliation::SccpForgedMintProofV1},
};
use iroha_sccp::{light_client::proof::SccpSourceProofV1, v1::payload::SccpTransferPayloadV1};
use std::{
    io::Read as _,
    path::{Path, PathBuf},
};

/// JSON base64 plus bounded payload/field overhead, checked while reading the file.
const MAX_PROOF_JSON_BYTES: usize = 2 * SCCP_SOURCE_PROOF_MAX_BYTES_V1 + 16_384;

/// `iroha sccp reconcile` operations.
#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Show effective holds, the proof window, forged supply and fixed payout rate.
    Status(StatusArgs),
    /// Submit an authenticated destination finalization proof within an open window.
    ProveMint(ProveMintArgs),
}

/// Optional route selection for reconciliation status.
#[derive(Debug, clap::Args)]
pub struct StatusArgs {
    /// External network profile; omit to page across all external routes.
    #[arg(long)]
    network: Option<String>,
    /// Specific nonzero revision of the selected network.
    #[arg(long, requires = "network", value_parser = clap::value_parser!(u32).range(1..))]
    revision: Option<u32>,
    /// Network of the previous page's next cursor; requires after-revision.
    #[arg(long, requires = "after_revision")]
    after_network: Option<String>,
    /// Revision of the previous page's next cursor; requires after-network.
    #[arg(long, requires = "after_network", value_parser = clap::value_parser!(u32).range(1..))]
    after_revision: Option<u32>,
    /// Maximum scalar rows in this page.
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..=64))]
    limit: u32,
}

/// Authenticated proof bundle and immutable route identity.
#[derive(Debug, clap::Args)]
pub struct ProveMintArgs {
    /// Destination network (`ethereum-mainnet`, `bsc-mainnet`, `ton-mainnet`).
    #[arg(long)]
    network: String,
    /// Quarantined destination revision with an open reconciliation window.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    revision: u32,
    /// Norito JSON `SccpForgedMintProofV1` file with source proof and canonical payload preimage.
    #[arg(long)]
    proof: PathBuf,
}

impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Self::Status(args) => {
                let network = args.network.as_deref().map(parse_network).transpose()?;
                let after = args
                    .after_network
                    .as_deref()
                    .map(|network| -> Result<_> {
                        Ok(iroha_sccp::api::SccpForgeryHoldCursorV1 {
                            network: parse_network(network)?,
                            revision: args.after_revision.ok_or_else(|| {
                                eyre::eyre!("after-network requires after-revision")
                            })?,
                        })
                    })
                    .transpose()?;
                let view = blocking(context)?.sccp().forgery_hold(
                    iroha_sccp::api::SccpForgeryHoldQuery {
                        network,
                        revision: args.revision,
                        after,
                        limit: args.limit as usize,
                    },
                )?;
                context.print_data(&view)
            }
            Self::ProveMint(args) => {
                let network = parse_network(&args.network)?;
                let proof = read_proof(&args.proof)?;
                validate_route(&proof, network, args.revision)?;
                context.finish(vec![InstructionBox::from(ProveSccpForgedMintV1 {
                    network,
                    revision: args.revision,
                    proof,
                })])
            }
        }
    }
}

fn read_proof(path: &Path) -> Result<SccpForgedMintProofV1> {
    let file = std::fs::File::open(path).wrap_err("open forged-mint proof")?;
    let mut bytes = Vec::new();
    file.take((MAX_PROOF_JSON_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .wrap_err("read forged-mint proof")?;
    eyre::ensure!(
        bytes.len() <= MAX_PROOF_JSON_BYTES,
        "forged-mint proof JSON exceeds its bound"
    );
    norito::json::from_slice(&bytes).wrap_err("decode SccpForgedMintProofV1 JSON")
}

/// Local structural check only; Core authenticates the event and payload message-id binding.
fn validate_route(
    proof: &SccpForgedMintProofV1,
    network: SccpNetworkV1,
    revision: u32,
) -> Result<()> {
    SccpSourceProofV1::from_frame(proof.source.as_bytes())?.expect_network(network)?;
    let payload = SccpTransferPayloadV1::decode(proof.payload.as_bytes())?;
    eyre::ensure!(
        revision != 0
            && payload.source() == Some(SccpNetworkV1::SoraTaira)
            && payload.target() == Some(network)
            && payload.route_revision == revision,
        "forged-mint payload must name the selected outbound route revision"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[derive(clap::Parser)]
    struct Args {
        #[command(subcommand)]
        command: Command,
    }

    #[test]
    fn reconcile_arguments_require_exact_nonzero_route_for_proving() {
        assert!(Args::try_parse_from(["reconcile", "status"]).is_ok());
        assert!(Args::try_parse_from(["reconcile", "status", "--limit", "65"]).is_err());
        assert!(
            Args::try_parse_from(["reconcile", "status", "--after-network", "ton-mainnet"])
                .is_err()
        );
        assert!(
            Args::try_parse_from([
                "reconcile",
                "status",
                "--after-network",
                "ton-mainnet",
                "--after-revision",
                "7",
                "--limit",
                "2"
            ])
            .is_ok()
        );
        assert!(Args::try_parse_from(["reconcile", "status", "--revision", "1"]).is_err());
        assert!(
            Args::try_parse_from([
                "reconcile",
                "prove-mint",
                "--network",
                "ton-mainnet",
                "--revision",
                "1",
                "--proof",
                "mint.json"
            ])
            .is_ok()
        );
        assert!(
            Args::try_parse_from([
                "reconcile",
                "prove-mint",
                "--network",
                "ton-mainnet",
                "--revision",
                "0",
                "--proof",
                "mint.json"
            ])
            .is_err()
        );
    }

    #[test]
    fn proof_file_reader_refuses_malformed_and_oversized_input() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"{}").unwrap();
        assert!(read_proof(file.path()).is_err());
        file.as_file()
            .set_len((MAX_PROOF_JSON_BYTES + 1) as u64)
            .unwrap();
        assert!(
            read_proof(file.path())
                .unwrap_err()
                .to_string()
                .contains("exceeds its bound")
        );
    }

    #[test]
    fn proof_wrapper_roundtrips_and_route_validation_rejects_cross_network_or_revision() {
        use iroha::data_model::sccp::reconciliation::SccpForgedMintPayloadV1;
        use iroha_sccp::{
            ethereum_source::EthereumNativeMptProofV1,
            light_client::ethereum::{
                EthereumAncestryV1, EthereumEventSelectorV1, EthereumLogRefV1,
                EthereumProofAnchorV1, EthereumSourceProofV1, EthereumStoredCheckpointRefV1,
            },
        };
        let network = SccpNetworkV1::EthereumMainnet;
        let source = SccpSourceProofV1::Ethereum(EthereumSourceProofV1 {
            anchor: EthereumProofAnchorV1::StoredCheckpoint(EthereumStoredCheckpointRefV1 {
                source_height: 42,
            }),
            ancestry: EthereumAncestryV1::SameBlock,
            event_header: vec![0xc0],
            transaction_index: 3,
            receipt_proof: EthereumNativeMptProofV1 {
                nodes: vec![vec![1, 2, 3]],
            },
            event: EthereumEventSelectorV1::Finalized(EthereumLogRefV1 { log_index: 1 }),
        })
        .to_bytes()
        .unwrap();
        let payload =
            SccpTransferPayloadV1::outbound(network, 1, 7, 1_000, 10, vec![2; 32], vec![1; 20])
                .unwrap();
        let proof = SccpForgedMintProofV1 {
            source,
            payload: SccpForgedMintPayloadV1::new(payload.encode().unwrap()).unwrap(),
        };
        assert!(validate_route(&proof, network, 7).is_ok());
        assert!(validate_route(&proof, network, 8).is_err());
        assert!(validate_route(&proof, SccpNetworkV1::BscMainnet, 7).is_err());
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), norito::json::to_vec(&proof).unwrap()).unwrap();
        assert_eq!(read_proof(file.path()).unwrap(), proof);
    }
}
