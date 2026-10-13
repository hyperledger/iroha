//! Original-root forgery candidates, durable submission and committed evidence status.

use super::{AnchorArgs, blocking, flows, origin};
use crate::{Run, RunContext};
use eyre::{Result, WrapErr as _, ensure, eyre};
use iroha::data_model::{
    isi::sccp::SubmitSccpForgeryEvidenceV1,
    sccp::{generation::SccpAnchorV1, native::SccpForgeryRuleV1},
};
use iroha_sccp::v1::{
    evidence::{anchor_chunk_position, forgery_evidence_id},
    finality::{SccpFinalityHeaderV1, verify_certificate},
};
use std::{
    io::Read as _,
    path::{Path, PathBuf},
};

const MAX_EVIDENCE_JSON: u64 = 32 * 1024;

/// Forgery evidence commands backed by original certified state.
#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Verify a destination certificate against an original native cut and build a candidate.
    Build(BuildArgs),
    /// Recheck and durably submit an original-root evidence candidate.
    Submit(SubmitArgs),
    /// Read one committed record or a bounded page of original evidence statuses.
    Status(StatusArgs),
    /// Read an original completed-chunk anchor witness.
    Anchor(AnchorArgs),
}

/// Candidate construction from an exact fixed certificate.
#[derive(Debug, clap::Args)]
pub struct BuildArgs {
    /// Independently selected genesis and complete certified World cut.
    #[command(flatten)]
    origin: origin::OriginArgs,
    /// Norito JSON SubmitSccpForgeryEvidenceV1; any supplied anchor is replaced from the node.
    #[arg(long)]
    certificate: PathBuf,
}

/// Durable candidate recheck and submission.
#[derive(Debug, clap::Args)]
pub struct SubmitArgs {
    /// Independently selected genesis and complete certified World cut.
    #[command(flatten)]
    origin: origin::OriginArgs,
    /// Norito JSON output of evidence build or monitor.
    #[arg(long)]
    candidate: PathBuf,
    /// Durable operation selection; defaults to the deterministic evidence id.
    #[command(flatten)]
    flow: flows::FlowArgs,
}

/// Exact evidence selection or bounded forward pagination.
#[derive(Debug, clap::Args)]
pub struct StatusArgs {
    /// Exact 32-byte evidence id; mutually exclusive with paging arguments.
    #[arg(long, conflicts_with_all = ["after", "limit"])]
    evidence_id: Option<String>,
    /// Exclusive evidence-id cursor from the previous page.
    #[arg(long)]
    after: Option<String>,
    /// Page size, at most 64; defaults to 64.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=64))]
    limit: Option<u32>,
}

/// A locally verified mismatch at a selected original cut, awaiting current Core admission.
#[derive(Debug, norito::json::JsonSerialize, norito::json::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub(super) struct Candidate {
    pub network_id: [u8; 32],
    pub consensus_instance: [u8; 32],
    pub observed_at_height: u64,
    pub evidence_id: [u8; 32],
    pub rule: SccpForgeryRuleV1,
    pub evidence: SubmitSccpForgeryEvidenceV1,
}

fn read_json<T: norito::json::JsonDeserialize>(path: &Path) -> Result<T> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_EVIDENCE_JSON + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_EVIDENCE_JSON,
        "evidence JSON must fit its 32 KiB input bound"
    );
    norito::json::from_slice(&bytes).wrap_err("decode SCCP evidence JSON")
}

fn classify(
    height: u64,
    generation_start: u64,
    generation_end: Option<u64>,
    tip: u64,
    block_hash: [u8; 32],
    result: [u8; 32],
    anchor: Option<SccpAnchorV1>,
) -> Result<Option<SccpForgeryRuleV1>> {
    if height < generation_start || generation_end.is_some_and(|end| height > end) {
        return Ok(Some(SccpForgeryRuleV1::E1));
    }
    if height > tip {
        return Ok(Some(SccpForgeryRuleV1::E2));
    }
    let anchor =
        anchor.ok_or_else(|| eyre!("the original certified height anchor is unavailable"))?;
    if block_hash != anchor.core_hash {
        return Ok(Some(SccpForgeryRuleV1::E3));
    }
    if result != anchor.result {
        return Ok(Some(SccpForgeryRuleV1::E4));
    }
    Ok(None)
}

/// Reuse the exact native walk; endpoint-supplied committees and anchors never select authority.
pub(super) fn inspect<C: RunContext>(
    context: &C,
    client: &iroha::blocking::Client,
    args: &origin::OriginArgs,
    mut evidence: SubmitSccpForgeryEvidenceV1,
) -> Result<Option<Candidate>> {
    let header = SccpFinalityHeaderV1::parse(&evidence.header)?;
    ensure!(
        header.is_active(),
        "NotEvidence: the certificate is inactive"
    );
    let (original, anchor) =
        origin::authenticate_origin_with_anchor(context, client, args, Some(header.height()))?;
    ensure!(
        header.network_id() == original.network,
        "NotEvidence: the certificate names another network"
    );
    let generation = original.verify_generation(
        header.generation(),
        client.sccp().committee(header.generation())?,
    )?;
    let certified = verify_certificate(
        &original.instance,
        &evidence.qc,
        &evidence.header,
        &evidence.aggregate_signature,
        &generation.keys,
    )?;
    let Some(rule) = classify(
        header.height(),
        generation.start_height,
        generation.end.map(|end| end.end_height),
        original.height(),
        certified.qc.block_hash,
        certified.result,
        anchor,
    )?
    else {
        return Ok(None);
    };
    evidence.anchor = None;
    if matches!(rule, SccpForgeryRuleV1::E3 | SccpForgeryRuleV1::E4) {
        let (chunk, _) =
            anchor_chunk_position(header.height()).ok_or_else(|| eyre!("zero claim height"))?;
        let (open, _) =
            anchor_chunk_position(original.height()).ok_or_else(|| eyre!("zero native tip"))?;
        if chunk < open {
            let response = client
                .sccp()
                .anchor_witness(std::num::NonZeroU64::new(header.height()).unwrap())?;
            ensure!(
                response.height == header.height() && response.chunk == chunk,
                "anchor response names another height"
            );
            let witness = response
                .witness
                .ok_or_else(|| eyre!("completed anchor witness unavailable"))?;
            original.verify_anchor_witness(header.height(), &witness)?;
            let native = anchor.ok_or_else(|| eyre!("original native anchor unavailable"))?;
            ensure!(
                witness.core_hash == native.core_hash && witness.result == native.result,
                "anchor witness differs from original contiguous native verification"
            );
            evidence.anchor = Some(witness);
        }
    }
    Ok(Some(Candidate {
        network_id: original.network,
        consensus_instance: original.instance,
        observed_at_height: original.height(),
        evidence_id: forgery_evidence_id(
            generation.generation,
            &certified.message,
            certified.qc.signers,
        ),
        rule,
        evidence,
    }))
}

fn build<C: RunContext>(
    context: &C,
    client: &iroha::blocking::Client,
    args: &origin::OriginArgs,
    evidence: SubmitSccpForgeryEvidenceV1,
) -> Result<Candidate> {
    inspect(context, client, args, evidence)?.ok_or_else(|| {
        eyre!("NotEvidence: the certificate names the original native block and result")
    })
}

impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client = blocking(context)?;
        match self {
            Self::Build(args) => context.print_data(&build(
                context,
                &client,
                &args.origin,
                read_json(&args.certificate)?,
            )?),
            Self::Submit(args) => {
                let offered: Candidate = read_json(&args.candidate)?;
                ensure!(
                    offered.network_id == *context.config().network_id.as_bytes(),
                    "candidate names another configured network"
                );
                let flow = flows::open(
                    context,
                    iroha_sccp_wallet::journal::SccpFlowKindV1::EvidenceSubmission,
                    &args.flow,
                    offered.evidence_id,
                )?;
                if flows::recover_taira(
                    context,
                    &flow,
                    iroha_sccp_wallet::flow::SccpFlowActionV1::RecordEvidence,
                )? {
                    return Ok(());
                }
                let checked = build(context, &client, &args.origin, offered.evidence)?;
                ensure!(
                    offered.network_id == checked.network_id
                        && offered.consensus_instance == checked.consensus_instance
                        && offered.evidence_id == checked.evidence_id,
                    "candidate identity differs from the independently selected original state"
                );
                let source = flows::evidence("sccp.native_evidence", &checked)?;
                flows::taira(
                    context,
                    &flow,
                    iroha_sccp_wallet::flow::SccpFlowActionV1::RecordEvidence,
                    vec![checked.evidence.into()],
                    vec![source],
                )?;
                Ok(())
            }
            Self::Status(args) => {
                if let Some(id) = args.evidence_id {
                    context.print_data(&client.sccp().evidence(&super::parse_word(&id)?)?)
                } else {
                    context.print_data(&client.sccp().evidence_page(
                        args.after.as_deref().map(super::parse_word).transpose()?,
                        args.limit.unwrap_or(64) as usize,
                    )?)
                }
            }
            Self::Anchor(args) => context.print_data(&client.sccp().anchor_witness(args.height)?),
        }
    }
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
    fn original_mismatch_rules_preserve_order_and_never_label_a_genuine_anchor() {
        let anchor = Some(SccpAnchorV1 {
            core_hash: [1; 32],
            result: [2; 32],
        });
        assert_eq!(
            classify(4, 5, None, 3, [1; 32], [2; 32], None).unwrap(),
            Some(SccpForgeryRuleV1::E1)
        );
        assert_eq!(
            classify(8, 5, Some(7), 6, [1; 32], [2; 32], None).unwrap(),
            Some(SccpForgeryRuleV1::E1)
        );
        assert_eq!(
            classify(8, 5, None, 7, [1; 32], [2; 32], None).unwrap(),
            Some(SccpForgeryRuleV1::E2)
        );
        assert_eq!(
            classify(7, 5, None, 7, [9; 32], [9; 32], anchor).unwrap(),
            Some(SccpForgeryRuleV1::E3)
        );
        assert_eq!(
            classify(7, 5, None, 7, [1; 32], [9; 32], anchor).unwrap(),
            Some(SccpForgeryRuleV1::E4)
        );
        assert!(
            classify(7, 5, None, 7, [1; 32], [2; 32], anchor)
                .unwrap()
                .is_none()
        );
        assert!(classify(7, 5, None, 7, [9; 32], [9; 32], None).is_err());
        assert!(
            classify(5, 5, Some(5), 7, [1; 32], [2; 32], anchor)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn status_arguments_are_bounded_and_exact_selection_excludes_paging() {
        assert!(Args::try_parse_from(["evidence", "status"]).is_ok());
        assert!(Args::try_parse_from(["evidence", "status", "--limit", "0"]).is_err());
        assert!(Args::try_parse_from(["evidence", "status", "--limit", "65"]).is_err());
        assert!(
            Args::try_parse_from(["evidence", "status", "--evidence-id", "ab", "--limit", "1"])
                .is_err()
        );
        assert!(Args::try_parse_from(["evidence", "anchor", "0"]).is_err());
        assert!(Args::try_parse_from(["evidence", "anchor", "1"]).is_ok());
    }

    #[test]
    fn evidence_reader_rejects_empty_malformed_and_oversized_input() {
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(read_json::<SubmitSccpForgeryEvidenceV1>(file.path()).is_err());
        std::fs::write(file.path(), b"{}").unwrap();
        assert!(read_json::<SubmitSccpForgeryEvidenceV1>(file.path()).is_err());
        file.as_file().set_len(MAX_EVIDENCE_JSON + 1).unwrap();
        assert!(read_json::<SubmitSccpForgeryEvidenceV1>(file.path()).is_err());
    }
}
