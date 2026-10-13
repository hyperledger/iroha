//! Read-only destination comparison against independently selected original native state.
//!
//! RPC observations are discovery data. Only a verified original-generation signature and
//! an E1–E4 mismatch become an evidence candidate; suggested Parliament actions are unsigned.

use super::{blocking, evidence, origin};
use crate::{Run, RunContext};
use eyre::{Result, ensure, eyre};
use iroha::data_model::{
    bridge::SccpNetworkV1,
    isi::sccp::SubmitSccpForgeryEvidenceV1,
    sccp::{
        deployment::SccpDeploymentV1,
        governance::{
            SccpAttestDeploymentProgressActionV1, SccpDeploymentProgressV1, SccpGovernanceActionV1,
            SccpRouteRevisionActionV1,
        },
        registry::SccpRouteRevisionV1,
    },
};
use iroha_sccp::v1::{
    committee::CommitteeStateV1,
    evm_abi::PauseViewV1,
    finality::{SccpFinalityHeaderV1, checkpoint_id, verify_certificate},
    proof::DestinationV1,
};
use std::{collections::BTreeMap, num::NonZeroU64};

const WARNING_MS: u64 = 3 * 24 * 60 * 60 * 1000;

/// One bounded monitor pass. Repeat with the printed cursors to scan retained event history.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Independently selected original native authority and complete certified World cut.
    #[command(flatten)]
    origin: origin::OriginArgs,
    /// Restrict configured pinned deployments to one external network.
    #[arg(long)]
    network: Option<String>,
    /// Restrict to one revision; requires network.
    #[arg(long, requires = "network")]
    revision: Option<NonZeroU64>,
    /// Exclusive EVM discovery cursor BLOCK:LOG_INDEX; requires one exact revision.
    #[arg(long, requires = "revision", conflicts_with = "ton_cursor")]
    evm_cursor: Option<String>,
    /// Next older TON transaction cursor LT:HASH; requires one exact revision.
    #[arg(long, requires = "revision", conflicts_with = "evm_cursor")]
    ton_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, norito::json::JsonSerialize)]
pub(crate) struct EvmCursor {
    pub block: u64,
    pub log_index: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, norito::json::JsonSerialize)]
pub(crate) struct TonCursor {
    pub lt: u64,
    pub hash: [u8; 32],
}

pub(crate) struct Observation {
    pub network: [u8; 32],
    pub instance: [u8; 32],
    pub committee: CommitteeStateV1,
    pub checkpoints: BTreeMap<u64, [u8; 32]>,
    pub now_ms: u64,
    pub pause: PauseViewV1,
}
#[derive(Default)]
pub(crate) struct Discovery {
    pub certificates: Vec<SubmitSccpForgeryEvidenceV1>,
    pub next_evm: Option<EvmCursor>,
    pub next_ton: Option<TonCursor>,
    pub ton_history_complete: bool,
}

#[derive(norito::json::JsonSerialize)]
struct Report {
    network: SccpNetworkV1,
    revision: u32,
    original_height: u64,
    observation: Option<Observed>,
    warnings: Vec<String>,
    candidates: Vec<evidence::Candidate>,
    suggested_action: Option<SccpGovernanceActionV1>,
    next_evm: Option<EvmCursor>,
    next_ton: Option<TonCursor>,
    ton_history_complete: bool,
}
#[derive(norito::json::JsonSerialize)]
struct Observed {
    generation: u64,
    committee_root: [u8; 32],
    start_height: u64,
    high: u64,
    until_ms: u64,
    equivocated: bool,
    destination_time_ms: u64,
    checkpoint_headers: BTreeMap<u64, [u8; 32]>,
    control_nonce: u64,
    parliament_paused: bool,
    fast_pause_until_ms: u64,
    effective_pause: bool,
}

fn evm_cursor(text: &str) -> Result<EvmCursor> {
    let (block, index) = text
        .split_once(':')
        .ok_or_else(|| eyre!("EVM cursor is BLOCK:LOG_INDEX"))?;
    Ok(EvmCursor {
        block: decimal(block)?,
        log_index: decimal(index)?,
    })
}
fn ton_cursor(text: &str) -> Result<TonCursor> {
    let (lt, hash) = text
        .split_once(':')
        .ok_or_else(|| eyre!("TON cursor is LT:HASH"))?;
    let lt = decimal(lt)?;
    ensure!(lt != 0, "TON transaction logical time must be positive");
    Ok(TonCursor {
        lt,
        hash: super::parse_word(hash)?,
    })
}
fn decimal(text: &str) -> Result<u64> {
    ensure!(
        !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()),
        "cursor integer must be decimal"
    );
    Ok(text.parse()?)
}
fn expiry_warning(until_ms: u64, now_ms: u64) -> bool {
    now_ms >= until_ms.saturating_sub(WARNING_MS)
}
fn recommendation(
    network: SccpNetworkV1,
    revision: &SccpRouteRevisionV1,
    maximum: Option<u64>,
    observed: &Observation,
    matches_original: bool,
) -> Option<SccpGovernanceActionV1> {
    if !revision.forgery_held(maximum) || revision.quarantine.is_some() {
        return None;
    }
    let progress = if matches_original && !observed.committee.is_live(observed.now_ms) {
        Some(SccpDeploymentProgressV1::Frozen)
    } else if matches_original
        && maximum.is_some_and(|maximum| observed.committee.generation > maximum)
    {
        Some(SccpDeploymentProgressV1::Generation {
            generation: observed.committee.generation,
            committee_root: observed.committee.root,
        })
    } else {
        None
    };
    Some(match progress {
        Some(at) => SccpGovernanceActionV1::AttestSccpDeploymentProgress(
            SccpAttestDeploymentProgressActionV1 {
                network,
                revision: revision.revision,
                at,
            },
        ),
        None => SccpGovernanceActionV1::QuarantineSccpRevision(SccpRouteRevisionActionV1 {
            network,
            revision: revision.revision,
        }),
    })
}

fn checkpoint_matches<C: RunContext>(
    context: &C,
    client: &iroha::blocking::Client,
    args: &origin::OriginArgs,
    height: u64,
    observed: [u8; 32],
) -> Result<bool> {
    if height > args.at_height {
        return Ok(false);
    }
    let (original, anchor) =
        origin::authenticate_origin_with_anchor(context, client, args, Some(height))?;
    let certificate = client.sccp().finality(super::SccpFinalityAt::Height(
        NonZeroU64::new(height).ok_or_else(|| eyre!("zero checkpoint"))?,
    ))?;
    let header = SccpFinalityHeaderV1::parse(&certificate.header)?;
    ensure!(
        header.height() == height && header.network_id() == original.network,
        "checkpoint response coordinates differ"
    );
    let generation = original.verify_generation(
        header.generation(),
        client.sccp().committee(header.generation())?,
    )?;
    let verified = verify_certificate(
        &original.instance,
        &certificate.qc,
        &certificate.header,
        &certificate.aggregate_signature,
        &generation.keys,
    )?;
    let anchor = anchor.ok_or_else(|| eyre!("original checkpoint anchor unavailable"))?;
    ensure!(
        anchor.core_hash == verified.qc.block_hash && anchor.result == verified.result,
        "checkpoint source is not the original native result"
    );
    Ok(checkpoint_id(&certificate.header) == observed)
}

impl Run for Args {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client = blocking(context)?;
        let original = origin::authenticate_origin(context, &client, &self.origin)?;
        let capabilities = client.sccp().capabilities()?;
        let maximum = original.forgery_max(&capabilities)?;
        let config = context.sccp_config()?;
        let selected_network = self
            .network
            .as_deref()
            .map(super::parse_network)
            .transpose()?;
        let selected_revision = self
            .revision
            .map(|value| u32::try_from(value.get()))
            .transpose()?;
        let after_evm = self.evm_cursor.as_deref().map(evm_cursor).transpose()?;
        let after_ton = self.ton_cursor.as_deref().map(ton_cursor).transpose()?;
        ensure!(
            after_evm.is_none() || selected_network != Some(SccpNetworkV1::TonMainnet),
            "EVM cursor cannot select TON"
        );
        ensure!(
            after_ton.is_none() || selected_network == Some(SccpNetworkV1::TonMainnet),
            "TON cursor requires ton-mainnet"
        );
        let pins = config
            .deployments
            .get(&context.config().network_id)
            .ok_or_else(|| eyre!("no deployments pinned for the configured network"))?;
        let selected: Vec<_> = pins
            .iter()
            .filter(|(network, _)| selected_network.is_none_or(|selected| selected == **network))
            .flat_map(|(network, revisions)| {
                revisions
                    .iter()
                    .filter(move |(revision, _)| {
                        selected_revision.is_none_or(|selected| selected == **revision)
                    })
                    .map(move |(revision, deployment)| (*network, *revision, *deployment))
            })
            .take(65)
            .collect();
        ensure!(
            !selected.is_empty() && selected.len() <= 64,
            "monitor requires 1..=64 pinned deployments; narrow --network/--revision"
        );
        let registry = client.sccp().registry()?;
        let mut reports = Vec::with_capacity(selected.len());
        for (network, number, pinned) in selected {
            let route = registry
                .iter()
                .find(|route| route.network == network)
                .ok_or_else(|| eyre!("pinned route is absent"))?;
            original.verify_route(network, route)?;
            let revision = route
                .revisions
                .get(&number)
                .ok_or_else(|| eyre!("pinned revision is absent"))?;
            ensure!(
                revision.deployment == pinned,
                "registered deployment differs from the configured pin"
            );
            let destination = DestinationV1 {
                network,
                route_revision: number,
                destination_word: revision.destination_word,
            };
            let mut report = Report {
                network,
                revision: number,
                original_height: original.height(),
                observation: None,
                warnings: Vec::new(),
                candidates: Vec::new(),
                suggested_action: (revision.forgery_held(maximum) && revision.quarantine.is_none())
                    .then_some(SccpGovernanceActionV1::QuarantineSccpRevision(
                        SccpRouteRevisionActionV1 {
                            network,
                            revision: number,
                        },
                    )),
                next_evm: None,
                next_ton: None,
                ton_history_complete: false,
            };
            let result = (|| -> Result<()> {
                let (observed, discovery) = match pinned {
                    SccpDeploymentV1::Evm(deployment) => {
                        let reader = super::evm::EvmDestination::monitor_connect(
                            &config,
                            network,
                            deployment.address,
                            destination,
                            deployment.runtime_code_hash,
                        )?;
                        (
                            reader.monitor_observe()?,
                            reader.monitor_certificates(after_evm)?,
                        )
                    }
                    SccpDeploymentV1::Ton(deployment) => {
                        let reader = super::ton::TonDestination::monitor_connect(
                            &config,
                            deployment.master_account,
                            destination,
                        )?;
                        (
                            reader.monitor_observe()?,
                            reader.monitor_certificates(after_ton)?,
                        )
                    }
                };
                ensure!(
                    observed.network == original.network && observed.instance == original.instance,
                    "destination identity differs from the selected original native root"
                );
                let native = original.verify_generation(
                    observed.committee.generation,
                    client.sccp().committee(observed.committee.generation)?,
                )?;
                let mut matches_original = observed.committee.root == native.committee_root
                    && observed.committee.start == native.start_height
                    && observed.committee.until_ms <= native.deadline_ms;
                if observed.committee.high > original.height()
                    || (observed.committee.high >= observed.committee.start
                        && !observed.checkpoints.contains_key(&observed.committee.high))
                    || observed
                        .committee
                        .high
                        .checked_add(1)
                        .is_none_or(|next| next < observed.committee.start)
                {
                    matches_original = false;
                    report.warnings.push(
                        "Destination high-water mark has no matching original checkpoint".into(),
                    );
                }
                if !matches_original {
                    report.warnings.push(
                        "Destination committee differs from its original native generation".into(),
                    );
                }
                if expiry_warning(observed.committee.until_ms, observed.now_ms) {
                    report.warnings.push(
                        "Destination trust deadline is within three days or has expired".into(),
                    );
                }
                ensure!(
                    observed.checkpoints.len() <= 64,
                    "destination checkpoint observation exceeds bound"
                );
                for (&height, &header) in &observed.checkpoints {
                    if !checkpoint_matches(context, &client, &self.origin, height, header)? {
                        matches_original = false;
                        report.warnings.push(format!("Checkpoint {height} differs from the selected original native cut; seek its published certificate"));
                    }
                }
                let nonce = revision
                    .next_control_nonce
                    .checked_sub(1)
                    .ok_or_else(|| eyre!("invalid original control nonce"))?;
                let expected_fast = if nonce == 0 {
                    0
                } else {
                    let controls = client.sccp().controls(network, number, nonce - 1, 1)?;
                    ensure!(
                        controls.network == network
                            && controls.revision == number
                            && controls.next_control_nonce == revision.next_control_nonce
                            && controls.controls.len() == 1
                            && controls.controls[0].control_nonce == nonce,
                        "latest control response differs from original revision"
                    );
                    original.verify_record_control(
                        network,
                        revision,
                        nonce,
                        &controls.controls[0].record,
                    )?;
                    controls.controls[0].record.fast_pause_until_ms
                };
                if observed.pause.control_nonce != nonce
                    || observed.pause.parliament_paused != revision.destination_paused
                    || observed.pause.fast_pause_until_ms != expected_fast
                {
                    report.warnings.push("Destination pause differs from the selected latest control; inspect and apply that control".into());
                }
                let mut discovery_complete = true;
                for certificate in discovery.certificates {
                    match evidence::inspect(context, &client, &self.origin, certificate) {
                        Ok(Some(candidate)) => {
                            matches_original = false;
                            report.candidates.push(candidate);
                        }
                        Ok(None) => {}
                        Err(error) => {
                            discovery_complete = false;
                            report.warnings.push(format!(
                                "Published certificate refused before evidence authority; retain discovery cursor for retry: {error}"
                            ));
                        }
                    }
                }
                report.suggested_action =
                    recommendation(network, revision, maximum, &observed, matches_original);
                report.next_evm = if discovery_complete {
                    discovery.next_evm
                } else {
                    after_evm
                };
                report.next_ton = if discovery_complete {
                    discovery.next_ton
                } else {
                    after_ton
                };
                report.ton_history_complete = discovery_complete && discovery.ton_history_complete;
                report.observation = Some(Observed {
                    generation: observed.committee.generation,
                    committee_root: observed.committee.root,
                    start_height: observed.committee.start,
                    high: observed.committee.high,
                    until_ms: observed.committee.until_ms,
                    equivocated: observed.committee.equivocated,
                    destination_time_ms: observed.now_ms,
                    checkpoint_headers: observed.checkpoints,
                    control_nonce: observed.pause.control_nonce,
                    parliament_paused: observed.pause.parliament_paused,
                    fast_pause_until_ms: observed.pause.fast_pause_until_ms,
                    effective_pause: observed.pause.effective,
                });
                Ok(())
            })();
            if let Err(error) = result {
                report
                    .warnings
                    .push(format!("Observation unavailable: {error}"));
            }
            reports.push(report);
        }
        context.print_data(&reports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn held_revision_suggestions_never_attest_divergence_or_unobserved_progress() {
        use iroha::data_model::sccp::deployment::{SccpCommitteePinV1, SccpEvmDeploymentV1};
        let network = SccpNetworkV1::EthereumMainnet;
        let revision = SccpRouteRevisionV1::staged(
            1,
            SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
                address: [1; 20],
                runtime_code_hash: [2; 32],
            }),
            SccpCommitteePinV1 {
                generation: 1,
                committee_root: [3; 32],
                start_height: 1,
                until_ms: 100,
            },
            100,
            1,
        );
        let mut observed = Observation {
            network: [4; 32],
            instance: [5; 32],
            committee: CommitteeStateV1 {
                generation: 3,
                root: [6; 32],
                start: 20,
                high: 21,
                until_ms: 100,
                equivocated: false,
            },
            checkpoints: BTreeMap::new(),
            now_ms: 100,
            pause: PauseViewV1 {
                parliament_paused: false,
                fast_pause_until_ms: 0,
                control_nonce: 0,
                effective: false,
            },
        };
        assert!(recommendation(network, &revision, None, &observed, true).is_none());
        assert!(matches!(
            recommendation(network, &revision, Some(2), &observed, true),
            Some(SccpGovernanceActionV1::AttestSccpDeploymentProgress(
                SccpAttestDeploymentProgressActionV1 {
                    at: SccpDeploymentProgressV1::Generation { generation: 3, .. },
                    ..
                }
            ))
        ));
        assert!(matches!(
            recommendation(network, &revision, Some(2), &observed, false),
            Some(SccpGovernanceActionV1::QuarantineSccpRevision(_))
        ));
        assert!(matches!(
            recommendation(network, &revision, Some(3), &observed, true),
            Some(SccpGovernanceActionV1::QuarantineSccpRevision(_))
        ));
        observed.now_ms = 101;
        assert!(matches!(
            recommendation(network, &revision, Some(3), &observed, true),
            Some(SccpGovernanceActionV1::AttestSccpDeploymentProgress(
                SccpAttestDeploymentProgressActionV1 {
                    at: SccpDeploymentProgressV1::Frozen,
                    ..
                }
            ))
        ));
        observed.now_ms = 100;
        observed.committee.equivocated = true;
        assert!(matches!(
            recommendation(network, &revision, Some(3), &observed, true),
            Some(SccpGovernanceActionV1::AttestSccpDeploymentProgress(
                SccpAttestDeploymentProgressActionV1 {
                    at: SccpDeploymentProgressV1::Frozen,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn cursors_are_exact_and_expiry_warning_includes_boundary() {
        assert_eq!(
            evm_cursor("12:7").unwrap(),
            EvmCursor {
                block: 12,
                log_index: 7
            }
        );
        for malformed in ["", "12", "-1:0", "1:2:3", "1:+2", "1:18446744073709551616"] {
            assert!(evm_cursor(malformed).is_err());
        }
        assert!(ton_cursor(&format!("1:{}", "ab".repeat(32))).is_ok());
        assert!(ton_cursor(&format!("0:{}", "ab".repeat(32))).is_err());
        assert!(expiry_warning(WARNING_MS + 10, 10));
        assert!(!expiry_warning(WARNING_MS + 10, 9));
        assert!(expiry_warning(0, 0));
    }
}
