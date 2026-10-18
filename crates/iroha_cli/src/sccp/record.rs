//! Source and destination guards before the first journaled outbound submission.

use super::*;
use eyre::ensure;
use iroha::data_model::sccp::{
    deployment::SccpDeploymentV1, generation::SccpCommitteeGenerationV1, params::SccpParametersV1,
    registry::SccpRouteRevisionV1,
};
use iroha_sccp::v1::{committee::CommitteeStateV1, proof::DestinationV1};
use iroha_sccp_wallet::{
    flow::SccpFlowActionV1 as Action,
    journal::{SccpEvidenceItemV1, SccpFlowKindV1},
    pure::{
        bundle::DestinationContextV1,
        control::{DestinationControlStateV1, TairaControlV1, check_may_record},
        rotation::{check_committee_horizon, verify_rotation_steps},
    },
};

#[derive(norito::derive::JsonSerialize)]
struct RecordObservation {
    network: [u8; 32],
    instance: [u8; 32],
    generation: u64,
    root: [u8; 32],
    start: u64,
    until_ms: u64,
    high: u64,
    equivocated: bool,
    now_ms: u64,
    control_nonce: u64,
    parliament_paused: bool,
    fast_pause_until_ms: u64,
}

#[derive(norito::derive::JsonSerialize)]
struct RecordIntent<'a> {
    sender: &'a iroha::data_model::account::AccountId,
    network: SccpNetworkV1,
    amount: &'a Numeric,
    recipient: String,
    revision: Option<u32>,
}

fn require_recordable(
    parameters: &SccpParametersV1,
    revision: &SccpRouteRevisionV1,
    forgery_max: Option<u64>,
    amount: u128,
) -> Result<()> {
    ensure!(parameters.enabled, "SCCP value transfers are disabled");
    ensure!(
        revision.activation == SccpRouteActivationV1::Bidirectional,
        "the selected route revision is not Bidirectional"
    );
    ensure!(
        !revision.destination_frozen
            && revision.quarantine.is_none()
            && !revision.forgery_held(forgery_max),
        "the selected route revision is held"
    );
    ensure!(
        amount != 0 && amount >= parameters.min_outbound_amount && amount <= revision.headroom(),
        "amount is below the configured minimum or exceeds available route headroom"
    );
    Ok(())
}

fn require_native_committee(
    state: &CommitteeStateV1,
    native: &SccpCommitteeGenerationV1,
) -> Result<()> {
    let same_committee = state.root == native.committee_root;
    ensure!(
        state.generation == native.generation
            && same_committee
            && state.start == native.start_height
            && state.until_ms <= native.deadline_ms,
        "destination committee differs from its original native generation"
    );
    Ok(())
}

/// Check a single coherent code-bound destination observation and every original rotation.
#[allow(clippy::too_many_arguments)]
pub(super) fn preflight(
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    revision: &SccpRouteRevisionV1,
    context: &DestinationContextV1<'_>,
    applied: &DestinationControlStateV1,
    parameters: &SccpParametersV1,
    current: u64,
    margin_ms: u64,
) -> Result<Vec<SccpEvidenceItemV1>> {
    ensure!(
        context.taira_network_id == original.network
            && context.consensus_instance == original.instance,
        "destination differs from the independently selected native origin"
    );
    let from = context.committee_state.generation;
    original.record_interval(from, current)?;
    let candidate = client.sccp().committee(from)?;
    let mut native = original.verify_generation(from, candidate.clone())?;
    require_native_committee(&context.committee_state, &native)?;
    let mut evidence = vec![
        flows::evidence("taira.original_destination_generation", &candidate)?,
        flows::evidence(
            "destination.record_observation",
            &RecordObservation {
                network: context.taira_network_id,
                instance: context.consensus_instance,
                generation: from,
                root: context.committee_state.root,
                start: context.committee_state.start,
                until_ms: context.committee_state.until_ms,
                high: context.committee_state.high,
                equivocated: context.committee_state.equivocated,
                now_ms: context.now_ms,
                control_nonce: applied.control_nonce,
                parliament_paused: applied.parliament_paused,
                fast_pause_until_ms: applied.fast_pause_until_ms,
            },
        )?,
    ];
    let mut steps = Vec::new();
    let mut cursor = from;
    while cursor < current {
        let page = client.sccp().rotations(
            cursor,
            iroha_sccp::v1::destination::MAX_CERTIFICATES_PER_CALL,
        )?;
        ensure!(!page.is_empty(), "original rotation history is unavailable");
        for step in page {
            if cursor == current {
                break;
            }
            step.check_shape()?;
            let header =
                iroha_sccp::v1::finality::SccpFinalityHeaderV1::parse(&step.certificate.header)
                    .map_err(|error| eyre!("rotation header: {error}"))?;
            ensure!(
                header.generation() == cursor,
                "rotation page skips or repeats a generation"
            );
            cursor = cursor
                .checked_add(1)
                .ok_or_else(|| eyre!("generation overflows"))?;
            let end = native
                .end
                .ok_or_else(|| eyre!("rotation generation has no original end"))?;
            ensure!(
                header.height() == end.end_height
                    && header.timestamp_ms() == end.end_timestamp_ms
                    && header.validity_ms() == end.successor_validity_ms
                    && header.next_committee_root() == end.next_committee_root,
                "rotation differs from its original committed generation end"
            );
            let successor = client.sccp().committee(cursor)?;
            let successor = original.verify_generation(cursor, successor)?;
            ensure!(
                header.next_committee_root() == successor.committee_root
                    && header.height().checked_add(1) == Some(successor.start_height),
                "rotation successor differs from original World history"
            );
            native = successor;
            steps.push(step);
        }
    }
    let plan = verify_rotation_steps(&steps, context, current)?;
    check_committee_horizon(
        &context.committee_state,
        &plan,
        context.now_ms,
        parameters.outbound_ttl_ms,
        margin_ms,
    )?;
    evidence.push(flows::evidence("taira.original_rotation_chain", &steps)?);
    let nonce = revision
        .next_control_nonce
        .checked_sub(1)
        .ok_or_else(|| eyre!("invalid original next control nonce"))?;
    let latest = if nonce == 0 {
        ensure!(
            !revision.destination_paused,
            "original route lacks its pause control"
        );
        None
    } else {
        let page =
            client
                .sccp()
                .controls(context.destination.network, revision.revision, nonce - 1, 1)?;
        ensure!(
            page.network == context.destination.network
                && page.revision == revision.revision
                && page.next_control_nonce == revision.next_control_nonce
                && page.controls.len() == 1
                && page.controls[0].control_nonce == nonce,
            "latest control differs from the selected original source cut"
        );
        let control = &page.controls[0].record;
        original.verify_record_control(context.destination.network, revision, nonce, control)?;
        evidence.push(flows::evidence("taira.original_latest_control", &page)?);
        Some(TairaControlV1 {
            control_nonce: nonce,
            parliament_paused: control.parliament_paused,
            fast_pause_until_ms: control.fast_pause_until_ms,
        })
    };
    check_may_record(applied, latest.as_ref(), context.now_ms)?;
    Ok(evidence)
}

pub(super) fn send<C: RunContext>(context: &mut C, args: &SendArgs) -> Result<()> {
    let network = parse_network(&args.network)?;
    let recipient = parse_recipient(network, &args.recipient)?;
    let amount: Numeric = args
        .amount
        .parse()
        .map_err(|_| eyre!("invalid decimal XOR amount"))?;
    let units = iroha_sccp::v1::amount::taira_units(&amount)?;
    let intent = flows::intent(&norito::json::to_vec(&RecordIntent {
        sender: &context.config().account,
        network,
        amount: &amount,
        recipient: hex::encode(&recipient),
        revision: args.revision,
    })?);
    let client = blocking(context)?;
    let original = origin::authenticate_origin(context, &client, &args.origin)?;
    let flow = flows::open(context, SccpFlowKindV1::Outbound, &args.flow, intent)?;
    if flows::recover_taira(context, &original, &flow, Action::Record)? {
        let step = flow
            .latest(Action::Record)?
            .ok_or_else(|| eyre!("original record custody disappeared"))?;
        if !flows::confirmed(step.outcome()?.as_ref()) {
            return Ok(());
        }
        let retained = step
            .record()
            .evidence
            .iter()
            .find(|item| item.label == "taira.original_route")
            .ok_or_else(|| eyre!("original record lacks its pre-submission route"))?;
        let route: iroha::data_model::sccp::registry::SccpRouteV1 =
            norito::json::from_slice(&retained.bytes)?;
        let (revision, from_nonce) = retained_locator(&route, network)?;
        let sent = SentTransfer {
            sender: context.config().account.clone(),
            amount: units,
            recipient,
        };
        let view = locate_sent(
            &blocking(context)?,
            &step,
            network,
            revision,
            from_nonce,
            &sent,
        )?;
        return context.print_data(&view);
    }
    let capabilities = client.sccp().capabilities()?;
    let parameters = original.parameters(&capabilities)?;
    let current = original.current_generation(&capabilities)?;
    let route = client
        .sccp()
        .registry()?
        .into_iter()
        .find(|route| route.network == network)
        .ok_or_else(|| eyre!("the selected route is absent"))?;
    original.verify_route(network, &route)?;
    let revision = route
        .live_revision()
        .ok_or_else(|| eyre!("route has no live revision"))?;
    ensure!(
        args.revision
            .is_none_or(|requested| requested == revision.revision),
        "requested revision is not the live revision"
    );
    require_recordable(
        &parameters,
        revision,
        original.forgery_max(&capabilities)?,
        units,
    )?;
    let destination = DestinationV1 {
        network,
        route_revision: revision.revision,
        destination_word: revision.destination_word,
    };
    let margin = origin::AuthenticatedOrigin::record_margin(args.inclusion_margin_ms)?;
    let mut evidence = match revision.deployment {
        SccpDeploymentV1::Evm(deployment) => {
            let constructor = iroha_sccp::v1::evm_abi::ConstructorArgsV1 {
                taira_network_id: original.network,
                consensus_instance: original.instance,
                network,
                route_revision: revision.revision,
                max_wrapped_supply: revision.max_wrapped_supply,
                pin: revision.initial_committee,
            };
            ensure!(
                constructor.address() == deployment.address,
                "registered EVM address differs from canonical CREATE2"
            );
            evm::EvmDestination::connect(
                &context.sccp_config()?,
                &args.rpc_url,
                network,
                deployment.address,
                destination,
                deployment.runtime_code_hash,
            )?
            .record_preflight(
                &client,
                &original,
                revision,
                &parameters,
                current,
                margin,
            )?
        }
        SccpDeploymentV1::Ton(deployment) => {
            let keys = original.verify_pin_generation(
                client
                    .sccp()
                    .committee(revision.initial_committee.generation)?,
                &revision.initial_committee,
            )?;
            let init = iroha_sccp::v1::ton_cell::TonMinterInitV1 {
                taira_network_id: original.network,
                consensus_instance: original.instance,
                route_revision: revision.revision,
                max_supply: revision.max_wrapped_supply,
                pin: revision.initial_committee,
                keys,
                wallet_code: deployment.wallet_code,
                bucket_code: deployment.bucket_code,
            };
            ensure!(
                iroha_sccp::v1::ton_cell::minter_account_id(&init, deployment.minter_code)?
                    == deployment.master_account,
                "registered minter differs from its canonical StateInit"
            );
            ton::TonDestination::connect(
                &context.sccp_config()?,
                &args.rpc_url,
                deployment.master_account,
                destination,
            )?
            .record_preflight(
                &client,
                &original,
                revision,
                &parameters,
                current,
                margin,
            )?
        }
    };
    evidence.push(flows::evidence("taira.original_route", &route)?);
    evidence.push(flows::evidence(
        "taira.original_capabilities",
        &capabilities,
    )?);
    let outcome = flows::taira(
        context,
        &original,
        &flow,
        Action::Record,
        vec![InstructionBox::from(RecordSccpMessage {
            network,
            expected_revision: revision.revision,
            amount,
            recipient: recipient.clone(),
        })],
        evidence,
    )?;
    if !flows::confirmed(outcome.as_ref()) {
        return Ok(());
    }
    let sent = SentTransfer {
        sender: context.config().account.clone(),
        amount: units,
        recipient,
    };
    let step = flow
        .latest(Action::Record)?
        .ok_or_else(|| eyre!("original record custody disappeared"))?;
    let view = locate_sent(
        &client,
        &step,
        network,
        revision.revision,
        revision.next_outbound_nonce,
        &sent,
    )?;
    context.print_data(&view)
}

/// A bounded discovery hint, never authority for a transaction or its outcome.
#[derive(norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct RecordDiscovery {
    network: SccpNetworkV1,
    revision: u32,
    first_nonce: u64,
    next_nonce: u64,
}

/// Scan at most sixteen pages, preserving forward progress across polls and restarts.
pub(super) fn locate_sent_scan(
    step: &iroha_sccp_wallet::journal::SccpJournalStep,
    network: SccpNetworkV1,
    revision: u32,
    first_nonce: u64,
    sent: &SentTransfer,
    mut fetch: impl FnMut(u64) -> Result<iroha_sccp::api::SccpOutboundPageV1>,
) -> Result<Option<iroha_sccp::api::SccpOutboundMessageViewV1>> {
    let mut from_nonce = step
        .discovery::<RecordDiscovery>()?
        .filter(|hint| {
            hint.network == network
                && hint.revision == revision
                && hint.first_nonce == first_nonce
                && hint.next_nonce >= first_nonce
        })
        .map_or(first_nonce, |hint| hint.next_nonce);
    for _ in 0..16 {
        let page = fetch(from_nonce)?;
        ensure!(
            page.network == network && page.revision == revision,
            "outbound discovery page names another route"
        );
        ensure!(
            page.records.len() <= iroha_sccp::api::MAX_OUTBOUND_PAGE
                && page.records.iter().all(|view| {
                    view.record.network == network
                        && view.record.revision == revision
                        && view.record.nonce >= from_nonce
                        && view.record.nonce < page.next_outbound_nonce
                })
                && page
                    .records
                    .windows(2)
                    .all(|pair| pair[0].record.nonce < pair[1].record.nonce),
            "outbound discovery records violate the original route or nonce interval"
        );
        if let Some(view) = page.records.iter().find(|view| sent.matches(&view.record)) {
            return Ok(Some(view.clone()));
        }
        let Some(next) = page.next_from_nonce else {
            return Ok(None);
        };
        ensure!(
            next > from_nonce
                && next < page.next_outbound_nonce
                && page
                    .records
                    .last()
                    .is_some_and(|view| view.record.nonce < next),
            "outbound discovery cursor does not advance past its records"
        );
        step.save_discovery(&RecordDiscovery {
            network,
            revision,
            first_nonce,
            next_nonce: next,
        })?;
        from_nonce = next;
    }
    Ok(None)
}

fn retained_locator(
    route: &iroha::data_model::sccp::registry::SccpRouteV1,
    network: SccpNetworkV1,
) -> Result<(u32, u64)> {
    ensure!(
        route.network == network,
        "original route names another network"
    );
    let revision = route
        .live_revision()
        .ok_or_else(|| eyre!("original route lacks the recorded live revision"))?;
    Ok((revision.revision, revision.next_outbound_nonce))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha::data_model::sccp::{
        deployment::{SccpCommitteePinV1, SccpEvmDeploymentV1},
        generation::SccpGenerationCauseV1,
    };

    #[test]
    fn send_discovery_resumes_after_sixteen_pages_without_changing_original_custody() {
        use iroha_data_model::{
            NetworkId,
            sccp::outbound::{SccpOutboundMessageRecordV1, SccpOutboundStatusV1},
        };
        use iroha_sccp::api::{
            SccpOutboundMessageViewV1, SccpOutboundPageV1, SccpOutboundStateV1, SccpRecordedStateV1,
        };
        use iroha_sccp_wallet::{
            flow::SccpFlowV1,
            journal::{SccpFlowIdV1, SccpJournalRoot},
        };
        let base =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/sccp-continuation");
        std::fs::create_dir_all(&base).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("send-cursor-")
            .tempdir_in(base)
            .unwrap();
        let network_id = NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed([8; 32])),
        );
        let flow = SccpFlowV1::open(
            SccpJournalRoot::open(&dir.path().join("journal"))
                .unwrap()
                .network(&network_id)
                .unwrap()
                .flow(&SccpFlowIdV1 {
                    kind: SccpFlowKindV1::Outbound,
                    id: [9; 32],
                })
                .unwrap(),
            *network_id.as_bytes(),
        )
        .unwrap();
        let network = SccpNetworkV1::EthereumMainnet;
        let step = flow
            .prepare(
                Action::Record,
                SccpNetworkV1::SoraTaira,
                vec![1, 2, 3],
                vec![SccpEvidenceItemV1 {
                    label: "original.record_intent".to_owned(),
                    bytes: vec![4],
                }],
            )
            .unwrap();
        let original = step.record().clone();
        step.begin_submission().unwrap();
        let sent = SentTransfer {
            sender: iroha_test_samples::ALICE_ID.clone(),
            amount: 15,
            recipient: vec![0x11; 20],
        };
        let page = |nonce, matching| {
            let amount = if matching { 15 } else { 16 };
            let payload = iroha_sccp::v1::payload::SccpTransferPayloadV1::outbound(
                network,
                nonce,
                1,
                900,
                amount,
                vec![1; 32],
                sent.recipient.clone(),
            )
            .unwrap()
            .encode()
            .unwrap();
            SccpOutboundPageV1 {
                network,
                revision: 1,
                next_outbound_nonce: 100,
                records: vec![SccpOutboundMessageViewV1 {
                    message_id: [u8::try_from(nonce).expect("fixture nonces fit u8"); 32],
                    record: SccpOutboundMessageRecordV1 {
                        network,
                        revision: 1,
                        nonce,
                        height: 8,
                        commitment_index: 0,
                        deadline_ms: 900,
                        sender: sent.sender.clone(),
                        amount,
                        payload,
                        leaf: [0; 32],
                        status: SccpOutboundStatusV1::Recorded,
                    },
                    state: SccpOutboundStateV1::Recorded(SccpRecordedStateV1 {
                        deadline_ms: 900,
                        provable: true,
                    }),
                }],
                next_from_nonce: Some(nonce + 1),
            }
        };
        let mut fetched = Vec::new();
        assert!(
            locate_sent_scan(&step, network, 1, 50, &sent, |nonce| {
                fetched.push(nonce);
                Ok(page(nonce, false))
            })
            .unwrap()
            .is_none()
        );
        assert_eq!(fetched, (50..66).collect::<Vec<_>>());
        assert_eq!(
            step.discovery::<RecordDiscovery>()
                .unwrap()
                .unwrap()
                .next_nonce,
            66
        );
        drop(step);
        let step = flow.latest(Action::Record).unwrap().unwrap();
        fetched.clear();
        let found = locate_sent_scan(&step, network, 1, 50, &sent, |nonce| {
            fetched.push(nonce);
            Ok(page(nonce, nonce == 67))
        })
        .unwrap()
        .unwrap();
        assert_eq!(fetched, [66, 67]);
        assert_eq!(found.record.nonce, 67);
        assert_eq!(step.record(), &original);
        assert!(step.outcome().unwrap().is_none());
        assert!(
            !step.begin_submission().unwrap(),
            "discovery must never resubmit original bytes"
        );

        for hint in [
            RecordDiscovery {
                network,
                revision: 2,
                first_nonce: 50,
                next_nonce: 90,
            },
            RecordDiscovery {
                network: SccpNetworkV1::TonMainnet,
                revision: 1,
                first_nonce: 50,
                next_nonce: 90,
            },
            RecordDiscovery {
                network,
                revision: 1,
                first_nonce: 49,
                next_nonce: 90,
            },
            RecordDiscovery {
                network,
                revision: 1,
                first_nonce: 50,
                next_nonce: 49,
            },
        ] {
            step.save_discovery(&hint).unwrap();
            let found = locate_sent_scan(&step, network, 1, 50, &sent, |nonce| {
                assert_eq!(
                    nonce, 50,
                    "invalid hint must restart at the retained original nonce"
                );
                Ok(page(nonce, true))
            })
            .unwrap()
            .unwrap();
            assert_eq!(found.record.nonce, 50);
        }
        step.save_discovery(&0_u64).unwrap();
        assert!(
            locate_sent_scan(&step, network, 1, 50, &sent, |nonce| {
                let mut wrong = page(nonce, true);
                wrong.records[0].record.nonce = 49;
                Ok(wrong)
            })
            .is_err(),
            "matching payload before the original nonce must be refused"
        );
        assert!(
            locate_sent_scan(&step, network, 1, 50, &sent, |nonce| {
                let mut wrong = page(nonce, true);
                wrong.network = SccpNetworkV1::TonMainnet;
                Ok(wrong)
            })
            .is_err(),
            "matching payload on another route must be refused"
        );
        assert_eq!(step.record(), &original);
    }

    fn revision() -> SccpRouteRevisionV1 {
        let mut row = SccpRouteRevisionV1::staged(
            1,
            SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
                address: [1; 20],
                runtime_code_hash: [2; 32],
            }),
            SccpCommitteePinV1 {
                generation: 3,
                committee_root: [3; 32],
                start_height: 7,
                until_ms: 1000,
            },
            100,
            7,
        );
        row.activation = SccpRouteActivationV1::Bidirectional;
        row
    }

    #[test]
    fn recovered_send_uses_original_pre_submission_nonce_and_revision() {
        let network = SccpNetworkV1::EthereumMainnet;
        let mut route = iroha::data_model::sccp::registry::SccpRouteV1::empty(
            network,
            iroha_test_samples::ALICE_ID.clone(),
        )
        .unwrap();
        let mut row = revision();
        row.next_outbound_nonce = 37;
        route.revisions.insert(row.revision, row);
        let retained = norito::json::to_vec(&route).unwrap();
        route.revisions.get_mut(&1).unwrap().next_outbound_nonce = 99;
        let original = norito::json::from_slice(&retained).unwrap();
        assert_eq!(retained_locator(&original, network).unwrap(), (1, 37));
        assert!(retained_locator(&original, SccpNetworkV1::TonMainnet).is_err());
        route.revisions.clear();
        assert!(retained_locator(&route, network).is_err());
    }

    #[test]
    fn record_intent_encodes_recipient_bytes_as_canonical_hex() {
        let amount: Numeric = "1".parse().unwrap();
        let bytes = norito::json::to_vec(&RecordIntent {
            sender: &iroha_test_samples::ALICE_ID,
            network: SccpNetworkV1::EthereumMainnet,
            amount: &amount,
            recipient: hex::encode([0, 1, 128, 255]),
            revision: Some(7),
        })
        .unwrap();
        let value: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
        assert_eq!(value.get("recipient"), Some(&norito::json!("000180ff")));
    }

    #[test]
    fn record_rejects_disabled_held_frozen_and_exhausted_routes_before_signing() {
        let params = SccpParametersV1 {
            min_outbound_amount: 2,
            ..SccpParametersV1::taira_default()
        };
        let row = revision();
        assert!(require_recordable(&params, &row, Some(2), 100).is_ok());
        for state in [
            SccpRouteActivationV1::Staged,
            SccpRouteActivationV1::Paused,
            SccpRouteActivationV1::InboundOnly,
            SccpRouteActivationV1::Retired,
        ] {
            assert!(
                require_recordable(
                    &params,
                    &SccpRouteRevisionV1 {
                        activation: state,
                        ..row
                    },
                    None,
                    100
                )
                .is_err()
            );
        }
        let mut disabled = params;
        disabled.enabled = false;
        assert!(require_recordable(&disabled, &row, None, 100).is_err());
        assert!(require_recordable(&params, &row, Some(3), 100).is_err());
        assert!(
            require_recordable(
                &params,
                &SccpRouteRevisionV1 {
                    destination_frozen: true,
                    ..row
                },
                None,
                100
            )
            .is_err()
        );
        assert!(require_recordable(&params, &row, None, 0).is_err());
        assert!(require_recordable(&params, &row, None, 1).is_err());
        assert!(require_recordable(&params, &row, None, 2).is_ok());
        assert!(require_recordable(&params, &row, None, 101).is_err());
        assert!(
            require_recordable(
                &params,
                &SccpRouteRevisionV1 {
                    liability: 100,
                    ..row
                },
                None,
                2
            )
            .is_err()
        );
    }

    #[test]
    fn destination_committee_is_bound_to_original_generation_and_horizon() {
        let row = SccpCommitteeGenerationV1 {
            generation: 3,
            committee_root: [3; 32],
            keys: Vec::new(),
            members: Vec::new(),
            cause: SccpGenerationCauseV1::Heartbeat,
            start_height: 7,
            start_timestamp_ms: 100,
            start_lc: 100,
            validity_ms: 900,
            deadline_ms: 1000,
            grace_ms: 100,
            progress_cap_ms: 100,
            liable_until_lc: 1100,
            dest_cleared_lc: None,
            end: None,
        };
        let state = CommitteeStateV1 {
            generation: 3,
            root: [3; 32],
            start: 7,
            high: 8,
            until_ms: 999,
            equivocated: false,
        };
        require_native_committee(&state, &row).unwrap();
        for changed in [
            CommitteeStateV1 {
                generation: 4,
                ..state
            },
            CommitteeStateV1 {
                root: [4; 32],
                ..state
            },
            CommitteeStateV1 { start: 8, ..state },
            CommitteeStateV1 {
                until_ms: 1001,
                ..state
            },
        ] {
            assert!(require_native_committee(&changed, &row).is_err());
        }
    }
}
