//! Outbound value path: `RecordSccpMessage` (`specs/sccp.md` §4.4). Owner: ws32.
//!
//! Recording checks activation, committed-parent finality health, amount, sender and recipient rules and
//! the supply cap, locks XOR into the route escrow and then records the message per §4.4 steps
//! 9–14 through [`record_outbound_message`], which inbound bounces (§4.12.5) reuse.
//!
//! The message id binds the escrow lock, so the record is planned ([`plan`]) before the lock
//! and written ([`write_planned`]) after it; a failed transaction rolls back both.

use super::{
    Error, eligibility::TransactionParent, escrow, hold, leaves, original_read::OriginalRead, store,
};
use crate::state::{StateReadOnly, StateTransaction};
use iroha_data_model::{
    account::{AccountAddress, AccountId},
    bridge::SccpNetworkV1,
    isi::sccp::RecordSccpMessage,
    sccp::{
        control::{SccpLeafRefV1, SccpTransferLeafRefV1},
        deployment::SccpDeploymentV1,
        events::{SccpEvent, SccpMessageRecordedV1},
        outbound::{SccpOutboundMessageRecordV1, SccpOutboundStatusV1},
        registry::SccpRouteActivationV1,
    },
};
use iroha_sccp::v1::{
    amount::{check_lane_amount, taira_units},
    hashes::transfer_leaf,
    network::account_codec,
    payload::{SccpTransferPayloadV1, is_valid_account},
};

/// Inputs of §4.4 steps 9–14 for one outbound message on `(network, revision)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRecordArgsV1 {
    /// External target network.
    pub network: SccpNetworkV1,
    /// Route revision whose next outbound nonce the message consumes.
    pub revision: u32,
    /// Amount in Taira units.
    pub amount: u128,
    /// Taira sender; its `AccountAddress` bytes are the payload's codec-3 sender.
    pub sender: AccountId,
    /// Recipient bytes in the target's codec (§3.1).
    pub recipient: Vec<u8>,
}

/// A planned outbound record (§4.4 steps 9–11): everything but the leaf index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedOutboundV1 {
    /// Dense per-revision nonce the message consumes.
    pub nonce: u64,
    /// Destination-time mint deadline.
    pub deadline_ms: u64,
    /// Encoded §3.2 payload.
    pub payload: Vec<u8>,
    /// §3.3 message id under the live `NetworkId`.
    pub message_id: [u8; 32],
    /// Transfer leaf under the revision's destination word.
    pub leaf: [u8; 32],
}

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP: RecordSccpMessage refused: {reason}").into())
}

/// Return the codec-3 `AccountAddress` bytes of `account` (§3.1).
///
/// # Errors
///
/// Fails when the account has no canonical address encoding.
pub fn sender_bytes(account: &AccountId) -> Result<Vec<u8>, Error> {
    AccountAddress::from_account_id(account)
        .and_then(|address| address.canonical_bytes())
        .map_err(|error| refuse(format_args!("sender has no account address: {error}")))
}

/// Check §4.4 step 5: `recipient` is valid for `network`'s codec and is not the destination
/// deployment itself (the EVM contract or the TON minter).
fn check_recipient(
    network: SccpNetworkV1,
    deployment: &SccpDeploymentV1,
    recipient: &[u8],
) -> Result<(), Error> {
    if !is_valid_account(account_codec(network), recipient) {
        return Err(refuse("recipient is invalid for the target codec"));
    }
    let is_deployment = match deployment {
        SccpDeploymentV1::Evm(evm) => recipient == evm.address.as_slice(),
        SccpDeploymentV1::Ton(ton) => recipient.get(4..) == Some(ton.master_account.as_slice()),
    };
    if is_deployment {
        return Err(refuse("recipient is the destination deployment"));
    }
    Ok(())
}

/// Check §4.4 step 2 against the committed parent, not this block's own updates.
fn check_finality<'a>(parent: impl OriginalRead<'a> + 'a) -> Result<(), Error> {
    if parent.degraded_run() != 0 && !cfg!(all(test, sumeragi_core_mutation = "HC225")) {
        return Err(refuse(
            "SccpFinalityDegraded: the committed parent has degraded finality",
        ));
    }
    Ok(())
}

/// Execute `RecordSccpMessage` (§4.4 steps 1–14).
///
/// # Errors
///
/// Refuses when SCCP is absent or disabled, the revision is not the route's unpaused
/// `Bidirectional` one, the parent finality is degraded, the amount, sender or recipient breaks a rule,
/// the supply cap or the block's leaf limit would be exceeded, or the escrow lock fails.
pub fn execute_record(
    instruction: RecordSccpMessage,
    authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let world = &*state_transaction.world;
    let params = store::parameters::get(world)
        .as_ref()
        .ok_or_else(|| refuse("SCCP does not exist on this network"))?;
    // Step 1: enabled, the expected unpaused Bidirectional revision.
    if !params.enabled {
        return Err(refuse("SCCP is disabled"));
    }
    let min_outbound_amount = params.min_outbound_amount;
    let network = instruction.network;
    let route = store::routes::get(world, &network)
        .ok_or_else(|| refuse(format_args!("no route to {}", network.profile_key())))?;
    let revision = route
        .revisions
        .get(&instruction.expected_revision)
        .filter(|revision| revision.activation == SccpRouteActivationV1::Bidirectional)
        .ok_or_else(|| {
            refuse(format_args!(
                "revision {} is not the Bidirectional revision",
                instruction.expected_revision
            ))
        })?;
    if revision.destination_paused {
        return Err(refuse("the destination is paused by the Parliament"));
    }
    if hold::forgery_or_quarantine(world, revision) {
        return Err(refuse("SccpForgeryHold: the revision is held"));
    }
    let timestamp_ms = state_transaction.block_unix_timestamp_ms();
    if hold::fast_taira(world, network, Some(timestamp_ms))
        || hold::fast_destination(world, network, instruction.expected_revision, timestamp_ms)
    {
        return Err(refuse("the revision is fast-paused"));
    }
    // Step 2 is exactly the committed parent's degraded state (§4.4, §4.6).
    check_finality(TransactionParent(&state_transaction.world))?;
    let height = state_transaction._curr_block.height().get();
    // Step 3: exact Taira units within the floor and the lane bound.
    let amount = taira_units(&instruction.amount)
        .map_err(|error| refuse(format_args!("amount: {error}")))?;
    if amount < min_outbound_amount {
        return Err(refuse(format_args!(
            "amount {amount} is below the minimum {min_outbound_amount}"
        )));
    }
    check_lane_amount(amount, SccpNetworkV1::SoraTaira, network)
        .map_err(|error| refuse(format_args!("amount: {error}")))?;
    // Steps 4–5: sender and recipient.
    let sender = sender_bytes(authority)?;
    if sender.len() > iroha_sccp::v1::constants::MAX_TAIRA_ACCOUNT_BYTES {
        return Err(refuse("sender address exceeds 1024 bytes"));
    }
    check_recipient(network, &revision.deployment, &instruction.recipient)?;
    // Step 6: supply cap.
    if revision
        .liability
        .checked_add(amount)
        .is_none_or(|liability| liability > revision.max_wrapped_supply)
    {
        return Err(refuse("the revision's supply cap would be exceeded"));
    }
    // Step 7: leaf capacity.
    if leaves::leaf_count_at(world, height) >= leaves::MAX_LEAVES_PER_BLOCK as usize {
        return Err(refuse(
            "the block already holds the maximum number of leaves",
        ));
    }
    let args = OutboundRecordArgsV1 {
        network,
        revision: instruction.expected_revision,
        amount,
        sender: authority.clone(),
        recipient: instruction.recipient,
    };
    let planned = plan(state_transaction, &args)?;
    // Step 8: lock into the escrow and count the liability.
    escrow::lock(
        state_transaction,
        network,
        authority,
        amount,
        planned.message_id,
    )?;
    let mut route = store::routes::get(&*state_transaction.world, &network)
        .cloned()
        .ok_or_else(|| refuse("the route disappeared"))?;
    let revision = route
        .revisions
        .get_mut(&args.revision)
        .ok_or_else(|| refuse("the revision disappeared"))?;
    revision.liability = revision
        .liability
        .checked_add(amount)
        .ok_or_else(|| refuse("liability overflows"))?;
    store::routes::insert(state_transaction, network, route)?;
    write_planned(state_transaction, &args, planned).map(|_| ())
}

/// Plan §4.4 steps 9–11 of `args` against the executing block without writing anything.
///
/// # Errors
///
/// Fails when the route revision is unknown or held, the payload breaks a §3.2 rule,
/// or the message id is already recorded.
pub fn plan(
    state_transaction: &StateTransaction<'_, '_>,
    args: &OutboundRecordArgsV1,
) -> Result<PlannedOutboundV1, Error> {
    let world = &*state_transaction.world;
    let params = store::parameters::get(world)
        .as_ref()
        .ok_or_else(|| refuse("SCCP does not exist on this network"))?;
    let revision = store::routes::get(world, &args.network)
        .and_then(|route| route.revisions.get(&args.revision))
        .ok_or_else(|| refuse(format_args!("revision {} is unknown", args.revision)))?;
    // Internal bounce callers obey the same permanent quarantine and forgery gate.
    if hold::forgery_or_quarantine(world, revision) {
        return Err(refuse("SccpForgeryHold: the revision is held"));
    }
    let nonce = revision.next_outbound_nonce;
    let deadline_ms = state_transaction
        .block_unix_timestamp_ms()
        .checked_add(params.outbound_ttl_ms)
        .ok_or_else(|| refuse("deadline overflows"))?;
    let payload = SccpTransferPayloadV1::outbound(
        args.network,
        nonce,
        args.revision,
        deadline_ms,
        args.amount,
        sender_bytes(&args.sender)?,
        args.recipient.clone(),
    )
    .map_err(|error| refuse(format_args!("payload: {error}")))?;
    let network_id = state_transaction.network_id().as_bytes();
    let message_id = payload
        .message_id(network_id)
        .map_err(|error| refuse(format_args!("payload: {error}")))?;
    if store::outbound_messages::contains(world, &message_id) {
        return Err(refuse("the message id is already recorded"));
    }
    let payload = payload
        .encode()
        .map_err(|error| refuse(format_args!("payload: {error}")))?;
    Ok(PlannedOutboundV1 {
        nonce,
        deadline_ms,
        payload,
        message_id,
        leaf: transfer_leaf(&message_id, &revision.destination_word),
    })
}

/// Write `planned` for `args` (§4.4 steps 9 and 12–14) and return its message id.
///
/// # Errors
///
/// Fails when the revision is held, its nonce moved since planning, or the block's leaves
/// are full.
pub fn write_planned(
    state_transaction: &mut StateTransaction<'_, '_>,
    args: &OutboundRecordArgsV1,
    planned: PlannedOutboundV1,
) -> Result<[u8; 32], Error> {
    let mut route = store::routes::get(&*state_transaction.world, &args.network)
        .cloned()
        .ok_or_else(|| refuse("the route is unknown"))?;
    let revision = route
        .revisions
        .get_mut(&args.revision)
        .filter(|revision| revision.next_outbound_nonce == planned.nonce)
        .ok_or_else(|| refuse("the planned nonce is stale"))?;
    // The hold may have changed since planning; refuse before the first write.
    if hold::forgery_or_quarantine(&*state_transaction.world, revision) {
        return Err(refuse("SccpForgeryHold: the revision is held"));
    }
    revision.next_outbound_nonce = planned
        .nonce
        .checked_add(1)
        .ok_or_else(|| refuse("the outbound nonce is exhausted"))?;
    store::routes::insert(state_transaction, args.network, route)?;
    let height = state_transaction._curr_block.height().get();
    let commitment_index = leaves::allocate_leaf(
        state_transaction,
        SccpLeafRefV1::Transfer(SccpTransferLeafRefV1 {
            message_id: planned.message_id,
        }),
    )?;
    store::outbound_by_nonce::insert(
        state_transaction,
        (args.network, args.revision, planned.nonce),
        planned.message_id,
    )?;
    store::outbound_messages::insert(
        state_transaction,
        planned.message_id,
        SccpOutboundMessageRecordV1 {
            network: args.network,
            revision: args.revision,
            nonce: planned.nonce,
            height,
            commitment_index,
            deadline_ms: planned.deadline_ms,
            sender: args.sender.clone(),
            amount: args.amount,
            payload: planned.payload,
            leaf: planned.leaf,
            status: SccpOutboundStatusV1::Recorded,
        },
    )?;
    state_transaction
        .world
        .emit_events(Some(SccpEvent::MessageRecorded(SccpMessageRecordedV1 {
            message_id: planned.message_id,
            network: args.network,
            revision: args.revision,
            nonce: planned.nonce,
            height,
            commitment_index,
            deadline_ms: planned.deadline_ms,
        })));
    Ok(planned.message_id)
}

/// Record one outbound message per §4.4 steps 9–14 and return its message id.
///
/// The caller owns the value side (escrow and liability); inbound bounces (§4.12.5) record
/// from the escrow this way.
///
/// # Errors
///
/// See [`plan`] and [`write_planned`].
pub fn record_outbound_message(
    state_transaction: &mut StateTransaction<'_, '_>,
    args: OutboundRecordArgsV1,
) -> Result<[u8; 32], Error> {
    let planned = plan(state_transaction, &args)?;
    write_planned(state_transaction, &args, planned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        smartcontracts::isi::sccp::test_support::{
            ONE_XOR, authority, header, sample_generation_at,
        },
        state::{State, World},
    };
    use iroha_data_model::{
        Registrable,
        account::Account,
        asset::{Asset, AssetBalancePolicy, AssetDefinition, AssetId},
        sccp::{
            deployment::SccpEvmDeploymentV1, escrow::sccp_taira_xor_asset_definition_id,
            params::SccpParametersV1, registry::SccpRouteRevisionV1,
        },
    };
    use iroha_primitives::numeric::Numeric;
    use mv::storage::StorageReadOnly;

    const CONTRACT: [u8; 20] = [0xc0; 20];

    /// A state whose `authority(1)` holds 10 XOR.
    fn funded_state() -> State {
        let holder = authority(1);
        let xor = sccp_taira_xor_asset_definition_id();
        let definition = AssetDefinition::numeric(
            xor.clone(),
            "XOR".to_owned(),
            AssetBalancePolicy::Global,
            None,
        )
        .build(&holder);
        let world = World::with_assets(
            [],
            [Account::new(holder.clone()).build(&holder)],
            [definition],
            [Asset::new(
                AssetId::of(xor, holder.clone()),
                escrow::xor_quantity(10 * ONE_XOR).expect("quantity"),
            )],
            [],
        );
        State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        )
    }

    /// Inject existing state with a native generation and Bidirectional Ethereum revision.
    /// This does not establish the currently blocked RegisterRoute or launch requirements.
    fn setup(stx: &mut StateTransaction<'_, '_>, max_wrapped_supply: u128) {
        store::parameters::set(stx, Some(SccpParametersV1::taira_default()));
        escrow::create_route_escrows(stx).expect("escrows");
        crate::smartcontracts::isi::sccp::test_support::install_generation(
            stx,
            1,
            sample_generation_at(1, 1),
        )
        .expect("generation");
        store::committee_current::set(stx, 1);
        let mut route = store::routes::get(&*stx.world, &SccpNetworkV1::EthereumMainnet)
            .cloned()
            .expect("route");
        let mut revision = SccpRouteRevisionV1::staged(
            1,
            SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
                address: CONTRACT,
                runtime_code_hash: [0x34; 32],
            }),
            crate::smartcontracts::isi::sccp::test_support::sample_pin(
                store::committee_generations::get(&*stx.world, &1).expect("generation"),
            ),
            max_wrapped_supply,
            2,
        );
        revision.activation = SccpRouteActivationV1::Bidirectional;
        route.revisions.insert(1, revision);
        store::routes::insert(stx, SccpNetworkV1::EthereumMainnet, route).expect("route");
    }

    fn record(amount_xor: u32, recipient: [u8; 20]) -> RecordSccpMessage {
        RecordSccpMessage {
            network: SccpNetworkV1::EthereumMainnet,
            expected_revision: 1,
            amount: Numeric::new(amount_xor, 0),
            recipient: recipient.to_vec(),
        }
    }

    fn refusal(result: Result<(), Error>) -> String {
        result.expect_err("refused").to_string()
    }

    #[test]
    fn a_hold_refuses_record_plan_and_publication_before_any_value_effect() {
        let state = funded_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::new(b"hold-record"));
        setup(&mut stx, 100 * ONE_XOR);
        let args = OutboundRecordArgsV1 {
            network: SccpNetworkV1::EthereumMainnet,
            revision: 1,
            amount: ONE_XOR,
            sender: authority(1),
            recipient: vec![0x22; 20],
        };
        let planned = plan(&stx, &args).expect("unheld plan");
        let before_route = store::routes::get(&*stx.world, &args.network)
            .unwrap()
            .clone();
        let before_balance =
            crate::smartcontracts::isi::sccp::test_support::xor_balance(&*stx.world, &authority(1));
        // A recorded generation equal to the floor holds even a plan made earlier.
        *stx.world.sccp_forgery_max_generation.get_mut() = Some(1);
        assert!(
            refusal(execute_record(
                record(1, [0x22; 20]),
                &authority(1),
                &mut stx
            ))
            .contains("SccpForgeryHold")
        );
        assert!(
            plan(&stx, &args)
                .unwrap_err()
                .to_string()
                .contains("SccpForgeryHold")
        );
        assert!(
            write_planned(&mut stx, &args, planned)
                .unwrap_err()
                .to_string()
                .contains("SccpForgeryHold")
        );
        assert_eq!(
            store::routes::get(&*stx.world, &args.network),
            Some(&before_route)
        );
        assert_eq!(
            crate::smartcontracts::isi::sccp::test_support::xor_balance(&*stx.world, &authority(1),),
            before_balance
        );
        assert!(store::outbound_messages::is_empty(&*stx.world));
        assert!(store::outbound_by_nonce::is_empty(&*stx.world));
        assert_eq!(leaves::leaf_count_at(&*stx.world, 5), 0);
        crate::smartcontracts::isi::sccp::test_support::assert_escrow_invariant(
            &*stx.world,
            "held outbound",
        );
    }

    #[test]
    fn a_record_locks_counts_and_commits_one_leaf() {
        let state = funded_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::new(
            b"a_record_locks_counts_and_commits_one_leaf",
        ));
        setup(&mut stx, 100 * ONE_XOR);
        execute_record(record(2, [0x22; 20]), &authority(1), &mut stx).expect("record");
        execute_record(record(3, [0x23; 20]), &authority(1), &mut stx).expect("record");

        let route =
            store::routes::get(&*stx.world, &SccpNetworkV1::EthereumMainnet).expect("route");
        let revision = route.revisions.get(&1).expect("revision");
        assert_eq!(revision.liability, 5 * ONE_XOR);
        assert_eq!(revision.next_outbound_nonce, 2);
        let escrow_balance = stx
            .world
            .assets
            .get(&AssetId::of(
                sccp_taira_xor_asset_definition_id(),
                route.escrow.clone(),
            ))
            .map(|value| value.as_ref().clone());
        assert_eq!(
            escrow_balance,
            Some(escrow::xor_quantity(5 * ONE_XOR).unwrap())
        );

        let second =
            *store::outbound_by_nonce::get(&*stx.world, &(SccpNetworkV1::EthereumMainnet, 1, 1))
                .expect("nonce 1");
        let message = store::outbound_messages::get(&*stx.world, &second).expect("record");
        assert_eq!(message.height, 5);
        assert_eq!(message.commitment_index, 1);
        assert_eq!(message.amount, 3 * ONE_XOR);
        assert_eq!(message.sender, authority(1));
        assert!(message.status.is_recorded());
        assert_eq!(
            message.deadline_ms,
            stx.block_unix_timestamp_ms() + SccpParametersV1::taira_default().outbound_ttl_ms
        );
        assert_eq!(
            message.leaf,
            transfer_leaf(&second, &revision.destination_word)
        );
        let decoded = SccpTransferPayloadV1::decode(&message.payload).expect("payload");
        assert_eq!(decoded.nonce, 1);
        assert_eq!(decoded.recipient.bytes, vec![0x23; 20]);
        assert_eq!(
            decoded.message_id(stx.network_id().as_bytes()).expect("id"),
            second
        );
        assert_eq!(leaves::leaf_count_at(&*stx.world, 5), 2);
    }

    #[test]
    fn recording_enforces_the_route_amount_recipient_and_cap_rules() {
        let state = funded_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::new(
            b"recording_enforces_the_route_amount_recipient_and_cap_rules",
        ));
        let error = refusal(execute_record(
            record(2, [0x22; 20]),
            &authority(1),
            &mut stx,
        ));
        assert!(error.contains("does not exist"), "{error}");
        setup(&mut stx, 3 * ONE_XOR);

        let mut wrong_revision = record(2, [0x22; 20]);
        wrong_revision.expected_revision = 2;
        let error = refusal(execute_record(wrong_revision, &authority(1), &mut stx));
        assert!(error.contains("Bidirectional"), "{error}");

        let mut dust = record(2, [0x22; 20]);
        dust.amount = Numeric::new(1_u32, 1);
        let error = refusal(execute_record(dust, &authority(1), &mut stx));
        assert!(error.contains("below the minimum"), "{error}");

        let mut inexact = record(2, [0x22; 20]);
        inexact.amount = Numeric::new(1_u32, 10);
        refusal(execute_record(inexact, &authority(1), &mut stx));

        let error = refusal(execute_record(record(2, [0; 20]), &authority(1), &mut stx));
        assert!(error.contains("recipient"), "{error}");
        let error = refusal(execute_record(record(2, CONTRACT), &authority(1), &mut stx));
        assert!(error.contains("deployment"), "{error}");

        let error = refusal(execute_record(
            record(4, [0x22; 20]),
            &authority(1),
            &mut stx,
        ));
        assert!(error.contains("supply cap"), "{error}");

        let mut params = SccpParametersV1::taira_default();
        params.enabled = false;
        store::parameters::set(&mut stx, Some(params));
        let error = refusal(execute_record(
            record(2, [0x22; 20]),
            &authority(1),
            &mut stx,
        ));
        assert!(error.contains("disabled"), "{error}");
    }

    #[test]
    fn degraded_parent_refuses_before_money_nonce_or_leaf_and_recovers() {
        for parent_run in [1, 2, u32::MAX] {
            let state = funded_state();
            {
                let mut parent = state.world.block();
                *parent.sccp_degraded_run.get_mut() = parent_run;
                parent.commit();
            }
            let mut block = state.block(header(5));
            let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::new(
                b"degraded_parent_refuses_before_money_nonce_or_leaf_and_recovers",
            ));
            setup(&mut stx, 100 * ONE_XOR);
            // Even a repair in this block cannot change the committed-parent verdict.
            store::degraded_run::set(&mut stx, 0);
            let network = SccpNetworkV1::EthereumMainnet;
            let before_route = store::routes::get(&*stx.world, &network)
                .cloned()
                .expect("route");
            let before_assets = stx
                .world
                .assets
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Vec<_>>();
            let error = refusal(execute_record(
                record(2, [0x22; 20]),
                &authority(1),
                &mut stx,
            ));
            assert!(error.contains("SccpFinalityDegraded"), "{error}");
            assert_eq!(
                store::routes::get(&*stx.world, &network),
                Some(&before_route)
            );
            assert_eq!(
                stx.world
                    .assets
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Vec<_>>(),
                before_assets
            );
            assert_eq!(leaves::leaf_count_at(&*stx.world, 5), 0);
            assert_eq!(store::outbound_messages::len(&*stx.world), 0);
            assert_eq!(store::outbound_by_nonce::len(&*stx.world), 0);
            drop(stx);
            drop(block);

            // Recovery becomes visible only when the repaired parent is committed.
            // A fresh execution then consumes that parent's healthy preimage.
            {
                let mut parent = state.world.block();
                *parent.sccp_degraded_run.get_mut() = 0;
                parent.commit();
            }
            let mut recovered = state.block(header(6));
            let mut stx = recovered.transaction_for_fastpq_testing(iroha_crypto::Hash::new(
                b"degraded-parent-committed-recovery",
            ));
            setup(&mut stx, 100 * ONE_XOR);
            assert_eq!(TransactionParent(&stx.world).degraded_run(), 0);
            execute_record(record(2, [0x22; 20]), &authority(1), &mut stx)
                .expect("recovered committed parent");
            let route = store::routes::get(&*stx.world, &network).expect("route");
            assert_eq!(route.revisions[&1].liability, 2 * ONE_XOR);
            assert_eq!(route.revisions[&1].next_outbound_nonce, 1);
            assert_eq!(leaves::leaf_count_at(&*stx.world, 6), 1);
            assert_eq!(store::outbound_messages::len(&*stx.world), 1);
            assert_eq!(store::outbound_by_nonce::len(&*stx.world), 1);
            crate::smartcontracts::isi::sccp::test_support::assert_escrow_invariant(
                &*stx.world,
                "committed-parent recovery",
            );
        }
    }

    #[test]
    fn a_current_block_degradation_does_not_rewrite_the_parent_gate() {
        let state = funded_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::new(
            b"a_current_block_degradation_does_not_rewrite_the_parent_gate",
        ));
        setup(&mut stx, 100 * ONE_XOR);
        assert_eq!(TransactionParent(&stx.world).degraded_run(), 0);
        store::degraded_run::set(&mut stx, 2);
        execute_record(record(2, [0x22; 20]), &authority(1), &mut stx).expect("healthy parent");
        assert_eq!(leaves::leaf_count_at(&*stx.world, 5), 1);
        assert_eq!(store::outbound_messages::len(&*stx.world), 1);
        let route =
            store::routes::get(&*stx.world, &SccpNetworkV1::EthereumMainnet).expect("route");
        let revision = route.revisions.get(&1).expect("revision");
        assert_eq!(revision.liability, 2 * ONE_XOR);
        assert_eq!(revision.next_outbound_nonce, 1);
    }

    #[test]
    fn replacement_recording_uses_reverted_parent_finality() {
        for (original_run, successor_run) in [(1, 0), (0, 1)] {
            let state = funded_state();
            for run in [original_run, successor_run] {
                let mut world = state.world.block();
                *world.sccp_degraded_run.get_mut() = run;
                world.commit();
            }
            assert_eq!(
                *store::degraded_run::get(&state.world_view()),
                successor_run
            );
            let mut block = state.block_and_revert(header(5));
            let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::new(
                b"replacement_recording_uses_reverted_parent_finality",
            ));
            setup(&mut stx, 100 * ONE_XOR);
            // This transaction cannot substitute either the published successor or
            // its own repaired/degraded value for the replacement's actual parent.
            store::degraded_run::set(&mut stx, successor_run);
            let result = execute_record(record(2, [0x22; 20]), &authority(1), &mut stx);
            if original_run == 0 {
                result.expect("reverted parent is healthy");
                assert_eq!(leaves::leaf_count_at(&*stx.world, 5), 1);
                assert_eq!(store::outbound_messages::len(&*stx.world), 1);
            } else {
                let error = refusal(result);
                assert!(error.contains("SccpFinalityDegraded"), "{error}");
                assert_eq!(leaves::leaf_count_at(&*stx.world, 5), 0);
                assert_eq!(store::outbound_messages::len(&*stx.world), 0);
                let route = store::routes::get(&*stx.world, &SccpNetworkV1::EthereumMainnet)
                    .expect("route");
                assert_eq!(route.revisions.get(&1).unwrap().liability, 0);
            }
        }
    }

    #[test]
    fn bounces_record_without_touching_the_escrow() {
        let state = funded_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::new(
            b"bounces_record_without_touching_the_escrow",
        ));
        setup(&mut stx, 100 * ONE_XOR);
        let escrow = store::routes::get(&*stx.world, &SccpNetworkV1::EthereumMainnet)
            .expect("route")
            .escrow
            .clone();
        let id = record_outbound_message(
            &mut stx,
            OutboundRecordArgsV1 {
                network: SccpNetworkV1::EthereumMainnet,
                revision: 1,
                amount: ONE_XOR,
                sender: escrow,
                recipient: vec![0x22; 20],
            },
        )
        .expect("bounce");
        let route =
            store::routes::get(&*stx.world, &SccpNetworkV1::EthereumMainnet).expect("route");
        assert_eq!(route.revisions.get(&1).expect("revision").liability, 0);
        assert_eq!(
            store::outbound_by_nonce::get(&*stx.world, &(SccpNetworkV1::EthereumMainnet, 1, 0)),
            Some(&id)
        );
    }

    #[test]
    fn record_obeys_fast_pause_network_revision_and_exact_expiry_without_effects() {
        use crate::smartcontracts::isi::sccp::test_support::{
            assert_escrow_invariant, install_consumer_fast_pause,
        };
        let network = SccpNetworkV1::EthereumMainnet;
        // Route and pause are component preconditions, not a claimed governance enactment.
        for (pause_network, taira, revisions, until_delta, held) in [
            (network, true, vec![2], 1_i64, true),
            (network, false, vec![1], 1, true),
            (network, false, vec![2], 1, false),
            (SccpNetworkV1::TonMainnet, true, vec![1], 1, false),
            (network, true, vec![1], 0, false),
            (network, true, vec![1], -1, false),
        ] {
            let state = funded_state();
            let mut block = state.block(header(5));
            {
                let mut stx = block
                    .transaction_for_fastpq_testing(iroha_crypto::Hash::new(b"fast-pause-record"));
                setup(&mut stx, 100 * ONE_XOR);
                let now = stx.block_unix_timestamp_ms();
                install_consumer_fast_pause(
                    &mut stx,
                    pause_network,
                    taira,
                    revisions,
                    now.checked_add_signed(until_delta).unwrap(),
                );
                let before = store::routes::get(&*stx.world, &network).unwrap().clone();
                let before_assets = stx
                    .world
                    .assets
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Vec<_>>();
                let result = execute_record(record(2, [0x22; 20]), &authority(1), &mut stx);
                assert_eq!(
                    result.is_err(),
                    held,
                    "the actual Record instruction must respect the exact active pause"
                );
                let after = store::routes::get(&*stx.world, &network).unwrap();
                if held {
                    assert_eq!(after, &before, "refusal preserves liability and nonce");
                    assert_eq!(leaves::leaf_count_at(&*stx.world, 5), 0);
                    assert!(store::outbound_messages::is_empty(&*stx.world));
                    assert!(store::outbound_by_nonce::is_empty(&*stx.world));
                    assert_eq!(
                        stx.world
                            .assets
                            .iter()
                            .map(|(key, value)| (key.clone(), value.clone()))
                            .collect::<Vec<_>>(),
                        before_assets,
                        "refusal leaves sender and escrow balances unchanged"
                    );
                } else {
                    assert_eq!(after.revisions[&1].liability, 2 * ONE_XOR);
                    assert_eq!(after.revisions[&1].next_outbound_nonce, 1);
                    assert_eq!(leaves::leaf_count_at(&*stx.world, 5), 1);
                    assert_eq!(store::outbound_messages::len(&*stx.world), 1);
                    assert_eq!(store::outbound_by_nonce::len(&*stx.world), 1);
                }
                assert_escrow_invariant(&*stx.world, "fast-pause record");
            }
            assert!(
                store::routes::is_empty(&block.world),
                "dropping the transaction rolls all effects back"
            );
            assert!(
                store::fast_pauses::is_empty(&block.world),
                "retained pause rolls back with its transaction"
            );
        }
    }
}
