//! Outbound value path: `RecordSccpMessage` (`specs/sccp.md` §4.4). Owner: ws32.
//!
//! Recording checks activation, attestation liveness, amount, sender and recipient rules and
//! the supply cap, locks XOR into the route escrow and then records the message per §4.4 steps
//! 9–14 through [`record_outbound_message`], which inbound bounces (§4.12.5) reuse.
//!
//! The message id binds the escrow lock, so the record is planned ([`plan`]) before the lock
//! and written ([`write_planned`]) after it; a failed transaction rolls back both.

use super::{Error, escrow, leaves, roster, store};
use crate::state::{StateReadOnly, StateTransaction, WorldReadOnly};
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

/// Check §4.4 step 2 at block time `now_ms` and `height`: the signing generation is not inert
/// and its most recent subject older than `attestation_stall_ms` is attested.
fn check_liveness(
    world: &(impl WorldReadOnly + ?Sized),
    height: u64,
    now_ms: u64,
    stall_ms: u64,
) -> Result<(), Error> {
    let generation = roster::generation_for_height(world, height)
        .ok_or_else(|| refuse("no roster generation signs this height"))?;
    let signing = store::rosters::get(world, &generation)
        .ok_or_else(|| refuse(format_args!("generation {generation} is unknown")))?;
    if roster::is_inert(signing) {
        return Err(refuse(format_args!("generation {generation} is inert")));
    }
    let cutoff = now_ms.saturating_sub(stall_ms);
    // Subjects are written in height order with non-decreasing generations, so the newest
    // subject at or before the cutoff decides: an older generation's subject means this
    // generation has none that old.
    let stale = store::attestation_subjects::range(world, ..height)
        .rev()
        .find(|(_, subject)| subject.timestamp_ms <= cutoff);
    if let Some((stale_height, subject)) = stale
        && subject.generation == generation
        && store::attestation_status::get(world, stale_height)
            .is_none_or(|status| status.attested_at_height.is_none())
    {
        return Err(refuse(format_args!(
            "subject {stale_height} of generation {generation} is unattested past the stall window"
        )));
    }
    Ok(())
}

/// Execute `RecordSccpMessage` (§4.4 steps 1–14).
///
/// # Errors
///
/// Refuses when SCCP is absent or disabled, the revision is not the route's unpaused
/// `Bidirectional` one, attestation is stalled, the amount, sender or recipient breaks a rule,
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
    let (min_outbound_amount, stall_ms) = (params.min_outbound_amount, params.attestation_stall_ms);
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
    // Step 2: attestation liveness.
    let height = state_transaction._curr_block.height().get();
    let now_ms = state_transaction.block_unix_timestamp_ms();
    check_liveness(world, height, now_ms, stall_ms)?;
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
/// Fails when the route revision is unknown, the payload breaks a §3.2 rule, or the message id
/// is already recorded.
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
/// Fails when the revision's nonce moved since planning, or the block's leaves are full.
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
        smartcontracts::isi::sccp::test_support::{ONE_XOR, authority, header, sample_roster},
        state::{State, World},
    };
    use iroha_data_model::{
        Registrable,
        account::Account,
        asset::{Asset, AssetBalancePolicy, AssetDefinition, AssetId},
        sccp::{
            attestation::{SccpAttestationStatusV1, SccpAttestationSubjectV1},
            deployment::SccpEvmDeploymentV1,
            escrow::sccp_taira_xor_asset_definition_id,
            params::SccpParametersV1,
            registry::SccpRouteRevisionV1,
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

    /// Initialize SCCP with a live generation 1 and a Bidirectional Ethereum revision 1.
    fn setup(stx: &mut StateTransaction<'_, '_>, max_wrapped_supply: u128) {
        store::parameters::set(stx, Some(SccpParametersV1::taira_default()));
        escrow::create_route_escrows(stx).expect("escrows");
        store::rosters::insert(stx, 1, sample_roster(1, 1)).expect("roster");
        store::roster_current::set(stx, 1);
        let mut route = store::routes::get(&*stx.world, &SccpNetworkV1::EthereumMainnet)
            .cloned()
            .expect("route");
        let mut revision = SccpRouteRevisionV1::staged(
            1,
            SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
                address: CONTRACT,
                runtime_code_hash: [0x34; 32],
            }),
            max_wrapped_supply,
            1,
            [0x35; 32],
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
    fn a_stalled_or_inert_generation_blocks_recording() {
        let state = funded_state();
        let mut block = state.block(header(500));
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::new(
            b"a_stalled_or_inert_generation_blocks_recording",
        ));
        setup(&mut stx, 100 * ONE_XOR);
        let now = stx.block_unix_timestamp_ms();
        let stall = SccpParametersV1::taira_default().attestation_stall_ms;
        let subject = |height: u64, timestamp_ms: u64| SccpAttestationSubjectV1 {
            height,
            epoch: 0,
            timestamp_ms,
            sccp_root: [0; 32],
            message_count: 0,
            history_root: [0; 32],
            history_size: 0,
            generation: 1,
            roster_digest: [5; 32],
            next_roster_digest: [0; 32],
        };
        store::attestation_subjects::insert(&mut stx, 10, subject(10, now - stall - 1))
            .expect("subject");
        let error = refusal(execute_record(
            record(2, [0x22; 20]),
            &authority(1),
            &mut stx,
        ));
        assert!(error.contains("unattested"), "{error}");
        let status = SccpAttestationStatusV1 {
            attested_at_height: Some(11),
            ..SccpAttestationStatusV1::default()
        };
        store::attestation_status::insert(&mut stx, 10, status).expect("status");
        // A recent unattested subject is still inside its window.
        store::attestation_subjects::insert(&mut stx, 20, subject(20, now - 1)).expect("subject");
        execute_record(record(2, [0x22; 20]), &authority(1), &mut stx).expect("live");

        let mut inert = sample_roster(1, 1);
        for member in &mut inert.members {
            member.address = [0; 20];
        }
        store::rosters::insert(&mut stx, 1, inert).expect("roster");
        let error = refusal(execute_record(
            record(2, [0x22; 20]),
            &authority(1),
            &mut stx,
        ));
        assert!(error.contains("inert"), "{error}");
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
}
