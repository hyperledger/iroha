//! Settlement unit tests (`specs/sccp.md` §4.12, §4.15, §4.16).
//!
//! Every test asserts `balance(escrow(route)) = Σ_r liability(r) + stranded(route)` after each
//! step. Proofs and voids enter through [`record_proven`] and [`apply_void`], the effects of
//! `SubmitSccpInboundMessageV1` and `SubmitSccpOutboundVoidV1` after their light-client
//! verification.

use super::*;
use crate::{
    smartcontracts::{
        Execute,
        isi::sccp::{
            governance,
            inbound::{SccpProvenInboundV1, record_proven},
            test_support::{
                ONE_XOR, assert_escrow_invariant, authority, funded_xor_state, header,
                install_value_route, xor_balance,
            },
            voids::{SccpProvenVoidV1, apply_void},
        },
    },
    state::{State, StateReadOnly},
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    account::AccountAddress,
    isi::{SetAssetHoldingLimit, sccp::RecordSccpMessage},
    prelude::DataEvent,
    sccp::{
        control::SccpLeafRefV1,
        escrow::sccp_taira_xor_asset_definition_id,
        governance::{
            SccpGovernanceActionV1, SccpGovernanceProposalV1, SccpReleaseStrandedActionV1,
        },
        inbound::SccpSourceLocatorV1,
        outbound::{SccpOutboundMessageRecordV1, SccpVoidKindV1, SccpVoidStatusV1},
    },
};
use iroha_primitives::numeric::Numeric;
use std::{collections::BTreeMap, sync::Arc};

const ETH: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
const TON: SccpNetworkV1 = SccpNetworkV1::TonMainnet;
const FEE: u128 = 10_000_000;

fn holder() -> AccountId {
    authority(1)
}

fn state() -> State {
    funded_xor_state(&holder(), 1_000_000 * ONE_XOR)
}

fn id_of(label: &str) -> [u8; 32] {
    *Hash::new(label.as_bytes()).as_ref()
}

/// Install Bidirectional revision 1 of ETH (cap 1 000 XOR) and TON (cap 100 000 XOR).
fn install(stx: &mut StateTransaction<'_, '_>) {
    install_value_route(
        stx,
        ETH,
        1,
        SccpRouteActivationV1::Bidirectional,
        1_000 * ONE_XOR,
    );
    install_value_route(
        stx,
        TON,
        1,
        SccpRouteActivationV1::Bidirectional,
        100_000 * ONE_XOR,
    );
    assert_escrow_invariant(&*stx.world, "install");
}

/// Lock `amount` from the holder into `network`'s escrow as liability of `revision`, as
/// `RecordSccpMessage` step 8 does.
fn fund(stx: &mut StateTransaction<'_, '_>, network: SccpNetworkV1, revision: u32, amount: u128) {
    let escrow = escrow_of(stx, network);
    let binding = id_of(&format!(
        "fund/{network:?}/{}",
        xor_balance(&*stx.world, &escrow)
    ));
    escrow::lock(stx, network, &holder(), amount, binding).expect("lock");
    adjust_liability(stx, network, revision, to_i128(amount).expect("amount")).expect("liability");
    assert_escrow_invariant(&*stx.world, "fund");
}

fn address_bytes(account: &AccountId) -> Vec<u8> {
    AccountAddress::from_account_id(account)
        .and_then(|address| address.canonical_bytes())
        .expect("address")
}

/// A valid account of `network`'s codec (§3.1) derived from `seed`.
fn external_account(network: SccpNetworkV1, seed: u8) -> Vec<u8> {
    if network == TON {
        let mut bytes = vec![0; 4];
        bytes.extend_from_slice(&[seed; 32]);
        bytes
    } else {
        vec![seed; 20]
    }
}

/// Record a proven burn of `amount` to `recipient` on `(network, revision)` and return its
/// message id; recording never fails on a settlement refusal.
fn prove_on(
    stx: &mut StateTransaction<'_, '_>,
    (network, revision): (SccpNetworkV1, u32),
    nonce: u64,
    amount: u128,
    recipient: Vec<u8>,
    fee_due: u128,
) -> [u8; 32] {
    let payload = SccpTransferPayloadV1::inbound(
        network,
        nonce,
        revision,
        amount,
        external_account(network, 0x44),
        recipient,
    )
    .expect("payload");
    let message_id = payload
        .message_id(stx.network_id().as_bytes())
        .expect("message id");
    record_proven(
        stx,
        SccpProvenInboundV1 {
            network,
            revision,
            payload: payload.encode().expect("encode"),
            amount,
            message_id,
            source_locator: SccpSourceLocatorV1 {
                source_height: nonce + 100,
                block_hash: [7; 32],
                index_in_block: 0,
            },
            fee_due,
        },
    )
    .expect("a proven burn is recorded whatever its settlement does");
    assert_escrow_invariant(&*stx.world, "prove");
    message_id
}

fn prove(
    stx: &mut StateTransaction<'_, '_>,
    nonce: u64,
    amount: u128,
    recipient: Vec<u8>,
    fee_due: u128,
) -> [u8; 32] {
    prove_on(stx, (ETH, 1), nonce, amount, recipient, fee_due)
}

fn inbound_status(stx: &StateTransaction<'_, '_>, message_id: &[u8; 32]) -> SccpInboundStatusV1 {
    store::inbound_messages::get(&*stx.world, message_id)
        .expect("record")
        .status
}

fn pending(reason: SccpPendingReasonV1) -> SccpInboundStatusV1 {
    SccpInboundStatusV1::pending(reason)
}

fn outbound_status(stx: &StateTransaction<'_, '_>, message_id: &[u8; 32]) -> SccpOutboundStatusV1 {
    store::outbound_messages::get(&*stx.world, message_id)
        .expect("record")
        .status
}

fn liability(stx: &StateTransaction<'_, '_>, network: SccpNetworkV1, revision: u32) -> u128 {
    store::routes::get(&*stx.world, &network)
        .and_then(|route| route.revisions.get(&revision))
        .expect("revision")
        .liability
}

fn stranded(stx: &StateTransaction<'_, '_>, network: SccpNetworkV1) -> u128 {
    store::routes::get(&*stx.world, &network)
        .expect("route")
        .stranded
}

fn escrow_of(stx: &StateTransaction<'_, '_>, network: SccpNetworkV1) -> AccountId {
    store::routes::get(&*stx.world, &network)
        .expect("route")
        .escrow
        .clone()
}

fn set_enabled(stx: &mut StateTransaction<'_, '_>, enabled: bool) {
    let mut params = store::parameters::get(&*stx.world).clone().expect("SCCP");
    params.enabled = enabled;
    store::parameters::set(stx, Some(params));
}

fn set_activation(
    stx: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    revision: u32,
    activation: SccpRouteActivationV1,
) {
    let mut route = store::routes::get(&*stx.world, &network)
        .cloned()
        .expect("route");
    route
        .revisions
        .get_mut(&revision)
        .expect("revision")
        .activation = activation;
    store::routes::insert(stx, network, route).expect("route");
}

/// Set or clear the XOR holding limit of the registered `account` (the holder owns XOR).
fn set_holding_limit(stx: &mut StateTransaction<'_, '_>, account: &AccountId, limit: Option<u128>) {
    SetAssetHoldingLimit::new(
        account.clone(),
        sccp_taira_xor_asset_definition_id(),
        limit.map(|limit| escrow::xor_quantity(limit).expect("quantity")),
    )
    .execute(&holder(), stx)
    .expect("holding limit");
}

/// Register `account` with an XOR holding limit of zero: every credit to it is refused now.
fn refusing_account(stx: &mut StateTransaction<'_, '_>, seed: u8) -> AccountId {
    let account = authority(seed);
    recipients::ensure_registered(stx, &account).expect("register");
    set_holding_limit(stx, &account, Some(0));
    account
}

/// Mark the absent `account` as a retired retail rekey identity, which `Register<Account>`
/// refuses forever.
fn retired_account(stx: &mut StateTransaction<'_, '_>, seed: u8) -> AccountId {
    let account = authority(seed);
    let path = format!(
        "retail_fee_control_v1/retired/{}",
        hex::encode(Hash::new(account.to_string().as_bytes()).as_ref())
    )
    .parse()
    .expect("state path");
    stx.world
        .smart_contract_state
        .insert(path, norito::to_bytes(&holder()).expect("bytes"));
    account
}

/// Point the Nexus fee sink of this transaction at `sink` (an empty literal when `None`).
fn set_fee_sink(stx: &mut StateTransaction<'_, '_>, sink: Option<&AccountId>) {
    stx.nexus.fees.fee_sink_account_id = sink.map_or_else(String::new, |sink| {
        AccountAddress::from_account_id(sink)
            .and_then(|address| {
                address.to_i105_for_discriminant(
                    iroha_data_model::account::address::chain_discriminant(),
                )
            })
            .expect("i105 literal")
    });
}

/// Record an outbound message of `amount_xor` XOR from `sender` through `RecordSccpMessage`.
fn record_outbound(
    stx: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    amount_xor: u32,
    sender: &AccountId,
) -> Result<[u8; 32], Error> {
    outbound::execute_record(
        RecordSccpMessage {
            network,
            expected_revision: 1,
            amount: Numeric::new(amount_xor, 0),
            recipient: external_account(network, 0x22),
        },
        sender,
        stx,
    )?;
    let nonce = store::routes::get(&*stx.world, &network)
        .and_then(|route| route.revisions.get(&1))
        .expect("revision")
        .next_outbound_nonce
        - 1;
    Ok(*store::outbound_by_nonce::get(&*stx.world, &(network, 1, nonce)).expect("nonce"))
}

/// Seed a `Recorded` outbound message of revision 1 of `network` at `nonce` whose sender is
/// `sender`, funding its liability from the holder.
fn seed_outbound(
    stx: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    nonce: u64,
    sender: &AccountId,
    amount: u128,
) -> [u8; 32] {
    let message_id = seed_unfunded(stx, network, nonce, sender, amount);
    fund(stx, network, 1, amount);
    message_id
}

/// Seed a `Recorded` outbound message like [`seed_outbound`] without funding it; the caller
/// funds the total with one lock, since one transaction holds at most 16 FASTPQ transcripts.
fn seed_unfunded(
    stx: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    nonce: u64,
    sender: &AccountId,
    amount: u128,
) -> [u8; 32] {
    let message_id = id_of(&format!("seed/{network:?}/{nonce}"));
    store::outbound_messages::insert(
        stx,
        message_id,
        SccpOutboundMessageRecordV1 {
            network,
            revision: 1,
            nonce,
            height: 5,
            commitment_index: 0,
            deadline_ms: 1,
            sender: sender.clone(),
            amount,
            payload: Vec::new(),
            leaf: message_id,
            status: SccpOutboundStatusV1::Recorded,
        },
    )
    .expect("record");
    store::outbound_by_nonce::insert(stx, (network, 1, nonce), message_id).expect("index");
    let mut route = store::routes::get(&*stx.world, &network)
        .cloned()
        .expect("route");
    let revision = route.revisions.get_mut(&1).expect("revision");
    revision.next_outbound_nonce = revision.next_outbound_nonce.max(nonce + 1);
    store::routes::insert(stx, network, route).expect("route");
    message_id
}

fn void_expired(
    stx: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    nonce: u64,
) -> Result<(), Error> {
    apply_void(
        stx,
        network,
        1,
        SccpProvenVoidV1 {
            kind: SccpVoidKindV1::Expired,
            first_nonce: nonce,
            count: 1,
            message_id_or_zero: [0; 32],
        },
    )
}

fn void_frozen(
    stx: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    first_nonce: u64,
    count: u64,
) -> Result<(), Error> {
    apply_void(
        stx,
        network,
        1,
        SccpProvenVoidV1 {
            kind: SccpVoidKindV1::Frozen,
            first_nonce,
            count,
            message_id_or_zero: [0; 32],
        },
    )
}

fn sccp_events(stx: &StateTransaction<'_, '_>) -> Vec<SccpEvent> {
    stx.world
        .internal_event_buf
        .iter()
        .filter_map(|event| match event.as_ref() {
            DataEvent::Sccp(event) => Some(event.clone()),
            _ => None,
        })
        .collect()
}

fn voided_events(stx: &StateTransaction<'_, '_>) -> Vec<(u64, bool)> {
    sccp_events(stx)
        .into_iter()
        .filter_map(|event| match event {
            SccpEvent::OutboundVoided(voided) => Some((voided.nonce, voided.refund_pending)),
            _ => None,
        })
        .collect()
}

/// Assert that the stored pending counts equal the pending records (§4.14.2).
fn assert_pending_counts(stx: &StateTransaction<'_, '_>, context: &str) {
    let mut counts = BTreeMap::<(SccpNetworkV1, u32), (u64, u64)>::new();
    for (_, record) in store::inbound_messages::iter(&*stx.world) {
        if record.status.is_pending() {
            counts
                .entry((record.network, record.revision))
                .or_default()
                .0 += 1;
        }
    }
    for (_, record) in store::outbound_messages::iter(&*stx.world) {
        if record.status.is_refund_pending() {
            counts
                .entry((record.network, record.revision))
                .or_default()
                .1 += 1;
        }
    }
    let stored: BTreeMap<_, _> = store::pending_counts::iter(&*stx.world)
        .map(|(key, value)| (*key, *value))
        .collect();
    assert_eq!(stored, counts, "{context}: pending counts");
}

#[test]
fn a_release_without_a_fee_registers_and_credits_the_recipient() {
    let state = state();
    let mut block = state.block(header(5));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"release-without-fee"));
    install(&mut stx);
    fund(&mut stx, ETH, 1, 10 * ONE_XOR);
    let recipient = authority(20);
    assert!(stx.world.account(&recipient).is_err());

    let id = prove(&mut stx, 0, 3 * ONE_XOR, address_bytes(&recipient), 0);
    assert!(matches!(
        inbound_status(&stx, &id),
        SccpInboundStatusV1::Released(_)
    ));
    assert!(stx.world.account(&recipient).is_ok(), "registered");
    assert_eq!(xor_balance(&*stx.world, &recipient), 3 * ONE_XOR);
    assert_eq!(liability(&stx, ETH, 1), 7 * ONE_XOR);
    assert_eq!(store::pending_count(&*stx.world, &(ETH, 1)), (0, 0));
    let events = sccp_events(&stx);
    assert!(events.iter().any(|event| matches!(
        event,
        SccpEvent::RecipientRegistered(registered) if registered.account == recipient
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        SccpEvent::InboundReleased(released)
            if released.fee == 0 && released.amount == 3 * ONE_XOR
    )));
    // A settled message cannot be settled again.
    execute_settle(SettleSccpV1::inbound(id), &holder(), &mut stx).expect_err("not pending");
    assert_escrow_invariant(&*stx.world, "after release");
    assert_pending_counts(&stx, "after release");
}

#[test]
fn a_release_with_a_self_claim_fee_pays_the_fee_sink() {
    let state = state();
    let mut block = state.block(header(5));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"release-with-fee"));
    install(&mut stx);
    fund(&mut stx, ETH, 1, 10 * ONE_XOR);
    let sink = authority(30);
    recipients::ensure_registered(&mut stx, &sink).expect("sink");
    set_fee_sink(&mut stx, Some(&sink));

    let recipient = authority(21);
    let id = prove(&mut stx, 0, 2 * ONE_XOR, address_bytes(&recipient), FEE);
    assert!(matches!(
        inbound_status(&stx, &id),
        SccpInboundStatusV1::Released(_)
    ));
    assert_eq!(xor_balance(&*stx.world, &recipient), 2 * ONE_XOR - FEE);
    assert_eq!(xor_balance(&*stx.world, &sink), FEE);
    assert_eq!(liability(&stx, ETH, 1), 8 * ONE_XOR);
    assert!(sccp_events(&stx).iter().any(|event| matches!(
        event,
        SccpEvent::InboundReleased(released) if released.fee == FEE
    )));

    // A fee that consumes the whole amount pays only the sink and registers nobody.
    let empty = authority(22);
    let id = prove(&mut stx, 1, FEE, address_bytes(&empty), FEE);
    assert!(matches!(
        inbound_status(&stx, &id),
        SccpInboundStatusV1::Released(_)
    ));
    assert!(stx.world.account(&empty).is_err());
    assert_eq!(xor_balance(&*stx.world, &sink), 2 * FEE);

    // The sink claiming its own message receives one combined credit.
    let id = prove(&mut stx, 2, ONE_XOR, address_bytes(&sink), FEE);
    assert!(matches!(
        inbound_status(&stx, &id),
        SccpInboundStatusV1::Released(_)
    ));
    assert_eq!(xor_balance(&*stx.world, &sink), 2 * FEE + ONE_XOR);
    assert_escrow_invariant(&*stx.world, "after fees");
    assert_pending_counts(&stx, "after fees");
}

#[test]
fn every_hold_reason_keeps_the_proof_and_is_retried_by_settle() {
    let state = state();
    let mut block = state.block(header(5));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"hold-reasons"));
    install(&mut stx);
    fund(&mut stx, ETH, 1, 10 * ONE_XOR);
    let recipient = authority(23);
    let settle = |stx: &mut StateTransaction<'_, '_>, id: [u8; 32]| {
        let result = execute_settle(SettleSccpV1::inbound(id), &holder(), stx);
        assert_escrow_invariant(&*stx.world, "settle");
        assert_pending_counts(stx, "settle");
        result
    };

    // Disabled: the proof is recorded and a retry that changes nothing fails.
    set_enabled(&mut stx, false);
    let id = prove(&mut stx, 0, ONE_XOR, address_bytes(&recipient), 0);
    assert_eq!(
        inbound_status(&stx, &id),
        pending(SccpPendingReasonV1::Disabled)
    );
    settle(&mut stx, id).expect_err("unchanged");
    set_enabled(&mut stx, true);

    // Revision not settleable (paused).
    set_activation(&mut stx, ETH, 1, SccpRouteActivationV1::Paused);
    settle(&mut stx, id).expect("the reason changed");
    assert_eq!(
        inbound_status(&stx, &id),
        pending(SccpPendingReasonV1::RevisionNotSettleable)
    );
    settle(&mut stx, id).expect_err("unchanged");
    set_activation(&mut stx, ETH, 1, SccpRouteActivationV1::Bidirectional);
    settle(&mut stx, id).expect("released");
    assert!(matches!(
        inbound_status(&stx, &id),
        SccpInboundStatusV1::Released(_)
    ));

    // Liability shortfall.
    let id = prove(&mut stx, 1, 20 * ONE_XOR, address_bytes(&recipient), 0);
    assert_eq!(
        inbound_status(&stx, &id),
        pending(SccpPendingReasonV1::LiabilityShortfall)
    );
    assert!(sccp_events(&stx).iter().any(|event| matches!(
        event,
        SccpEvent::InboundLiabilityShortfall(shortfall)
            if shortfall.message_id == id && shortfall.liability == 9 * ONE_XOR
    )));
    settle(&mut stx, id).expect_err("unchanged");
    fund(&mut stx, ETH, 1, 11 * ONE_XOR);
    settle(&mut stx, id).expect("released");
    assert_eq!(xor_balance(&*stx.world, &recipient), 21 * ONE_XOR);

    // Credit refused by the recipient's holding limit.
    fund(&mut stx, ETH, 1, 10 * ONE_XOR);
    let refusing = refusing_account(&mut stx, 24);
    let id = prove(&mut stx, 2, ONE_XOR, address_bytes(&refusing), 0);
    assert_eq!(
        inbound_status(&stx, &id),
        pending(SccpPendingReasonV1::CreditRefused)
    );
    settle(&mut stx, id).expect_err("unchanged");
    set_holding_limit(&mut stx, &refusing, None);
    settle(&mut stx, id).expect("released");
    assert_eq!(xor_balance(&*stx.world, &refusing), ONE_XOR);

    // Fee sink unavailable: unregistered, unresolvable, then refusing the fee. The absent
    // recipient is registered before the sink's credit is refused, which alone is a change.
    let unknown_sink = authority(26);
    set_fee_sink(&mut stx, Some(&unknown_sink));
    let fresh = authority(25);
    let id = prove(&mut stx, 3, ONE_XOR, address_bytes(&fresh), FEE);
    assert_eq!(
        inbound_status(&stx, &id),
        pending(SccpPendingReasonV1::FeeSinkUnavailable),
        "an unregistered sink"
    );
    set_fee_sink(&mut stx, None);
    settle(&mut stx, id).expect_err("an unresolvable sink is the same hold");
    let sink = refusing_account(&mut stx, 26);
    set_fee_sink(&mut stx, Some(&sink));
    settle(&mut stx, id).expect("the recipient is registered now");
    assert!(stx.world.account(&fresh).is_ok());
    assert_eq!(
        inbound_status(&stx, &id),
        pending(SccpPendingReasonV1::FeeSinkUnavailable),
        "a sink whose credit is refused"
    );
    settle(&mut stx, id).expect_err("unchanged");
    set_holding_limit(&mut stx, &sink, None);
    settle(&mut stx, id).expect("released");
    assert_eq!(xor_balance(&*stx.world, &fresh), ONE_XOR - FEE);
    assert_eq!(xor_balance(&*stx.world, &sink), FEE);

    // A bounce without a free commitment leaf in the block.
    let escrow = escrow_of(&stx, ETH);
    for _ in 0..leaves::MAX_LEAVES_PER_BLOCK {
        leaves::allocate_leaf(&mut stx, SccpLeafRefV1::transfer([0xee; 32])).expect("leaf");
    }
    let id = prove(&mut stx, 4, ONE_XOR, address_bytes(&escrow), 0);
    assert_eq!(
        inbound_status(&stx, &id),
        pending(SccpPendingReasonV1::BlockLeavesFull)
    );
    settle(&mut stx, id).expect_err("unchanged");
    // A later block has free leaves again.
    for index in 0..leaves::MAX_LEAVES_PER_BLOCK {
        store::block_leaves::remove(&mut stx, (5, index));
    }
    settle(&mut stx, id).expect("bounced");
    assert!(matches!(
        inbound_status(&stx, &id),
        SccpInboundStatusV1::Bounced(_)
    ));
}

#[test]
fn recipients_that_can_never_be_credited_bounce() {
    let state = state();
    let mut block = state.block(header(5));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"bounces"));
    install(&mut stx);
    fund(&mut stx, ETH, 1, 10 * ONE_XOR);
    let escrow = escrow_of(&stx, ETH);
    let retired = retired_account(&mut stx, 27);
    let secp = AccountId::new(
        KeyPair::try_from_seed(vec![9; 32], Algorithm::Secp256k1)
            .expect("seed")
            .public_key()
            .clone(),
    );
    let mut crypto = (*stx.crypto).clone();
    crypto.allowed_signing = vec![Algorithm::Ed25519];
    stx.crypto = Arc::new(crypto);

    let cases = [
        (address_bytes(&escrow), SccpBounceReasonV1::EscrowRecipient),
        (
            vec![0xff, 1, 2, 3],
            SccpBounceReasonV1::UndecodableRecipient,
        ),
        (
            address_bytes(&retired),
            SccpBounceReasonV1::UnregistrableRecipient,
        ),
        (
            address_bytes(&secp),
            SccpBounceReasonV1::InadmissibleController,
        ),
    ];
    for (nonce, (recipient, reason)) in (0_u64..).zip(cases) {
        let next_nonce = store::routes::get(&*stx.world, &ETH)
            .and_then(|route| route.revisions.get(&1))
            .expect("revision")
            .next_outbound_nonce;
        let id = prove(&mut stx, nonce, ONE_XOR, recipient, FEE);
        let SccpInboundStatusV1::Bounced(bounce) = inbound_status(&stx, &id) else {
            panic!("{reason:?} must bounce");
        };
        let bounced = store::outbound_messages::get(&*stx.world, &bounce.bounce_message_id)
            .expect("bounce record")
            .clone();
        assert_eq!(bounced.sender, escrow);
        assert_eq!(bounced.amount, ONE_XOR, "a bounce returns the whole amount");
        assert_eq!(bounced.nonce, next_nonce);
        assert!(sccp_events(&stx).iter().any(|event| matches!(
            event,
            SccpEvent::InboundBounced(event) if event.message_id == id && event.reason == reason
        )));
    }
    assert!(stx.world.account(&retired).is_err(), "never registered");
    assert_eq!(
        liability(&stx, ETH, 1),
        10 * ONE_XOR,
        "a bounce moves the liability to its outbound message"
    );
    assert_escrow_invariant(&*stx.world, "after bounces");
    assert_pending_counts(&stx, "after bounces");
}

#[test]
fn a_bounce_uses_the_bidirectional_revision_only_while_its_cap_has_room() {
    let state = state();
    let mut block = state.block(header(5));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"bounce-cap"));
    install_value_route(
        &mut stx,
        ETH,
        1,
        SccpRouteActivationV1::InboundOnly,
        1_000 * ONE_XOR,
    );
    install_value_route(
        &mut stx,
        ETH,
        2,
        SccpRouteActivationV1::Bidirectional,
        10 * ONE_XOR,
    );
    fund(&mut stx, ETH, 1, 5 * ONE_XOR);
    fund(&mut stx, ETH, 2, 9 * ONE_XOR);
    let escrow = escrow_of(&stx, ETH);

    let target = |stx: &StateTransaction<'_, '_>, id: &[u8; 32]| {
        let SccpInboundStatusV1::Bounced(bounce) = inbound_status(stx, id) else {
            panic!("bounced");
        };
        store::outbound_messages::get(&*stx.world, &bounce.bounce_message_id)
            .expect("bounce")
            .revision
    };
    // 9 + 3 exceeds the cap of revision 2: the bounce stays on revision 1.
    let id = prove_on(
        &mut stx,
        (ETH, 1),
        0,
        3 * ONE_XOR,
        address_bytes(&escrow),
        0,
    );
    assert_eq!(target(&stx, &id), 1);
    assert_eq!(liability(&stx, ETH, 1), 5 * ONE_XOR);
    assert_eq!(liability(&stx, ETH, 2), 9 * ONE_XOR);
    // 9 + 1 fills the cap of revision 2 exactly.
    let id = prove_on(&mut stx, (ETH, 1), 1, ONE_XOR, address_bytes(&escrow), 0);
    assert_eq!(target(&stx, &id), 2);
    assert_eq!(liability(&stx, ETH, 1), 4 * ONE_XOR);
    assert_eq!(liability(&stx, ETH, 2), 10 * ONE_XOR);
    assert_escrow_invariant(&*stx.world, "full cap");
    assert_pending_counts(&stx, "full cap");
}

#[test]
fn refunds_credit_the_sender_or_strand_and_never_abort() {
    let state = state();
    let mut block = state.block(header(5));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"refunds"));
    install(&mut stx);
    let escrow = escrow_of(&stx, ETH);
    let refusing = refusing_account(&mut stx, 31);
    let retired = retired_account(&mut stx, 32);
    let absent = authority(33);

    let by_holder = record_outbound(&mut stx, ETH, 2, &holder()).expect("record");
    assert_escrow_invariant(&*stx.world, "record");
    let by_escrow = seed_outbound(&mut stx, ETH, 1, &escrow, ONE_XOR);
    let by_retired = seed_outbound(&mut stx, ETH, 2, &retired, ONE_XOR);
    let by_refusing = seed_outbound(&mut stx, ETH, 3, &refusing, ONE_XOR);
    let by_absent = seed_outbound(&mut stx, ETH, 4, &absent, ONE_XOR);
    let holder_before = xor_balance(&*stx.world, &holder());

    void_expired(&mut stx, ETH, 0).expect("void");
    assert!(matches!(
        outbound_status(&stx, &by_holder),
        SccpOutboundStatusV1::Refunded(_)
    ));
    assert_eq!(
        xor_balance(&*stx.world, &holder()),
        holder_before + 2 * ONE_XOR
    );
    void_expired(&mut stx, ETH, 0).expect_err("a replayed void changes nothing");

    void_expired(&mut stx, ETH, 1).expect("void");
    assert!(matches!(
        outbound_status(&stx, &by_escrow),
        SccpOutboundStatusV1::Stranded(_)
    ));
    void_expired(&mut stx, ETH, 2).expect("void");
    assert!(matches!(
        outbound_status(&stx, &by_retired),
        SccpOutboundStatusV1::Stranded(_)
    ));
    assert_eq!(stranded(&stx, ETH), 2 * ONE_XOR);
    void_expired(&mut stx, ETH, 3).expect("void");
    assert_eq!(
        outbound_status(&stx, &by_refusing),
        SccpOutboundStatusV1::Voided(SccpVoidStatusV1 {
            kind: SccpVoidKindV1::Expired,
            proven_at_height: 5,
            refund_pending: true,
        })
    );
    void_expired(&mut stx, ETH, 4).expect("void");
    assert!(matches!(
        outbound_status(&stx, &by_absent),
        SccpOutboundStatusV1::Refunded(_)
    ));
    assert_eq!(
        xor_balance(&*stx.world, &absent),
        ONE_XOR,
        "registered and refunded"
    );
    assert_eq!(
        voided_events(&stx),
        vec![(0, false), (1, false), (2, false), (3, true), (4, false)],
        "OutboundVoided reports whether the refund still waits"
    );
    assert_escrow_invariant(&*stx.world, "after voids");
    assert_pending_counts(&stx, "after voids");

    // The held refund retries through SettleSccpV1::Refund.
    let retry = || SettleSccpV1::refund(ETH, 1, 3);
    execute_settle(retry(), &holder(), &mut stx).expect_err("still refused");
    set_enabled(&mut stx, false);
    set_holding_limit(&mut stx, &refusing, None);
    execute_settle(retry(), &holder(), &mut stx).expect_err("SCCP is disabled");
    set_enabled(&mut stx, true);
    set_activation(&mut stx, ETH, 1, SccpRouteActivationV1::Paused);
    execute_settle(retry(), &holder(), &mut stx).expect_err("the revision is paused");
    set_activation(&mut stx, ETH, 1, SccpRouteActivationV1::Bidirectional);
    execute_settle(retry(), &holder(), &mut stx).expect("refunded");
    assert!(matches!(
        outbound_status(&stx, &by_refusing),
        SccpOutboundStatusV1::Refunded(_)
    ));
    assert_eq!(xor_balance(&*stx.world, &refusing), ONE_XOR);
    execute_settle(retry(), &holder(), &mut stx).expect_err("nothing pending");
    assert_eq!(liability(&stx, ETH, 1), 0);
    assert_escrow_invariant(&*stx.world, "after retries");
    assert_pending_counts(&stx, "after retries");
}

#[test]
fn release_stranded_pays_out_only_stranded_value() {
    let state = state();
    let mut block = state.block(header(5));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"release-stranded"));
    install(&mut stx);
    let escrow = escrow_of(&stx, TON);
    seed_outbound(&mut stx, TON, 0, &escrow, 3 * ONE_XOR);
    seed_outbound(&mut stx, TON, 1, &holder(), 2 * ONE_XOR);
    void_expired(&mut stx, TON, 0).expect("void");
    assert_eq!(stranded(&stx, TON), 3 * ONE_XOR);
    let network_id = *stx.network_id();
    let release = |amount: u128, recipient: &AccountId| SccpGovernanceProposalV1 {
        network_id,
        base_revisions: Vec::new(),
        actions: vec![SccpGovernanceActionV1::ReleaseStranded(
            SccpReleaseStrandedActionV1 {
                network: TON,
                amount,
                recipient: recipient.clone(),
                memo: "recovered bounce".to_owned(),
            },
        )],
    };
    let recipient = authority(40);
    governance::enact(&mut stx, &release(3 * ONE_XOR + 1, &recipient), [1; 32])
        .expect_err("only 3 XOR is stranded");
    governance::enact(&mut stx, &release(ONE_XOR, &escrow), [2; 32])
        .expect_err("an escrow recipient");
    governance::enact(&mut stx, &release(2 * ONE_XOR, &recipient), [3; 32]).expect("release");
    assert_eq!(xor_balance(&*stx.world, &recipient), 2 * ONE_XOR);
    assert_eq!(stranded(&stx, TON), ONE_XOR);
    assert_eq!(
        liability(&stx, TON, 1),
        2 * ONE_XOR,
        "liability is untouched"
    );
    assert!(sccp_events(&stx).iter().any(|event| matches!(
        event,
        SccpEvent::StrandedReleased(released) if released.amount == 2 * ONE_XOR
    )));
    assert_escrow_invariant(&*stx.world, "after release");
    assert_pending_counts(&stx, "after release");
}

#[test]
fn a_frozen_void_of_a_full_ton_bucket_refunds_strands_and_holds_without_aborting() {
    let state = state();
    let mut block = state.block(header(5));
    let (escrow, refusing, retired, ids) = {
        let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"frozen-ton-setup"));
        install(&mut stx);
        let escrow = escrow_of(&stx, TON);
        let refusing = refusing_account(&mut stx, 41);
        let retired = retired_account(&mut stx, 42);
        let sender = |nonce: u64| match nonce {
            7 => escrow.clone(),
            100 => retired.clone(),
            200 => refusing.clone(),
            300 => authority(43),
            _ => holder(),
        };
        let ids: Vec<[u8; 32]> = (0..512)
            .map(|nonce| seed_unfunded(&mut stx, TON, nonce, &sender(nonce), ONE_XOR))
            .collect();
        fund(&mut stx, TON, 1, 512 * ONE_XOR);
        // Nonce 5 was voided and refunded earlier: the frozen range skips it.
        void_expired(&mut stx, TON, 5).expect("expired void");
        stx.apply();
        (escrow, refusing, retired, ids)
    };
    let holder_before = {
        let stx = block.transaction();
        xor_balance(&*stx.world, &holder())
    };

    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"frozen-ton-void"));
    void_frozen(&mut stx, TON, 0, 513).expect_err("past one TON bucket");
    void_frozen(&mut stx, TON, 0, 512).expect("a full TON bucket in one transaction");
    let budget = crate::smartcontracts::isi::sccp::voids::inline_refund_budget(&stx);
    assert_eq!(budget, 8);
    let route = store::routes::get(&*stx.world, &TON).expect("route");
    let revision = route.revisions.get(&1).expect("revision");
    assert_eq!(revision.activation, SccpRouteActivationV1::InboundOnly);
    assert!(revision.destination_frozen);
    assert_eq!(
        route.stranded,
        2 * ONE_XOR,
        "the escrow and retired senders"
    );
    // Inline: nonces 0–4, 6, 8 and 9 refunded; 7 and 100 stranded; the rest pending.
    let inline = [0_usize, 1, 2, 3, 4, 6, 8, 9];
    for nonce in inline {
        assert!(matches!(
            outbound_status(&stx, &ids[nonce]),
            SccpOutboundStatusV1::Refunded(_)
        ));
    }
    for nonce in [7, 100] {
        assert!(matches!(
            outbound_status(&stx, &ids[nonce]),
            SccpOutboundStatusV1::Stranded(_)
        ));
    }
    assert_eq!(
        xor_balance(&*stx.world, &holder()),
        holder_before + 8 * ONE_XOR
    );
    assert_eq!(store::pending_count(&*stx.world, &(TON, 1)), (0, 501));
    assert_eq!(revision.liability, 501 * ONE_XOR);
    let voided = voided_events(&stx);
    assert_eq!(voided.len(), 511, "every Recorded nonce of the range");
    for (nonce, refund_pending) in &voided {
        let inline = inline.contains(&usize::try_from(*nonce).expect("nonce"));
        let stranded = *nonce == 7 || *nonce == 100;
        assert_eq!(*refund_pending, !inline && !stranded, "nonce {nonce}");
    }
    assert!(stx.world.account(&authority(43)).is_err(), "deferred");
    assert_escrow_invariant(&*stx.world, "after the frozen void");
    assert_pending_counts(&stx, "after the frozen void");
    // A replay of the frozen void changes nothing.
    void_frozen(&mut stx, TON, 0, 512).expect_err("replay");
    stx.apply();

    // The pending refunds drain through SettleSccpV1::Refund, a budget per transaction.
    let pending: Vec<u64> = {
        let stx = block.transaction();
        (0..512_u64)
            .filter(|nonce| {
                *nonce != 200
                    && outbound_status(&stx, &ids[usize::try_from(*nonce).expect("nonce")])
                        .is_refund_pending()
            })
            .collect()
    };
    assert_eq!(pending.len(), 500);
    for (batch, nonces) in pending.chunks(8).enumerate() {
        let mut stx =
            block.transaction_for_fastpq_testing(Hash::new(format!("frozen-ton-drain/{batch}")));
        for nonce in nonces {
            execute_settle(SettleSccpV1::refund(TON, 1, *nonce), &holder(), &mut stx)
                .expect("refund");
        }
        assert_escrow_invariant(&*stx.world, "drain");
        stx.apply();
    }
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"frozen-ton-end"));
    execute_settle(SettleSccpV1::refund(TON, 1, 200), &holder(), &mut stx)
        .expect_err("the refusing sender still refuses");
    assert_eq!(
        xor_balance(&*stx.world, &holder()),
        holder_before + 507 * ONE_XOR
    );
    assert_eq!(xor_balance(&*stx.world, &authority(43)), ONE_XOR);
    assert!(outbound_status(&stx, &ids[200]).is_refund_pending());
    assert_eq!(store::pending_count(&*stx.world, &(TON, 1)), (0, 1));
    assert_eq!(
        liability(&stx, TON, 1),
        ONE_XOR,
        "only the held refund remains"
    );
    set_holding_limit(&mut stx, &refusing, None);
    execute_settle(SettleSccpV1::refund(TON, 1, 200), &holder(), &mut stx).expect("refund");
    assert_eq!(liability(&stx, TON, 1), 0);
    // Inbound proofs still settle on the drained revision.
    fund(&mut stx, TON, 1, ONE_XOR);
    let recipient = authority(44);
    let id = prove_on(&mut stx, (TON, 1), 0, ONE_XOR, address_bytes(&recipient), 0);
    assert!(matches!(
        inbound_status(&stx, &id),
        SccpInboundStatusV1::Released(_)
    ));
    assert_eq!(stranded(&stx, TON), 2 * ONE_XOR);
    assert!(stx.world.account(&retired).is_err());
    assert_ne!(escrow, retired);
    assert_escrow_invariant(&*stx.world, "after the drain");
    assert_pending_counts(&stx, "after the drain");
}

#[test]
fn void_ranges_and_message_ids_are_checked_before_any_effect() {
    let state = state();
    let mut block = state.block(header(5));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"void-ranges"));
    install(&mut stx);
    for nonce in 0..3 {
        seed_outbound(&mut stx, ETH, nonce, &holder(), ONE_XOR);
    }
    void_frozen(&mut stx, ETH, 0, 257).expect_err("past the EVM bound");
    let expired = |count, message_id_or_zero| SccpProvenVoidV1 {
        kind: SccpVoidKindV1::Expired,
        first_nonce: 0,
        count,
        message_id_or_zero,
    };
    apply_void(&mut stx, ETH, 1, expired(2, [0; 32])).expect_err("an expired void is one nonce");
    apply_void(&mut stx, ETH, 1, expired(1, [9; 32])).expect_err("another message id");
    assert_eq!(liability(&stx, ETH, 1), 3 * ONE_XOR, "nothing happened");
    void_frozen(&mut stx, ETH, 0, 256).expect("the EVM bound");
    assert_eq!(liability(&stx, ETH, 1), 0);
    assert_escrow_invariant(&*stx.world, "after the EVM frozen void");
    assert_pending_counts(&stx, "after the EVM frozen void");
}

#[test]
fn a_void_never_releases_a_multisig_sender_inline() {
    use iroha_data_model::account::controller::{MultisigMember, MultisigPolicy};
    let state = state();
    let mut block = state.block(header(5));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"multisig-void"));
    install(&mut stx);
    let members = [0x51_u8, 0x52]
        .into_iter()
        .map(|seed| {
            let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("seed");
            MultisigMember::new(key.public_key().clone(), 1).expect("member")
        })
        .collect();
    let multisig = AccountId::new_multisig(MultisigPolicy::new(1, members).expect("policy"));
    let by_multisig = seed_outbound(&mut stx, ETH, 0, &multisig, ONE_XOR);
    let by_holder = seed_outbound(&mut stx, ETH, 1, &holder(), ONE_XOR);
    void_frozen(&mut stx, ETH, 0, 2).expect("frozen void");
    // The multisig sender's refund waits for SettleSccpV1::Refund and spends no inline budget.
    assert!(outbound_status(&stx, &by_multisig).is_refund_pending());
    assert!(
        stx.world.account(&multisig).is_err(),
        "nothing was registered"
    );
    assert!(matches!(
        outbound_status(&stx, &by_holder),
        SccpOutboundStatusV1::Refunded(_)
    ));
    assert_eq!(voided_events(&stx), vec![(0, true), (1, false)]);
    assert_eq!(liability(&stx, ETH, 1), ONE_XOR);
    assert_escrow_invariant(&*stx.world, "after the multisig void");
    assert_pending_counts(&stx, "after the multisig void");
}

/// Deterministic 64-bit generator (SplitMix64), so every seed replays exactly.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn pick<T: Clone>(&mut self, items: &[T]) -> Option<T> {
        let len = u64::try_from(items.len()).ok().filter(|len| *len > 0)?;
        items.get(usize::try_from(self.below(len)).ok()?).cloned()
    }
}

/// Run one pseudo-random operation of the sequence in `stx`.
fn random_operation(
    stx: &mut StateTransaction<'_, '_>,
    rng: &mut SplitMix64,
    accounts: &RandomAccounts,
    inbound_nonce: &mut u64,
    sink_resolves: &mut bool,
) -> (u64, Result<(), Error>) {
    let network = if rng.below(2) == 0 { ETH } else { TON };
    let operation = rng.below(10);
    let result = match operation {
        0 | 1 => {
            let amount = u32::try_from(rng.below(5) + 1).expect("small");
            record_outbound(stx, network, amount, &holder()).map(|_| ())
        }
        2 | 3 => {
            let fresh = authority(70 + u8::try_from(rng.below(8)).expect("small"));
            let recipients = [
                address_bytes(&fresh),
                address_bytes(&holder()),
                address_bytes(&accounts.refusing),
                address_bytes(&accounts.retired),
                address_bytes(&escrow_of(stx, network)),
                vec![0xff, 1, 2, 3],
            ];
            let recipient = rng.pick(&recipients).expect("recipient");
            let amount = u128::from(rng.below(4) + 1) * ONE_XOR / 2;
            let fee = if rng.below(2) == 0 { 0 } else { FEE };
            *inbound_nonce += 1;
            prove_on(stx, (network, 1), *inbound_nonce, amount, recipient, fee);
            Ok(())
        }
        4 => {
            let recorded: Vec<u64> = store::outbound_messages::iter(&*stx.world)
                .filter(|(_, record)| record.network == network && record.status.is_recorded())
                .map(|(_, record)| record.nonce)
                .collect();
            rng.pick(&recorded).map_or(Ok(()), |nonce| {
                // No refund refusal may abort the void of a `Recorded` nonce.
                let result = void_expired(stx, network, nonce);
                assert!(result.is_ok(), "void of Recorded nonce {nonce}: {result:?}");
                result
            })
        }
        5 => {
            let pending: Vec<[u8; 32]> = store::inbound_messages::iter(&*stx.world)
                .filter(|(_, record)| record.status.is_pending())
                .map(|(id, _)| *id)
                .collect();
            rng.pick(&pending).map_or(Ok(()), |id| {
                execute_settle(SettleSccpV1::inbound(id), &holder(), stx)
            })
        }
        6 => {
            let held: Vec<(SccpNetworkV1, u32, u64)> = store::outbound_messages::iter(&*stx.world)
                .filter(|(_, record)| record.status.is_refund_pending())
                .map(|(_, record)| (record.network, record.revision, record.nonce))
                .collect();
            rng.pick(&held)
                .map_or(Ok(()), |(network, revision, nonce)| {
                    execute_settle(
                        SettleSccpV1::refund(network, revision, nonce),
                        &holder(),
                        stx,
                    )
                })
        }
        7 => {
            match rng.below(4) {
                0 => {
                    let enabled = store::parameters::get(&*stx.world)
                        .as_ref()
                        .is_some_and(|params| params.enabled);
                    set_enabled(stx, !enabled);
                }
                1 => {
                    let limit = (rng.below(2) == 0).then_some(0);
                    set_holding_limit(stx, &accounts.refusing, limit);
                }
                2 => *sink_resolves = !*sink_resolves,
                _ => {
                    let activation = store::routes::get(&*stx.world, &ETH)
                        .and_then(|route| route.revisions.get(&1))
                        .expect("revision")
                        .activation;
                    match activation {
                        SccpRouteActivationV1::Bidirectional => {
                            set_activation(stx, ETH, 1, SccpRouteActivationV1::Paused);
                        }
                        SccpRouteActivationV1::Paused => {
                            set_activation(stx, ETH, 1, SccpRouteActivationV1::Bidirectional);
                        }
                        _ => {}
                    }
                }
            }
            Ok(())
        }
        8 => {
            fund(stx, network, 1, u128::from(rng.below(3) + 1) * ONE_XOR);
            Ok(())
        }
        _ => {
            if rng.below(4) == 0 {
                let next = store::routes::get(&*stx.world, &network)
                    .and_then(|route| route.revisions.get(&1))
                    .expect("revision")
                    .next_outbound_nonce;
                let first = rng.below(next.max(1));
                let max =
                    iroha_sccp::v1::network::max_void_frozen_range(network).expect("external");
                let count = 1 + rng.below(max);
                // A frozen void fails only as a replay: it names no `Recorded` nonce and the
                // revision is already frozen and drained. No refund refusal aborts it.
                let world = &*stx.world;
                let names_recorded = (first..first + count).any(|nonce| {
                    store::outbound_by_nonce::get(world, &(network, 1, nonce))
                        .and_then(|id| store::outbound_messages::get(world, id))
                        .is_some_and(|record| record.status.is_recorded())
                });
                let replay = store::routes::get(world, &network)
                    .and_then(|route| route.revisions.get(&1))
                    .is_some_and(|revision| {
                        revision.destination_frozen && !revision.activation.is_live()
                    });
                let result = void_frozen(stx, network, first, count);
                assert_eq!(
                    result.is_ok(),
                    names_recorded || !replay,
                    "frozen void of {count} nonces from {first}: {result:?}"
                );
                result
            } else {
                Ok(())
            }
        }
    };
    (operation, result)
}

/// Accounts with a fixed role in the pseudo-random sequence.
struct RandomAccounts {
    sink: AccountId,
    refusing: AccountId,
    retired: AccountId,
}

/// Final statuses a pseudo-random sequence reached, so the sequences are known to exercise
/// every settlement outcome rather than failing their way through.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Outcomes {
    released: usize,
    bounced: usize,
    inbound_held: usize,
    refunded: usize,
    stranded: usize,
    refund_held: usize,
}

impl Outcomes {
    fn of(stx: &StateTransaction<'_, '_>) -> Self {
        let mut outcomes = Self::default();
        for (_, record) in store::inbound_messages::iter(&*stx.world) {
            match record.status {
                SccpInboundStatusV1::Released(_) => outcomes.released += 1,
                SccpInboundStatusV1::Bounced(_) => outcomes.bounced += 1,
                SccpInboundStatusV1::Pending(_) => outcomes.inbound_held += 1,
            }
        }
        for (_, record) in store::outbound_messages::iter(&*stx.world) {
            match record.status {
                SccpOutboundStatusV1::Refunded(_) => outcomes.refunded += 1,
                SccpOutboundStatusV1::Stranded(_) => outcomes.stranded += 1,
                status if status.is_refund_pending() => outcomes.refund_held += 1,
                _ => {}
            }
        }
        outcomes
    }

    fn add(self, other: Self) -> Self {
        Self {
            released: self.released + other.released,
            bounced: self.bounced + other.bounced,
            inbound_held: self.inbound_held + other.inbound_held,
            refunded: self.refunded + other.refunded,
            stranded: self.stranded + other.stranded,
            refund_held: self.refund_held + other.refund_held,
        }
    }
}

/// Run `steps` pseudo-random value operations from `seed`, each in its own transaction that
/// applies only when it succeeds, checking the escrow invariant and the pending counts after
/// every step, and return the final outcomes.
fn run_operation_sequence(seed: u64, steps: u64) -> Outcomes {
    let state = state();
    let mut block = state.block(header(5));
    let accounts = {
        let mut stx = block.transaction_for_fastpq_testing(Hash::new(format!("seq/{seed}")));
        install(&mut stx);
        fund(&mut stx, ETH, 1, 20 * ONE_XOR);
        fund(&mut stx, TON, 1, 20 * ONE_XOR);
        let sink = authority(60);
        recipients::ensure_registered(&mut stx, &sink).expect("sink");
        let accounts = RandomAccounts {
            sink,
            refusing: refusing_account(&mut stx, 61),
            retired: retired_account(&mut stx, 62),
        };
        stx.apply();
        accounts
    };
    let mut rng = SplitMix64(seed);
    let (mut inbound_nonce, mut sink_resolves) = (0_u64, true);
    for step in 0..steps {
        let mut stx = block.transaction_for_fastpq_testing(Hash::new(format!("seq/{seed}/{step}")));
        set_fee_sink(&mut stx, sink_resolves.then_some(&accounts.sink));
        let (operation, result) = random_operation(
            &mut stx,
            &mut rng,
            &accounts,
            &mut inbound_nonce,
            &mut sink_resolves,
        );
        if result.is_ok() {
            let context = format!("seed {seed} step {step} operation {operation}");
            assert_escrow_invariant(&*stx.world, &context);
            assert_pending_counts(&stx, &context);
            stx.apply();
        }
    }
    let stx = block.transaction();
    assert_escrow_invariant(&*stx.world, &format!("seed {seed} end"));
    assert_pending_counts(&stx, &format!("seed {seed} end"));
    Outcomes::of(&stx)
}

#[test]
fn pseudo_random_operation_sequences_keep_the_escrow_invariant() {
    let total = [1, 7, 42, 2026, 0x5cc9]
        .into_iter()
        .map(|seed| run_operation_sequence(seed, 150))
        .fold(Outcomes::default(), Outcomes::add);
    for (name, count) in [
        ("released", total.released),
        ("bounced", total.bounced),
        ("inbound held", total.inbound_held),
        ("refunded", total.refunded),
        ("stranded", total.stranded),
        ("refund held", total.refund_held),
    ] {
        assert!(count > 0, "no sequence reached a {name} message: {total:?}");
    }
}

#[test]
fn release_credits_skip_zero_legs_and_merge_a_self_sink() {
    let (recipient, sink) = (authority(1), authority(2));
    let refused = SccpPendingReasonV1::CreditRefused;
    let unavailable = SccpPendingReasonV1::FeeSinkUnavailable;
    assert_eq!(
        release_credits(&recipient, 5, None, 0),
        vec![(recipient.clone(), 5, refused)]
    );
    assert_eq!(
        release_credits(&recipient, 5, Some(&sink), 2),
        vec![
            (recipient.clone(), 5, refused),
            (sink.clone(), 2, unavailable)
        ]
    );
    assert_eq!(
        release_credits(&recipient, 0, Some(&sink), 2),
        vec![(sink.clone(), 2, unavailable)]
    );
    assert_eq!(
        release_credits(&recipient, 5, Some(&recipient), 2),
        vec![(recipient.clone(), 7, refused)]
    );
    assert!(release_credits(&recipient, 0, None, 0).is_empty());
}

#[test]
fn refund_outcomes_report_changes_and_holds() {
    assert!(!SccpRefundOutcomeV1::Held { changed: false }.changed());
    assert!(SccpRefundOutcomeV1::Held { changed: true }.changed());
    assert!(SccpRefundOutcomeV1::Refunded.changed());
    assert!(SccpRefundOutcomeV1::Stranded.changed());
    assert!(SccpRefundOutcomeV1::Held { changed: true }.is_held());
    assert!(!SccpRefundOutcomeV1::Refunded.is_held());
    assert!(!SccpRefundOutcomeV1::Stranded.is_held());
}
