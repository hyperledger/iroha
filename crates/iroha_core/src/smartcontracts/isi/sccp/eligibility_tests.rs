//! Real-classifier tests of SCCP fee-exemption eligibility for the inbound kinds
//! (`specs/sccp.md` §4.12.4, §4.13.4, §4.19).
//!
//! Every self-claim and keeper-advance shape, from every kind of authority, goes through the
//! one shared predicate against a committed parent World: queue admission
//! ([`admission::classify`]), fee quoting ([`crate::executor::quote_nexus_fee_admission_payload`]),
//! the per-block cap count ([`admission::exempt_class_of_entrypoint`]) and execution
//! ([`fees::exempt_class_in_block`]). No test override stands in for a classifier. The
//! self-claim fee is charged only to exempt self-claims. A keeper advance is eligible from any
//! authority, registered or not, and only such an advance admits an absent authority.

use super::{
    admission::{self, SccpExemptClassV1},
    escrow, fees,
    inbound::{SccpProvenInboundV1, record_proven},
    settle::{self, execute_settle},
    store,
    test_support::{
        ONE_XOR, assert_escrow_invariant, funded_xor_state, header, install_value_route,
        xor_balance,
    },
};
use crate::state::{State, StateReadOnly, StateTransaction};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::{Account, AccountAddress, AccountId},
    bridge::SccpNetworkV1,
    isi::{
        InstructionBox, Register,
        sccp::{AdvanceSccpLightClientV1, SettleSccpV1, SubmitSccpInboundMessageV1},
    },
    sccp::{
        inbound::{SccpInboundStatusV1, SccpSourceLocatorV1, SccpSourceProofBytesV1},
        params::SccpParametersV1,
        registry::SccpRouteActivationV1,
    },
    transaction::{FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionEntrypoint},
};
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
use iroha_sccp::{
    light_client::{
        bsc::BscLcAdvanceV1,
        ethereum::{EthereumHeaderSegmentV1, EthereumLcAdvanceV1},
        proof::{SccpLcAdvanceV1, SccpLcSegmentV1},
    },
    v1::payload::SccpTransferPayloadV1,
};

const ETH: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
const BSC: SccpNetworkV1 = SccpNetworkV1::BscMainnet;
const TON: SccpNetworkV1 = SccpNetworkV1::TonMainnet;
/// `inbound_self_claim_fee` of the Taira default parameters.
const FEE: u128 = SccpParametersV1::taira_default().inbound_self_claim_fee;
/// The XOR holder of [`funded_xor_state`], here a funded relayer.
const RELAYER: u8 = 1;
const RECIPIENT: u8 = 0x21;
const STRANGER: u8 = 0x22;
/// A node's keeper key: an Ed25519 key whose account is never registered or funded.
const KEEPER: u8 = 0x31;

fn ed25519(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("deterministic seed")
}

fn account(seed: u8) -> AccountId {
    AccountId::new(ed25519(seed).public_key().clone())
}

fn address_bytes(account: &AccountId) -> Vec<u8> {
    AccountAddress::from_account_id(account)
        .and_then(|address| address.canonical_bytes())
        .expect("address")
}

/// A valid source-chain account of `network` (§3.1).
fn source_account(network: SccpNetworkV1) -> Vec<u8> {
    if network == TON {
        let mut bytes = vec![0; 4];
        bytes.extend_from_slice(&[0x44; 32]);
        bytes
    } else {
        vec![0x44; 20]
    }
}

fn payload(network: SccpNetworkV1, nonce: u64, amount: u128, recipient: Vec<u8>) -> Vec<u8> {
    SccpTransferPayloadV1::inbound(
        network,
        nonce,
        1,
        amount,
        source_account(network),
        recipient,
    )
    .and_then(|payload| payload.encode())
    .expect("payload")
}

/// Record a proven burn of `amount` to `recipient` on revision 1 of `network` and return its
/// message id.
fn prove(
    stx: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    nonce: u64,
    amount: u128,
    recipient: &AccountId,
) -> [u8; 32] {
    let bytes = payload(network, nonce, amount, address_bytes(recipient));
    let message_id = SccpTransferPayloadV1::decode(&bytes)
        .and_then(|payload| payload.message_id(stx.network_id().as_bytes()))
        .expect("message id");
    record_proven(
        stx,
        SccpProvenInboundV1 {
            network,
            revision: 1,
            payload: bytes,
            amount,
            message_id,
            source_locator: SccpSourceLocatorV1 {
                source_height: nonce + 100,
                block_hash: [7; 32],
                index_in_block: 0,
            },
            fee_due: 0,
        },
    )
    .expect("recorded");
    message_id
}

fn set_enabled(stx: &mut StateTransaction<'_, '_>, enabled: bool) {
    let mut params = store::parameters::get(&*stx.world).clone().expect("SCCP");
    params.enabled = enabled;
    store::parameters::set(stx, Some(params));
}

/// The committed parent World every case is judged against.
struct Parent {
    state: State,
    /// `Pending{Disabled}` ETH message of 10 XOR to the recipient; SCCP is enabled again and
    /// the revision's liability covers it, so a settle progresses.
    settleable: [u8; 32],
    /// `Pending` ETH message to the recipient whose amount equals the self-claim fee.
    at_fee: [u8; 32],
    /// TON message to the recipient held by a liability shortfall.
    shortfall: [u8; 32],
}

fn parent() -> Parent {
    let state = funded_xor_state(&account(RELAYER), 1_000 * ONE_XOR);
    let recipient = account(RECIPIENT);
    let (settleable, at_fee, shortfall);
    {
        // The genesis boundary derives the AXT incarnation of the XOR definition, so this
        // fixture block may commit its world overlay.
        let mut block = state.block(header(1));
        {
            let mut stx = block.transaction();
            // Fee quoting needs the explicit immutable root scope of the network.
            stx.world
                .parameters
                .get_mut()
                .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
                    iroha_data_model::block::consensus::SumeragiRootScope::Global,
                ))
                .expect("fixture global root scope");
            install_value_route(
                &mut stx,
                ETH,
                1,
                SccpRouteActivationV1::Bidirectional,
                1_000 * ONE_XOR,
            );
            install_value_route(
                &mut stx,
                TON,
                1,
                SccpRouteActivationV1::Bidirectional,
                1_000 * ONE_XOR,
            );
            // Liability only: these records are classified, never released.
            settle::adjust_liability(
                &mut stx,
                ETH,
                1,
                i128::try_from(100 * ONE_XOR).expect("amount"),
            )
            .expect("liability");
            set_enabled(&mut stx, false);
            settleable = prove(&mut stx, ETH, 0, 10 * ONE_XOR, &recipient);
            at_fee = prove(&mut stx, ETH, 1, FEE, &recipient);
            set_enabled(&mut stx, true);
            shortfall = prove(&mut stx, TON, 0, 10 * ONE_XOR, &recipient);
            stx.apply();
        }
        block
            .commit_world_overlay_for_testing()
            .expect("commit the parent World");
    }
    Parent {
        state,
        settleable,
        at_fee,
        shortfall,
    }
}

fn signed(signer: &KeyPair, instructions: Vec<InstructionBox>) -> SignedTransaction {
    TransactionBuilder::new(
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
            b"eligibility",
        ))),
        AccountId::new(signer.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(instructions)
    .sign(signer.private_key())
}

fn submit(network: SccpNetworkV1, amount: u128, recipient: Vec<u8>) -> InstructionBox {
    SubmitSccpInboundMessageV1 {
        network,
        revision: 1,
        payload: payload(network, 7, amount, recipient),
        proof: SccpSourceProofBytesV1::new(vec![0x4e, 0x52, 0x54, 0x30, 0x01])
            .expect("bounded proof"),
    }
    .into()
}

/// A decodable advance of `network` (ETH or BSC) that proves nothing, or an ETH `Backfill`.
fn advance_of(network: SccpNetworkV1, backfill: bool) -> InstructionBox {
    let advance = if backfill {
        SccpLcAdvanceV1::Backfill {
            segment: SccpLcSegmentV1::Ethereum(EthereumHeaderSegmentV1 {
                headers: Vec::new(),
            }),
        }
    } else if network == BSC {
        SccpLcAdvanceV1::Bsc(BscLcAdvanceV1 { steps: Vec::new() })
    } else {
        SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
            updates: Vec::new(),
        })
    };
    AdvanceSccpLightClientV1 {
        network,
        expected_state_hash: None,
        advance: advance.to_bytes().expect("bounded advance"),
    }
    .into()
}

fn advance(backfill: bool) -> InstructionBox {
    advance_of(ETH, backfill)
}

fn self_registration(account: &AccountId) -> InstructionBox {
    Register::account(Account::new(account.clone())).into()
}

/// What admission, quoting, the cap and execution must agree on for one case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    /// Not eligible: admitted by SCCP as an ordinary transaction, quoted the ordinary fee, not
    /// counted, not exempt.
    Ordinary,
    /// Eligible and valid: admitted with keys of the class, quoted zero, counted, exempt.
    Admitted(SccpExemptClassV1),
    /// Eligible but invalid: rejected at admission; quoted zero, counted and exempt on success
    /// if a proposer includes it anyway (it then fails and is charged).
    Rejected(SccpExemptClassV1),
}

impl Expected {
    const fn class(self) -> Option<SccpExemptClassV1> {
        match self {
            Self::Ordinary => None,
            Self::Admitted(class) | Self::Rejected(class) => Some(class),
        }
    }
}

fn nexus() -> iroha_config::parameters::actual::Nexus {
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.settlement_mode = iroha_config::parameters::actual::NexusFeeSettlementMode::Direct;
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus
}

#[test]
#[allow(clippy::too_many_lines)]
fn every_inbound_shape_and_authority_is_classified_quoted_counted_and_executed_alike() {
    let parent = parent();
    let recipient = account(RECIPIENT);
    let to_recipient = address_bytes(&recipient);
    let keeper = ed25519(KEEPER);
    let self_claim = SccpExemptClassV1::SelfClaim;
    let keeper_advance = SccpExemptClassV1::KeeperAdvance { network: ETH };
    let ten = 10 * ONE_XOR;
    let cases: Vec<(&str, KeyPair, Vec<InstructionBox>, Expected)> = vec![
        (
            "recipient proof (the proof itself does not verify)",
            ed25519(RECIPIENT),
            vec![submit(ETH, ten, to_recipient.clone())],
            Expected::Rejected(self_claim),
        ),
        (
            "recipient proof with self-registration",
            ed25519(RECIPIENT),
            vec![
                self_registration(&recipient),
                submit(ETH, ten, to_recipient.clone()),
            ],
            Expected::Rejected(self_claim),
        ),
        (
            "relayer proof",
            ed25519(RELAYER),
            vec![submit(ETH, ten, to_recipient.clone())],
            Expected::Ordinary,
        ),
        (
            "relayer proof for an undecodable recipient",
            ed25519(RELAYER),
            vec![submit(ETH, ten, vec![0xff, 1, 2, 3])],
            Expected::Ordinary,
        ),
        (
            "recipient proof of an amount at the fee",
            ed25519(RECIPIENT),
            vec![submit(ETH, FEE, to_recipient.clone())],
            Expected::Ordinary,
        ),
        (
            "canonical recipient claim with advances (TODO(ws41))",
            ed25519(RECIPIENT),
            vec![
                self_registration(&recipient),
                advance(false),
                submit(ETH, ten, to_recipient.clone()),
            ],
            Expected::Ordinary,
        ),
        (
            "recipient settle that progresses",
            ed25519(RECIPIENT),
            vec![SettleSccpV1::inbound(parent.settleable).into()],
            Expected::Admitted(self_claim),
        ),
        (
            "third-party settle",
            ed25519(STRANGER),
            vec![SettleSccpV1::inbound(parent.settleable).into()],
            Expected::Ordinary,
        ),
        (
            "recipient settle of an amount at the fee",
            ed25519(RECIPIENT),
            vec![SettleSccpV1::inbound(parent.at_fee).into()],
            Expected::Ordinary,
        ),
        (
            "recipient settle that cannot progress",
            ed25519(RECIPIENT),
            vec![SettleSccpV1::inbound(parent.shortfall).into()],
            Expected::Ordinary,
        ),
        (
            "recipient settle of an unknown message",
            ed25519(RECIPIENT),
            vec![SettleSccpV1::inbound([9; 32]).into()],
            Expected::Ordinary,
        ),
        (
            "refund settle",
            ed25519(RECIPIENT),
            vec![SettleSccpV1::refund(ETH, 1, 0).into()],
            Expected::Ordinary,
        ),
        (
            "advance from an unregistered keeper key (the light client is not installed)",
            keeper.clone(),
            vec![advance(false)],
            Expected::Rejected(keeper_advance),
        ),
        (
            "keeper Backfill",
            keeper.clone(),
            vec![advance(true)],
            Expected::Ordinary,
        ),
        (
            "standalone advance by a registered account (the light client is not installed)",
            ed25519(RELAYER),
            vec![advance_of(BSC, false)],
            Expected::Rejected(SccpExemptClassV1::KeeperAdvance { network: BSC }),
        ),
        (
            "two advances in one transaction",
            keeper,
            vec![advance(false), advance(false)],
            Expected::Ordinary,
        ),
    ];
    let nexus = nexus();
    let pipeline = iroha_config::parameters::actual::Pipeline::default();
    let view = parent.state.view();
    let world = view.world();
    let mut counted = Vec::new();
    let mut expected_counted = Vec::new();
    for (name, signer, instructions, expected) in &cases {
        let transaction = signed(signer, instructions.clone());
        let payload = transaction.payload();
        // Eligibility.
        assert_eq!(
            fees::exempt_class(
                world,
                payload,
                crate::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
                    .expect("original parent time")
            ),
            expected.class(),
            "{name}: eligibility"
        );
        assert_eq!(
            fees::exempt_on_success(
                world,
                payload,
                crate::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
                    .expect("original parent time")
            ),
            expected.class().is_some(),
            "{name}: exemption on success"
        );
        // Queue admission.
        let classified = admission::classify(world, &view, 3, &transaction);
        match expected {
            Expected::Ordinary => {
                assert_eq!(classified, Ok(None), "{name}: admitted as ordinary");
            }
            Expected::Admitted(class) => assert_eq!(
                classified.map(|keys| keys.map(|keys| keys.class)),
                Ok(Some(*class)),
                "{name}: admitted as exempt"
            ),
            Expected::Rejected(_) => {
                assert!(classified.is_err(), "{name}: rejected, got {classified:?}");
            }
        }
        // Fee quoting.
        let quote = crate::executor::quote_nexus_fee_admission_payload(
            world,
            &nexus,
            &pipeline,
            &view.zk().gas,
            payload,
            0,
            crate::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
                .expect("original committed fixture time"),
            3,
            Some(DataSpaceId::UNIVERSAL),
        );
        let quoted_zero = matches!(&quote, Ok(quote) if quote.charges.is_empty());
        assert_eq!(
            quoted_zero,
            expected.class().is_some(),
            "{name}: quote {quote:?}"
        );
        // The per-block cap counts exactly the eligible transactions.
        if let Some(class) = admission::exempt_class_of_entrypoint(
            world,
            &TransactionEntrypoint::External(transaction),
            crate::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
                .expect("original parent time"),
        ) {
            counted.push(class);
        }
        if let Some(class) = expected.class() {
            expected_counted.push(class);
        }
    }
    assert_eq!(counted, expected_counted);
    assert!(admission::block_exempt_cap_ok(world, &counted));
    assert!(
        !admission::block_exempt_cap_ok(world, &[keeper_advance, keeper_advance]),
        "one exempt advance per network per block, whoever signs it"
    );
    drop(view);
    // Execution of the next block judges the same predicate against the same parent World,
    // whatever the block itself writes first.
    let mut block = parent.state.block(header(3));
    let mut stx = block.transaction();
    set_enabled(&mut stx, false);
    for (name, signer, instructions, expected) in cases {
        let transaction = signed(&signer, instructions);
        assert_eq!(
            fees::exempt_class_in_block(&stx, transaction.payload())
                .expect("original parent source"),
            expected.class(),
            "{name}: execution"
        );
    }
}

/// Lock `amount` from the XOR holder into `network`'s escrow as liability of revision 1.
fn fund(stx: &mut StateTransaction<'_, '_>, network: SccpNetworkV1, amount: u128) {
    escrow::lock(stx, network, &account(RELAYER), amount, [0x46; 32]).expect("lock");
    settle::adjust_liability(stx, network, 1, i128::try_from(amount).expect("amount"))
        .expect("liability");
}

fn set_fee_sink(stx: &mut StateTransaction<'_, '_>, sink: &AccountId) {
    stx.nexus.fees.fee_sink_account_id = AccountAddress::from_account_id(sink)
        .and_then(|address| {
            address
                .to_i105_for_discriminant(iroha_data_model::account::address::chain_discriminant())
        })
        .expect("i105 literal");
}

#[test]
fn only_an_exempt_settle_makes_the_self_claim_fee_due() {
    let state = funded_xor_state(&account(RELAYER), 1_000 * ONE_XOR);
    let mut block = state.block(header(4));
    let mut stx = block.transaction_for_fastpq_testing(Hash::new(b"exempt-settle-fee"));
    install_value_route(
        &mut stx,
        ETH,
        1,
        SccpRouteActivationV1::Bidirectional,
        1_000 * ONE_XOR,
    );
    fund(&mut stx, ETH, 100 * ONE_XOR);
    let sink = account(0x30);
    super::recipients::ensure_registered(&mut stx, &sink).expect("sink");
    set_fee_sink(&mut stx, &sink);
    set_enabled(&mut stx, false);
    let paid_recipient = account(0x23);
    let relayed_recipient = account(0x24);
    let exempt_recipient = account(0x25);
    let paid = prove(&mut stx, ETH, 0, 2 * ONE_XOR, &paid_recipient);
    let relayed = prove(&mut stx, ETH, 1, 2 * ONE_XOR, &relayed_recipient);
    let exempt = prove(&mut stx, ETH, 2, 2 * ONE_XOR, &exempt_recipient);
    set_enabled(&mut stx, true);
    let released = |stx: &StateTransaction<'_, '_>, id: &[u8; 32]| {
        matches!(
            store::inbound_messages::get(&*stx.world, id)
                .expect("record")
                .status,
            SccpInboundStatusV1::Released(_)
        )
    };

    // The recipient settling for the ordinary fee is not charged the self-claim fee as well.
    execute_settle(SettleSccpV1::inbound(paid), &paid_recipient, &mut stx).expect("settle");
    assert!(released(&stx, &paid));
    assert_eq!(xor_balance(&*stx.world, &paid_recipient), 2 * ONE_XOR);

    // A third-party settle, even with another authority's exempt marker, adds no fee.
    stx.sccp_exempt_self_claim = Some(exempt_recipient.clone());
    execute_settle(SettleSccpV1::inbound(relayed), &account(STRANGER), &mut stx).expect("settle");
    assert!(released(&stx, &relayed));
    assert_eq!(xor_balance(&*stx.world, &relayed_recipient), 2 * ONE_XOR);
    assert_eq!(xor_balance(&*stx.world, &sink), 0);

    // The exempt self-claim settle owes the fee once, deducted at release.
    execute_settle(SettleSccpV1::inbound(exempt), &exempt_recipient, &mut stx).expect("settle");
    assert!(released(&stx, &exempt));
    assert_eq!(
        store::inbound_messages::get(&*stx.world, &exempt)
            .expect("record")
            .fee_due,
        FEE
    );
    assert_eq!(
        xor_balance(&*stx.world, &exempt_recipient),
        2 * ONE_XOR - FEE
    );
    assert_eq!(xor_balance(&*stx.world, &sink), FEE);
    assert_escrow_invariant(&*stx.world, "settles");
}

#[test]
fn a_relayer_proof_is_charged_once_and_owes_no_self_claim_fee() {
    let parent = parent();
    let transaction = signed(
        &ed25519(RELAYER),
        vec![submit(
            ETH,
            10 * ONE_XOR,
            address_bytes(&account(RECIPIENT)),
        )],
    );
    let view = parent.state.view();
    assert_eq!(
        admission::classify(view.world(), &view, 3, &transaction),
        Ok(None),
        "a relayer proof is admitted as an ordinary transaction"
    );
    let mut nexus = nexus();
    nexus.fees.fee_asset_id =
        iroha_data_model::sccp::escrow::sccp_taira_xor_asset_definition_id().canonical_address();
    let draft = crate::executor::quote_nexus_fee_admission_draft(
        view.world(),
        &nexus,
        &iroha_config::parameters::actual::Pipeline::default(),
        &view.zk().gas,
        transaction.payload(),
        0,
        crate::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
            .expect("original committed fixture time"),
        3,
        Some(DataSpaceId::UNIVERSAL),
    )
    .expect("the funded relayer can pay the ordinary fee");
    assert!(
        !draft.quote.charges.is_empty(),
        "the relayer is quoted the ordinary fee once: {draft:?}"
    );
    assert!(!draft.recommended_intent.charge_limits().is_empty());
    drop(view);
    let mut block = parent.state.block(header(3));
    let stx = block.transaction();
    assert_eq!(
        fees::exempt_class_in_block(&stx, transaction.payload()).expect("original parent source"),
        None,
        "execution charges the ordinary fee and marks no exempt self-claim"
    );
    assert_eq!(stx.sccp_exempt_self_claim, None);
}

#[test]
fn only_an_eligible_advance_admits_an_absent_authority() {
    use crate::state::WorldReadOnly as _;
    let parent = parent();
    let keeper = account(KEEPER);
    assert!(
        parent.state.view().world().account(&keeper).is_err(),
        "the keeper key has no account"
    );
    let admits = |instructions: Vec<InstructionBox>| {
        let transaction = signed(&ed25519(KEEPER), instructions);
        let sccp = admission::allows_unregistered_authority(
            transaction.instructions(),
            transaction.authority(),
        );
        // The SCCP rule is the only one that can admit these shapes.
        assert_eq!(
            crate::tx::allows_unregistered_authority(
                transaction.instructions(),
                transaction.authority()
            ),
            sccp
        );
        sccp
    };
    assert!(admits(vec![advance(false)]));
    assert!(admits(vec![advance_of(BSC, false)]));
    assert!(
        !admits(vec![advance(true)]),
        "a Backfill pays the ordinary fee, so its authority must exist"
    );
    assert!(!admits(vec![advance(false), advance(false)]));
    assert!(!admits(vec![SettleSccpV1::inbound([1; 32]).into()]));
    assert!(!admits(vec![submit(
        ETH,
        10 * ONE_XOR,
        address_bytes(&keeper)
    )]));
    assert!(!admits(vec![SettleSccpV1::refund(ETH, 1, 0).into()]));
}

#[test]
fn self_claim_pause_eligibility_uses_parent_time_not_fee_observation_horizon() {
    use super::test_support::install_consumer_fast_pause;
    let parent = parent();
    let mut block = parent.state.block(header(2));
    let mut stx = block.transaction();
    let now = stx.block_unix_timestamp_ms();
    install_consumer_fast_pause(&mut stx, ETH, true, vec![2], now + 1);
    let transaction = signed(
        &ed25519(RECIPIENT),
        vec![SettleSccpV1::inbound(parent.settleable).into()],
    );
    let payload = transaction.payload();
    let world = &*stx.world;
    let entry = TransactionEntrypoint::External(transaction.clone());
    // Controlled original-time inputs to the pure World classifier. Full native source
    // binding is independently exercised by hold::tests; no proof authority is fabricated.
    for (parent_time, expected) in [
        (Some(now), None),
        (None, None),
        (Some(now + 1), Some(SccpExemptClassV1::SelfClaim)),
    ] {
        assert_eq!(fees::exempt_class(world, payload, parent_time), expected);
        assert_eq!(
            admission::exempt_class_of_entrypoint(world, &entry, parent_time),
            expected
        );
        for fee_observation_ms in [0, now, now + 1, u64::MAX] {
            let quote = crate::executor::quote_nexus_fee_admission_payload(
                world,
                &nexus(),
                &iroha_config::parameters::actual::Pipeline::default(),
                &stx.zk.gas,
                payload,
                fee_observation_ms,
                parent_time,
                3,
                Some(DataSpaceId::UNIVERSAL),
            );
            assert_eq!(
                matches!(quote, Ok(quote) if quote.charges.is_empty()),
                expected.is_some(),
                "fee horizon must not expire a committed pause"
            );
        }
    }
    let proof = signed(
        &ed25519(RECIPIENT),
        vec![submit(
            ETH,
            10 * ONE_XOR,
            address_bytes(&account(RECIPIENT)),
        )],
    );
    assert_eq!(
        fees::exempt_class(world, proof.payload(), Some(now)),
        Some(SccpExemptClassV1::SelfClaim),
        "hold preserves proof admission eligibility; verification is still required"
    );
    let keeper = signed(&ed25519(KEEPER), vec![advance(false)]);
    assert_eq!(
        fees::exempt_class(world, keeper.payload(), Some(now)),
        Some(SccpExemptClassV1::KeeperAdvance { network: ETH })
    );
}

#[test]
fn charged_parent_self_claim_is_not_reclassified_by_expired_executing_world() {
    use super::test_support::install_consumer_fast_pause;
    let parent = parent();
    let execution_time = u64::try_from(header(3).creation_time().as_millis()).unwrap();
    {
        let mut block = parent.state.block(header(2));
        let mut stx = block.transaction();
        install_consumer_fast_pause(&mut stx, ETH, true, vec![2], execution_time);
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("component parent precondition");
    }
    let mut block = parent.state.block(header(3));
    let mut stx = block.transaction();
    stx.nexus.fees = nexus().fees;
    stx.nexus.fees.fee_asset_id =
        iroha_data_model::sccp::escrow::sccp_taira_xor_asset_definition_id().canonical_address();
    let transaction = signed(
        &ed25519(RECIPIENT),
        vec![SettleSccpV1::inbound(parent.settleable).into()],
    );
    assert_eq!(
        fees::exempt_class_in_block(&stx, transaction.payload()).expect("original empty source"),
        None,
        "this independent World fixture has no native committed time and cannot expire its parent's pause"
    );
    assert_eq!(
        fees::exempt_class(
            &*stx.world,
            transaction.payload(),
            Some(stx.block_unix_timestamp_ms())
        ),
        Some(SccpExemptClassV1::SelfClaim),
        "the executing time has reached expiry"
    );
    let before = store::inbound_messages::get(&*stx.world, &parent.settleable)
        .unwrap()
        .clone();
    crate::executor::validate_transaction_fee_admission(&mut stx, &transaction)
        .expect_err("charged parent decision must enforce signed fee limits instead of quoting zero against the executing World");
    assert_eq!(
        store::inbound_messages::get(&*stx.world, &parent.settleable),
        Some(&before)
    );
    assert_eq!(stx.sccp_exempt_self_claim, None);
}

#[test]
fn original_eligibility_preimages_survive_siblings_rollback_and_replacement() {
    use super::eligibility::{BlockParent, Current, TransactionParent};
    use iroha_data_model::sccp::outbound::SccpStatusHeightV1;
    let parent = parent();
    let budget = parent.state.view().execution_budget();
    let transaction = signed(
        &ed25519(RECIPIENT),
        vec![SettleSccpV1::inbound(parent.settleable).into()],
    );
    let expected = Some(SccpExemptClassV1::SelfClaim);
    let check = |source: &dyn super::eligibility::EligibilityRead| {
        assert!(
            source.parameters().unwrap().enabled,
            "eligibility must retain the original pre-block parameters through local and sibling writes"
        );
        assert!(
            source
                .parameters()
                .unwrap()
                .max_exempt_transactions_per_block
                > 0
        );
        assert_eq!(
            source.route(ETH).unwrap().revisions[&1].activation,
            SccpRouteActivationV1::Bidirectional
        );
        assert!(
            source
                .inbound(&parent.settleable)
                .unwrap()
                .status
                .is_pending()
        );
        assert!(source.pause(ETH).is_none());
        assert_eq!(
            fees::exempt_class_from(source, transaction.payload(), None),
            expected
        );
    };
    check(&Current(&parent.state.world_view()));
    let mut block = parent
        .state
        .world
        .try_block(&budget)
        .expect("original World admission");
    for apply in [false, true] {
        let mut tx = block.transaction_without_telemetry(Default::default(), 0);
        let parameters = tx.sccp_parameters.get_mut().as_mut().unwrap();
        parameters.enabled = false;
        parameters.max_exempt_transactions_per_block = 0;
        tx.sccp_routes
            .get_mut(&ETH)
            .unwrap()
            .revisions
            .get_mut(&1)
            .unwrap()
            .activation = SccpRouteActivationV1::Paused;
        tx.sccp_inbound_messages
            .get_mut(&parent.settleable)
            .unwrap()
            .status = SccpInboundStatusV1::Released(SccpStatusHeightV1 { height: 2 });
        let pause = super::pause_record::RetainedSccpFastPause::admit(
            &super::test_support::sample_fast_pause(1),
            &budget,
        )
        .unwrap();
        tx.sccp_fast_pauses.insert(ETH, pause);
        assert_eq!(fees::exempt_class(&*tx, transaction.payload(), None), None);
        check(&TransactionParent(&tx));
        if apply {
            tx.apply();
        } else {
            drop(tx);
        }
        check(&BlockParent(&block));
    }
    assert_eq!(
        fees::exempt_class(&block, transaction.payload(), None),
        None
    );
    block.commit();
    assert_eq!(
        fees::exempt_class(&parent.state.world_view(), transaction.payload(), None),
        None,
        "the still-published successor is held"
    );
    // A replacement's exact baseline is the reverted predecessor, not a fresh view of the
    // held successor above. No native receipt/authority is invented by this World-only test.
    let mut replacement = parent
        .state
        .world
        .try_block_and_revert(&budget)
        .expect("original replacement admission");
    check(&BlockParent(&replacement));
    let mut tx = replacement.transaction_without_telemetry(Default::default(), 0);
    tx.sccp_parameters.get_mut().as_mut().unwrap().enabled = false;
    check(&TransactionParent(&tx));
    drop(tx);
    check(&BlockParent(&replacement));
    drop(replacement);
    assert_eq!(
        fees::exempt_class(&parent.state.world_view(), transaction.payload(), None),
        None,
        "dropping replacement preserves the original committed successor"
    );
}
