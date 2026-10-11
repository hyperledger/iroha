//! Recipient classification and implicit registration (`specs/sccp.md` §4.12.3, §4.16, §4.19).
//! Owner: ws32.
//!
//! A codec-3 recipient decodes as an `AccountAddress`. It can never be credited when it is an
//! SCCP escrow, when its controller uses an algorithm account admission refuses, or when it is
//! absent and `Register<Account>` refuses its identity (`domain::isi::precheck_register_account`,
//! the check `Register<Account>` itself runs first, so the two cannot drift); such inbound
//! messages bounce and such refunds strand. Every other recipient is creditable: an absent one
//! is registered with the effect and fee classification of `Register<Account>`, and settlement
//! then prechecks the release movement itself ([`escrow::precheck_release`]), holding the
//! record when the movement refuses the credit now.

use super::{Error, escrow};
use crate::{
    smartcontracts::{
        Execute,
        isi::domain::isi::{ensure_controller_capabilities, precheck_register_account},
    },
    state::{StateTransaction, WorldReadOnly},
};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountAddress, AccountId},
    bridge::SccpNetworkV1,
    isi::Register,
    sccp::events::{SccpBounceReasonV1, SccpEvent, SccpRecipientRegisteredV1},
};

/// Identity classification of a credit recipient (§4.12.3 steps 2–3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SccpRecipientClassV1 {
    /// Decodes to an account that exists or can be registered. Settlement still prechecks the
    /// release movement once the account exists.
    Creditable {
        /// Recipient account.
        account: AccountId,
        /// Whether the account already exists.
        registered: bool,
    },
    /// Decodes, but the account can never be credited: an inbound message bounces, a refund
    /// strands.
    Uncreditable {
        /// Recipient account.
        account: AccountId,
        /// Why it can never be credited.
        reason: SccpBounceReasonV1,
    },
    /// Does not decode as an `AccountAddress`; the message bounces.
    Undecodable,
}

/// Classify the codec-3 recipient `bytes` of an inbound credit (§4.12.3 steps 2–3).
#[must_use]
pub fn classify_recipient(
    state_transaction: &StateTransaction<'_, '_>,
    bytes: &[u8],
) -> SccpRecipientClassV1 {
    AccountAddress::from_canonical_bytes(bytes)
        .and_then(|address| address.to_account_id())
        .map_or(SccpRecipientClassV1::Undecodable, |account| {
            classify_account(state_transaction, account)
        })
}

/// Classify the identity of `account` as the recipient of an XOR credit (§4.12.3 step 3).
///
/// It can never be credited when it is an SCCP escrow, when its controller uses a signing
/// algorithm or curve that account admission refuses, or when it is absent and
/// `Register<Account>(Account::new(account))` refuses its identity. Refusals that depend on
/// the movement (transfer control, holding limit, custody, usage policy) are not permanent and
/// are left to the release precheck.
#[must_use]
pub fn classify_account(
    state_transaction: &StateTransaction<'_, '_>,
    account: AccountId,
) -> SccpRecipientClassV1 {
    let world = &*state_transaction.world;
    let registered = world.account(&account).is_ok();
    let reason = if escrow::is_escrow(world, &account) {
        Some(SccpBounceReasonV1::EscrowRecipient)
    } else if ensure_controller_capabilities(
        account.controller(),
        &state_transaction.crypto.allowed_signing,
        &state_transaction.crypto.allowed_curve_ids,
    )
    .is_err()
    {
        Some(SccpBounceReasonV1::InadmissibleController)
    } else if !registered
        && precheck_register_account(
            state_transaction,
            &Account::new(account.clone()).build(&account),
        )
        .is_err()
    {
        Some(SccpBounceReasonV1::UnregistrableRecipient)
    } else {
        None
    };
    match reason {
        Some(reason) => SccpRecipientClassV1::Uncreditable { account, reason },
        None => SccpRecipientClassV1::Creditable {
            account,
            registered,
        },
    }
}

/// Register `account` if it does not exist, returning whether it was registered now.
///
/// The registration executes `Register<Account>(Account::new(account))` as the account itself,
/// so it has exactly the effects, controller checks and events of an ordinary registration
/// (§4.12.3, §4.19); core applies it without an executor permission check because the SCCP
/// rule, not a user, authorizes it.
///
/// # Errors
///
/// Propagates the rejection of the `Register<Account>` execution (for example a controller
/// algorithm that account admission refuses).
pub fn ensure_registered(
    state_transaction: &mut StateTransaction<'_, '_>,
    account: &AccountId,
) -> Result<bool, Error> {
    if state_transaction.world.account(account).is_ok() {
        return Ok(false);
    }
    Register::account(Account::new(account.clone())).execute(account, state_transaction)?;
    Ok(true)
}

/// Register the absent recipient `account` of a credit on `network`'s route and emit
/// `SccpRecipientRegistered` (§4.12.3 step 5, §4.16); return whether it was registered now.
///
/// `message_id` names the inbound or outbound message being settled, `None` for a stranded
/// release.
///
/// # Errors
///
/// Propagates the rejection of the `Register<Account>` execution.
pub fn register_recipient(
    state_transaction: &mut StateTransaction<'_, '_>,
    account: &AccountId,
    network: SccpNetworkV1,
    message_id: Option<[u8; 32]>,
) -> Result<bool, Error> {
    let registered = ensure_registered(state_transaction, account)?;
    if registered {
        state_transaction
            .world
            .emit_events(Some(SccpEvent::RecipientRegistered(
                SccpRecipientRegisteredV1 {
                    account: account.clone(),
                    network,
                    message_id,
                },
            )));
    }
    Ok(registered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{authority, blank_state, header};

    #[test]
    fn registration_is_idempotent() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        assert_eq!(ensure_registered(&mut stx, &authority(1)), Ok(true));
        assert!(stx.world.account(&authority(1)).is_ok());
        assert_eq!(ensure_registered(&mut stx, &authority(1)), Ok(false));
        let network = SccpNetworkV1::TonMainnet;
        assert_eq!(
            register_recipient(&mut stx, &authority(2), network, Some([1; 32])),
            Ok(true)
        );
        assert_eq!(
            register_recipient(&mut stx, &authority(2), network, Some([1; 32])),
            Ok(false)
        );
        assert!(stx.world.account(&authority(2)).is_ok());
    }

    fn address_bytes(account: &AccountId) -> Vec<u8> {
        AccountAddress::from_account_id(account)
            .and_then(|address| address.canonical_bytes())
            .expect("address")
    }

    #[test]
    fn recipients_are_decoded_and_classified() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        assert_eq!(
            classify_recipient(&stx, &[]),
            SccpRecipientClassV1::Undecodable
        );
        assert_eq!(
            classify_recipient(&stx, &[0xff, 1, 2, 3]),
            SccpRecipientClassV1::Undecodable
        );
        let fresh = authority(1);
        assert_eq!(
            classify_recipient(&stx, &address_bytes(&fresh)),
            SccpRecipientClassV1::Creditable {
                account: fresh.clone(),
                registered: false
            }
        );
        escrow::create_route_escrows(&mut stx).expect("escrows");
        let escrow = escrow::escrow_account(
            &stx.network_id,
            iroha_data_model::bridge::SccpNetworkV1::EthereumMainnet,
        )
        .expect("route");
        assert_eq!(
            classify_recipient(&stx, &address_bytes(&escrow)),
            SccpRecipientClassV1::Uncreditable {
                account: escrow,
                reason: SccpBounceReasonV1::EscrowRecipient
            }
        );
        ensure_registered(&mut stx, &fresh).expect("register");
        assert_eq!(
            classify_account(&stx, fresh.clone()),
            SccpRecipientClassV1::Creditable {
                account: fresh,
                registered: true
            }
        );
    }

    /// Mark `account` as a retired retail rekey identity.
    fn retire(stx: &mut StateTransaction<'_, '_>, account: &AccountId) {
        let path = format!(
            "retail_fee_control_v1/retired/{}",
            hex::encode(iroha_crypto::Hash::new(account.to_string().as_bytes()).as_ref())
        )
        .parse()
        .expect("state path");
        stx.world
            .smart_contract_state
            .insert(path, norito::to_bytes(&authority(1)).expect("bytes"));
    }

    #[test]
    fn identities_register_account_refuses_are_unregistrable() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let retired = authority(3);
        retire(&mut stx, &retired);
        let built = Account::new(retired.clone()).build(&retired);
        let precheck = precheck_register_account(&stx, &built).expect_err("retired identity");
        let registration = Register::account(Account::new(retired.clone()))
            .execute(&retired, &mut stx)
            .expect_err("Register<Account> runs the same precheck");
        assert_eq!(precheck.to_string(), registration.to_string());
        assert_eq!(
            classify_account(&stx, retired.clone()),
            SccpRecipientClassV1::Uncreditable {
                account: retired,
                reason: SccpBounceReasonV1::UnregistrableRecipient
            }
        );

        let fresh = authority(4);
        precheck_register_account(&stx, &Account::new(fresh.clone()).build(&fresh))
            .expect("a fresh identity registers");
        ensure_registered(&mut stx, &fresh).expect("register");
        precheck_register_account(&stx, &Account::new(fresh.clone()).build(&fresh))
            .expect_err("an existing account is a repetition");
    }

    #[test]
    fn inadmissible_controllers_can_never_be_credited() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let secp = AccountId::new(
            iroha_crypto::KeyPair::try_from_seed(vec![9; 32], iroha_crypto::Algorithm::Secp256k1)
                .expect("seed")
                .public_key()
                .clone(),
        );
        assert!(matches!(
            classify_account(&stx, secp.clone()),
            SccpRecipientClassV1::Creditable { .. }
        ));
        let mut crypto = (*stx.crypto).clone();
        crypto.allowed_signing = vec![iroha_crypto::Algorithm::Ed25519];
        stx.crypto = std::sync::Arc::new(crypto);
        assert_eq!(
            classify_account(&stx, secp.clone()),
            SccpRecipientClassV1::Uncreditable {
                account: secp,
                reason: SccpBounceReasonV1::InadmissibleController
            }
        );
    }
}
