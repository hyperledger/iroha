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
use crate::execution_attempt::{ExecutionAttemptError, canonical_decode_attempt_error};
use crate::{
    smartcontracts::{
        Execute,
        isi::domain::isi::{ensure_controller_policy, precheck_register_account},
    },
    state::{StateTransaction, WorldReadOnly},
};
use iroha_data_model::{
    Registrable,
    account::{Account, AccountAddress, AccountAddressError, AccountId},
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
///
/// # Errors
/// Returns a missing original policy owner as a State prerequisite failure, or journals
/// the original local decoder/backend refusal without authorizing a permanent bounce.
#[must_use]
pub fn classify_recipient(
    state_transaction: &StateTransaction<'_, '_>,
    bytes: &[u8],
) -> Result<SccpRecipientClassV1, Error> {
    state_transaction
        .crypto_admission_policy()
        .map_err(|message| Error::InvariantViolation(message.into()))?;
    classify_recipient_attempt(state_transaction, || {
        AccountAddress::from_canonical_bytes(bytes).and_then(|address| address.to_account_id())
    })
}

/// Keep the real decoder call inside the canonical current-attempt observer.
fn classify_recipient_attempt(
    state_transaction: &StateTransaction<'_, '_>,
    decode: impl FnOnce() -> Result<AccountId, AccountAddressError>,
) -> Result<SccpRecipientClassV1, Error> {
    let decoded = norito::core::classify_decode_attempt(|| match decode() {
        Ok(account) => Ok(Ok(account)),
        Err(AccountAddressError::ScopedDecodeResource(original)) => {
            Err(norito::Error::ScopedDecodeResource(original))
        }
        Err(AccountAddressError::DecodeResource(original)) => Err(original.into()),
        Err(AccountAddressError::DecodeResourceLimit) => Err(norito::Error::Json(
            norito::json::Error::DecodeResourceLimit,
        )),
        Err(error) => Ok(Err(error)),
    });
    match decoded {
        Ok(Ok(account)) => classify_account(state_transaction, account),
        Ok(Err(AccountAddressError::UnsupportedImplementation(original))) => {
            // A missing implementation is local readiness, never an invalid controller.
            Err(state_transaction.world.attempt_error_to_instruction_error(
                ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::CryptoImplementationUnavailable(original).into(),
                ),
            ))
        }
        Ok(Err(_)) => Ok(SccpRecipientClassV1::Undecodable),
        Err(original) => Err(state_transaction.world.attempt_error_to_instruction_error(
            canonical_decode_attempt_error(original, |_| {
                // A protocol bound or stale/sibling report grants no retry authority and
                // is not evidence that this recipient's canonical bytes are malformed.
                Error::InvariantViolation(
                    "recipient decoder resource error lacks current-attempt provenance".into(),
                )
            }),
        )),
    }
}

/// Classify the identity of `account` as the recipient of an XOR credit (§4.12.3 step 3).
///
/// It can never be credited when it is an SCCP escrow, when its controller uses a signing
/// algorithm or curve that account admission refuses, or when it is absent and
/// `Register<Account>(Account::new(account))` refuses its identity. Refusals that depend on
/// the movement (transfer control, holding limit, custody, usage policy) are not permanent and
/// are left to the release precheck.
///
/// # Errors
/// Returns a missing original policy owner; it is not a permanent recipient bounce.
#[must_use]
pub fn classify_account(
    state_transaction: &StateTransaction<'_, '_>,
    account: AccountId,
) -> Result<SccpRecipientClassV1, Error> {
    let policy = state_transaction
        .crypto_admission_policy()
        .map_err(|message| Error::InvariantViolation(message.into()))?;
    let world = &*state_transaction.world;
    let registered = world.account(&account).is_ok();
    let reason = if escrow::is_escrow(world, &account) {
        Some(SccpBounceReasonV1::EscrowRecipient)
    } else if ensure_controller_policy(account.controller(), policy).is_err() {
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
    Ok(match reason {
        Some(reason) => SccpRecipientClassV1::Uncreditable { account, reason },
        None => SccpRecipientClassV1::Creditable {
            account,
            registered,
        },
    })
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
            classify_recipient(&stx, &[]).unwrap(),
            SccpRecipientClassV1::Undecodable
        );
        assert_eq!(
            classify_recipient(&stx, &[0xff, 1, 2, 3]).unwrap(),
            SccpRecipientClassV1::Undecodable
        );
        let fresh = authority(1);
        assert_eq!(
            classify_recipient(&stx, &address_bytes(&fresh)).unwrap(),
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
            classify_recipient(&stx, &address_bytes(&escrow)).unwrap(),
            SccpRecipientClassV1::Uncreditable {
                account: escrow,
                reason: SccpBounceReasonV1::EscrowRecipient
            }
        );
        ensure_registered(&mut stx, &fresh).expect("register");
        assert_eq!(
            classify_account(&stx, fresh.clone()).unwrap(),
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
            classify_account(&stx, retired.clone()).unwrap(),
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
        let stx = block.transaction();
        let secp = AccountId::new(
            iroha_crypto::KeyPair::try_from_seed(vec![9; 32], iroha_crypto::Algorithm::Secp256k1)
                .expect("seed")
                .public_key()
                .clone(),
        );
        assert!(matches!(
            classify_account(&stx, secp.clone()).unwrap(),
            SccpRecipientClassV1::Creditable { .. }
        ));
        drop(stx);
        drop(block);
        let policy = iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
            iroha_crypto::Algorithm::Ed25519,
        ])
        .unwrap();
        let mut parameters = state.world.parameters.block();
        parameters
            .get_mut()
            .set_parameter(policy.into_parameter().unwrap())
            .unwrap();
        parameters.commit();
        let mut block = state.block(header(2));
        let stx = block.transaction();
        assert_eq!(
            classify_account(&stx, secp.clone()).unwrap(),
            SccpRecipientClassV1::Uncreditable {
                account: secp,
                reason: SccpBounceReasonV1::InadmissibleController
            }
        );
    }

    #[test]
    fn missing_original_policy_is_not_a_permanent_recipient_bounce() {
        let state = crate::state::State::new_for_testing(
            crate::state::World::default(),
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
        {
            let mut block = state.block(header(2));
            let stx = block.transaction();
            assert!(classify_account(&stx, authority(7)).is_err());
            assert!(classify_recipient(&stx, &address_bytes(&authority(7))).is_err());
            assert!(classify_recipient(&stx, &[]).is_err());
        }
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_bytes(&state),
            before
        );
    }
    fn allocation_limits(bytes: usize) -> norito::DecodeLimits {
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
    }

    #[test]
    fn recipient_decoder_refusal_retains_original_and_retries_unchanged_source() {
        use norito::core::{DecodeBudgetContext, DecodeLocalRefusalKind};

        let state = blank_state();
        let account = authority(8);
        let source = address_bytes(&account);
        let bytes_before = source.clone();
        let pointer = source.as_ptr();
        let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
        let pool = iroha_allocation::AllocationBudget::new(
            DecodeBudgetContext::allocation_layout().size(),
        );
        let context = DecodeBudgetContext::try_new_owned(allocation_limits(usize::MAX), &pool)
            .expect("original decoder counter owner");
        let baseline = pool.reserved_bytes();
        let original = {
            let mut block = state.block(header(2));
            let mut stx = block.transaction();
            let error = context
                .with(|| {
                    norito::with_decode_limits_scope(allocation_limits(0), || {
                        classify_recipient(&stx, &source)
                    })
                })
                .expect_err("actual canonical key allocation is locally refused");
            assert!(matches!(error, Error::InvariantViolation(_)));
            let observed = stx
                .borrow_execution_deferral()
                .expect("sticky original refusal")
                .decode_refusal()
                .expect("actual decoder owner")
                .clone();
            assert_eq!(observed.kind(), DecodeLocalRefusalKind::EnclosingLimit);
            assert!(matches!(
                observed.resource_error(),
                norito::core::DecodeResourceError::TotalAllocationExceeded { limit: 0, .. }
            ));
            let original = stx.take_execution_deferral().expect("move once");
            assert_eq!(original.decode_refusal(), Some(&observed));
            assert!(stx.take_execution_deferral().is_none());
            assert!(
                stx.is_execution_deferred(),
                "moving the owner cannot permit publication"
            );
            original
        };
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_bytes(&state),
            before
        );
        assert_eq!(source, bytes_before);
        assert_eq!(source.as_ptr(), pointer);
        assert_eq!(pool.reserved_bytes(), baseline);
        {
            let mut block = state.block(header(2));
            let stx = block.transaction();
            assert_eq!(
                context.with(|| classify_recipient(&stx, &source)).unwrap(),
                SccpRecipientClassV1::Creditable {
                    account,
                    registered: false
                }
            );
            assert!(!stx.is_execution_deferred());
        }
        assert_eq!(source.as_ptr(), pointer);
        assert_eq!(source, bytes_before);
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_bytes(&state),
            before
        );
        drop(original);
        drop(context);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn sibling_decoder_report_cannot_authorize_recipient_retry_or_bounce() {
        use norito::core::{DecodeBudgetContext, classify_decode_attempt};

        let state = blank_state();
        let source = address_bytes(&authority(9));
        let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
        let pool = iroha_allocation::AllocationBudget::new(
            DecodeBudgetContext::allocation_layout().size(),
        );
        let context = DecodeBudgetContext::try_new_owned(allocation_limits(0), &pool).unwrap();
        {
            let mut block = state.block(header(2));
            let stx = block.transaction();
            context.with(|| {
                classify_decode_attempt(|| {
                    let saved = classify_decode_attempt(|| {
                        let AccountAddressError::ScopedDecodeResource(original) =
                            AccountAddress::from_canonical_bytes(&source).unwrap_err()
                        else { panic!("actual first parser refusal"); };
                        Err::<(), _>(norito::Error::ScopedDecodeResource(original))
                    }).unwrap_err().into_error();
                    let norito::Error::ScopedDecodeResource(saved) = saved
                    else { panic!("retain original sibling report"); };
                    let error = classify_recipient_attempt(&stx, || {
                        // Exercise the actual current parser too; its report cannot grant
                        // the retained sibling report this observer's authority.
                        let AccountAddressError::ScopedDecodeResource(current) =
                            AccountAddress::from_canonical_bytes(&source).unwrap_err()
                        else { panic!("actual current parser refusal"); };
                        assert_ne!(saved, current);
                        Err(AccountAddressError::ScopedDecodeResource(saved))
                    }).expect_err("foreign report is neither a bounce nor a retry");
                    assert!(matches!(error, Error::InvariantViolation(ref message)
                        if message.as_ref() == "recipient decoder resource error lacks current-attempt provenance"));
                    assert!(!stx.is_execution_deferred());
                    assert!(stx.borrow_execution_deferral().is_none());
                    Ok(())
                }).unwrap();
            });
        }
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_bytes(&state),
            before
        );
        drop(context);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn malformed_recipient_remains_completed_without_local_retry_owner() {
        let state = blank_state();
        let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
        {
            let mut block = state.block(header(2));
            let stx = block.transaction();
            for bytes in [&[][..], &[0xff, 1, 2, 3][..]] {
                assert_eq!(
                    classify_recipient(&stx, bytes).unwrap(),
                    SccpRecipientClassV1::Undecodable
                );
                assert!(!stx.is_execution_deferred());
            }
        }
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_bytes(&state),
            before
        );
    }

    #[cfg(not(feature = "gost"))]
    #[test]
    fn unavailable_recipient_key_implementation_is_not_a_permanent_bounce() {
        use iroha_crypto::{Algorithm, CryptoOperation};
        use iroha_data_model::account::curve::CurveId;

        let state = blank_state();
        let before = crate::snapshot::canonical_state_snapshot_bytes(&state);
        let algorithm = Algorithm::Gost3410_2012_256ParamSetA;
        let expected = algorithm
            .require_implementation(CryptoOperation::ParsePublicKey)
            .expect_err("this control requires the actual absent-GOST feature graph");
        let key = hex::decode(
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/account/gost256a_public_key.hex"
            ))
            .trim(),
        )
        .unwrap();
        let sample = address_bytes(&authority(10));
        let mut source = vec![
            sample[0],
            sample[1],
            CurveId::from_algorithm(algorithm).as_u8(),
            u8::try_from(key.len()).unwrap(),
        ];
        source.extend_from_slice(&key);
        let original_source = source.clone();
        let original = AccountAddress::from_canonical_bytes(&source).unwrap_err();
        assert!(
            matches!(original, AccountAddressError::UnsupportedImplementation(cause)
            if cause == expected)
        );
        {
            let mut block = state.block(header(2));
            let mut stx = block.transaction();
            assert!(classify_recipient(&stx, &source).is_err());
            let owner = stx
                .take_execution_deferral()
                .expect("actual backend refusal");
            assert_eq!(
                owner.reason(),
                ivm::error::ExecutionDeferral::CryptoImplementationUnavailable(expected)
            );
            assert!(owner.decode_refusal().is_none());
            assert!(owner.allocation_refusal().is_none());
            assert!(stx.is_execution_deferred());
        }
        assert_eq!(source, original_source);
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_bytes(&state),
            before
        );
    }
}
