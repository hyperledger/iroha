//! Pure coherence checks for prospective effective chain and privacy byte limits.
//!
//! Callers select the transaction and block limits that apply at the same height,
//! then validate each current or pending privacy policy against those limits.
//! These helpers neither select a consensus schedule nor mutate policy owners.
//! The action count and aggregate byte budget are independent limits: admitting
//! two actions does not promise that two individually maximal actions fit.

use core::num::{NonZeroU32, NonZeroU64};

use super::BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES;
use crate::privacy::{
    PrivacyConsensusLimitsV1, PrivacyConsensusLimitsValidationError, PrivacyConsensusPolicyV1,
    PrivacyPolicyValidationErrorV1,
};

/// A concrete incompatibility between byte limits selected for the same height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResourceCoherenceError {
    /// Adding the mandatory block reserve to the transaction cap overflowed.
    #[error(
        "transaction cap {max_transaction_bytes} plus block reserve {reserve_bytes} overflows u64"
    )]
    TransactionReserveOverflow {
        /// Prospective framed transaction cap.
        max_transaction_bytes: u64,
        /// Mandatory block bytes reserved for non-transaction fields.
        reserve_bytes: u32,
    },
    /// A maximum transaction and the block reserve exceed the block payload cap.
    #[error(
        "transaction cap {max_transaction_bytes} plus block reserve {reserve_bytes} requires {required_block_bytes} bytes, exceeding block cap {max_block_bytes}"
    )]
    TransactionExceedsBlock {
        /// Prospective framed transaction cap.
        max_transaction_bytes: u64,
        /// Mandatory block bytes reserved for non-transaction fields.
        reserve_bytes: u32,
        /// Exact sum of the transaction cap and reserve.
        required_block_bytes: u64,
        /// Prospective block payload cap.
        max_block_bytes: u32,
    },
    /// The privacy profile itself has invalid fields or field ordering.
    #[error("invalid privacy limits: {0}")]
    InvalidPrivacyLimits(PrivacyConsensusLimitsValidationError),
    /// A permitted individual action is larger than the transaction cap.
    #[error(
        "privacy action cap {max_action_bytes} exceeds transaction cap {max_transaction_bytes}"
    )]
    PrivacyActionExceedsTransaction {
        /// Prospective canonical action cap.
        max_action_bytes: u32,
        /// Prospective framed transaction cap.
        max_transaction_bytes: u64,
    },
    /// The transaction's aggregate privacy budget exceeds its total byte cap.
    #[error(
        "privacy transaction budget {max_privacy_bytes_per_transaction} exceeds transaction cap {max_transaction_bytes}"
    )]
    PrivacyTransactionExceedsTransaction {
        /// Prospective aggregate privacy bytes per transaction.
        max_privacy_bytes_per_transaction: u32,
        /// Prospective framed transaction cap.
        max_transaction_bytes: u64,
    },
    /// The block's aggregate privacy budget leaves insufficient framing reserve.
    #[error(
        "privacy block budget {max_privacy_bytes_per_block} plus block reserve {reserve_bytes} requires {required_block_bytes} bytes, exceeding block cap {max_block_bytes}"
    )]
    PrivacyBlockExceedsPayload {
        /// Prospective aggregate privacy bytes per block.
        max_privacy_bytes_per_block: u32,
        /// Mandatory block bytes reserved for non-transaction fields.
        reserve_bytes: u32,
        /// Exact sum of the privacy budget and reserve.
        required_block_bytes: u64,
        /// Prospective block payload cap.
        max_block_bytes: u32,
    },
}

/// Invalid resource policy at a specific committed or successor height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SuccessorResourceCoherenceError {
    /// The carried current/pending privacy policy is invalid at the committed height.
    #[error("invalid privacy policy after height {committed_height}: {error}")]
    InvalidPrivacyPolicy {
        /// Height whose complete candidate or restored state is being checked.
        committed_height: u64,
        /// Original typed policy/schedule failure.
        error: PrivacyPolicyValidationErrorV1,
    },
    /// Both successor heights cannot be represented.
    #[error("two successor heights cannot follow committed height {committed_height}")]
    HeightOverflow {
        /// Height whose two successors are required.
        committed_height: u64,
    },
    /// Limits which become effective at the named height are incoherent.
    #[error("incoherent resource policy at height {effective_height}: {error}")]
    AtHeight {
        /// Exact first or second successor height.
        effective_height: u64,
        /// Original typed byte-coherence failure.
        error: ResourceCoherenceError,
    },
}

/// Validate a complete candidate against its two applicable successor block caps.
///
/// Transaction limits apply immediately to the next block. The caller supplies
/// each authenticated block cap explicitly because consensus parameters have a
/// two-block scheduling lag. Genesis supplies its final cap for both successors.
/// A pending privacy tightening is selected only at its signed effective height.
/// Later tightenings cannot increase any byte ceiling, so validating the current
/// profile against the second successor also covers the intervening future.
///
/// # Errors
/// Rejects invalid privacy policy/schedule, height overflow, and the first
/// incoherent successor, preserving its exact height and typed numeric error.
pub fn validate_successor_resource_limits(
    committed_height: u64,
    max_transaction_bytes: NonZeroU64,
    next_max_block_bytes: NonZeroU32,
    after_next_max_block_bytes: NonZeroU32,
    privacy: &PrivacyConsensusPolicyV1,
) -> Result<(), SuccessorResourceCoherenceError> {
    privacy
        .validate_at_committed_height(committed_height)
        .map_err(
            |error| SuccessorResourceCoherenceError::InvalidPrivacyPolicy {
                committed_height,
                error,
            },
        )?;
    let next = committed_height
        .checked_add(1)
        .ok_or(SuccessorResourceCoherenceError::HeightOverflow { committed_height })?;
    let after_next = next
        .checked_add(1)
        .ok_or(SuccessorResourceCoherenceError::HeightOverflow { committed_height })?;
    for (effective_height, cap) in [
        (next, next_max_block_bytes),
        (after_next, after_next_max_block_bytes),
    ] {
        let limits = privacy
            .pending_tightening
            .as_ref()
            .filter(|pending| pending.effective_at_height <= effective_height)
            .map_or(&privacy.current_limits, |pending| &pending.next_limits);
        validate_privacy_chain_limits(max_transaction_bytes, cap, limits).map_err(|error| {
            SuccessorResourceCoherenceError::AtHeight {
                effective_height,
                error,
            }
        })?;
    }
    Ok(())
}

/// Check that a maximum framed transaction fits the selected block payload.
///
/// Both arguments must describe policy effective at the same height. This check
/// uses the protocol reserve, not local transport capacity or configuration.
/// It does not change the ordinary per-block check of actual canonical bytes.
///
/// # Errors
/// Returns the exact offending limits when the sum overflows or exceeds the
/// block payload cap. Equality is accepted.
pub fn validate_transaction_block_limits(
    max_transaction_bytes: NonZeroU64,
    max_block_bytes: NonZeroU32,
) -> Result<(), ResourceCoherenceError> {
    let max_transaction_bytes = max_transaction_bytes.get();
    let max_block_bytes = max_block_bytes.get();
    let reserve_bytes = BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES;
    let required_block_bytes = max_transaction_bytes
        .checked_add(u64::from(reserve_bytes))
        .ok_or(ResourceCoherenceError::TransactionReserveOverflow {
            max_transaction_bytes,
            reserve_bytes,
        })?;
    if required_block_bytes > u64::from(max_block_bytes) {
        return Err(ResourceCoherenceError::TransactionExceedsBlock {
            max_transaction_bytes,
            reserve_bytes,
            required_block_bytes,
            max_block_bytes,
        });
    }
    Ok(())
}

/// Check one current or prospective privacy policy against effective chain caps.
///
/// Checks chain coherence, the privacy profile's own invariants, individual
/// action and aggregate transaction byte limits, then aggregate block bytes.
/// Callers with a scheduled change validate each policy against the chain caps
/// applicable to it; this function does not assume when either policy activates.
///
/// Action count remains independently enforced alongside actual aggregate
/// bytes. These necessary byte relationships do not promise that a maximum
/// action fits arbitrary transaction metadata, or replace checks of the actual
/// encoded transaction and block.
///
/// # Errors
/// Returns the first invalid relationship in the order above, retaining the
/// exact offending values. Equality is accepted at every byte boundary.
pub fn validate_privacy_chain_limits(
    max_transaction_bytes: NonZeroU64,
    max_block_bytes: NonZeroU32,
    privacy: &PrivacyConsensusLimitsV1,
) -> Result<(), ResourceCoherenceError> {
    validate_transaction_block_limits(max_transaction_bytes, max_block_bytes)?;
    privacy
        .validate()
        .map_err(ResourceCoherenceError::InvalidPrivacyLimits)?;
    let max_transaction_bytes = max_transaction_bytes.get();
    let max_block_bytes = max_block_bytes.get();
    if u64::from(privacy.max_action_bytes) > max_transaction_bytes {
        return Err(ResourceCoherenceError::PrivacyActionExceedsTransaction {
            max_action_bytes: privacy.max_action_bytes,
            max_transaction_bytes,
        });
    }
    if u64::from(privacy.max_privacy_bytes_per_transaction) > max_transaction_bytes {
        return Err(
            ResourceCoherenceError::PrivacyTransactionExceedsTransaction {
                max_privacy_bytes_per_transaction: privacy.max_privacy_bytes_per_transaction,
                max_transaction_bytes,
            },
        );
    }
    let reserve_bytes = BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES;
    // Both operands are u32. Widen before adding so their exact sum fits u64.
    let required_block_bytes =
        u64::from(privacy.max_privacy_bytes_per_block) + u64::from(reserve_bytes);
    if required_block_bytes > u64::from(max_block_bytes) {
        return Err(ResourceCoherenceError::PrivacyBlockExceedsPayload {
            max_privacy_bytes_per_block: privacy.max_privacy_bytes_per_block,
            reserve_bytes,
            required_block_bytes,
            max_block_bytes,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::PrivacyConsensusPolicyTighteningV1;

    fn tx(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap()
    }

    fn block(value: u32) -> NonZeroU32 {
        NonZeroU32::new(value).unwrap()
    }

    fn privacy_limits(action: u32, transaction: u32, block: u32) -> PrivacyConsensusLimitsV1 {
        PrivacyConsensusLimitsV1 {
            max_proof_bytes_per_action: action,
            max_action_bytes: action,
            max_privacy_bytes_per_transaction: transaction,
            max_privacy_bytes_per_block: block,
            max_statement_and_encrypted_output_bytes_per_transaction: action.min(256 * 1024),
            ..PrivacyConsensusLimitsV1::taira_default()
        }
    }

    #[test]
    fn selected_first_release_defaults_are_coherent() {
        let parameters = crate::parameter::Parameters::default();
        assert_eq!(
            validate_privacy_chain_limits(
                parameters.transaction().max_tx_bytes(),
                parameters.sumeragi().max_block_bytes(),
                &PrivacyConsensusLimitsV1::taira_default(),
            ),
            Ok(())
        );
    }

    #[test]
    fn transaction_exact_and_one_above_every_representative_boundary() {
        let reserve = BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES;
        for cap in [reserve + 1, reserve + 2, 16 * 1024 * 1024, u32::MAX] {
            let fitting = u64::from(cap - reserve);
            assert_eq!(
                validate_transaction_block_limits(tx(fitting), block(cap)),
                Ok(())
            );
            assert_eq!(
                validate_transaction_block_limits(tx(fitting + 1), block(cap)),
                Err(ResourceCoherenceError::TransactionExceedsBlock {
                    max_transaction_bytes: fitting + 1,
                    reserve_bytes: reserve,
                    required_block_bytes: u64::from(cap) + 1,
                    max_block_bytes: cap,
                })
            );
        }
    }

    #[test]
    fn a_block_at_or_below_the_reserve_has_no_transaction_capacity() {
        let reserve = BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES;
        for cap in [1, reserve - 1, reserve] {
            assert_eq!(
                validate_transaction_block_limits(tx(1), block(cap)),
                Err(ResourceCoherenceError::TransactionExceedsBlock {
                    max_transaction_bytes: 1,
                    reserve_bytes: reserve,
                    required_block_bytes: u64::from(reserve) + 1,
                    max_block_bytes: cap,
                })
            );
        }
    }

    #[test]
    fn transaction_reserve_overflow_preserves_both_operands() {
        let reserve = BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES;
        let largest_sum = u64::MAX - u64::from(reserve);
        assert_eq!(
            validate_transaction_block_limits(tx(largest_sum), block(u32::MAX)),
            Err(ResourceCoherenceError::TransactionExceedsBlock {
                max_transaction_bytes: largest_sum,
                reserve_bytes: reserve,
                required_block_bytes: u64::MAX,
                max_block_bytes: u32::MAX,
            })
        );
        for cap in [largest_sum + 1, u64::MAX] {
            assert_eq!(
                validate_transaction_block_limits(tx(cap), block(u32::MAX)),
                Err(ResourceCoherenceError::TransactionReserveOverflow {
                    max_transaction_bytes: cap,
                    reserve_bytes: reserve,
                })
            );
        }
    }

    #[test]
    fn privacy_action_exact_and_one_above_transaction_cap() {
        let cap = 1024;
        let block = block(BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES + cap + 1);
        assert_eq!(
            validate_privacy_chain_limits(tx(cap.into()), block, &privacy_limits(cap, cap, cap)),
            Ok(())
        );
        assert_eq!(
            validate_privacy_chain_limits(
                tx(cap.into()),
                block,
                &privacy_limits(cap + 1, cap + 1, cap + 1)
            ),
            Err(ResourceCoherenceError::PrivacyActionExceedsTransaction {
                max_action_bytes: cap + 1,
                max_transaction_bytes: cap.into(),
            })
        );
    }

    #[test]
    fn privacy_transaction_exact_and_one_above_transaction_cap() {
        let cap = 1024;
        let block = block(BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES + cap + 1);
        assert_eq!(
            validate_privacy_chain_limits(tx(cap.into()), block, &privacy_limits(1, cap, cap)),
            Ok(())
        );
        assert_eq!(
            validate_privacy_chain_limits(
                tx(cap.into()),
                block,
                &privacy_limits(1, cap + 1, cap + 1)
            ),
            Err(
                ResourceCoherenceError::PrivacyTransactionExceedsTransaction {
                    max_privacy_bytes_per_transaction: cap + 1,
                    max_transaction_bytes: cap.into(),
                }
            )
        );
    }

    #[test]
    fn privacy_block_exact_and_one_above_payload_budget() {
        let cap = 1024 * 1024;
        let reserve = BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES;
        let available = cap - reserve;
        assert_eq!(
            validate_privacy_chain_limits(
                tx(1024),
                block(cap),
                &privacy_limits(1, 1024, available)
            ),
            Ok(())
        );
        assert_eq!(
            validate_privacy_chain_limits(
                tx(1024),
                block(cap),
                &privacy_limits(1, 1024, available + 1)
            ),
            Err(ResourceCoherenceError::PrivacyBlockExceedsPayload {
                max_privacy_bytes_per_block: available + 1,
                reserve_bytes: reserve,
                required_block_bytes: u64::from(cap) + 1,
                max_block_bytes: cap,
            })
        );
    }

    #[test]
    fn independent_count_and_actual_aggregate_allow_two_nonmaximal_actions() {
        let cap = 16 * 1024 * 1024;
        let limits = privacy_limits(
            9 * 1024 * 1024,
            9 * 1024 * 1024,
            cap - BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES,
        );
        assert_eq!(limits.max_actions_per_block, 2);
        assert!(
            u64::from(limits.max_actions_per_block) * u64::from(limits.max_action_bytes)
                > u64::from(cap)
        );
        assert_eq!(
            validate_privacy_chain_limits(tx(10 * 1024 * 1024), block(cap), &limits),
            Ok(())
        );
    }

    #[test]
    fn intrinsic_privacy_failure_is_preserved() {
        let mut limits = privacy_limits(1, 1, 1);
        limits.max_actions_per_transaction = 0;
        let original = limits.validate().unwrap_err();
        assert_eq!(
            validate_privacy_chain_limits(
                tx(1),
                block(BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES + 1),
                &limits
            ),
            Err(ResourceCoherenceError::InvalidPrivacyLimits(original))
        );
    }

    #[test]
    fn chain_failure_precedes_privacy_failure_deterministically() {
        let mut limits = privacy_limits(1, 1, 1);
        limits.max_actions_per_transaction = 0;
        let original = validate_transaction_block_limits(tx(u64::MAX), block(1));
        assert_eq!(
            validate_privacy_chain_limits(tx(u64::MAX), block(1), &limits),
            original
        );
    }

    #[test]
    fn the_caller_selects_current_and_pending_effective_caps() {
        let current = privacy_limits(1024, 1024, 2048);
        let pending = privacy_limits(512, 512, 1024);
        let lower = block(BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES + 1024);
        let higher = block(BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES + 2048);
        assert!(matches!(
            validate_privacy_chain_limits(tx(1024), lower, &current),
            Err(ResourceCoherenceError::PrivacyBlockExceedsPayload { .. })
        ));
        assert_eq!(
            validate_privacy_chain_limits(tx(1024), higher, &current),
            Ok(())
        );
        assert_eq!(
            validate_privacy_chain_limits(tx(1024), lower, &pending),
            Ok(())
        );
    }

    fn genesis_tightening(effective_at_height: u64) -> PrivacyConsensusPolicyV1 {
        PrivacyConsensusPolicyV1 {
            current_limits: PrivacyConsensusLimitsV1::taira_default(),
            pending_tightening: Some(PrivacyConsensusPolicyTighteningV1 {
                scheduled_at_height: 1,
                effective_at_height,
                next_limits: privacy_limits(2 * 1024 * 1024, 2 * 1024 * 1024, 3 * 1024 * 1024),
            }),
        }
    }

    #[test]
    fn lower_genesis_caps_with_tightening_at_height_two_are_coherent() {
        let cap = block(4 * 1024 * 1024);
        assert_eq!(
            validate_successor_resource_limits(
                1,
                tx(3 * 1024 * 1024),
                cap,
                cap,
                &genesis_tightening(2),
            ),
            Ok(())
        );
    }

    #[test]
    fn tightening_at_height_three_does_not_cover_incoherent_height_two() {
        let cap = block(4 * 1024 * 1024);
        assert_eq!(
            validate_successor_resource_limits(
                1,
                tx(3 * 1024 * 1024),
                cap,
                cap,
                &genesis_tightening(3),
            ),
            Err(SuccessorResourceCoherenceError::AtHeight {
                effective_height: 2,
                error: ResourceCoherenceError::PrivacyActionExceedsTransaction {
                    max_action_bytes: PrivacyConsensusLimitsV1::taira_default().max_action_bytes,
                    max_transaction_bytes: 3 * 1024 * 1024,
                },
            })
        );
    }

    #[test]
    fn raising_block_cap_at_lag_two_cannot_authorize_a_transaction_one_block_early() {
        let cap = block(16 * 1024 * 1024);
        let tx_cap = tx(12 * 1024 * 1024);
        let next_cap = block(11 * 1024 * 1024);
        let expected = validate_transaction_block_limits(tx_cap, next_cap).unwrap_err();
        assert_eq!(
            validate_successor_resource_limits(
                5,
                tx_cap,
                next_cap,
                cap,
                &PrivacyConsensusPolicyV1::taira_default(),
            ),
            Err(SuccessorResourceCoherenceError::AtHeight {
                effective_height: 6,
                error: expected,
            })
        );
    }

    #[test]
    fn second_successor_checks_its_own_block_cap() {
        let privacy = PrivacyConsensusPolicyV1 {
            current_limits: privacy_limits(1, 1, 1),
            pending_tightening: None,
        };
        let next_cap = block(BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES + 1024);
        let after_cap = block(BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES + 1023);
        let expected = validate_transaction_block_limits(tx(1024), after_cap).unwrap_err();
        assert_eq!(
            validate_successor_resource_limits(5, tx(1024), next_cap, after_cap, &privacy),
            Err(SuccessorResourceCoherenceError::AtHeight {
                effective_height: 7,
                error: expected,
            })
        );
    }

    #[test]
    fn successor_height_overflow_is_typed() {
        let cap = block(16 * 1024 * 1024);
        for committed_height in [u64::MAX - 1, u64::MAX] {
            assert_eq!(
                validate_successor_resource_limits(
                    committed_height,
                    tx(10 * 1024 * 1024),
                    cap,
                    cap,
                    &PrivacyConsensusPolicyV1::taira_default(),
                ),
                Err(SuccessorResourceCoherenceError::HeightOverflow { committed_height })
            );
        }
    }

    #[test]
    fn malformed_pending_schedule_keeps_its_original_typed_failure() {
        let cap = block(16 * 1024 * 1024);
        let privacy = genesis_tightening(2);
        let original = privacy.validate_at_committed_height(2).unwrap_err();
        assert_eq!(
            validate_successor_resource_limits(2, tx(10 * 1024 * 1024), cap, cap, &privacy),
            Err(SuccessorResourceCoherenceError::InvalidPrivacyPolicy {
                committed_height: 2,
                error: original,
            })
        );
    }
}
