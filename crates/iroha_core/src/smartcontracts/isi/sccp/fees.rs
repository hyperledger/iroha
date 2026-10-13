//! Fee exemption of SCCP transactions (`specs/sccp.md` §4.19). Owner: ws41 (keeper advances,
//! recipient self-claims).
//!
//! [`exempt_class`] is the single eligibility predicate: a pure function of the committed
//! parent World and its original committed time, the authority and the signed payload.
//! Admission pre-verification ([`super::admission::classify`]), fee quoting, the per-block
//! exempt cap ([`super::admission::exempt_class_of_entrypoint`]) and execution
//! ([`exempt_on_success`], [`exempt_class_in_block`]) all call it, so a transaction is quoted,
//! admitted, counted and executed as exempt exactly when it is eligible. A transaction of an
//! exempt shape that is not eligible is never refused for that: it pays the ordinary fee.
//!
//! Eligible forgery evidence is exempt only on success; R-EX rejects a failed carrier.
//! For other eligible transactions that fail, the executor charges
//! the ordinary Nexus fee within its signed fee intent, when that intent covers the fee and
//! the payer can pay it (`ExecutionFeeExemption::ExemptOnSuccess`).

use super::{
    admission::{self, SccpExemptClassV1},
    light_clients, self_claim,
};
use crate::state::{StateTransaction, WorldReadOnly};
use iroha_data_model::{
    isi::{InstructionBox, sccp::AdvanceSccpLightClientV1},
    transaction::{Executable, TransactionPayload},
};

/// Return the only instruction of `payload` as a `T`, if it has exactly one.
fn single<T: 'static>(payload: &TransactionPayload) -> Option<&T> {
    let Executable::Instructions(instructions) = &payload.instructions else {
        return None;
    };
    let instructions: &[InstructionBox] = instructions;
    let [only] = instructions else {
        return None;
    };
    only.as_any().downcast_ref::<T>()
}

/// Return the exempt class `payload` is eligible for against the committed parent World
/// `world`, or `None` when it pays the ordinary fee (§4.19).
///
/// Only a payload with an [`admission::exempt_shape`] can be eligible, and only while SCCP
/// exists. Per class:
///
/// * keeper advance: [`light_clients::keeper_advance_eligible`], from any authority, registered
///   or not, unless it is a `Backfill` (§4.13.4);
/// * self-claim: [`self_claim::eligible`], the recipient claiming more than the self-claim fee
///   (§4.12.4).
///
/// The predicate never verifies proofs or signatures; admission pre-verifies every eligible
/// transaction and rejects an eligible one that is invalid.
#[must_use]
pub fn exempt_class(
    world: &(impl WorldReadOnly + ?Sized),
    payload: &TransactionPayload,
    committed_time_ms: Option<u64>,
) -> Option<SccpExemptClassV1> {
    exempt_class_from(
        &super::eligibility::Current(world),
        payload,
        committed_time_ms,
    )
}

/// Classify using the exact borrowed current or acquired pre-block facts.
pub(crate) fn exempt_class_from(
    source: &(impl super::eligibility::EligibilityRead + ?Sized),
    payload: &TransactionPayload,
    committed_time_ms: Option<u64>,
) -> Option<SccpExemptClassV1> {
    if source.parameters().is_none() {
        return None;
    }
    let class = admission::exempt_shape(payload)?;
    let eligible = match class {
        SccpExemptClassV1::ForgeryEvidence => true,
        SccpExemptClassV1::KeeperAdvance { .. } => single::<AdvanceSccpLightClientV1>(payload)
            .is_some_and(light_clients::keeper_advance_eligible),
        SccpExemptClassV1::SelfClaim => self_claim::eligible_from(
            source,
            &payload.authority,
            &payload.instructions,
            committed_time_ms,
        ),
    };
    eligible.then_some(class)
}

/// Return whether the transaction with `payload` is exempt from the Nexus fee when it
/// succeeds, judged against the committed parent World `world` ([`exempt_class`]).
#[must_use]
pub fn exempt_on_success(
    world: &(impl WorldReadOnly + ?Sized),
    payload: &TransactionPayload,
    committed_time_ms: Option<u64>,
) -> bool {
    exempt_class(world, payload, committed_time_ms).is_some()
}

/// Return the [`exempt_class`] of `payload` executing in `state_transaction`, judged against
/// the committed parent World of the executing block rather than the block's own writes, so
/// execution, the per-block cap and admission agree.
/// # Errors
/// Returns the original committed-time source mismatch before exemption is granted.
pub fn exempt_class_in_block(
    state_transaction: &StateTransaction<'_, '_>,
    payload: &TransactionPayload,
) -> Result<Option<SccpExemptClassV1>, super::hold::SccpCommittedTimeError> {
    // An unshaped payload is never eligible and needs no parent eligibility facts.
    if admission::exempt_shape(payload).is_none() {
        return Ok(None);
    }
    let committed_time_ms = super::hold::committed_time_ms(state_transaction)?;
    Ok(exempt_class_from(
        &super::eligibility::TransactionParent(&state_transaction.world),
        payload,
        committed_time_ms,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::{
        store,
        test_support::{
            SampleInstructions, authority, blank_state, header, sample_signed_transaction,
        },
    };
    use iroha_data_model::{bridge::SccpNetworkV1, sccp::params::SccpParametersV1};
    use iroha_sccp::light_client::{
        ethereum::{EthereumHeaderSegmentV1, EthereumLcAdvanceV1},
        proof::{SccpLcAdvanceV1, SccpLcSegmentV1},
    };

    const NETWORK: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;

    fn with_instructions(instructions: Vec<InstructionBox>) -> TransactionPayload {
        let mut payload = sample_signed_transaction().payload().clone();
        payload.instructions = Executable::Instructions(instructions.into());
        payload
    }

    fn frame(advance: &SccpLcAdvanceV1) -> AdvanceSccpLightClientV1 {
        AdvanceSccpLightClientV1 {
            network: NETWORK,
            expected_state_hash: None,
            advance: advance.to_bytes().expect("bounded advance"),
        }
    }

    /// A decodable Ethereum advance that proves nothing: eligible from any authority.
    fn eligible_advance() -> AdvanceSccpLightClientV1 {
        frame(&SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
            updates: Vec::new(),
        }))
    }

    #[test]
    fn nothing_is_exempt_without_sccp() {
        let state = blank_state();
        let view = state.world_view();
        assert!(!exempt_on_success(
            &view,
            sample_signed_transaction().payload(),
            None
        ));
        let advance = with_instructions(vec![eligible_advance().into()]);
        assert_eq!(exempt_class(&view, &advance, None), None);
    }

    #[test]
    fn an_unshaped_payload_is_never_exempt_even_with_sccp() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
        let ordinary = sample_signed_transaction();
        assert_eq!(admission::exempt_shape(ordinary.payload()), None);
        assert!(!exempt_on_success(&*stx.world, ordinary.payload(), None));
        let record = with_instructions(vec![SampleInstructions::record().into()]);
        assert!(!exempt_on_success(&*stx.world, &record, None));
        assert!(single::<AdvanceSccpLightClientV1>(&record).is_none());
    }

    #[test]
    fn keeper_advances_are_exempt_from_any_authority_with_sccp_only() {
        let advance = eligible_advance();
        let backfill = frame(&SccpLcAdvanceV1::Backfill {
            segment: SccpLcSegmentV1::Ethereum(EthereumHeaderSegmentV1 {
                headers: Vec::new(),
            }),
        });
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let payload = with_instructions(vec![advance.clone().into()]);
        assert!(!exempt_on_success(&*stx.world, &payload, None), "no SCCP");
        store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
        let class = Some(SccpExemptClassV1::KeeperAdvance { network: NETWORK });
        assert_eq!(exempt_class(&*stx.world, &payload, None), class);
        // No account of the test World is registered: the authority does not matter.
        for seed in [1, 2] {
            let mut other = payload.clone();
            other.authority = authority(seed);
            assert_eq!(exempt_class(&*stx.world, &other, None), class);
        }
        assert_eq!(
            exempt_class(&*stx.world, &with_instructions(vec![backfill.into()]), None),
            None,
            "a Backfill pays the ordinary fee"
        );
        assert_eq!(
            exempt_class(
                &*stx.world,
                &with_instructions(vec![advance.clone().into(), advance.into()]),
                None
            ),
            None,
            "only a single advance has the keeper-advance shape"
        );
    }

    #[test]
    fn the_exempt_classes_are_keeper_advance_and_self_claim() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
        // A self-claim shape whose claim does not exist is not eligible: it pays.
        let settle = with_instructions(vec![SampleInstructions::settle().into()]);
        assert_eq!(
            admission::exempt_shape(&settle),
            Some(SccpExemptClassV1::SelfClaim)
        );
        assert_eq!(exempt_class(&*stx.world, &settle, None), None);
        // No other SCCP instruction has an exempt shape.
        for instruction in [
            InstructionBox::from(SampleInstructions::initialize()),
            SampleInstructions::record().into(),
            SampleInstructions::void().into(),
            SampleInstructions::equivocation().into(),
        ] {
            assert_eq!(
                exempt_class(&*stx.world, &with_instructions(vec![instruction]), None),
                None
            );
        }
    }

    #[test]
    fn execution_judges_eligibility_against_the_parent_world() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let payload = with_instructions(vec![eligible_advance().into()]);
        store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
        assert!(
            exempt_on_success(&*stx.world, &payload, None),
            "eligible against the block's own writes"
        );
        assert_eq!(
            exempt_class_in_block(&stx, &payload).expect("original parent source"),
            None,
            "the parent World has no SCCP, so execution does not exempt it"
        );
        assert_eq!(
            exempt_class_in_block(&stx, sample_signed_transaction().payload())
                .expect("original parent source"),
            None
        );
    }
}
