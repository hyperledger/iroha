//! Fee exemption of SCCP transactions (`specs/sccp.md` §4.19). Owners: ws31 (attestations,
//! key bindings, fault evidence) and ws41 (keeper advances, recipient self-claims).
//!
//! [`exempt_class`] is the single eligibility predicate: a pure function of the committed
//! parent World (the state the next block executes on), the authority and the signed payload.
//! Admission pre-verification ([`super::admission::classify`]), fee quoting, the per-block
//! exempt cap ([`super::admission::exempt_class_of_entrypoint`]) and execution
//! ([`exempt_on_success`], [`exempt_class_in_block`]) all call it, so a transaction is quoted,
//! admitted, counted and executed as exempt exactly when it is eligible. A transaction of an
//! exempt shape that is not eligible is never refused for that: it pays the ordinary fee.
//!
//! An eligible transaction is exempt when it succeeds. When it fails, the executor charges
//! the ordinary Nexus fee within its signed fee intent, when that intent covers the fee and
//! the payer can pay it (`ExecutionFeeExemption::ExemptOnSuccess`).

use super::{
    admission::{self, SccpExemptClassV1},
    bridge_keys, light_clients, params, self_claim, store,
};
use crate::state::{StateTransaction, WorldReadOnly};
use iroha_data_model::{
    isi::{
        InstructionBox,
        sccp::{AdvanceSccpLightClientV1, SetSccpBridgeKeyV1},
    },
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
/// * attestation batch: the authority is a registered bridge key's account (§4.8);
/// * key binding: [`bridge_keys::binding_exempt`], once per peer per epoch (§4.2.3);
/// * fault evidence: always (§4.11);
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
) -> Option<SccpExemptClassV1> {
    if !params::exists(world) {
        return None;
    }
    let class = admission::exempt_shape(payload)?;
    let authority = &payload.authority;
    let eligible = match class {
        SccpExemptClassV1::Attestation => bridge_keys::bridge_key_address_of(authority)
            .is_some_and(|address| store::bridge_key_owners::contains(world, &address)),
        SccpExemptClassV1::KeyBinding => single::<SetSccpBridgeKeyV1>(payload)
            .is_some_and(|set| bridge_keys::binding_exempt(world, set, authority)),
        SccpExemptClassV1::Fault => true,
        SccpExemptClassV1::KeeperAdvance { .. } => single::<AdvanceSccpLightClientV1>(payload)
            .is_some_and(light_clients::keeper_advance_eligible),
        SccpExemptClassV1::SelfClaim => {
            self_claim::eligible(world, authority, &payload.instructions)
        }
    };
    eligible.then_some(class)
}

/// Return whether the transaction with `payload` is exempt from the Nexus fee when it
/// succeeds, judged against the committed parent World `world` ([`exempt_class`]).
#[must_use]
pub fn exempt_on_success(
    world: &(impl WorldReadOnly + ?Sized),
    payload: &TransactionPayload,
) -> bool {
    exempt_class(world, payload).is_some()
}

/// Return the [`exempt_class`] of `payload` executing in `state_transaction`, judged against
/// the committed parent World of the executing block rather than the block's own writes, so
/// execution, the per-block cap and admission agree.
#[must_use]
pub fn exempt_class_in_block(
    state_transaction: &StateTransaction<'_, '_>,
    payload: &TransactionPayload,
) -> Option<SccpExemptClassV1> {
    // An unshaped payload is never eligible; skip pinning the parent view for it.
    admission::exempt_shape(payload)?;
    exempt_class(&state_transaction.sccp_parent_world_view(), payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{
        SampleInstructions, blank_state, header, peer, sample_signed_transaction,
    };
    use iroha_data_model::sccp::params::SccpParametersV1;
    use iroha_sccp::v1::key_file::SccpBridgeKeyFileV1;

    fn with_instructions(instructions: Vec<InstructionBox>) -> TransactionPayload {
        let mut payload = sample_signed_transaction().payload().clone();
        payload.instructions = Executable::Instructions(instructions.into());
        payload
    }

    #[test]
    fn nothing_is_exempt_without_sccp() {
        let state = blank_state();
        let view = state.world_view();
        assert!(!exempt_on_success(
            &view,
            sample_signed_transaction().payload()
        ));
        let fault = with_instructions(vec![SampleInstructions::fault().into()]);
        assert_eq!(exempt_class(&view, &fault), None);
    }

    #[test]
    fn an_unshaped_payload_is_never_exempt_even_with_sccp() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
        let ordinary = sample_signed_transaction();
        assert_eq!(admission::exempt_shape(ordinary.payload()), None);
        assert!(!exempt_on_success(&*stx.world, ordinary.payload()));
        let record = with_instructions(vec![SampleInstructions::record().into()]);
        assert!(!exempt_on_success(&*stx.world, &record));
        assert!(single::<SetSccpBridgeKeyV1>(&record).is_none());
    }

    #[test]
    fn attestations_are_exempt_only_from_registered_bridge_key_accounts() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
        let key = SccpBridgeKeyFileV1::new([7; 32], 0).expect("key");
        let account =
            bridge_keys::account_of(&key.public_key().expect("public key")).expect("account");
        let mut payload = with_instructions(vec![SampleInstructions::attestations().into()]);
        payload.authority = account;
        assert!(
            !exempt_on_success(&*stx.world, &payload),
            "unregistered key"
        );
        store::bridge_key_owners::insert(&mut stx, key.address().expect("address"), peer(1))
            .expect("owner");
        assert_eq!(
            exempt_class(&*stx.world, &payload),
            Some(SccpExemptClassV1::Attestation)
        );
    }

    #[test]
    fn keeper_advances_are_exempt_from_any_authority_with_sccp_only() {
        use crate::smartcontracts::isi::sccp::test_support::authority;
        use iroha_sccp::light_client::{
            ethereum::{EthereumHeaderSegmentV1, EthereumLcAdvanceV1},
            proof::{SccpLcAdvanceV1, SccpLcSegmentV1},
        };
        let network = iroha_data_model::bridge::SccpNetworkV1::EthereumMainnet;
        let frame = |advance: SccpLcAdvanceV1| AdvanceSccpLightClientV1 {
            network,
            expected_state_hash: None,
            advance: advance.to_bytes().expect("bounded advance"),
        };
        let advance = frame(SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
            updates: Vec::new(),
        }));
        let backfill = frame(SccpLcAdvanceV1::Backfill {
            segment: SccpLcSegmentV1::Ethereum(EthereumHeaderSegmentV1 {
                headers: Vec::new(),
            }),
        });
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let payload = with_instructions(vec![advance.clone().into()]);
        assert!(!exempt_on_success(&*stx.world, &payload), "no SCCP");
        store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
        let class = Some(SccpExemptClassV1::KeeperAdvance { network });
        assert_eq!(exempt_class(&*stx.world, &payload), class);
        // No account of the test World is registered: the authority does not matter.
        for seed in [1, 2] {
            let mut other = payload.clone();
            other.authority = authority(seed);
            assert_eq!(exempt_class(&*stx.world, &other), class);
        }
        assert_eq!(
            exempt_class(&*stx.world, &with_instructions(vec![backfill.into()])),
            None,
            "a Backfill pays the ordinary fee"
        );
        assert_eq!(
            exempt_class(
                &*stx.world,
                &with_instructions(vec![advance.clone().into(), advance.into()])
            ),
            None,
            "only a single advance has the keeper-advance shape"
        );
    }

    #[test]
    fn fault_evidence_is_exempt_with_sccp_only() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let payload = with_instructions(vec![SampleInstructions::fault().into()]);
        assert!(!exempt_on_success(&*stx.world, &payload), "no SCCP");
        store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
        assert!(exempt_on_success(&*stx.world, &payload));
    }

    #[test]
    fn execution_judges_eligibility_against_the_parent_world() {
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let payload = with_instructions(vec![SampleInstructions::fault().into()]);
        store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
        assert!(
            exempt_on_success(&*stx.world, &payload),
            "eligible against the block's own writes"
        );
        assert_eq!(
            exempt_class_in_block(&stx, &payload),
            None,
            "the parent World has no SCCP, so execution does not exempt it"
        );
        assert_eq!(
            exempt_class_in_block(&stx, sample_signed_transaction().payload()),
            None
        );
    }
}
