//! Narrow authority-shape exceptions used during transaction admission.

use iroha_data_model::{
    Registrable,
    account::{Account, AccountId},
    isi::InstructionBox,
    transaction::Executable,
};
use iroha_executor_data_model::isi::multisig::MultisigInstructionBox;

fn instruction_self_registers_authority(
    instruction: &InstructionBox,
    authority: &AccountId,
) -> bool {
    let maybe_registration = instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::Register<Account>>()
        .map(|register| register.object())
        .or_else(|| {
            instruction
                .as_any()
                .downcast_ref::<iroha_data_model::isi::RegisterBox>()
                .and_then(|register| match register {
                    iroha_data_model::isi::RegisterBox::Account(register) => {
                        Some(register.object())
                    }
                    _ => None,
                })
        });
    let Some(registration) = maybe_registration else {
        return false;
    };
    registration.clone().build(authority).id == *authority
}

/// Return whether the executable's first instruction registers its exact authority.
///
/// Exact self-registration is one permitted shape for entering admission before the authority
/// exists in world state. Keeping this recognition in Core lets
/// pre-admission services, such as fee quoting, apply the same instruction-shape rule.
#[must_use]
pub fn executable_self_registers_authority(executable: &Executable, authority: &AccountId) -> bool {
    match executable {
        Executable::Instructions(instructions) => {
            let Some((first, _rest)) = instructions.split_first() else {
                return false;
            };
            instruction_self_registers_authority(first, authority)
        }
        Executable::ContractCall(_)
        | Executable::Batch(_)
        | Executable::IvmProved(_)
        | Executable::Ivm(_) => false,
    }
}

/// Return whether admission may accept an authority that is absent from world state.
///
/// This includes exact first-instruction account self-registration, the existing multisig
/// proposal envelope path, whose authorisation is established from multisig membership rather
/// than a materialised authority account, and the SCCP rules of
/// [`crate::smartcontracts::isi::sccp::admission::allows_unregistered_authority`]: a keeper
/// advance from any authority (`specs/sccp.md` §4.19).
#[must_use]
pub fn allows_unregistered_authority(executable: &Executable, authority: &AccountId) -> bool {
    executable_self_registers_authority(executable, authority)
        || matches!(
            executable,
            Executable::Instructions(instructions)
                if instructions_allow_multisig_envelope_authority(instructions)
        )
        || crate::smartcontracts::isi::sccp::admission::allows_unregistered_authority(
            executable, authority,
        )
}

pub(crate) fn instructions_allow_multisig_envelope_authority(
    instructions: &[InstructionBox],
) -> bool {
    !instructions.is_empty()
        && instructions.iter().all(|instruction| {
            matches!(
                MultisigInstructionBox::try_from(instruction),
                Ok(MultisigInstructionBox::Propose(_))
                    | Ok(MultisigInstructionBox::Approve(_))
                    | Ok(MultisigInstructionBox::Cancel(_))
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};

    fn account(seed: u8) -> AccountId {
        let key_pair =
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("deterministic seed");
        AccountId::new(key_pair.public_key().clone())
    }

    #[test]
    fn only_the_listed_shapes_admit_an_absent_authority() {
        let authority = account(1);
        let self_registration = Executable::Instructions(
            vec![InstructionBox::from(
                iroha_data_model::isi::Register::account(Account::new(authority.clone())),
            )]
            .into(),
        );
        assert!(allows_unregistered_authority(
            &self_registration,
            &authority
        ));
        assert!(!allows_unregistered_authority(
            &self_registration,
            &account(2)
        ));
        let log = Executable::Instructions(
            vec![InstructionBox::from(iroha_data_model::isi::Log::new(
                iroha_data_model::Level::INFO,
                "not a registration".to_owned(),
            ))]
            .into(),
        );
        assert!(!allows_unregistered_authority(&log, &authority));
    }

    #[test]
    fn a_keeper_advance_admits_any_absent_authority() {
        use iroha_data_model::{bridge::SccpNetworkV1, isi::sccp::AdvanceSccpLightClientV1};
        use iroha_sccp::light_client::{
            ethereum::{EthereumHeaderSegmentV1, EthereumLcAdvanceV1},
            proof::{SccpLcAdvanceV1, SccpLcSegmentV1},
        };
        let executable = |advance: SccpLcAdvanceV1| {
            Executable::Instructions(
                vec![InstructionBox::from(AdvanceSccpLightClientV1 {
                    network: SccpNetworkV1::EthereumMainnet,
                    expected_state_hash: None,
                    advance: advance.to_bytes().expect("bounded advance"),
                })]
                .into(),
            )
        };
        let advance = executable(SccpLcAdvanceV1::Ethereum(EthereumLcAdvanceV1 {
            updates: Vec::new(),
        }));
        for seed in [1, 2] {
            assert!(allows_unregistered_authority(&advance, &account(seed)));
        }
        let backfill = executable(SccpLcAdvanceV1::Backfill {
            segment: SccpLcSegmentV1::Ethereum(EthereumHeaderSegmentV1 {
                headers: Vec::new(),
            }),
        });
        assert!(
            !allows_unregistered_authority(&backfill, &account(1)),
            "a Backfill pays the ordinary fee, so its authority must exist"
        );
    }
}
