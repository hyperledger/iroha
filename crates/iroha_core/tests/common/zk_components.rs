//! Direct ZK handler fixtures, separate from signed transaction/root admission.
use iroha_core::{smartcontracts::Execute, state::StateTransaction};
use iroha_data_model::{
    ValidationFail,
    prelude::{AccountId, InstructionBox},
};

/// Execute one component handler with its real permissions and validation.
/// This helper provides no transaction, genesis or block-publication authority.
pub(crate) fn execute_isi_component(
    state: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
    instruction: InstructionBox,
) -> Result<(), ValidationFail> {
    macro_rules! run {
        ($($ty:ty),+ $(,)?) => {
            $(if let Some(value) = instruction.as_any().downcast_ref::<$ty>() {
                return value.clone().execute(authority, state)
                    .map_err(ValidationFail::InstructionFailed);
            })+
        };
    }
    run!(
        iroha_data_model::isi::verifying_keys::RegisterVerifyingKey,
        iroha_data_model::isi::verifying_keys::UpdateVerifyingKey,
        iroha_data_model::isi::zk::VerifyProof,
        iroha_data_model::isi::zk::PruneProofs,
        iroha_data_model::isi::zk::RegisterZkAsset,
        iroha_data_model::isi::zk::ScheduleConfidentialPolicyTransition,
        iroha_data_model::isi::zk::CancelConfidentialPolicyTransition,
        iroha_data_model::isi::RegisterBox,
        iroha_data_model::isi::GrantBox,
    );
    panic!("instruction is outside the explicit ZK component fixture")
}
