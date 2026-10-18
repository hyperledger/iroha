//! Parameter module split into system and custom parameters.
pub mod custom;
pub mod execution_output;
pub mod fastpq_source;
pub mod governance_clock;
pub mod parliament_ballot;
pub use execution_output::ExecutionOutputPolicyV1;
pub use fastpq_source::{
    FastpqMandatorySourcePolicyV1, FastpqSourceLimitsV1, FastpqSourcePolicyV1,
};
pub use governance_clock::GovernanceClockParametersV1;
pub use parliament_ballot::ParliamentBallotParametersV1;
pub mod system;
pub(crate) use custom::CustomParameters;
pub use custom::{CustomParameter, CustomParameterId};
pub use system::{
    BlockParameter, BlockParameters, Parameter, Parameters, SmartContractParameter,
    SmartContractParameters, SumeragiParameter, SumeragiParameters, TransactionParameter,
    TransactionParameters,
};
pub mod prelude {
    //! Prelude: re-export of most commonly used traits, structs and macros in this crate.
    pub use super::{Parameter, Parameters, SmartContractParameters, TransactionParameters};
}

#[cfg(test)]
mod captured_parameter_identity_tests;

#[cfg(test)]
mod execution_output_parameter_tests;
