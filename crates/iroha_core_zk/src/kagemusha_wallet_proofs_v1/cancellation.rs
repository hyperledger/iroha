//! Typed cancellation classification at the native wallet proof boundary.
//! Invalid inputs, resource failures and cancellation never share a soft-verdict flag.

/// Exact error classification, implemented explicitly for each native source family.
pub(crate) trait NativeProofError {
    fn is_cancelled(&self) -> bool;
}

macro_rules! cancellable {
    ($($ty:ty),+ $(,)?) => {$(
        impl NativeProofError for $ty {
            fn is_cancelled(&self) -> bool { <$ty>::is_cancelled(self) }
        }
    )+};
}
cancellable!(
    super::Error,
    iroha_plonk::keys::KeyError,
    iroha_plonk::pcs::ipa::IpaError,
    iroha_plonk::VerifyError,
    iroha_plonk::ProverError,
    iroha_plonk_recursion::Error,
    iroha_kagemusha_proof::SigmaError,
    iroha_kagemusha_proof::admin_sigma::native::AdminSigmaError,
    iroha_kagemusha_proof::q_sigma::native::QSigmaError,
    iroha_kagemusha_proof::q_signature::native::QSignatureError,
);
macro_rules! cancellable_copy {
    ($($ty:ty),+ $(,)?) => {$(
        impl NativeProofError for $ty {
            fn is_cancelled(&self) -> bool { <$ty>::is_cancelled(*self) }
        }
    )+};
}
cancellable_copy!(
    iroha_kagemusha_proof::a_relation::native::bootstrap::Error,
    iroha_kagemusha_proof::a_relation::native::load::Error,
    iroha_kagemusha_proof::a_relation::native::send::Error,
    iroha_kagemusha_proof::a_relation::native::receive::Error,
    iroha_kagemusha_proof::a_relation::native::archive::Error,
    iroha_kagemusha_proof::a_relation::native::consuming::Error,
    iroha_kagemusha_proof::a_relation::native::refresh::Error,
    iroha_kagemusha_proof::omega::native::Error,
);

// These APIs decode fixed metadata or derive pinned parameters during trusted
// installation without taking a cancellation signal. Active wallet imports and
// folds borrow the installation's retained parameters. Their failures are hard;
// new arithmetic error families require an explicit cancellation review.
macro_rules! noncancellable {
    ($($ty:ty),+ $(,)?) => {$(
        impl NativeProofError for $ty {
            fn is_cancelled(&self) -> bool { false }
        }
    )+};
}
noncancellable!(
    norito::Error,
    iroha_plonk::keys::VkError,
    iroha_plonk::pcs::ipa::ParamsTrustError,
    iroha_kagemusha_proof::a_relation::native::artifact::ArtifactError,
    iroha_plonk::protocol::ProtocolError,
    iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletValidationErrorV1,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_cancellation_is_not_a_proof_or_profile_verdict() {
        assert!(NativeProofError::is_cancelled(
            &super::super::Error::Cancelled
        ));
        assert!(NativeProofError::is_cancelled(
            &iroha_plonk::ProverError::Cancelled
        ));
        for error in [
            super::super::Error::Proof,
            super::super::Error::Profile,
            super::super::Error::Unavailable,
            super::super::Error::Authority,
        ] {
            assert!(!NativeProofError::is_cancelled(&error));
        }
    }
}
