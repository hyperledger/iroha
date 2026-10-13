//! Finite source retries around completed local verification, before any submission.

use super::BuildError;
use iroha_sccp::light_client::SccpLcError;

/// The last original failure of a build-and-verify operation.
#[derive(Debug)]
pub enum VerifiedBuildError {
    /// Building from the selected source failed.
    Build(BuildError),
    /// Completed local verification rejected the built evidence.
    Verify(SccpLcError),
}
impl core::fmt::Display for VerifiedBuildError {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Build(error) => write!(output, "building source evidence: {error}"),
            Self::Verify(error) => write!(output, "verifying source evidence: {error}"),
        }
    }
}
impl std::error::Error for VerifiedBuildError {}

/// Build and verify with at most `attempts.max(1)` source selections.
///
/// Each verification must start from the same original committed state and selected profile;
/// never reuse a replay mutated by a failed attempt. Only malformed/inconsistent build data
/// or a typed invalid-source verification error rotates the endpoints. Transport failover
/// already has its own finite policy. This helper performs no signing or submission.
///
/// # Errors
/// Preserves the last build or verification failure; state, freshness, profile and physical
/// resource errors stop immediately without rotation.
pub fn build_verified<T>(
    attempts: usize,
    mut build: impl FnMut() -> Result<T, BuildError>,
    mut verify: impl FnMut(&T) -> Result<(), SccpLcError>,
    mut rotate: impl FnMut(),
) -> Result<T, VerifiedBuildError> {
    let mut remaining = attempts.max(1);
    loop {
        let error = match build() {
            Ok(value) => match verify(&value) {
                Ok(()) => return Ok(value),
                Err(error) => VerifiedBuildError::Verify(error),
            },
            Err(error) => VerifiedBuildError::Build(error),
        };
        let retry = match &error {
            VerifiedBuildError::Build(BuildError::Json(_) | BuildError::Inconsistent(_)) => true,
            VerifiedBuildError::Build(BuildError::Rpc(_) | BuildError::Unavailable(_)) => false,
            VerifiedBuildError::Verify(error) => error.is_invalid_source_data(),
        };
        remaining -= 1;
        if !retry || remaining == 0 {
            return Err(error);
        }
        rotate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::bridge::SccpNetworkV1;
    use std::cell::Cell;

    #[test]
    fn invalid_proof_rotates_before_rebuilding_and_never_returns_unverified_data() {
        let source = Cell::new(0);
        let calls = Cell::new(0);
        let result = build_verified(
            2,
            || {
                calls.set(calls.get() + 1);
                Ok(source.get())
            },
            |value| {
                if *value == 0 {
                    Err(SccpLcError::MalformedFrame("source"))
                } else {
                    Ok(())
                }
            },
            || source.set(source.get() + 1),
        );
        assert_eq!(result.unwrap(), 1);
        assert_eq!(calls.get(), 2);
        assert_eq!(source.get(), 1);
    }

    #[test]
    fn invalid_source_retries_are_finite_and_unrelated_refusals_do_not_rotate() {
        let rotations = Cell::new(0);
        let error = build_verified(
            3,
            || Ok(()),
            |()| Err(SccpLcError::MalformedFrame("source")),
            || rotations.set(rotations.get() + 1),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            VerifiedBuildError::Verify(SccpLcError::MalformedFrame("source"))
        ));
        assert_eq!(rotations.get(), 2);
        for error in [
            SccpLcError::Frozen(SccpNetworkV1::BscMainnet),
            SccpLcError::UnknownSigningSet { set_id: 1 },
        ] {
            rotations.set(0);
            let result = build_verified(
                3,
                || Ok(()),
                |()| Err(error),
                || rotations.set(rotations.get() + 1),
            );
            assert!(matches!(result, Err(VerifiedBuildError::Verify(actual)) if actual == error));
            assert_eq!(rotations.get(), 0);
        }
        rotations.set(0);
        let mut calls = 0;
        let value = build_verified(
            2,
            || {
                calls += 1;
                if calls == 1 {
                    Err(BuildError::Inconsistent("bad root".into()))
                } else {
                    Ok(7)
                }
            },
            |_| Ok(()),
            || rotations.set(rotations.get() + 1),
        )
        .unwrap();
        assert_eq!(value, 7);
        assert_eq!(rotations.get(), 1);
    }
}
