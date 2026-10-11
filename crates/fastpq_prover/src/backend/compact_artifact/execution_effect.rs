//! Whole ordinary artifact verification over independently bound complete effects.

use super::*;
use crate::{
    backend::{
        compact_bundle::execution_effect::{
            self as bundle, EffectVerificationInputs, EffectVerificationLimits,
        },
        offline_compact::{ExecutionEffectVerificationLimits, ExpectedExecutionEffects},
    },
    gadgets::public_transfer_statement::execution_effect::SourceExecutionEffectStatement,
};
use iroha_allocation::{AllocationBudget, AllocationReservation};

pub(in crate::backend) fn verify(
    bytes: &[u8],
    expected: ExpectedExecutionEffects<'_>,
    limits: &ExecutionEffectVerificationLimits,
    budget: &AllocationBudget,
    reservation: &mut AllocationReservation,
) -> Result<VerifiedArtifact, ArtifactError> {
    if !reservation.belongs_to(budget) {
        return Err(Error::AllocationForeignPool.into());
    }
    norito::core::with_decode_limits_scope(limits.total_decode, || {
        let profile = execution_effect_profile::execution_effect_profile_id();
        let artifact = FastpqOrdinaryCompactArtifactV1::decode_canonical_with_limits(
            bytes,
            profile,
            limits.transport,
        )?;
        if artifact.source != *expected.source {
            return Err(Error::PublicIoMismatch {
                field: "compact_artifact_execution_source",
            }
            .into());
        }
        let view = SourceExecutionEffectStatement::from_owned(&artifact.statement);
        // Hash the exact full canonical statement, not a transfer projection or advertised digest.
        let digest = view.digest(limits.public_policy().max_public_bytes)?;
        if digest != expected.statement.statement_digest {
            return Err(Error::PublicIoMismatch {
                field: "compact_artifact_public_statement_digest",
            }
            .into());
        }
        let public = limits.public_policy();
        for (limit, actual, max) in [
            (
                "max_execution_effects",
                view.effects().effects.len(),
                public.max_effects,
            ),
            (
                "max_execution_effect_rows",
                artifact.statement.transitions.len(),
                public.max_rows,
            ),
        ] {
            if actual > max {
                return Err(Error::VerifierLimitExceeded { limit, actual, max }.into());
            }
        }
        let checked = bundle::verify(
            &EffectVerificationInputs {
                statement: &view,
                source: expected.source,
                expected: expected.statement,
            },
            &artifact.bundle_frame,
            EffectVerificationLimits {
                public: limits.public_policy(),
                bundle: limits.bundle.internal(),
                max_segment_decode_allocation_charges: limits.max_segment_decode_allocation_charges,
            },
            budget,
            reservation,
        )?;
        finish_artifact_for_profile(
            FastpqProofKindV1::OrdinaryCompact,
            profile,
            digest.into(),
            bytes,
            &artifact.bundle_frame,
            checked,
        )
        .map_err(ArtifactError::Verify)
    })
}
