//! Actual candidate canonical context, stamp and proof verification inside the arena.
//!
//! The caller supplies authenticated context bytes and trusted body/network identity.
//! Recomputing context digests does not authenticate the originating chain history.

use std::sync::Arc;

use iroha_data_model::{
    NetworkId,
    governance::{
        anonymous_ballot::{AuthenticatedBallotContextV1, BallotScopeV1, NullifierV1},
        types::BodyInstanceId,
    },
};
use iroha_parliament_ballot::{
    ballot::{
        BlockBallotStateV1, BlockBallotValidityV1, BlockInvalidReasonV1, check_block_ballot_v1,
    },
    context::ScopedBallotContextV1,
};

/// Fixed metadata crosses the worker boundary; no decoded value or error owner escapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub outcome: &'static str,
    pub stage: &'static str,
    pub exit: i32,
}

impl Outcome {
    pub const fn new(outcome: &'static str, stage: &'static str, exit: i32) -> Self {
        Self {
            outcome,
            stage,
            exit,
        }
    }

    pub const fn unavailable(stage: &'static str) -> Self {
        Self::new("worker_error", stage, 4)
    }
}

struct Scope {
    network: NetworkId,
    context: Arc<ScopedBallotContextV1>,
}

impl BlockBallotStateV1 for Scope {
    fn network_id(&self) -> NetworkId {
        self.network
    }

    fn scope_context(&self, scope: &BallotScopeV1) -> Option<Arc<ScopedBallotContextV1>> {
        (scope == self.context.scope()).then(|| Arc::clone(&self.context))
    }

    // check_block_ballot_v1 deliberately never asks for execution decisions. These
    // conservative answers grant no casting-window or nullifier authority.
    fn casting_open(&self, _: &BallotScopeV1) -> bool {
        false
    }

    fn nullifier_accepted(&self, _: &BallotScopeV1, _: &NullifierV1) -> bool {
        true
    }
}

/// Decode the complete context, recompute all derived fields, verify the actual stamp
/// and proof, and destroy every decoded/derived value before returning fixed metadata.
pub fn cold(envelope: &[u8], context: &[u8], network: NetworkId, body: BodyInstanceId) -> Outcome {
    let context = match AuthenticatedBallotContextV1::decode_canonical_bounded(context) {
        Ok(context) => context,
        Err(_) => return Outcome::unavailable("context_decode"),
    };
    if context.body_context.network_id != network {
        return Outcome::unavailable("context_network");
    }
    let context = match ScopedBallotContextV1::new(context, body) {
        Ok(context) => Arc::new(context),
        Err(_) => return Outcome::unavailable("context_check"),
    };
    let state = Scope { network, context };
    match check_block_ballot_v1(&state, envelope) {
        Ok(BlockBallotValidityV1::Valid(_)) => Outcome::new("accepted", "complete", 0),
        Ok(BlockBallotValidityV1::Invalid(reason)) => rejected(reason),
        Err(_) => Outcome::unavailable("verification_unavailable"),
    }
}

fn rejected(reason: BlockInvalidReasonV1) -> Outcome {
    let stage = match reason {
        BlockInvalidReasonV1::Oversize { .. } => "envelope_size",
        BlockInvalidReasonV1::Malformed { .. } => "envelope_decode",
        BlockInvalidReasonV1::WrongNetwork => "envelope_network",
        BlockInvalidReasonV1::UnknownScope => "envelope_scope",
        BlockInvalidReasonV1::UnknownProfile => "envelope_profile",
        BlockInvalidReasonV1::InsufficientStamp => "stamp",
        BlockInvalidReasonV1::ProofLength { .. } => "proof_length",
        BlockInvalidReasonV1::ProofRejected => "proof",
    };
    Outcome::new("rejected", stage, 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::CONTEXT_MAX;

    #[test]
    fn invalid_ballots_and_local_unavailability_are_distinct() {
        let reasons = [
            BlockInvalidReasonV1::Oversize { actual: 1, max: 0 },
            BlockInvalidReasonV1::Malformed {
                reason: "test".into(),
            },
            BlockInvalidReasonV1::WrongNetwork,
            BlockInvalidReasonV1::UnknownScope,
            BlockInvalidReasonV1::UnknownProfile,
            BlockInvalidReasonV1::InsufficientStamp,
            BlockInvalidReasonV1::ProofLength {
                expected: 1,
                actual: 0,
            },
            BlockInvalidReasonV1::ProofRejected,
        ];
        let labels = [
            "envelope_size",
            "envelope_decode",
            "envelope_network",
            "envelope_scope",
            "envelope_profile",
            "stamp",
            "proof_length",
            "proof",
        ];
        for (reason, label) in reasons.into_iter().zip(labels) {
            assert_eq!(rejected(reason), Outcome::new("rejected", label, 1));
        }
        for stage in [
            "context_decode",
            "context_network",
            "context_check",
            "verification_unavailable",
        ] {
            assert_eq!(
                Outcome::unavailable(stage),
                Outcome::new("worker_error", stage, 4)
            );
        }
    }

    #[test]
    fn malformed_context_never_claims_invalid_proof() {
        let literal = norito::literal::format("hash", &"11".repeat(32));
        let network = literal.parse().unwrap();
        for bytes in [Vec::new(), vec![0; 10], vec![0; CONTEXT_MAX + 1]] {
            assert_eq!(
                cold(&[], &bytes, network, BodyInstanceId::new([3; 32])),
                Outcome::unavailable("context_decode")
            );
        }
    }
}
