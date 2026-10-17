//! One retained original global cut and native branch through every local acquisition refusal.

use iroha_data_model::block::consensus::LaneEvidenceScope;
use iroha_sumeragi::message::Evidence;

use super::{NativeEvidenceError, VerifiedNativeEvidence, lane::LaneProofRead};
use crate::sumeragi::runtime_availability::history::{
    HistoryCapture, HistoryScan, LaneEvidenceContext,
};

enum Stage {
    Captured(HistoryCapture),
    History(HistoryScan),
    Context(LaneEvidenceContext),
    Native(LaneProofRead),
    Consumed,
}
/// The caller owns this job until completion or explicit cancellation of its original State cut.
/// Construction performs no disk I/O; the original World view must be dropped before polling.
pub(crate) struct LaneEvidenceRead {
    scope: LaneEvidenceScope,
    height: u64,
    stage: Stage,
}
impl LaneEvidenceRead {
    pub(in crate::sumeragi) fn new(
        capture: HistoryCapture,
        scope: LaneEvidenceScope,
        height: u64,
    ) -> Self {
        Self {
            scope,
            height,
            stage: Stage::Captured(capture),
        }
    }
    pub(crate) fn poll(
        &mut self,
        evidence: &Evidence,
    ) -> Result<VerifiedNativeEvidence, NativeEvidenceError> {
        if super::subject(evidence).1 != self.height {
            return Err(NativeEvidenceError::Context(
                "native evidence subject differs from its original read".into(),
            ));
        }
        loop {
            // Borrow the active read while it performs nested canonical decoding. Moving the
            // whole stage here keeps several large debug temporaries below the decoder and
            // can overflow a normal test/embedding thread before local refusal is observable.
            match &mut self.stage {
                Stage::Captured(_) => self.open_history()?,
                Stage::History(history) => {
                    history.complete().map_err(NativeEvidenceError::Source)?;
                    self.finish_history()?;
                }
                Stage::Context(_) => self.open_native()?,
                Stage::Native(native) => {
                    native.poll().map_err(NativeEvidenceError::Source)?;
                    return native.verify(evidence);
                }
                Stage::Consumed => {
                    return Err(NativeEvidenceError::Source(
                        std::io::Error::from(std::io::ErrorKind::InvalidData).into(),
                    ));
                }
            }
        }
    }
    fn open_history(&mut self) -> Result<(), NativeEvidenceError> {
        let Stage::Captured(capture) = std::mem::replace(&mut self.stage, Stage::Consumed) else {
            return Err(NativeEvidenceError::Source(
                std::io::Error::from(std::io::ErrorKind::InvalidData).into(),
            ));
        };
        match HistoryScan::open_for_evidence(capture, self.scope) {
            Ok(history) => {
                self.stage = Stage::History(history);
                Ok(())
            }
            Err((capture, error)) => {
                self.stage = Stage::Captured(capture);
                Err(NativeEvidenceError::Source(error))
            }
        }
    }
    fn finish_history(&mut self) -> Result<(), NativeEvidenceError> {
        let Stage::History(history) = std::mem::replace(&mut self.stage, Stage::Consumed) else {
            return Err(NativeEvidenceError::Source(
                std::io::Error::from(std::io::ErrorKind::InvalidData).into(),
            ));
        };
        // Complete authentication does not waive the ambient decoder field ceiling.
        // The consuming handoff returns the original history on every failure.
        match history.finish_evidence() {
            Ok(context) => {
                self.stage = Stage::Context(context);
                Ok(())
            }
            Err((history, error)) => {
                if !cfg!(all(test, sumeragi_core_mutation = "HC6")) {
                    self.stage = Stage::History(history);
                }
                Err(NativeEvidenceError::Source(error))
            }
        }
    }
    fn open_native(&mut self) -> Result<(), NativeEvidenceError> {
        let Stage::Context(context) = std::mem::replace(&mut self.stage, Stage::Consumed) else {
            return Err(NativeEvidenceError::Source(
                std::io::Error::from(std::io::ErrorKind::InvalidData).into(),
            ));
        };
        let frontier = match context.payload.custody_record(&self.scope.incarnation) {
            Ok(row) => row.map(|row| row.frontier()),
            Err(error) => {
                self.stage = Stage::Context(context);
                return Err(NativeEvidenceError::Source(
                    crate::sumeragi::runtime_availability::history::payload_error(error),
                ));
            }
        };
        if frontier.is_some_and(|frontier| {
            self.height
                .checked_sub(1)
                .is_none_or(|parent| parent > frontier.height)
        }) {
            self.stage = Stage::Context(context);
            return Err(NativeEvidenceError::Context(
                "native subject lacks original globally merged coverage".into(),
            ));
        }
        match LaneProofRead::new(context, self.height) {
            Ok(native) => {
                self.stage = Stage::Native(native);
                Ok(())
            }
            Err((context, error)) => {
                self.stage = Stage::Context(context);
                Err(NativeEvidenceError::Source(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::StateReadOnly;
    use std::io;
    #[test]
    fn completed_lane_history_retains_original_owner_on_finish_decode_refusal() {
        let (chain, record, _guard) =
            crate::sumeragi::runtime_availability::tests::npos_fixed_lane_chain_at(4);
        let state = chain.state();
        let generation = state.state_view_generation();
        let budget = state.ivm_execution_budget();
        let baseline = budget.reserved_bytes();
        let view = state.view();
        let tip = view.native_execution_tip().unwrap();
        let capture = HistoryCapture::from_view(state, &view, generation)
            .unwrap()
            .unwrap();
        let scope = LaneEvidenceScope {
            lane: record.lane,
            incarnation: record.incarnation,
            created_at: record.created_at,
            admission_parent_height: tip.height(),
            admission_parent_hash: tip.iroha_hash(),
            admission_parent_core_hash: tip.core_hash().0,
            admission_parent_result: tip.result().0,
        };
        drop(view);
        let mut reader = LaneEvidenceRead::new(capture, scope, 1);
        reader.open_history().unwrap();
        let Stage::History(history) = &mut reader.stage else {
            panic!("original history")
        };
        history.complete().unwrap();
        let retained = budget.reserved_bytes();
        assert!(retained > baseline);
        norito::core::with_decode_limits_scope(
            norito::core::DecodeLimits::new(1024, 1, 4096, 0, 32),
            || {
                assert!(matches!(reader.finish_history(),
                    Err(NativeEvidenceError::Source(error)) if error.io_kind() == io::ErrorKind::WouldBlock));
            },
        );
        assert!(
            matches!(&reader.stage, Stage::History(_)),
            "even borrowed field inspection can refuse the active local decode ceiling"
        );
        assert_eq!(budget.reserved_bytes(), retained);
        reader.finish_history().unwrap();
        assert!(matches!(&reader.stage, Stage::Context(_)));
        let retained = budget.reserved_bytes();
        norito::core::with_decode_limits_scope(
            norito::core::DecodeLimits::new(1024, 1, 4096, 0, 32),
            || {
                assert!(
                    matches!(reader.open_native(), Err(NativeEvidenceError::Source(error))
                if error.io_kind() == io::ErrorKind::WouldBlock && matches!(error, crate::execution_attempt::ExecutionAttemptError::Deferred(_)))
                )
            },
        );
        assert!(matches!(&reader.stage, Stage::Context(_)));
        assert_eq!(budget.reserved_bytes(), retained);
        reader.open_native().unwrap();
        assert!(matches!(&reader.stage, Stage::Native(_)));
        drop(reader);
        assert_eq!(budget.reserved_bytes(), baseline);
    }
}
