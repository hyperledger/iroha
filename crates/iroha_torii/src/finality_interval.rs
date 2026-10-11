//! Request-owned native interval production and exact last-byte response custody.
//!
//! One actual query reservation funds the original Core owner, cooperative stop
//! control and encoded response. No response DTO is copied into another graph.
//! Nested native verifier graphs retain the Core producer's explicit TODO; this
//! route does not turn a cumulative decode allowance into physical graph custody.

use super::*;
use iroha_allocation::ChargedShared;
use iroha_core::{
    state::{FinalityProofIntervalReadError, StateViewError},
    sumeragi::finality::{
        NativeFinalityProofInterval, NativeFinalityProofIntervalError,
        NativeFinalityProofIntervalLimits, ProofDestinationError,
    },
};
use iroha_data_model::sumeragi_finality::{MAX_FINALITY_BLOCK_BYTES, SumeragiFinalityProof};
use std::{num::NonZeroUsize, sync::atomic::Ordering};

/// Original outer HTTP deadline, captured before route admission or physical work.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RouteExecutionDeadline(pub(crate) Instant);

struct CancelOnDrop {
    // Retire the charged control before the last original query credit, including
    // an unpolled HTTP future whose native worker has already returned an error.
    flag: ChargedShared<AtomicBool>,
    #[cfg(not(all(test, sumeragi_torii_mutation = "TOR3")))]
    _owner: history_producer::HistoryProducerOwner,
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.flag.store(true, Ordering::Release);
    }
}
impl CancelOnDrop {
    fn new(owner: &history_producer::HistoryProducerOwner) -> Result<Self, Error> {
        let mut reservation = owner
            .response_metadata()
            .try_reserve(ChargedShared::<AtomicBool>::allocation_layout())
            .map_err(|_| native_projection_response::capacity())?;
        ChargedShared::from_reservation(AtomicBool::new(false), &mut reservation)
            .map(|flag| Self {
                flag,
                #[cfg(not(all(test, sumeragi_torii_mutation = "TOR3")))]
                _owner: owner.clone(),
            })
            .map_err(|_| native_projection_response::capacity())
    }
}

/// Current single-proof and interval responses share one actual native producer.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Selection {
    /// Preserve the existing standalone canonical proof response shape.
    Single(u64),
    /// Retain at most 64 consecutive canonical proofs without another response graph.
    Interval { from: u64, to: u64 },
}
impl Selection {
    /// Exact requested first and final heights for the shared producer.
    pub(crate) fn range(self) -> (u64, u64) {
        match self {
            Self::Single(height) => (height, height),
            Self::Interval { from, to } => (from, to),
        }
    }
    /// Preserve the existing independent admission key for standalone reads.
    pub(crate) fn rate_hint(self) -> &'static str {
        match self {
            Self::Single(_) => "/v1/bridge/finality/{height}",
            Self::Interval { .. } => "/v1/bridge/finality/interval/{from}/{to}",
        }
    }
    /// Charge the actual response against its route's existing egress key.
    pub(crate) fn egress_hint(self) -> &'static str {
        match self {
            Self::Single(_) => "v1/bridge/finality",
            Self::Interval { .. } => "v1/bridge/finality/interval",
        }
    }
}

/// Exact body extent accompanies the already prepaid HTTP source; no collection follows.
pub(crate) struct PreparedResponse {
    /// Already admitted canonical body retaining its original query owner.
    pub(crate) response: AxResponse,
    /// Complete encoded HTTP content extent, including canonical outer framing.
    pub(crate) bytes: usize,
}
impl PreparedResponse {
    fn deadline(format: ResponseFormat) -> Self {
        Self {
            response: route_timeout_error_response(format),
            bytes: 0,
        }
    }
}

fn invalid_interval() -> Error {
    Error::AppQueryValidation {
        code: "invalid_finality_interval",
        message: "Finality intervals require 1 to 64 consecutive positive heights.".to_owned(),
    }
}
fn source_error(error: FinalityProofIntervalReadError) -> Error {
    match error {
        FinalityProofIntervalReadError::StateView(StateViewError::Busy(_)) => {
            Error::AppServiceUnavailable {
                code: "finality_history_busy",
                message: "The original State publication has not completed.".to_owned(),
            }
        }
        FinalityProofIntervalReadError::Proof(NativeFinalityProofIntervalError::Backing(_))
        | FinalityProofIntervalReadError::Proof(NativeFinalityProofIntervalError::Destination(
            ProofDestinationError::Admission(_)
            | ProofDestinationError::Buffer(_)
            | ProofDestinationError::Key(_),
        )) => native_projection_response::capacity(),
        FinalityProofIntervalReadError::Proof(NativeFinalityProofIntervalError::Proof(
            iroha_core::sumeragi::finality::ProofError::Deferred(original),
        )) => canonical_history::query_attempt_error(
            iroha_core::execution_attempt::ExecutionAttemptError::Deferred(original),
        ),
        FinalityProofIntervalReadError::Proof(NativeFinalityProofIntervalError::Proof(error)) => {
            routing::map_current_finality_error(error)
        }
        error => Error::Query(iroha_data_model::ValidationFail::InternalError(
            error.to_string(),
        )),
    }
}

// Canonical Vec framing borrows the original immutable proofs. Both binary and
// JSON emission use the existing codec's sequence/leaf kernels, never reencoding
// a proof through a copied Vec or constructing an unchecked response authority.
#[derive(Clone, Copy)]
struct BorrowedInterval<'a>(&'a NativeFinalityProofInterval);
impl BorrowedInterval<'_> {
    fn proofs(&self) -> impl ExactSizeIterator<Item = &SumeragiFinalityProof> {
        (0..self.0.len()).map(move |index| self.0.proof(index).expect("immutable interval member"))
    }
}
impl norito::NoritoSchema for BorrowedInterval<'_> {
    fn nominal_name() -> String {
        "iroha_torii::finality_interval::BorrowedInterval<'_>".to_owned()
    }
    fn frame_name() -> String {
        <Vec<SumeragiFinalityProof> as norito::NoritoSchema>::frame_name()
    }
}
impl norito::core::SerializePayload for BorrowedInterval<'_> {
    fn serialize(&self, out: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        norito::core::write_element_sequence::<SumeragiFinalityProof, _>(out, self.proofs())
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::sequence_encoded_len_hint(self.proofs())
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::sequence_encoded_len_exact(self.proofs())
    }
}
impl norito::json::JsonSerialize for BorrowedInterval<'_> {
    fn json_serialize(&self, out: &mut String) {
        out.push('[');
        for (index, proof) in self.proofs().enumerate() {
            if index != 0 {
                out.push(',');
            }
            norito::json::JsonSerialize::json_serialize(proof, out);
        }
        out.push(']');
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| {
            out.push('[')?;
            for (index, proof) in self.proofs().enumerate() {
                if index != 0 {
                    out.push(',')?;
                }
                norito::json::JsonSerialize::json_serialize_to(proof, out)?;
            }
            out.push(']')
        })();
        out.end_container();
        result
    }
}

/// Produce and encode under the original physical worker, response and deadline owners.
pub(crate) async fn prepare(
    state: Arc<CoreState>,
    selection: Selection,
    format: ResponseFormat,
    admission: QueryAdmissionPermit,
    response_limit: usize,
    deadline: Instant,
) -> Result<PreparedResponse, Error> {
    let (from, to) = selection.range();
    let from = NonZeroU64::new(from).ok_or_else(invalid_interval)?;
    let to = NonZeroU64::new(to).ok_or_else(invalid_interval)?;
    let owner = history_producer::HistoryProducerOwner::from_admission(&admission)?;
    // Keep both configured HTTP content and the actual response corridor; neither
    // the interval count nor a native frame-length receipt grants more bytes.
    let response_limit = response_limit.min(owner.response_bytes());
    let limits = NativeFinalityProofIntervalLimits::new(
        from,
        to,
        NonZeroUsize::new(MAX_FINALITY_BLOCK_BYTES).expect("positive canonical block ceiling"),
        NonZeroUsize::new(response_limit).ok_or_else(native_projection_response::capacity)?,
        deadline,
    )
    .map_err(|_| invalid_interval())?;
    if Instant::now() >= deadline {
        return Ok(PreparedResponse::deadline(format));
    }
    run_with_stop(admission, owner, move |owner, physical_cancel| {
        let interval = match state.read_finality_proof_interval(
            &owner.canonical_history_budget(),
            &limits,
            &physical_cancel,
        ) {
            Ok(interval) => interval,
            Err(FinalityProofIntervalReadError::Proof(
                NativeFinalityProofIntervalError::Deadline
                | NativeFinalityProofIntervalError::Destination(ProofDestinationError::Deadline),
            )) => return Ok(PreparedResponse::deadline(format)),
            Err(error) => return Err(source_error(error)),
        };
        let encoded = match selection {
            Selection::Single(_) => native_projection_response::encode(
                interval.proof(0).expect("successful singleton interval"),
                format,
                response_limit,
                owner.cold_frames(),
                native_projection_response::capacity,
            ),
            Selection::Interval { .. } => native_projection_response::encode(
                &BorrowedInterval(&interval),
                format,
                response_limit,
                owner.cold_frames(),
                native_projection_response::capacity,
            ),
        }?;
        // The full outer header and sequence framing were counted before
        // allocation. Core's individual-frame sum is never the HTTP extent.
        let bytes = encoded.as_ref().len();
        drop(interval);
        if Instant::now() >= deadline {
            return Ok(PreparedResponse::deadline(format));
        }
        if physical_cancel.load(Ordering::Acquire) {
            return Err(native_projection_response::capacity());
        }
        let encoded = response_memory_custody::owned(encoded, &owner)
            .map_err(|_| native_projection_response::capacity())?;
        let mut response = response_memory_custody::json(encoded, &owner)
            .map_err(|_| native_projection_response::capacity())?;
        if matches!(format, ResponseFormat::Norito) {
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-norito"),
            );
        }
        Ok(PreparedResponse { response, bytes })
    })
    .await
}

async fn run_with_stop<T, F>(
    admission: QueryAdmissionPermit,
    owner: history_producer::HistoryProducerOwner,
    work: F,
) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce(
            history_producer::HistoryProducerOwner,
            ChargedShared<AtomicBool>,
        ) -> Result<T, Error>
        + Send
        + 'static,
{
    let cancelled = CancelOnDrop::new(&owner)?;
    let physical_cancel = cancelled.flag.clone();
    let result = routing::run_admitted_blocking(
        admission,
        "finite finality interval worker failed",
        move || work(owner, physical_cancel),
    )
    .await;
    // On cancellation this guard is dropped with the HTTP future. The physical
    // worker keeps the original flag and every admission permit until it retires.
    drop(cancelled);
    result
}

#[cfg(test)]
mod tests;
