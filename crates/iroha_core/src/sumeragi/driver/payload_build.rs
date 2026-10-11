//! One retained builder source and its exact funded wire image, before RS16 authoring.

use std::io::{self, Write};

use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_sumeragi::{availability::PayloadBytes, message::ByteAdmissionError};

/// A local resource refusal preserves the original source and completed encoding.
#[derive(Debug)]
pub enum PayloadBuildError {
    /// Original pool or allocator refusal.
    Admission(ByteAdmissionError),
    /// The canonical writer failed; this source cannot safely be retried.
    Encoding(norito::Error),
    /// The exact canonical image exceeds the requested block limit.
    TooLarge,
    /// A previous writer failure poisoned this job.
    Poisoned,
}

impl PayloadBuildError {
    /// Whether the same owner can retry when the original pool has capacity.
    pub fn is_local_refusal(&self) -> bool {
        matches!(self, Self::Admission(error) if error.is_local_refusal())
    }
}

/// A concrete source may prepare its original children before canonical wire publication.
/// No source, mutable graph or allocation may escape this job through this interface.
pub(in crate::sumeragi) trait PayloadSourcePreparation {
    /// Exact owning-layer preparation refusal; never replaced with a string.
    type Error;
    /// Whether this same source already retains the supplied original pool.
    fn prepared_for(&self, budget: &AllocationBudget) -> bool;
    /// Prepare original children without consuming the source on refusal.
    fn prepare_for(&mut self, budget: &AllocationBudget) -> Result<(), Self::Error>;
}

/// Original concrete refusal or an attempt to change an already written source.
#[derive(Debug)]
pub(in crate::sumeragi) enum SourcePreparationError<E> {
    /// An unprepared source has a partial, poisoned or completed original wire image.
    Frozen,
    /// The concrete source retained its exact original preparation refusal.
    Source(E),
}

/// Owns the original application object until its exact wire bytes are admitted.
pub struct PayloadBuild<T> {
    source: T,
    budget: AllocationBudget,
    max_bytes: usize,
    bytes: Option<ChargedBuffer<u8>>,
    payload: Option<PayloadBytes>,
    encoded: bool,
    poisoned: bool,
}

impl<T> PayloadBuild<T> {
    /// Retain the selected source without encoding, cloning or allocating a bulk buffer.
    pub fn new(source: T, budget: AllocationBudget, max_bytes: usize) -> Self {
        Self {
            source,
            budget,
            max_bytes,
            bytes: None,
            payload: None,
            encoded: false,
            poisoned: false,
        }
    }

    /// Borrow the unchanged source for request identity and quarantine bookkeeping.
    pub fn source(&self) -> &T {
        &self.source
    }

    /// Whether the original source and its completed immutable output remain owned here.
    pub(in crate::sumeragi) fn is_completed(&self) -> bool {
        self.payload.is_some()
    }

    /// Borrow the actual retained encoding for source/refund regressions.
    /// This grants no input, parent or publication authority.
    #[cfg(test)]
    pub(crate) fn encoded_backing_for_test(&self) -> Option<&[u8]> {
        self.bytes.as_ref().map(ChargedBuffer::as_slice)
    }

    /// Encode directly into exact charged backing, then admit immutable shared custody.
    /// Completed encoding survives shared-control refusal without another writer call.
    ///
    /// # Errors
    /// Returns this same source and partial owner on every refusal or encoding failure.
    #[allow(
        clippy::result_large_err,
        reason = "retain the actual original source and backing"
    )]
    pub fn finish(
        mut self,
        length: impl FnOnce(&T) -> Result<usize, norito::Error>,
        encode: impl FnOnce(&T, &mut dyn Write) -> Result<(), norito::Error>,
    ) -> Result<(T, PayloadBytes), (Self, PayloadBuildError)> {
        match self.finish_retained(length, encode) {
            Ok(payload) => Ok((self.source, payload)),
            Err(error) => Err((self, error)),
        }
    }

    /// Lend the same admitted output while this job retains its unchanged original source.
    /// Completed canonical work survives later same-source requests; this method grants no
    /// authority to reuse it under a changed parent, request, journal or selected input.
    ///
    /// # Errors
    /// Retains the exact source, partial backing and concrete cause on every refusal.
    pub(in crate::sumeragi) fn finish_retained(
        &mut self,
        length: impl FnOnce(&T) -> Result<usize, norito::Error>,
        encode: impl FnOnce(&T, &mut dyn Write) -> Result<(), norito::Error>,
    ) -> Result<PayloadBytes, PayloadBuildError> {
        if self.poisoned {
            return Err(PayloadBuildError::Poisoned);
        }
        if let Some(payload) = self.payload.as_ref() {
            return Ok(payload.clone());
        }
        if !self.encoded {
            let length = match length(&self.source) {
                Ok(length) if length <= self.max_bytes => length,
                Ok(_) => return Err(PayloadBuildError::TooLarge),
                Err(error) => return Err(PayloadBuildError::Encoding(error)),
            };
            let mut bytes = match ChargedBuffer::new(length, &self.budget) {
                Ok(bytes) => bytes,
                Err(error) => {
                    return Err(PayloadBuildError::Admission(ByteAdmissionError::Buffer(
                        error,
                    )));
                }
            };
            let result = encode(&self.source, &mut FixedWriter(&mut bytes));
            self.bytes = Some(bytes);
            if let Err(error) = result {
                self.poisoned = true;
                return Err(PayloadBuildError::Encoding(error));
            }
            if self
                .bytes
                .as_ref()
                .expect("retained output")
                .as_slice()
                .len()
                != length
            {
                self.poisoned = true;
                return Err(PayloadBuildError::Encoding(norito::Error::LengthMismatch));
            }
            self.encoded = true;
        }
        let bytes = self.bytes.take().expect("completed original wire image");
        match PayloadBytes::from_charged(bytes, &self.budget) {
            Ok(payload) => {
                self.payload = Some(payload);
                Ok(self
                    .payload
                    .as_ref()
                    .expect("original admitted output")
                    .clone())
            }
            Err((bytes, error)) => {
                self.bytes = Some(bytes);
                Err(PayloadBuildError::Admission(error))
            }
        }
    }
}

impl<T> PayloadBuild<T> {
    /// Prepare the original graph only before its first writer invocation.
    /// Same-pool completed preparation is idempotent across later output refusals.
    pub(in crate::sumeragi) fn prepare_source(
        &mut self,
    ) -> Result<(), SourcePreparationError<T::Error>>
    where
        T: PayloadSourcePreparation,
    {
        if self.source.prepared_for(&self.budget) {
            return Ok(());
        }
        if self.poisoned || self.encoded || self.bytes.is_some() {
            return Err(SourcePreparationError::Frozen);
        }
        self.source
            .prepare_for(&self.budget)
            .map_err(SourcePreparationError::Source)
    }
}

struct FixedWriter<'a>(&'a mut ChargedBuffer<u8>);

impl Write for FixedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.append(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn source() -> Box<[u8]> {
        (0..127).collect::<Vec<u8>>().into_boxed_slice()
    }

    #[test]
    fn backing_refusal_keeps_original_source_without_encoding() {
        let budget = AllocationBudget::new(0);
        let source = source();
        let pointer = source.as_ptr();
        let job = PayloadBuild::new(source, budget.clone(), 127);
        let (job, error) = job
            .finish(|s| Ok(s.len()), |_, _| panic!("unfunded writer ran"))
            .err()
            .expect("funding must refuse");
        assert!(error.is_local_refusal());
        assert_eq!(job.source().as_ptr(), pointer);
        assert_eq!(budget.reserved_bytes(), 0);
        budget.set_limit_bytes(4096);
        let (source, payload) = job
            .finish(
                |s| Ok(s.len()),
                |s, w| {
                    w.write_all(s)?;
                    Ok(())
                },
            )
            .ok()
            .expect("same owner resumes");
        assert_eq!(source.as_ptr(), pointer);
        assert_eq!(payload.as_slice(), source.as_ref());
        assert!(payload.admitted_to(&budget));
        assert!(!payload.admitted_to(&AllocationBudget::new(4096)));
    }

    #[test]
    fn shared_control_refusal_keeps_exact_encoded_backing_without_reencoding() {
        let budget = AllocationBudget::new(4096);
        let calls = Cell::new(0);
        let job = PayloadBuild::new(source(), budget.clone(), 127);
        let (job, error) = job
            .finish(
                |s| Ok(s.len()),
                |s, w| {
                    calls.set(calls.get() + 1);
                    w.write_all(s)?;
                    budget.set_limit_bytes(budget.reserved_bytes());
                    Ok(())
                },
            )
            .err()
            .expect("shared control must refuse");
        assert!(error.is_local_refusal());
        let pointer = job.bytes.as_ref().unwrap().as_slice().as_ptr();
        let held = budget.reserved_bytes();
        let (job, _) = job
            .finish(
                |_| panic!("count repeated"),
                |_, _| panic!("encoding repeated"),
            )
            .err()
            .expect("refusal remains");
        assert_eq!(job.bytes.as_ref().unwrap().as_slice().as_ptr(), pointer);
        assert_eq!(budget.reserved_bytes(), held);
        budget.set_limit_bytes(4096);
        let (_, payload) = job
            .finish(
                |_| panic!("count repeated"),
                |_, _| panic!("encoding repeated"),
            )
            .ok()
            .expect("original backing shared");
        assert_eq!(payload.as_slice().as_ptr(), pointer);
        assert_eq!(calls.get(), 1);
        drop(payload);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn exact_cap_rejects_before_output_allocation() {
        let budget = AllocationBudget::new(4096);
        let job = PayloadBuild::new(source(), budget.clone(), 126);
        let (_, error) = job
            .finish(|s| Ok(s.len()), |_, _| panic!("oversize writer ran"))
            .err()
            .expect("cap");
        assert!(matches!(error, PayloadBuildError::TooLarge));
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn partial_writer_failure_never_reenters_source() {
        let budget = AllocationBudget::new(4096);
        let job = PayloadBuild::new(source(), budget, 127);
        let (job, error) = job
            .finish(
                |s| Ok(s.len()),
                |_, w| {
                    w.write_all(&[1, 2, 3])?;
                    Err(norito::Error::LengthMismatch)
                },
            )
            .err()
            .expect("writer failure");
        assert!(!error.is_local_refusal());
        let (job, error) = job
            .finish(
                |_| panic!("failed source counted"),
                |_, _| panic!("failed writer repeated"),
            )
            .err()
            .expect("poisoned");
        assert!(matches!(error, PayloadBuildError::Poisoned));
        assert_eq!(job.bytes.unwrap().as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn dishonest_length_and_overflow_cannot_publish_payload() {
        for claimed in [1, 128] {
            let job = PayloadBuild::new(source(), AllocationBudget::new(4096), 128);
            let (_, error) = job
                .finish(
                    |_| Ok(claimed),
                    |s, w| {
                        w.write_all(s)?;
                        Ok(())
                    },
                )
                .err()
                .expect("length mismatch");
            assert!(matches!(error, PayloadBuildError::Encoding(_)));
        }
    }

    struct PreparingSource {
        original: Box<[u8]>,
        reservation: Option<iroha_allocation::AllocationReservation>,
        preparations: usize,
    }

    impl PayloadSourcePreparation for PreparingSource {
        type Error = iroha_allocation::AllocationRefusal;

        fn prepared_for(&self, budget: &AllocationBudget) -> bool {
            self.reservation
                .as_ref()
                .is_some_and(|owner| owner.belongs_to(budget))
        }

        fn prepare_for(&mut self, budget: &AllocationBudget) -> Result<(), Self::Error> {
            let original = budget.try_reserve_bytes(1)?;
            self.reservation = Some(original);
            self.preparations += 1;
            Ok(())
        }
    }

    fn preparing_source() -> PreparingSource {
        PreparingSource {
            original: source(),
            reservation: None,
            preparations: 0,
        }
    }

    #[test]
    fn source_preparation_refusal_keeps_original_job_and_refusal_before_any_writer() {
        let budget = AllocationBudget::new(128);
        let pressure = budget.try_reserve_bytes(128).unwrap();
        let original = preparing_source();
        let pointer = original.original.as_ptr();
        let mut job = PayloadBuild::new(original, budget.clone(), 127);
        let SourcePreparationError::Source(error) = job.prepare_source().unwrap_err() else {
            panic!("original source refuses before first writer");
        };
        assert!(matches!(
            error,
            iroha_allocation::AllocationRefusal::Capacity {
                requested_bytes: 1,
                reserved_bytes: 128,
                limit_bytes: 128,
                ..
            }
        ));
        assert_eq!(job.source().original.as_ptr(), pointer);
        assert_eq!(job.source().preparations, 0);
        assert!(job.bytes.is_none());
        assert!(!job.encoded);
        assert!(!job.poisoned);
        drop(pressure);
        job.prepare_source().unwrap();
        assert_eq!(job.source().original.as_ptr(), pointer);
        assert_eq!(job.source().preparations, 1);
        assert_eq!(budget.reserved_bytes(), 1);
        drop(job);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn source_preparation_cannot_change_original_partial_or_completed_wire() {
        for completed in [false, true] {
            let budget = AllocationBudget::new(4096);
            let original = preparing_source();
            let pointer = original.original.as_ptr();
            let job = PayloadBuild::new(original, budget.clone(), 127);
            let (mut job, error) = job
                .finish(
                    |s| Ok(s.original.len()),
                    |s, writer| {
                        if completed {
                            writer.write_all(&s.original)?;
                            budget.set_limit_bytes(budget.reserved_bytes());
                            Ok(())
                        } else {
                            writer.write_all(&s.original[..3])?;
                            Err(norito::Error::LengthMismatch)
                        }
                    },
                )
                .err()
                .expect("retain original wire on writer/control refusal");
            assert_eq!(error.is_local_refusal(), completed);
            let wire = job.bytes.as_ref().unwrap().as_slice().as_ptr();
            let held = budget.reserved_bytes();
            assert!(matches!(
                job.prepare_source(),
                Err(SourcePreparationError::Frozen)
            ));
            assert_eq!(job.source().original.as_ptr(), pointer);
            assert_eq!(job.bytes.as_ref().unwrap().as_slice().as_ptr(), wire);
            assert_eq!(job.source().preparations, 0);
            assert_eq!(budget.reserved_bytes(), held);
        }
    }

    #[test]
    fn source_preparation_is_idempotent_through_exact_encoded_shared_control_retry() {
        let budget = AllocationBudget::new(4096);
        let calls = Cell::new(0);
        let original = preparing_source();
        let pointer = original.original.as_ptr();
        let mut job = PayloadBuild::new(original, budget.clone(), 127);
        job.prepare_source().unwrap();
        let (mut job, _) = job
            .finish(
                |s| Ok(s.original.len()),
                |s, writer| {
                    calls.set(calls.get() + 1);
                    writer.write_all(&s.original)?;
                    budget.set_limit_bytes(budget.reserved_bytes());
                    Ok(())
                },
            )
            .err()
            .expect("shared-control admission refuses after original encoding");
        let wire = job.bytes.as_ref().unwrap().as_slice().as_ptr();
        let held = budget.reserved_bytes();
        job.prepare_source().unwrap();
        assert_eq!(job.source().preparations, 1);
        assert_eq!(job.source().original.as_ptr(), pointer);
        assert_eq!(budget.reserved_bytes(), held);
        budget.set_limit_bytes(4096);
        let (source, payload) = job
            .finish(
                |_| panic!("completed original wire cannot be counted again"),
                |_, _| panic!("completed original wire cannot be encoded again"),
            )
            .ok()
            .expect("same completed original owner resumes");
        assert_eq!(source.original.as_ptr(), pointer);
        assert_eq!(payload.as_slice().as_ptr(), wire);
        assert_eq!(calls.get(), 1);
        assert_eq!(source.preparations, 1);
        assert!(payload.admitted_to(&budget));
        drop(payload);
        drop(source);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn retained_completion_lends_same_source_and_output_without_reencoding_or_new_charge() {
        let budget = AllocationBudget::new(4096);
        let calls = Cell::new(0);
        let original = preparing_source();
        let pointer = original.original.as_ptr();
        let mut job = PayloadBuild::new(original, budget.clone(), 127);
        assert!(!job.is_completed());
        job.prepare_source().unwrap();
        let original = job
            .finish_retained(
                |s| Ok(s.original.len()),
                |s, writer| {
                    calls.set(calls.get() + 1);
                    writer.write_all(&s.original)?;
                    Ok(())
                },
            )
            .unwrap();
        assert!(job.is_completed());
        assert!(job.bytes.is_none());
        assert!(original.admitted_to(&budget));
        let held = budget.reserved_bytes();
        let blocker = budget
            .try_reserve_bytes(budget.limit_bytes() - held)
            .unwrap();
        job.prepare_source().unwrap();
        let retry = job
            .finish_retained(
                |_| panic!("completed source counted again"),
                |_, _| panic!("completed source written again"),
            )
            .unwrap();
        assert!(std::ptr::eq(
            original.as_slice().as_ptr(),
            retry.as_slice().as_ptr()
        ));
        assert_eq!(job.source().original.as_ptr(), pointer);
        assert_eq!(job.source().preparations, 1);
        assert_eq!(calls.get(), 1);
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        drop(blocker);
        // The existing consuming API delegates to the same kernel and moves this
        // source; it does not replace either original backing or shared control.
        let (source, consumed) = job
            .finish(
                |_| panic!("completed consuming source counted again"),
                |_, _| panic!("completed consuming source written again"),
            )
            .ok()
            .expect("move the original completed source");
        assert_eq!(source.original.as_ptr(), pointer);
        assert!(std::ptr::eq(
            original.as_slice().as_ptr(),
            consumed.as_slice().as_ptr()
        ));
        assert_eq!(budget.reserved_bytes(), held);
        drop((source, retry, consumed));
        assert_eq!(budget.reserved_bytes(), held - 1);
        drop(original);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn retained_completion_preserves_exact_shared_refusal_and_successful_writer() {
        let budget = AllocationBudget::new(4096);
        let original = source();
        let source_pointer = original.as_ptr();
        let mut job = PayloadBuild::new(original, budget.clone(), 127);
        let error = job
            .finish_retained(
                |s| Ok(s.len()),
                |s, writer| {
                    writer.write_all(s)?;
                    budget.set_limit_bytes(budget.reserved_bytes());
                    Ok(())
                },
            )
            .unwrap_err();
        assert!(error.is_local_refusal());
        assert!(!job.is_completed());
        let pointer = job.bytes.as_ref().unwrap().as_slice().as_ptr();
        let held = budget.reserved_bytes();
        let retry = job
            .finish_retained(
                |_| panic!("refused original count repeated"),
                |_, _| panic!("refused original writer repeated"),
            )
            .unwrap_err();
        match (error, retry) {
            (
                PayloadBuildError::Admission(ByteAdmissionError::ControlAdmission(original)),
                PayloadBuildError::Admission(ByteAdmissionError::ControlAdmission(actual)),
            ) => {
                assert_eq!(original, actual);
            }
            _ => panic!("retry must retain the exact shared admission cause"),
        }
        assert_eq!(job.source().as_ptr(), source_pointer);
        assert_eq!(job.bytes.as_ref().unwrap().as_slice().as_ptr(), pointer);
        assert_eq!(budget.reserved_bytes(), held);
        budget.set_limit_bytes(4096);
        let output = job
            .finish_retained(
                |_| panic!("admitted original count repeated"),
                |_, _| panic!("admitted original writer repeated"),
            )
            .unwrap();
        assert!(job.is_completed());
        assert_eq!(output.as_slice().as_ptr(), pointer);
        drop(output);
        assert!(budget.reserved_bytes() >= held);
        drop(job);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn retained_completed_source_cannot_acquire_preparation_after_its_canonical_writer() {
        let budget = AllocationBudget::new(4096);
        let original = preparing_source();
        let pointer = original.original.as_ptr();
        let mut job = PayloadBuild::new(original, budget.clone(), 127);
        let output = job
            .finish_retained(
                |s| Ok(s.original.len()),
                |s, writer| {
                    writer.write_all(&s.original)?;
                    Ok(())
                },
            )
            .unwrap();
        let held = budget.reserved_bytes();
        assert!(job.is_completed());
        assert!(matches!(
            job.prepare_source(),
            Err(SourcePreparationError::Frozen)
        ));
        assert_eq!(job.source().original.as_ptr(), pointer);
        assert_eq!(job.source().preparations, 0);
        assert_eq!(budget.reserved_bytes(), held);
        drop((job, output));
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
