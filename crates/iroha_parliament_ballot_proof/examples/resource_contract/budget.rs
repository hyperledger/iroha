//! Atomic reservation for one complete bounded standalone verification.
//!
//! One unit buys one cold call, including record/statement decoding, descriptor
//! construction, public validation, proof verification and ordinary-return
//! cleanup. The same unit applies to both rows, both roles, all actual list sizes
//! up to 1,000, and both feature modes. Malformed input earns no refund. This is
//! an abstract service reservation, not a CPU instruction count, calibrated gas
//! price, admission stamp difficulty or qualified production `B_work` value.
//!
//! The byte debit is the actual outer `TEST_RECORD` slice length. It includes
//! the test statement's list/context and is not production envelope `B_bytes`.
//! Input size and both budgets are checked before reading or copying the record.
//! Admission rejects perform only fixed-size arithmetic; callers must separately
//! bound their admission request rate. A granted reservation stays spent even if
//! it is dropped, its input length changes, verification fails, or a worker dies.
//! No wall clock, allocator observation, hardware feature or claimed seat count
//! participates in charging. Production qualification remains false.

use iroha_parliament_ballot_proof::{
    profile::{Profile, ProfileError, Role, Row},
    proving::VerifyError,
    registration,
    test_codec::{self, TestCodecError},
    vote,
};
use thiserror::Error;

/// Largest outer test record admitted by this experimental service.
///
/// Every canonical supported record fits this cap, including 1,000-entry lists.
/// The cap alone supplies no production schema or ingress-memory certificate.
pub const MAX_INPUT_BYTES: usize = 425_984;

/// One complete bounded cold verification, without a validity-dependent refund.
pub const VERIFICATION_UNITS: u64 = 1;

/// Why a reservation was refused before any record read, copy or verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AdmissionError {
    /// The actual outer slice length exceeds the service cap.
    #[error("input length {actual} exceeds the service cap {limit}")]
    InputTooLarge {
        /// Actual outer length, never a length decoded from the record.
        actual: usize,
        /// Maximum length accepted by this service.
        limit: usize,
    },
    /// There is no full verification reservation left.
    #[error("verification reservation budget exhausted")]
    WorkExhausted,
    /// The exact outer length exceeds the remaining byte allowance.
    #[error("input byte budget exhausted")]
    BytesExhausted,
}

/// The amount irreversibly debited for an admitted invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Charge {
    /// Complete verification calls reserved; always [`VERIFICATION_UNITS`].
    pub verification_units: u64,
    /// Actual admitted outer input length, not a declared payload length.
    pub input_bytes: u64,
}

/// Remaining quotas for a serialized sequence of standalone calls.
///
/// This object is deliberately not `Clone`; it is an accounting owner, not a
/// security authority or a replacement for committed production policy.
#[derive(Debug, PartialEq, Eq)]
pub struct Budget {
    units: u64,
    input_bytes: u64,
}

impl Budget {
    /// Create explicit quotas; no default, environment or hardware calibration.
    pub const fn new(units: u64, input_bytes: u64) -> Self {
        Self { units, input_bytes }
    }

    /// Complete verification reservations still available.
    pub const fn remaining_units(&self) -> u64 {
        self.units
    }

    /// Outer input bytes still available.
    pub const fn remaining_input_bytes(&self) -> u64 {
        self.input_bytes
    }

    /// Debit both quotas atomically before the caller copies or decodes input.
    ///
    /// A token authorizes at most one verification of a slice of `input_len`.
    /// Its contents may be arbitrary; they receive no shape-dependent discount.
    /// Dropping the token never restores the debit.
    ///
    /// # Errors
    /// [`AdmissionError`], checking outer size, work and bytes in that order.
    /// Every refusal leaves both balances unchanged.
    pub fn reserve(&mut self, input_len: usize) -> Result<Reservation, AdmissionError> {
        if input_len > MAX_INPUT_BYTES {
            return Err(AdmissionError::InputTooLarge {
                actual: input_len,
                limit: MAX_INPUT_BYTES,
            });
        }
        // The service cap fits u32, hence every supported usize/u64 target.
        let input_bytes = u64::try_from(input_len).map_err(|_| AdmissionError::InputTooLarge {
            actual: input_len,
            limit: MAX_INPUT_BYTES,
        })?;
        let units_left = self
            .units
            .checked_sub(VERIFICATION_UNITS)
            .ok_or(AdmissionError::WorkExhausted)?;
        let bytes_left = self
            .input_bytes
            .checked_sub(input_bytes)
            .ok_or(AdmissionError::BytesExhausted)?;
        // Only commit after both checks succeed. No wrapping or saturating debit.
        self.units = units_left;
        self.input_bytes = bytes_left;
        Ok(Reservation {
            charge: Charge {
                verification_units: VERIFICATION_UNITS,
                input_bytes,
            },
        })
    }
}

/// A spent, non-clonable authorization for at most one bounded cold call.
#[derive(Debug)]
#[must_use = "dropping a reservation leaves its debit spent"]
pub struct Reservation {
    charge: Charge,
}

/// Error after reservation. The full debit is retained for every variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VerificationError {
    /// The caller supplied a different outer length from the one reserved.
    #[error("reserved {expected} input bytes but received {actual}")]
    InputLengthChanged {
        /// Exact length admitted before the copy.
        expected: u64,
        /// Actual length now supplied.
        actual: usize,
    },
    /// The frozen descriptor could not be compiled.
    #[error(transparent)]
    Profile(#[from] ProfileError),
    /// The test record or statement is malformed.
    #[error(transparent)]
    Codec(#[from] TestCodecError),
    /// The ordinary verifier refused the statement/proof or reported a failure.
    #[error(transparent)]
    Proof(#[from] VerifyError),
}

/// A fixed-size result returned after all verifier-owned objects have dropped.
///
/// The caller's record backing storage belongs to the outer workspace and must
/// remain charged until it is released. An allocator abort or stack failure
/// cannot produce this value and must be classified separately by the worker
/// supervisor; it must never be relabeled an invalid proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "inspect the verification result; a spent charge does not imply acceptance"]
pub struct Receipt {
    /// Irreversible charge, independent of the result.
    pub charge: Charge,
    /// Normal-return verification outcome.
    pub result: Result<(), VerificationError>,
}

impl Reservation {
    /// Inspect the already-spent charge, including before worker dispatch.
    pub const fn charge(&self) -> Charge {
        self.charge
    }

    /// Consume this token for one cold test-record verification.
    ///
    /// The input length is rechecked before descriptor work. The record is
    /// borrowed; the workspace owner makes any bounded input copy after reserve.
    /// Both rows and roles use the exact same charge, including malformed and
    /// late-invalid inputs. No cache is consulted and no counter is searched.
    pub fn verify(self, row: Row, role: Role, record: &[u8]) -> Receipt {
        let result = if u64::try_from(record.len()).ok() == Some(self.charge.input_bytes) {
            verify_cold(row, role, record)
        } else {
            Err(VerificationError::InputLengthChanged {
                expected: self.charge.input_bytes,
                actual: record.len(),
            })
        };
        Receipt {
            charge: self.charge,
            result,
        }
    }
}

/// Own every decoded object within the charged call; drop before its receipt.
fn verify_cold(row: Row, role: Role, record: &[u8]) -> Result<(), VerificationError> {
    let profile = Profile::new(row)?;
    let (statement, proof) = test_codec::decode_record(&profile, role, record)?;
    match role {
        Role::Registration => {
            let statement = test_codec::decode_registration(&profile, statement)?;
            registration::verify(row, &statement, proof)?;
        }
        Role::Vote => {
            let statement = test_codec::decode_vote(&profile, statement)?;
            vote::verify(row, &statement, proof)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/common/mod.rs"]
mod common;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_budget_is_spent_and_failed_reservations_are_atomic() {
        let mut budget = Budget::new(1, 10);
        assert_eq!(budget.remaining_units(), 1);
        assert_eq!(budget.remaining_input_bytes(), 10);
        assert_eq!(
            budget.reserve(11).unwrap_err(),
            AdmissionError::BytesExhausted
        );
        assert_eq!(budget, Budget::new(1, 10));
        let spent = {
            let token = budget.reserve(10).expect("exact budget");
            // Scope ends without running verification: the token cannot refund.
            token.charge()
        };
        assert_eq!(
            spent,
            Charge {
                verification_units: 1,
                input_bytes: 10
            }
        );
        assert_eq!(budget.remaining_units(), 0);
        assert_eq!(budget.remaining_input_bytes(), 0);
        assert_eq!(
            budget.reserve(0).unwrap_err(),
            AdmissionError::WorkExhausted
        );
        assert_eq!(budget, Budget::new(0, 0));
    }

    #[test]
    fn outer_cap_and_large_budgets_do_not_wrap_or_partially_debit() {
        let mut budget = Budget::new(u64::MAX, u64::MAX);
        for length in [MAX_INPUT_BYTES + 1, usize::MAX] {
            assert_eq!(
                budget.reserve(length).unwrap_err(),
                AdmissionError::InputTooLarge {
                    actual: length,
                    limit: MAX_INPUT_BYTES,
                }
            );
            assert_eq!(budget, Budget::new(u64::MAX, u64::MAX));
        }
        let token = budget.reserve(MAX_INPUT_BYTES).expect("at cap");
        assert_eq!(token.charge().input_bytes, 425_984);
        assert_eq!(budget.remaining_units(), u64::MAX - 1);
        assert_eq!(budget.remaining_input_bytes(), u64::MAX - 425_984);
        let mut no_work = Budget::new(0, u64::MAX);
        assert_eq!(
            no_work.reserve(1).unwrap_err(),
            AdmissionError::WorkExhausted
        );
        assert_eq!(no_work, Budget::new(0, u64::MAX));
    }

    #[test]
    fn empty_malformed_calls_are_charged_and_length_substitution_is_refused() {
        for row in Row::ALL {
            for role in Role::ALL {
                let mut budget = Budget::new(2, 1);
                let empty = budget
                    .reserve(0)
                    .expect("empty still needs one unit")
                    .verify(row, role, &[]);
                assert_eq!(
                    empty.charge,
                    Charge {
                        verification_units: 1,
                        input_bytes: 0
                    }
                );
                assert_eq!(
                    empty.result,
                    Err(VerificationError::Codec(TestCodecError::Truncated))
                );
                let changed = budget
                    .reserve(1)
                    .expect("one byte reserved")
                    .verify(row, role, &[]);
                assert_eq!(
                    changed.result,
                    Err(VerificationError::InputLengthChanged {
                        expected: 1,
                        actual: 0
                    })
                );
                assert_eq!(
                    changed.charge,
                    Charge {
                        verification_units: 1,
                        input_bytes: 1
                    }
                );
                assert_eq!(budget, Budget::new(0, 0));
            }
        }
    }

    /// Preserve original independent proofs while constructing their test record.
    fn fixture_record(row: Row, role: Role) -> (Vec<u8>, usize) {
        let profile = Profile::new(row).expect("profile");
        let (statement, proof): (Vec<u8>, &[u8]) = match (row, role) {
            (Row::Candidate, Role::Registration) => (
                test_codec::encode_registration(&profile, &common::reg_case(row).statement)
                    .expect("statement"),
                include_bytes!("../../tests/fixtures/reg_fast.proof"),
            ),
            (Row::Comparator, Role::Registration) => (
                test_codec::encode_registration(&profile, &common::reg_case(row).statement)
                    .expect("statement"),
                include_bytes!("../../tests/fixtures/reg_comparator.proof"),
            ),
            (Row::Candidate, Role::Vote) => (
                test_codec::encode_vote(&profile, &common::vote_case(row, 3, 1).statement)
                    .expect("statement"),
                include_bytes!("../../tests/fixtures/vote_S3_i1_fast.proof"),
            ),
            (Row::Comparator, Role::Vote) => (
                test_codec::encode_vote(&profile, &common::vote_case(row, 3, 1).statement)
                    .expect("statement"),
                include_bytes!("../../tests/fixtures/vote_S3_i1_comparator.proof"),
            ),
        };
        let proof_offset = 8 + statement.len();
        (
            test_codec::encode_record(&statement, proof).expect("record"),
            proof_offset,
        )
    }

    #[test]
    fn honest_early_invalid_and_late_invalid_proofs_spend_the_same_unit() {
        use iroha_zkp_vole::{codec::Field, params::ProofParams, variant::Construction};

        for row in Row::ALL {
            for role in Role::ALL {
                let (mut record, proof_offset) = fixture_record(row, role);
                let len = u64::try_from(record.len()).expect("bounded fixture");
                let mut budget = Budget::new(3, 3 * len);
                let accepted = budget
                    .reserve(record.len())
                    .expect("first")
                    .verify(row, role, &record);
                assert_eq!(accepted.result, Ok(()));
                let params = ProofParams::new(row.vole(), role.witness_bits(), role.constraints())
                    .expect("dimensions");
                let coefficient =
                    proof_offset + Field::Coefficients.offset_as(Construction::Extended, &params);
                record[coefficient] ^= 1;
                let late = budget
                    .reserve(record.len())
                    .expect("second")
                    .verify(row, role, &record);
                assert_eq!(
                    late.result,
                    Err(VerificationError::Proof(VerifyError::Rejected))
                );
                // Preserve total length while making the outer declared length impossible.
                record[..4].copy_from_slice(&u32::MAX.to_le_bytes());
                let early = budget
                    .reserve(record.len())
                    .expect("third")
                    .verify(row, role, &record);
                assert_eq!(
                    early.result,
                    Err(VerificationError::Codec(TestCodecError::Truncated))
                );
                assert_eq!(accepted.charge, late.charge);
                assert_eq!(accepted.charge, early.charge);
                assert_eq!(
                    accepted.charge,
                    Charge {
                        verification_units: 1,
                        input_bytes: len
                    }
                );
                assert_eq!(budget, Budget::new(0, 0));
            }
        }
    }
}
