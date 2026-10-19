//! Atomic whole-call and actual two-input byte reservations for the candidate diagnostic.

use iroha_data_model::governance::anonymous_ballot::{
    ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1, BALLOT_CONTEXT_MAX_BYTES_V1,
};

/// Candidate envelope cap, applied independently before copying or decoding.
pub const ENVELOPE_MAX: usize = ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1;
/// Complete shared context cap, applied independently before copying or decoding.
pub const CONTEXT_MAX: usize = BALLOT_CONTEXT_MAX_BYTES_V1;
/// Combined cap; also supplies the reused fatal-control protocol's debit bound.
pub const MAX_INPUT_BYTES: usize = ENVELOPE_MAX + CONTEXT_MAX;
/// Indivisible cold-verification reservation; it is not a calibrated CPU-time unit.
pub const VERIFICATION_UNITS: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Charge {
    pub units: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    EnvelopeSize,
    ContextSize,
    Work,
    Bytes,
}

impl Refusal {
    pub const fn stage(self) -> &'static str {
        match self {
            Self::EnvelopeSize => "envelope_size",
            Self::ContextSize => "context_size",
            Self::Work => "work_budget",
            Self::Bytes => "byte_budget",
        }
    }
}

#[derive(Debug)]
pub struct Budget {
    units: u64,
    bytes: u64,
}

/// Linear token: it is neither Clone nor Copy, and there is no refund operation.
#[derive(Debug)]
pub struct Reservation {
    envelope: usize,
    context: usize,
    charge: Charge,
}

impl Budget {
    pub const fn new(units: u64, bytes: u64) -> Self {
        Self { units, bytes }
    }

    pub fn reserve(&mut self, envelope: usize, context: usize) -> Result<Reservation, Refusal> {
        if envelope > ENVELOPE_MAX {
            return Err(Refusal::EnvelopeSize);
        }
        if context > CONTEXT_MAX {
            return Err(Refusal::ContextSize);
        }
        // Both component caps are small fixed constants, so this addition is exact.
        let bytes = u64::try_from(envelope + context).expect("bounded input lengths");
        if self.units < VERIFICATION_UNITS {
            return Err(Refusal::Work);
        }
        if self.bytes < bytes {
            return Err(Refusal::Bytes);
        }
        self.units -= VERIFICATION_UNITS;
        self.bytes -= bytes;
        Ok(Reservation {
            envelope,
            context,
            charge: Charge {
                units: VERIFICATION_UNITS,
                bytes,
            },
        })
    }
}

impl Reservation {
    pub const fn charge(&self) -> Charge {
        self.charge
    }

    /// Consume the token even on mismatch; equal totals cannot exchange the two inputs.
    pub fn consume(self, envelope: &[u8], context: &[u8]) -> Result<Charge, Charge> {
        if envelope.len() == self.envelope && context.len() == self.context {
            Ok(self.charge)
        } else {
            Err(self.charge)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_caps_and_failed_budgets_have_no_debit() {
        assert_eq!(
            (ENVELOPE_MAX, CONTEXT_MAX, MAX_INPUT_BYTES),
            (262_144, 163_840, 425_984)
        );
        for (units, bytes, envelope, context, refusal) in [
            (1, u64::MAX, ENVELOPE_MAX + 1, 0, Refusal::EnvelopeSize),
            (1, u64::MAX, 0, CONTEXT_MAX + 1, Refusal::ContextSize),
            (1, u64::MAX, usize::MAX, usize::MAX, Refusal::EnvelopeSize),
            (0, 4, 2, 2, Refusal::Work),
            (1, 3, 2, 2, Refusal::Bytes),
        ] {
            let mut budget = Budget::new(units, bytes);
            assert_eq!(budget.reserve(envelope, context).unwrap_err(), refusal);
            assert_eq!((budget.units, budget.bytes), (units, bytes));
        }
    }

    #[test]
    fn reservation_is_whole_call_actual_bytes_and_not_refunded() {
        let mut budget = Budget::new(2, 7);
        let token = budget.reserve(3, 4).unwrap();
        assert_eq!(token.charge(), Charge { units: 1, bytes: 7 });
        assert_eq!(
            token.consume(&[0; 3], &[0; 4]),
            Ok(Charge { units: 1, bytes: 7 })
        );
        assert_eq!((budget.units, budget.bytes), (1, 0));
        // Unused reservations and failed consumption both retain their full debit.
        drop(budget.reserve(0, 0).unwrap());
        assert_eq!((budget.units, budget.bytes), (0, 0));
        let mut budget = Budget::new(1, 7);
        let token = budget.reserve(3, 4).unwrap();
        assert_eq!(
            token.consume(&[0; 4], &[0; 3]),
            Err(Charge { units: 1, bytes: 7 })
        );
        assert_eq!((budget.units, budget.bytes), (0, 0));
        let mut budget = Budget::new(1, MAX_INPUT_BYTES as u64);
        assert_eq!(
            budget
                .reserve(ENVELOPE_MAX, CONTEXT_MAX)
                .unwrap()
                .charge()
                .bytes,
            MAX_INPUT_BYTES as u64
        );
    }

    #[test]
    fn refusals_have_distinct_fixed_labels() {
        let cases = [
            Refusal::EnvelopeSize,
            Refusal::ContextSize,
            Refusal::Work,
            Refusal::Bytes,
        ];
        for (index, case) in cases.iter().enumerate() {
            assert!(!case.stage().is_empty());
            assert!(
                cases[..index]
                    .iter()
                    .all(|other| case.stage() != other.stage())
            );
        }
    }
}
