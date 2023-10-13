//! Retry period that is calculated as `min_period * 2 ^ min(exponent, max_exponent)`

/// Period for re-entrant polling
#[derive(Clone, Copy, Debug)]
pub struct RetryPeriod {
    /// The minimum period
    min_period: u64,
    /// The maximum exponent
    max_exponent: u8,
    /// The current exponent
    exponent: u8,
}

impl RetryPeriod {
    /// Constructs a new object
    pub const fn new(min_period: u64, max_exponent: u8) -> Self {
        Self {
            min_period,
            max_exponent,
            exponent: 0,
        }
    }

    /// Increases the exponent if it isn't at its maximum
    pub fn increase_exponent(&mut self) {
        if self.exponent < self.max_exponent {
            self.exponent = self.exponent.saturating_add(1);
        } else {
            self.exponent = self.max_exponent
        }
    }

    /// Returns the period
    pub fn period(&mut self) -> u64 {
        let mult = 2_u64.saturating_pow(self.exponent.into());
        self.min_period.saturating_mul(mult)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn increase_exponent_saturates() {
        let mut period = super::RetryPeriod {
            min_period: 32000_u64,
            max_exponent: u8::MAX,
            exponent: (u8::MAX - 1),
        };
        println!("testing {period:?}");
        let old = period.period();
        period.increase_exponent();
        assert_eq!(period.period(), 2_u64.saturating_mul(old));
        period.increase_exponent();
        assert_eq!(period.period(), 2_u64.saturating_mul(old));
    }
}
