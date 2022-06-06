/// Encapsulates the retry period that is calculated as `min_period * 2 ^ min(exponent, max_exponent)`
pub struct RetryPeriod {
    /// The minimum period
    min_period: u64,
    /// The maximum exponent
    max_exponent: u8,
    /// The current exponent
    exponent: u8,
}

impl RetryPeriod {
    pub const DEFAULT_MIN_RETRY_PERIOD: u64 = 1;
    pub const DEFAULT_MAX_RETRY_DELAY_EXPONENT: u8 = 4;

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
            self.exponent += 1;
        }
    }

    /// Returns the period
    pub fn period(&mut self) -> u64 {
        let mult = 2_u64.saturating_pow(self.exponent.into());
        self.min_period.saturating_mul(mult)
    }
}

impl Default for RetryPeriod {
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_MIN_RETRY_PERIOD,
            Self::DEFAULT_MAX_RETRY_DELAY_EXPONENT,
        )
    }
}
