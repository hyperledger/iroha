//! Period for re-entrant polling

use std::time::Duration;

/// Period for re-entrant polling
#[derive(Clone, Copy, Debug)]
pub struct RetryPeriod {
    /// The minimum period
    min_period: Duration,
    /// The maximum exponent
    max_exponent: u8,
    /// The current exponent
    exponent: u8,
}

impl RetryPeriod {
    /// Constructs a new object
    pub const fn new(min_period: Duration, max_exponent: u8) -> Self {
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

    /// Retry period that is calculated as `min_period * 2 ^ min(exponent, max_exponent)`
    pub fn period(&mut self) -> Duration {
        let mult = 2_u32.saturating_pow(self.exponent.into());
        self.min_period.saturating_mul(mult)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increase_exponent_saturates() {
        let mut value = RetryPeriod::new(Duration::from_secs(42), 10);
        println!("testing {value:?}");
        let initial_period = value.period();
        value.increase_exponent();
        assert_eq!(value.period(), initial_period.saturating_mul(2));
        value.increase_exponent();
        assert_eq!(value.period(), initial_period.saturating_mul(4));
    }
}
