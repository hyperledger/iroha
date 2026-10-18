//! Borrowed exact prefixes over the original staking keys; no secondary index.

use super::*;
use core::ops::{Bound, RangeBounds};
use iroha_primitives::{cmpext::MinMaxExt, impl_as_dyn_key};

/// The original stake tuple ordering with sentinels around every staker identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StakePrefix<'a> {
    lane: &'a LaneId,
    validator: &'a AccountId,
    staker: MinMaxExt<&'a AccountId>,
}

/// Exact stake-share range for one validator in one lane.
pub struct StakeBounds<'a> {
    start: StakePrefix<'a>,
    end: StakePrefix<'a>,
}

impl<'a> StakeBounds<'a> {
    /// Borrow bounds without constructing an artificial minimum account.
    pub fn new(lane: &'a LaneId, validator: &'a AccountId) -> Self {
        Self {
            start: StakePrefix {
                lane,
                validator,
                staker: MinMaxExt::Min,
            },
            end: StakePrefix {
                lane,
                validator,
                staker: MinMaxExt::Max,
            },
        }
    }
}

impl<'a> RangeBounds<dyn AsStakePrefix + 'a> for StakeBounds<'a> {
    fn start_bound(&self) -> Bound<&(dyn AsStakePrefix + 'a)> {
        Bound::Excluded(&self.start)
    }
    fn end_bound(&self) -> Bound<&(dyn AsStakePrefix + 'a)> {
        Bound::Excluded(&self.end)
    }
}

impl AsStakePrefix for StakeKey {
    fn as_key(&self) -> StakePrefix<'_> {
        StakePrefix {
            lane: &self.0,
            validator: &self.1,
            staker: (&self.2).into(),
        }
    }
}

impl_as_dyn_key! { target: StakeKey, key: StakePrefix<'_>, trait: AsStakePrefix }

/// The original validator tuple ordering with account sentinels.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ValidatorPrefix<'a> {
    lane: &'a LaneId,
    validator: MinMaxExt<&'a AccountId>,
}

/// Exact validator range for one policy-owned lane.
pub struct ValidatorBounds<'a> {
    start: ValidatorPrefix<'a>,
    end: ValidatorPrefix<'a>,
}

impl<'a> ValidatorBounds<'a> {
    /// Borrow the lane prefix without copying any account controller.
    pub fn new(lane: &'a LaneId) -> Self {
        Self {
            start: ValidatorPrefix {
                lane,
                validator: MinMaxExt::Min,
            },
            end: ValidatorPrefix {
                lane,
                validator: MinMaxExt::Max,
            },
        }
    }
}

impl<'a> RangeBounds<dyn AsValidatorPrefix + 'a> for ValidatorBounds<'a> {
    fn start_bound(&self) -> Bound<&(dyn AsValidatorPrefix + 'a)> {
        Bound::Excluded(&self.start)
    }
    fn end_bound(&self) -> Bound<&(dyn AsValidatorPrefix + 'a)> {
        Bound::Excluded(&self.end)
    }
}

impl AsValidatorPrefix for (LaneId, AccountId) {
    fn as_key(&self) -> ValidatorPrefix<'_> {
        ValidatorPrefix {
            lane: &self.0,
            validator: (&self.1).into(),
        }
    }
}

impl_as_dyn_key! {
    target: (LaneId, AccountId), key: ValidatorPrefix<'_>, trait: AsValidatorPrefix
}
