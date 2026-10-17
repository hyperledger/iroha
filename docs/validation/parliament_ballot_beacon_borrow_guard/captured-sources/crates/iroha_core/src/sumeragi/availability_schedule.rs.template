//! Historical availability authority supplied by the node's authenticated schedule owner.

use crate::execution_attempt::ExecutionAttemptError as Attempt;
use std::io;

use iroha_sumeragi::{
    availability::AvailabilitySource,
    types::{Hash32, HeightConfig},
};

/// An independently authenticated historical schedule, permanently bound to one instance.
///
/// Production implementations resolve the exact signed-genesis/certified-prefix authority,
/// including lane incarnation, original committee, parameters and availability layout. They
/// must never infer authority from the body or certificate currently being read. A failed
/// authentication or corrupt schedule is an error; only genuinely unknown authority is absent.
pub trait AvailabilitySchedule: Send + Sync {
    /// Immutable instance bound when this schedule owner was constructed.
    fn instance(&self) -> Hash32;

    /// Resolve the complete independently authenticated authority for `height`.
    ///
    /// # Errors
    /// Historical state is corrupt, cannot be authenticated, or cannot be read.
    fn height_config(&self, height: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>>;
}

/// Bind caller-selected identity to the independent historical schedule before any disk read.
/// No artifact bytes or claimed source fields enter this operation.
pub(super) fn resolve_source(
    schedule: &dyn AvailabilitySchedule,
    instance: Hash32,
    height: u64,
    block_hash: Hash32,
) -> Result<Option<AvailabilitySource>, Attempt<io::Error>> {
    if schedule.instance() != instance {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "availability schedule belongs to another instance",
        )
        .into());
    }
    let Some(config) = schedule.height_config(height)? else {
        return Ok(None);
    };
    AvailabilitySource::new(instance, height, block_hash, config)
        .map(Some)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid historical availability source: {error:?}"),
            )
            .into()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumeragi::body_record::tests::fixture;

    struct Schedule {
        instance: Hash32,
        config: Option<HeightConfig>,
        fail: bool,
    }
    impl AvailabilitySchedule for Schedule {
        fn instance(&self) -> Hash32 {
            self.instance
        }
        fn height_config(&self, _height: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>> {
            if self.fail {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "corrupt authenticated prefix",
                )
                .into());
            }
            Ok(self.config.clone())
        }
    }
    #[test]
    fn exact_requested_identity_and_complete_historical_configuration_are_bound() {
        let (_, source, _) = fixture(1);
        let schedule = Schedule {
            instance: source.instance(),
            config: Some(source.config().clone()),
            fail: false,
        };
        let resolved = resolve_source(
            &schedule,
            source.instance(),
            source.height(),
            source.block_hash(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(resolved, source);
        let other = Hash32([0x33; 32]);
        assert_eq!(
            resolve_source(&schedule, source.instance(), source.height(), other)
                .unwrap()
                .unwrap()
                .block_hash(),
            other
        );
        assert!(resolve_source(&schedule, other, source.height(), source.block_hash()).is_err());
    }
    #[test]
    fn absence_and_corrupt_or_out_of_range_authority_remain_distinct() {
        let (_, source, _) = fixture(1);
        let mut schedule = Schedule {
            instance: source.instance(),
            config: None,
            fail: false,
        };
        assert!(
            resolve_source(&schedule, source.instance(), 1, source.block_hash())
                .unwrap()
                .is_none()
        );
        schedule.fail = true;
        assert!(resolve_source(&schedule, source.instance(), 1, source.block_hash()).is_err());
        schedule.fail = false;
        let mut config = source.config().clone();
        config.epoch.first_height = 2;
        schedule.config = Some(config);
        assert!(resolve_source(&schedule, source.instance(), 1, source.block_hash()).is_err());
    }
}
