//! Strict developer seed selection; every selected campaign contains actual seeds.

use std::{env::VarError, ops::RangeInclusive};

/// Read the selected finite, nonempty seed range without allocating a seed list.
///
/// # Panics
/// Rejects malformed selected settings, a zero count or an overflowing range.
pub(super) fn from_env(default: u64) -> RangeInclusive<u64> {
    selection(default, std::env::var)
        .unwrap_or_else(|error| panic!("invalid simulator seed selection: {error}"))
}

fn unsigned(
    read: &mut impl FnMut(&'static str) -> Result<String, VarError>,
    name: &'static str,
) -> Result<Option<u64>, String> {
    match read(name) {
        Ok(value) => value
            .parse::<u64>()
            .map(Some)
            .map_err(|_| format!("{name} must be an unsigned 64-bit integer")),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(format!("{name} must be valid Unicode")),
    }
}

fn selection(
    default: u64,
    mut read: impl FnMut(&'static str) -> Result<String, VarError>,
) -> Result<RangeInclusive<u64>, String> {
    // An explicit single seed keeps its documented priority over sweep settings.
    if let Some(seed) = unsigned(&mut read, "SUMERAGI_SIM_SEED")? {
        return Ok(seed..=seed);
    }
    let first = unsigned(&mut read, "SUMERAGI_SIM_SEED_BASE")?.unwrap_or(0);
    let count = unsigned(&mut read, "SUMERAGI_SIM_SEEDS")?.unwrap_or(default);
    let offset = count
        .checked_sub(1)
        .ok_or_else(|| "SUMERAGI_SIM_SEEDS or its default must be positive".to_owned())?;
    let last = first
        .checked_add(offset)
        .ok_or_else(|| "SUMERAGI_SIM_SEED_BASE plus the selected count exceeds u64".to_owned())?;
    // Inclusive bounds admit u64::MAX itself without an overflowing end sentinel.
    Ok(first..=last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured(default: u64, values: &[(&str, &str)]) -> Result<RangeInclusive<u64>, String> {
        selection(default, |name| {
            values
                .iter()
                .find_map(|(key, value)| (*key == name).then(|| (*value).to_owned()))
                .ok_or(VarError::NotPresent)
        })
    }

    #[test]
    fn default_and_explicit_sweeps_execute_the_complete_ordered_range() {
        assert_eq!(configured(3, &[]).unwrap().collect::<Vec<_>>(), [0, 1, 2]);
        assert_eq!(
            configured(
                0,
                &[("SUMERAGI_SIM_SEED_BASE", "7"), ("SUMERAGI_SIM_SEEDS", "3")]
            )
            .unwrap()
            .collect::<Vec<_>>(),
            [7, 8, 9]
        );
        assert_eq!(
            configured(20, &[("SUMERAGI_SIM_SEEDS", "10000")])
                .unwrap()
                .count(),
            10_000
        );
    }

    #[test]
    fn zero_default_or_selected_count_cannot_qualify_an_empty_campaign() {
        assert!(configured(0, &[]).is_err());
        assert!(configured(20, &[("SUMERAGI_SIM_SEEDS", "0")]).is_err());
    }

    #[test]
    fn malformed_selected_values_never_fall_back_to_defaults() {
        for name in [
            "SUMERAGI_SIM_SEED",
            "SUMERAGI_SIM_SEED_BASE",
            "SUMERAGI_SIM_SEEDS",
        ] {
            for value in ["", "invalid", "-1", " 2", "18446744073709551616"] {
                let error = configured(20, &[(name, value)]).unwrap_err();
                assert!(error.contains(name));
            }
            let error = selection(20, |key| {
                if key == name {
                    Err(VarError::NotUnicode(std::ffi::OsString::from("unreadable")))
                } else {
                    Err(VarError::NotPresent)
                }
            })
            .unwrap_err();
            assert!(error.contains(name));
        }
    }

    #[test]
    fn exact_single_seed_retains_priority_including_the_maximum_seed() {
        for seed in ["0", "18446744073709551615"] {
            assert_eq!(
                configured(
                    0,
                    &[
                        ("SUMERAGI_SIM_SEED", seed),
                        ("SUMERAGI_SIM_SEED_BASE", "invalid"),
                        ("SUMERAGI_SIM_SEEDS", "0")
                    ]
                )
                .unwrap()
                .collect::<Vec<_>>(),
                [seed.parse::<u64>().unwrap()]
            );
        }
    }

    #[test]
    fn range_bounds_reject_overflow_and_include_the_last_u64_without_wrapping() {
        assert!(configured(2, &[("SUMERAGI_SIM_SEED_BASE", "18446744073709551615")]).is_err());
        assert_eq!(
            configured(1, &[("SUMERAGI_SIM_SEED_BASE", "18446744073709551615")])
                .unwrap()
                .collect::<Vec<_>>(),
            [u64::MAX]
        );
        assert_eq!(
            configured(2, &[("SUMERAGI_SIM_SEED_BASE", "18446744073709551614")])
                .unwrap()
                .collect::<Vec<_>>(),
            [u64::MAX - 1, u64::MAX]
        );
        let largest = configured(
            20,
            &[
                ("SUMERAGI_SIM_SEED_BASE", "1"),
                ("SUMERAGI_SIM_SEEDS", "18446744073709551615"),
            ],
        )
        .unwrap();
        assert_eq!((*largest.start(), *largest.end()), (1, u64::MAX));
        assert_eq!(largest.take(3).collect::<Vec<_>>(), [1, 2, 3]);
    }
}
