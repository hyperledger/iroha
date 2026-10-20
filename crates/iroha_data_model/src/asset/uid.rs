//! Additive identity-wide policy for public, globally scoped numeric assets.
use super::AssetDefinitionId;
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize, account::AccountId};
use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::collections::BTreeSet;

/// Deterministic calendar used by an identity's native activity limit.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(tag = "window", content = "value")]
#[norito_schema(name = "iroha_data_model::asset::uid::AssetUidDailyWindowV1")]
pub enum AssetUidDailyWindowV1 {
    /// Midnight-to-midnight UTC.
    UtcDay,
    /// Jerusalem local calendar day with the fixed Israel 2013 DST rule.
    ///
    /// Summer starts at 00:00 UTC on the Friday before the last Sunday in March
    /// and ends at 23:00 UTC on the Saturday before the last Sunday in October.
    /// This protocol rule is independent of operating-system timezone databases.
    JerusalemDay,
}

impl AssetUidDailyWindowV1 {
    /// Resolve the UTC instant at which the timestamp's local calendar day began.
    ///
    /// # Errors
    /// Rejects timestamps outside the supported date range, Jerusalem dates
    /// before the pinned 2013 rule, and buckets starting before the Unix epoch.
    pub fn day_start_ms(self, now_ms: u64) -> Result<u64, &'static str> {
        use time::{Duration, OffsetDateTime};
        let now = OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000)
            .map_err(|_| "asset UID timestamp is outside the calendar range")?;
        let midnight = match self {
            Self::UtcDay => now.date().midnight().assume_utc(),
            Self::JerusalemDay => {
                let local_date = now
                    .checked_add(Duration::hours(jerusalem_offset_hours(now)?))
                    .ok_or("asset UID local date is outside the calendar range")?
                    .date();
                // Midnight is unambiguous under the pinned rule, including
                // transition days. Its offset may differ from the current hour.
                let winter = local_date.midnight().assume_utc() - Duration::hours(2);
                if jerusalem_offset_hours(winter)? == 2 {
                    winter
                } else {
                    local_date.midnight().assume_utc() - Duration::hours(3)
                }
            }
        };
        u64::try_from(midnight.unix_timestamp_nanos() / 1_000_000)
            .map_err(|_| "asset UID calendar day begins before the Unix epoch")
    }
}

fn jerusalem_offset_hours(now: time::OffsetDateTime) -> Result<i64, &'static str> {
    use time::{Date, Duration, Month};
    let year = now.year();
    if year < 2013 {
        return Err("Jerusalem UID calendar requires the pinned rule from 2013");
    }
    let last_sunday = |month, last| -> Result<Date, &'static str> {
        let date = Date::from_calendar_date(year, month, last)
            .map_err(|_| "asset UID DST boundary is outside the calendar range")?;
        date.checked_sub(Duration::days(i64::from(
            date.weekday().number_days_from_sunday(),
        )))
        .ok_or("asset UID DST boundary underflow")
    };
    let start = (last_sunday(Month::March, 31)? - Duration::days(2))
        .midnight()
        .assume_utc();
    let end = (last_sunday(Month::October, 31)? - Duration::days(1))
        .with_hms(23, 0, 0)
        .map_err(|_| "invalid asset UID DST boundary")?
        .assume_utc();
    Ok(if now >= start && now < end { 3 } else { 2 })
}

/// Owner-installed aggregate policy. Members are retained after wallet closure.
///
/// This is independent of account-scoped transfer controls: both policies apply.
/// Identity is an opaque, nonzero issuer commitment, never an identifying number.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::uid::AssetUidPolicyV1")]
pub struct AssetUidPolicyV1 {
    /// Exact globally scoped asset definition.
    pub asset_definition_id: AssetDefinitionId,
    /// Opaque identity commitment shared by every wallet of this person.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub uid: [u8; 32],
    /// Starts at one and increases by exactly one on each authorized update.
    pub revision: u64,
    /// Complete append-only set of member accounts.
    pub accounts: BTreeSet<AccountId>,
    /// Maximum beneficial holdings, including unresolved conditional escrow.
    pub holding_limit: Option<Quantity>,
    /// Calendar selection, immutable after the first policy installation.
    pub daily_window: AssetUidDailyWindowV1,
    /// Maximum outgoing activity in one selected calendar day.
    ///
    /// Escrow funding counts once; settlement/refund does not count again.
    /// Updating this policy never resets its previously consumed usage.
    pub daily_limit: Option<Quantity>,
}

impl AssetUidPolicyV1 {
    /// Validate identity, revision and roster shape.
    ///
    /// # Errors
    /// Returns a description of the noncanonical policy.
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if self.uid == [0; 32] {
            return Err("asset UID commitment must be nonzero");
        }
        if self.revision == 0 || self.accounts.is_empty() {
            return Err("asset UID policy requires a positive revision and nonempty membership");
        }
        Ok(())
    }
}

/// Native account-to-identity binding. It cannot be reassigned or removed.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::uid::AssetUidBindingV1")]
pub struct AssetUidBindingV1 {
    /// Governed definition.
    pub asset_definition_id: AssetDefinitionId,
    /// Bound wallet owner.
    pub account_id: AccountId,
    /// Opaque identity commitment.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub uid: [u8; 32],
}

/// Persistent calendar usage, unaffected by membership changes or policy revisions.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::uid::AssetUidUsageV1")]
pub struct AssetUidUsageV1 {
    /// Governed definition.
    pub asset_definition_id: AssetDefinitionId,
    /// Opaque identity commitment.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub uid: [u8; 32],
    /// Calendar selection retained with the usage.
    pub daily_window: AssetUidDailyWindowV1,
    /// UTC milliseconds since Unix epoch at the start of the selected day.
    pub day_start_ms: u64,
    /// Gross activity consumed during that day.
    pub amount: Quantity,
}

/// Owner-authorized view of one UID at one captured native ledger state.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::uid::AssetUidPolicyViewV1")]
pub struct AssetUidPolicyViewV1 {
    /// Installed revision and complete retained account membership.
    pub policy: AssetUidPolicyV1,
    /// Wallet balances plus unresolved native escrow reserves.
    pub beneficial_holdings: Quantity,
    /// UTC instant of this view's selected calendar-day start.
    pub day_start_ms: u64,
    /// Gross activity consumed in the selected calendar day.
    pub daily_usage: Quantity,
    /// Authenticated ledger time of the captured view.
    pub ledger_time_ms: u64,
    /// Captured committed ledger height.
    pub as_of_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn instant(year: i32, month: u8, day: u8, hour: u8, minute: u8) -> u64 {
        let at = time::Date::from_calendar_date(year, month.try_into().unwrap(), day)
            .unwrap()
            .with_hms(hour, minute, 0)
            .unwrap()
            .assume_utc();
        u64::try_from(at.unix_timestamp_nanos() / 1_000_000).unwrap()
    }

    #[test]
    fn uid_calendar_jerusalem_spring_day_has_23_hours_without_midday_reset() {
        let window = AssetUidDailyWindowV1::JerusalemDay;
        let start = instant(2026, 3, 26, 22, 0);
        for now in [
            start,
            instant(2026, 3, 27, 0, 0),
            instant(2026, 3, 27, 20, 59),
        ] {
            assert_eq!(window.day_start_ms(now).unwrap(), start);
        }
        let next = instant(2026, 3, 27, 21, 0);
        assert_eq!(window.day_start_ms(next).unwrap(), next);
        assert_eq!(next - start, 23 * 60 * 60 * 1_000);
    }

    #[test]
    fn uid_calendar_jerusalem_autumn_day_has_25_hours_without_repeated_budget() {
        let window = AssetUidDailyWindowV1::JerusalemDay;
        let start = instant(2026, 10, 24, 21, 0);
        for now in [
            start,
            instant(2026, 10, 24, 23, 0),
            instant(2026, 10, 25, 21, 59),
        ] {
            assert_eq!(window.day_start_ms(now).unwrap(), start);
        }
        let next = instant(2026, 10, 25, 22, 0);
        assert_eq!(window.day_start_ms(next).unwrap(), next);
        assert_eq!(next - start, 25 * 60 * 60 * 1_000);
    }

    #[test]
    fn uid_calendar_utc_and_invalid_timestamps_are_exact() {
        let utc = AssetUidDailyWindowV1::UtcDay;
        assert_eq!(utc.day_start_ms(0).unwrap(), 0);
        assert_eq!(utc.day_start_ms(86_399_999).unwrap(), 0);
        assert_eq!(utc.day_start_ms(86_400_000).unwrap(), 86_400_000);
        assert!(utc.day_start_ms(u64::MAX).is_err());
        assert!(AssetUidDailyWindowV1::JerusalemDay.day_start_ms(0).is_err());
        assert!(
            AssetUidDailyWindowV1::JerusalemDay
                .day_start_ms(instant(9999, 12, 31, 23, 59))
                .is_err()
        );
    }
}
