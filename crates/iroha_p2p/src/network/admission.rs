//! Inbound address admission and bounded accept-rate ownership.

use std::{collections::HashMap, net::IpAddr, sync::atomic::Ordering, time::Duration};

use super::{
    ACCEPT_BUCKET_EVICTIONS, ACCEPT_BUCKETS_CURRENT, ACCEPT_IP_ALLOWED, ACCEPT_IP_THROTTLED,
    ACCEPT_PREFIX_ALLOWED, ACCEPT_PREFIX_CACHE_HITS, ACCEPT_PREFIX_CACHE_MISSES,
    ACCEPT_PREFIX_THROTTLED, ACCEPT_THROTTLED,
};

/// Parsed IPv4 or IPv6 network used by the inbound ACL.
#[derive(Clone, Debug)]
pub(super) struct IpNet {
    kind: IpKind,
}

#[derive(Clone, Debug)]
enum IpKind {
    V4 { net: u32, mask: u32 },
    V6 { net: [u8; 16], bits: u8 },
}

fn invalid_cidr(raw: &str, reason: &str) -> String {
    format!("invalid CIDR `{raw}`: {reason}")
}

fn parse_cidr(raw: &str) -> Result<IpNet, String> {
    let input = raw.trim();
    let (address, prefix) = input
        .split_once('/')
        .ok_or_else(|| invalid_cidr(raw, "missing prefix length"))?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| invalid_cidr(raw, "invalid IP address"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| invalid_cidr(raw, "invalid prefix length"))?;
    match address {
        IpAddr::V4(address) => {
            if prefix > 32 {
                return Err(invalid_cidr(raw, "IPv4 prefix is larger than 32"));
            }
            let raw = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            Ok(IpNet {
                kind: IpKind::V4 {
                    net: raw & mask,
                    mask,
                },
            })
        }
        IpAddr::V6(address) => {
            if prefix > 128 {
                return Err(invalid_cidr(raw, "IPv6 prefix is larger than 128"));
            }
            if let Some(address) = address.to_ipv4_mapped() {
                if prefix < 96 {
                    return Err(invalid_cidr(
                        raw,
                        "IPv4-mapped IPv6 prefix is smaller than 96",
                    ));
                }
                let prefix = prefix - 96;
                let raw = u32::from(address);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                return Ok(IpNet {
                    kind: IpKind::V4 {
                        net: raw & mask,
                        mask,
                    },
                });
            }
            let mut net = address.octets();
            let full_bytes = (prefix / 8) as usize;
            let rem_bits = prefix % 8;
            if full_bytes < 16 {
                if rem_bits == 0 {
                    for byte in net.iter_mut().skip(full_bytes) {
                        *byte = 0;
                    }
                } else {
                    for byte in net.iter_mut().skip(full_bytes + 1) {
                        *byte = 0;
                    }
                    net[full_bytes] &= 0xFF_u8 << (8 - rem_bits);
                }
            }
            Ok(IpNet {
                kind: IpKind::V6 { net, bits: prefix },
            })
        }
    }
}

/// Parse every network in an inbound ACL, rejecting the full set on one malformed entry.
pub(super) fn parse_cidrs(list: &[String]) -> Result<Vec<IpNet>, String> {
    list.iter().map(|entry| parse_cidr(entry)).collect()
}

/// Parse both inbound CIDR dimensions without permitting a partially applied ACL.
pub(super) fn parse_acl_cidrs(
    allow_cidrs: &[String],
    deny_cidrs: &[String],
) -> Result<(Vec<IpNet>, Vec<IpNet>), String> {
    let allow_nets = parse_cidrs(allow_cidrs)
        .map_err(|error| format!("network.allow_cidrs contains {error}"))?;
    let deny_nets =
        parse_cidrs(deny_cidrs).map_err(|error| format!("network.deny_cidrs contains {error}"))?;
    Ok((allow_nets, deny_nets))
}

fn cidr_contains(nets: &[IpNet], ip: IpAddr) -> bool {
    let ip = crate::preauth::canonical_remote_ip(ip);
    match ip {
        IpAddr::V4(v4) => {
            let raw = u32::from(v4);
            nets.iter().any(|net| match &net.kind {
                IpKind::V4 { net, mask } => (raw & mask) == *net,
                IpKind::V6 { .. } => false,
            })
        }
        IpAddr::V6(v6) => {
            let raw = v6.octets();
            nets.iter().any(|network| match &network.kind {
                IpKind::V6 { net, bits } => {
                    let full_bytes = (*bits / 8) as usize;
                    let rem_bits = *bits % 8;
                    (full_bytes == 0 || raw[..full_bytes] == net[..full_bytes])
                        && (rem_bits == 0 || {
                            let mask = 0xFF_u8 << (8 - rem_bits);
                            (raw[full_bytes] & mask) == (net[full_bytes] & mask)
                        })
                }
                IpKind::V4 { .. } => false,
            })
        }
    }
}

/// Token ownership used by accept admission and low-priority peer traffic.
#[derive(Debug, Clone)]
pub(super) struct TokenBucket {
    tokens: f64,
    last_refill: tokio::time::Instant,
    rate_per_sec: f64,
    burst: f64,
}

impl TokenBucket {
    pub(super) fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            last_refill: tokio::time::Instant::now(),
            rate_per_sec,
            burst,
        }
    }

    pub(super) fn allow(&mut self) -> bool {
        self.allow_at(tokio::time::Instant::now())
    }

    fn allow_at(&mut self, now: tokio::time::Instant) -> bool {
        self.refill(now);
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }

    /// Allow consuming an arbitrary amount from the bucket.
    pub(super) fn allow_n(&mut self, amount: f64) -> bool {
        self.allow_n_at(amount, tokio::time::Instant::now())
    }

    fn allow_n_at(&mut self, amount: f64, now: tokio::time::Instant) -> bool {
        self.refill(now);
        if self.tokens < amount {
            return false;
        }
        self.tokens -= amount;
        true
    }

    fn refill(&mut self, now: tokio::time::Instant) {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.last_refill = now;
        self.tokens = elapsed
            .mul_add(self.rate_per_sec, self.tokens)
            .min(self.burst);
    }

    fn update_shape(&mut self, rate_per_sec: f64, burst: f64) {
        self.rate_per_sec = rate_per_sec;
        self.burst = burst;
        self.tokens = self.tokens.min(self.burst);
    }
}

#[derive(Debug, Clone)]
pub(super) struct AcceptBucket {
    bucket: TokenBucket,
    last_seen: tokio::time::Instant,
}

impl AcceptBucket {
    fn new(rate_per_sec: f64, burst: f64, now: tokio::time::Instant) -> Self {
        Self {
            bucket: TokenBucket::new(rate_per_sec, burst),
            last_seen: now,
        }
    }

    fn allow(&mut self, now: tokio::time::Instant) -> bool {
        self.last_seen = now;
        self.bucket.allow_at(now)
    }

    fn update_shape(&mut self, rate_per_sec: f64, burst: f64) {
        self.bucket.update_shape(rate_per_sec, burst);
    }
}

/// Configured refill rate and optional burst for one accept-throttle dimension.
#[derive(Clone, Copy, Debug)]
pub(super) struct AcceptRate {
    pub(super) rate_per_sec: Option<f64>,
    pub(super) burst: Option<f64>,
}

/// Immutable shape of the inbound accept throttle.
#[derive(Clone, Copy, Debug)]
pub(super) struct AcceptThrottleParams {
    prefix_rate_per_sec: Option<f64>,
    prefix_burst: Option<f64>,
    prefix_v4_bits: u8,
    prefix_v6_bits: u8,
    ip_rate_per_sec: Option<f64>,
    ip_burst: Option<f64>,
    max_buckets: usize,
    bucket_idle: Duration,
}

impl AcceptThrottleParams {
    pub(super) fn new(
        AcceptRate {
            rate_per_sec: prefix_rate_per_sec,
            burst: prefix_burst,
        }: AcceptRate,
        prefix_v4_bits: u8,
        prefix_v6_bits: u8,
        AcceptRate {
            rate_per_sec: ip_rate_per_sec,
            burst: ip_burst,
        }: AcceptRate,
        max_buckets: usize,
        bucket_idle: Duration,
    ) -> Self {
        Self {
            prefix_rate_per_sec,
            prefix_burst,
            prefix_v4_bits,
            prefix_v6_bits,
            ip_rate_per_sec,
            ip_burst,
            max_buckets: max_buckets.max(1),
            bucket_idle,
        }
    }

    fn enabled_dimensions(self) -> usize {
        usize::from(self.prefix_rate_per_sec.is_some())
            + usize::from(self.ip_rate_per_sec.is_some())
    }

    fn has_valid_geometry(self) -> bool {
        self.max_buckets >= self.enabled_dimensions()
    }
}

/// Reject a cap that cannot retain one owner for every enabled throttle dimension.
pub(super) fn validate_accept_throttle_geometry(
    prefix_enabled: bool,
    ip_enabled: bool,
    max_buckets: usize,
) -> Result<(), String> {
    let required_buckets = usize::from(prefix_enabled) + usize::from(ip_enabled);
    if max_buckets < required_buckets {
        return Err(format!(
            "network.max_accept_buckets={max_buckets} cannot retain the {required_buckets} enabled accept-throttle dimensions"
        ));
    }
    Ok(())
}

fn oldest_bucket(
    buckets: &HashMap<IpBucketKey, AcceptBucket>,
) -> Option<(tokio::time::Instant, IpBucketKey)> {
    buckets
        .iter()
        .map(|(key, entry)| (entry.last_seen, *key))
        .min()
}

fn evict_oldest_accept_bucket(
    prefix_buckets: &mut HashMap<IpBucketKey, AcceptBucket>,
    ip_buckets: &mut HashMap<IpBucketKey, AcceptBucket>,
) -> bool {
    let prefix_oldest = oldest_bucket(prefix_buckets);
    let ip_oldest = oldest_bucket(ip_buckets);
    match (prefix_oldest, ip_oldest) {
        (Some(prefix), Some(ip)) if prefix <= ip => prefix_buckets.remove(&prefix.1).is_some(),
        (Some(_) | None, Some(ip)) => ip_buckets.remove(&ip.1).is_some(),
        (Some(prefix), None) => prefix_buckets.remove(&prefix.1).is_some(),
        (None, None) => false,
    }
}

fn prune_idle_accept_buckets(
    buckets: &mut HashMap<IpBucketKey, AcceptBucket>,
    bucket_idle: Duration,
    now: tokio::time::Instant,
) -> usize {
    if bucket_idle == Duration::ZERO {
        return 0;
    }
    let before = buckets.len();
    buckets.retain(|_, entry| now.saturating_duration_since(entry.last_seen) < bucket_idle);
    before.saturating_sub(buckets.len())
}

fn enforce_aggregate_bucket_cap(
    prefix_buckets: &mut HashMap<IpBucketKey, AcceptBucket>,
    ip_buckets: &mut HashMap<IpBucketKey, AcceptBucket>,
    max_buckets: usize,
    room_for_new_bucket: bool,
) -> usize {
    let retained_limit = max_buckets.saturating_sub(usize::from(room_for_new_bucket));
    let mut evicted = 0;
    while retained_bucket_count(prefix_buckets, ip_buckets) > retained_limit {
        if !evict_oldest_accept_bucket(prefix_buckets, ip_buckets) {
            break;
        }
        evicted += 1;
    }
    evicted
}

fn retained_bucket_count(
    prefix_buckets: &HashMap<IpBucketKey, AcceptBucket>,
    ip_buckets: &HashMap<IpBucketKey, AcceptBucket>,
) -> usize {
    prefix_buckets.len().saturating_add(ip_buckets.len())
}

fn consume_accept_bucket(
    buckets: &mut HashMap<IpBucketKey, AcceptBucket>,
    key: IpBucketKey,
    rate_per_sec: f64,
    burst: f64,
    now: tokio::time::Instant,
) -> (bool, bool) {
    let existed = buckets.contains_key(&key);
    let entry = buckets
        .entry(key)
        .or_insert_with(|| AcceptBucket::new(rate_per_sec, burst, now));
    entry.update_shape(rate_per_sec, burst);
    (entry.allow(now), existed)
}

fn update_accept_bucket_gauge(
    prefix_buckets: &HashMap<IpBucketKey, AcceptBucket>,
    ip_buckets: &HashMap<IpBucketKey, AcceptBucket>,
) {
    ACCEPT_BUCKETS_CURRENT.store(
        u64::try_from(retained_bucket_count(prefix_buckets, ip_buckets)).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
}

/// Evaluate inbound ACLs and then consume prefix and per-IP accept ownership.
pub(super) fn allow_ip_with_policy(
    allow_nets: &[IpNet],
    deny_nets: &[IpNet],
    allowlist_only: bool,
    params: AcceptThrottleParams,
    prefix_buckets: &mut HashMap<IpBucketKey, AcceptBucket>,
    ip_buckets: &mut HashMap<IpBucketKey, AcceptBucket>,
    ip: IpAddr,
) -> bool {
    if cidr_contains(deny_nets, ip) {
        return false;
    }
    let allowlist_present = !allow_nets.is_empty();
    let allowlisted = cidr_contains(allow_nets, ip);
    if allowlist_present && !allowlisted {
        return false;
    }
    let now = tokio::time::Instant::now();
    let evicted = prune_idle_accept_buckets(prefix_buckets, params.bucket_idle, now)
        + prune_idle_accept_buckets(ip_buckets, params.bucket_idle, now)
        + enforce_aggregate_bucket_cap(prefix_buckets, ip_buckets, params.max_buckets, false);
    if evicted > 0 {
        ACCEPT_BUCKET_EVICTIONS.fetch_add(evicted as u64, Ordering::Relaxed);
    }
    if allowlisted || (allowlist_only && allowlist_present) {
        update_accept_bucket_gauge(prefix_buckets, ip_buckets);
        return true;
    }
    if !params.has_valid_geometry() {
        ACCEPT_THROTTLED.fetch_add(1, Ordering::Relaxed);
        update_accept_bucket_gauge(prefix_buckets, ip_buckets);
        return false;
    }
    if let Some(rate) = params.prefix_rate_per_sec {
        let burst = params.prefix_burst.unwrap_or_else(|| rate.max(1.0));
        let key = ip_bucket_key(ip, params.prefix_v4_bits, params.prefix_v6_bits);
        let existed = prefix_buckets.contains_key(&key);
        let evicted =
            enforce_aggregate_bucket_cap(prefix_buckets, ip_buckets, params.max_buckets, !existed);
        if evicted > 0 {
            ACCEPT_BUCKET_EVICTIONS.fetch_add(evicted as u64, Ordering::Relaxed);
        }
        let (allow, consumed_existing) =
            consume_accept_bucket(prefix_buckets, key, rate, burst, now);
        debug_assert_eq!(existed, consumed_existing);
        if existed {
            ACCEPT_PREFIX_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
        } else {
            ACCEPT_PREFIX_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
        }
        if allow {
            ACCEPT_PREFIX_ALLOWED.fetch_add(1, Ordering::Relaxed);
        } else {
            ACCEPT_PREFIX_THROTTLED.fetch_add(1, Ordering::Relaxed);
            ACCEPT_THROTTLED.fetch_add(1, Ordering::Relaxed);
            update_accept_bucket_gauge(prefix_buckets, ip_buckets);
            return false;
        }
    } else {
        ACCEPT_PREFIX_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(rate) = params.ip_rate_per_sec {
        let burst = params.ip_burst.unwrap_or_else(|| rate.max(1.0));
        let key = ip_bucket_key(ip, 32, 128);
        let existed = ip_buckets.contains_key(&key);
        let evicted =
            enforce_aggregate_bucket_cap(prefix_buckets, ip_buckets, params.max_buckets, !existed);
        if evicted > 0 {
            ACCEPT_BUCKET_EVICTIONS.fetch_add(evicted as u64, Ordering::Relaxed);
        }
        let (allow, consumed_existing) = consume_accept_bucket(ip_buckets, key, rate, burst, now);
        debug_assert_eq!(existed, consumed_existing);
        if allow {
            ACCEPT_IP_ALLOWED.fetch_add(1, Ordering::Relaxed);
        } else {
            ACCEPT_IP_THROTTLED.fetch_add(1, Ordering::Relaxed);
            ACCEPT_THROTTLED.fetch_add(1, Ordering::Relaxed);
            update_accept_bucket_gauge(prefix_buckets, ip_buckets);
            return false;
        }
    }
    update_accept_bucket_gauge(prefix_buckets, ip_buckets);
    true
}

/// Coarse prefix key used by bounded accept buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct IpBucketKey([u8; 16], u8);

pub(super) fn ip_bucket_key(ip: IpAddr, prefix_v4_bits: u8, prefix_v6_bits: u8) -> IpBucketKey {
    match ip {
        IpAddr::V4(v4) => {
            let bits = prefix_v4_bits.min(32);
            let raw = u32::from_be_bytes(v4.octets());
            let masked = if bits == 0 {
                0
            } else {
                raw & (!0_u32 << (32 - bits))
            };
            let mut key = [0_u8; 16];
            key[..4].copy_from_slice(&masked.to_be_bytes());
            IpBucketKey(key, bits)
        }
        IpAddr::V6(v6) => {
            let bits = prefix_v6_bits.min(128);
            let raw = u128::from_be_bytes(v6.octets());
            let masked = if bits == 0 {
                0
            } else {
                raw & (!0_u128 << (128 - bits))
            };
            IpBucketKey(masked.to_be_bytes(), bits)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_membership_preserves_ipv4_and_ipv6_boundaries() {
        let nets = parse_cidrs(&["10.4.0.0/16".to_owned(), "2001:db8:5::/48".to_owned()])
            .expect("valid CIDRs");
        assert!(cidr_contains(&nets, IpAddr::from([10, 4, 8, 9])));
        assert!(!cidr_contains(&nets, IpAddr::from([10, 5, 8, 9])));
        assert!(cidr_contains(
            &nets,
            "2001:db8:5::1".parse().expect("valid IPv6")
        ));
        assert!(!cidr_contains(
            &nets,
            "2001:db8:6::1".parse().expect("valid IPv6")
        ));
    }

    #[test]
    fn malformed_cidr_rejects_the_whole_acl_dimension() {
        let error = parse_cidrs(&["10.0.0.0/8".to_owned(), "10.2.0.0/33".to_owned()])
            .expect_err("one malformed entry must reject the configured dimension");
        assert!(error.contains("10.2.0.0/33"));
    }

    #[test]
    fn mapped_ipv6_cidr_matches_canonical_ipv4_sources() {
        let nets = parse_cidrs(&["::ffff:192.0.2.0/120".to_owned()])
            .expect("mapped /120 is canonical IPv4 /24");
        assert!(cidr_contains(&nets, "192.0.2.17".parse().unwrap()));
        assert!(cidr_contains(&nets, "::ffff:192.0.2.17".parse().unwrap()));
        assert!(!cidr_contains(&nets, "192.0.3.17".parse().unwrap()));
        assert!(parse_cidrs(&["::ffff:192.0.2.0/95".to_owned()]).is_err());
    }

    #[test]
    fn token_ownership_stops_at_the_configured_burst() {
        let mut bucket = TokenBucket::new(1.0, 2.0);
        assert!(bucket.allow());
        assert!(bucket.allow());
        assert!(!bucket.allow());
    }

    #[test]
    fn accept_bucket_cap_is_aggregate_across_prefix_and_ip_maps() {
        const MAX_BUCKETS: usize = 7;
        let params = AcceptThrottleParams::new(
            AcceptRate {
                rate_per_sec: Some(1_000.0),
                burst: Some(1_000.0),
            },
            24,
            64,
            AcceptRate {
                rate_per_sec: Some(1_000.0),
                burst: Some(1_000.0),
            },
            MAX_BUCKETS,
            Duration::from_secs(60),
        );
        let mut prefix_buckets = HashMap::new();
        let mut ip_buckets = HashMap::new();

        for subnet in 0..32 {
            assert!(allow_ip_with_policy(
                &[],
                &[],
                false,
                params,
                &mut prefix_buckets,
                &mut ip_buckets,
                IpAddr::from([10, subnet, 0, 1]),
            ));
            assert!(
                retained_bucket_count(&prefix_buckets, &ip_buckets) <= MAX_BUCKETS,
                "the documented combined cap must cover both ownership maps"
            );
        }
    }

    #[test]
    fn insufficient_cap_for_enabled_dimensions_fails_closed() {
        let params = AcceptThrottleParams::new(
            AcceptRate {
                rate_per_sec: Some(1_000.0),
                burst: Some(1_000.0),
            },
            24,
            64,
            AcceptRate {
                rate_per_sec: Some(1_000.0),
                burst: Some(1_000.0),
            },
            1,
            Duration::from_secs(60),
        );
        let mut prefix_buckets = HashMap::new();
        let mut ip_buckets = HashMap::new();

        assert!(validate_accept_throttle_geometry(true, true, 1).is_err());
        for _ in 0..2 {
            assert!(!allow_ip_with_policy(
                &[],
                &[],
                false,
                params,
                &mut prefix_buckets,
                &mut ip_buckets,
                IpAddr::from([192, 0, 2, 1]),
            ));
        }
        assert!(prefix_buckets.is_empty());
        assert!(ip_buckets.is_empty());
    }
}
