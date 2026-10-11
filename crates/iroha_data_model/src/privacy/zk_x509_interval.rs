//! Canonical zk-X509 presentation-interval semantics.
//!
//! This module is the single definition of when a public presentation window is
//! covered by signed X.509 material. Statement validation, authoritative-state
//! admission and the verifier's public shape consume it in every build. The
//! native reference relation and the DER-to-bounds helper beside it
//! (`iroha_core_privacy`) consume it too, but they are compiled with the prover:
//! only for tests and the `privacy-release-evidence` feature. The in-relation
//! numeric rows enforce the same predicates independently and are
//! differentially tested against it. This module takes already-parsed seconds
//! and is available to every holder-side statement builder.
//!
//! For a leaf-first certification path with validity periods
//! `[notBefore_i, notAfter_i]` (both inclusive, RFC 5280 §4.1.2.5) and the one
//! governed complete CRL with update interval `[thisUpdate, nextUpdate)`, a
//! window `[start, end]` (both inclusive consensus seconds) is admitted exactly
//! when all of the following hold:
//!
//! * `start < end` and `end - start <= 300`;
//! * `start >= notBefore_i` for every certificate, so `start` is at least the
//!   **latest** `notBefore` in the path;
//! * `end <= notAfter_i` for every certificate, so `end` is at most the
//!   **earliest** `notAfter` in the path, whether that is the leaf, an
//!   intermediate or the root;
//! * `start >= thisUpdate`, `end < nextUpdate` (equality rejects) and
//!   `end - thisUpdate <= 300`;
//! * `end` does not exceed the last RFC 5280 calendar second.
//!
//! The executing block second must then lie inside `[start, end]`. The last
//! admissible block timestamp is therefore
//! `min(thisUpdate + 301, nextUpdate, Cmin + 1, end + 1) * 1000 - 1`
//! milliseconds, where `Cmin` is the earliest `notAfter` in the path.
//!
//! Shared cross-language vectors live in
//! `fixtures/zk/x509/interval_vectors_v1.json`; the public-boundary tests are
//! `tests/zk_x509_presentation_interval.rs`.

use core::fmt;

use thiserror::Error;

use super::{
    IrohaZkX509StarkP256StatementV1, PrivacyZkX509CrlRecordV1, ZK_X509_MAX_CHAIN_DEPTH_V1,
    ZK_X509_MAX_CRL_AGE_SECONDS_V1, ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1,
    ZK_X509_MIN_CHAIN_DEPTH_V1,
};

/// Last second representable by an RFC 5280 `GeneralizedTime`:
/// `9999-12-31T23:59:59Z`.
///
/// No signed certificate or CRL time exceeds it, so no admissible presentation
/// window does either.
pub const ZK_X509_MAX_UNIX_SECONDS_V1: u64 = 253_402_300_799;

/// Milliseconds per consensus second used by block-timestamp admission.
const MILLISECONDS_PER_SECOND_V1: u64 = 1_000;

/// Failure of the canonical zk-X509 presentation-interval definition.
///
/// Variants deliberately carry no certificate dates: those values are private
/// witness material on the holder side.
// Three public u64 window values outweigh the usize-only variant on 32-bit
// targets. Retain the small, allocation-free Copy error and its existing API.
#[cfg_attr(target_pointer_width = "32", allow(variant_size_differences))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PrivacyZkX509PresentationIntervalErrorV1 {
    /// The public window is empty, reversed, or wider than the closed ceiling.
    #[error(
        "X.509 presentation window [{start}, {end}] must be non-empty and no wider than {max_seconds} seconds"
    )]
    InvalidWindow {
        /// Inclusive presentation start.
        start: u64,
        /// Inclusive presentation end.
        end: u64,
        /// Closed first-release width ceiling.
        max_seconds: u64,
    },
    /// The certification path is outside the closed leaf-to-root depth range.
    #[error("X.509 certification path depth is outside the closed first-release profile")]
    InvalidChainDepth,
    /// One certificate's `notAfter` precedes its `notBefore`.
    #[error("X.509 certificate {index} validity ends before it begins")]
    InvalidCertificateValidity {
        /// Leaf-first position of the malformed certificate.
        index: usize,
    },
    /// The CRL `nextUpdate` is not strictly after its `thisUpdate`.
    #[error("X.509 CRL nextUpdate is not after thisUpdate")]
    InvalidCrlUpdateInterval,
    /// The signed intervals share no admissible presentation second.
    #[error("signed X.509 intervals share no admissible presentation second")]
    DisjointIntervals,
    /// The window starts before the latest signed lower bound.
    #[error("X.509 presentation starts before a signed interval begins")]
    StartsBeforeBounds,
    /// The window ends after the earliest signed upper bound.
    #[error("X.509 presentation ends after a signed interval ends")]
    EndsAfterBounds,
    /// A second-to-millisecond conversion does not fit the timestamp domain.
    #[error("X.509 presentation timestamp overflows Unix milliseconds")]
    TimestampOverflow,
}

impl PrivacyZkX509PresentationIntervalErrorV1 {
    /// Stable cross-language result code used by the shared interval vectors.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidWindow { .. } => "invalid-window",
            Self::InvalidChainDepth => "invalid-chain-depth",
            Self::InvalidCertificateValidity { .. } => "invalid-certificate-validity",
            Self::InvalidCrlUpdateInterval => "invalid-crl-update-interval",
            Self::DisjointIntervals => "disjoint-intervals",
            Self::StartsBeforeBounds => "starts-before-bounds",
            Self::EndsAfterBounds => "ends-after-bounds",
            Self::TimestampOverflow => "timestamp-overflow",
        }
    }
}

/// Complete verifier predicate over signed intervals and one public window.
///
/// Signed-interval failures take precedence over window failures: chain depth,
/// the lowest-index reversed certificate validity, a non-overlapping path, a
/// reversed CRL interval, a path that never overlaps the CRL, then the window
/// shape, its start and finally its end.
///
/// # Errors
///
/// Returns the first failing predicate in that order.
pub fn validate_zk_x509_presentation_interval_v1(
    certificates: &[PrivacyZkX509CertificateValidityV1],
    crl: PrivacyZkX509CrlUpdateIntervalV1,
    window: PrivacyZkX509PresentationWindowV1,
) -> Result<(), PrivacyZkX509PresentationIntervalErrorV1> {
    PrivacyZkX509PresentationBoundsV1::from_signed_intervals(certificates, crl)?.admit(window)
}

/// Signed validity period of one X.509 certificate.
///
/// Both bounds are inclusive Unix seconds (RFC 5280 §4.1.2.5). The values are
/// private witness material: `Debug` never prints them.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivacyZkX509CertificateValidityV1 {
    not_before_unix_seconds: u64,
    not_after_unix_seconds: u64,
}

impl PrivacyZkX509CertificateValidityV1 {
    /// Wrap one parsed `Validity` sequence.
    #[must_use]
    pub const fn new(not_before_unix_seconds: u64, not_after_unix_seconds: u64) -> Self {
        Self {
            not_before_unix_seconds,
            not_after_unix_seconds,
        }
    }
    /// Signed `notBefore`, inclusive.
    #[must_use]
    pub const fn not_before_unix_seconds(self) -> u64 {
        self.not_before_unix_seconds
    }
    /// Signed `notAfter`, inclusive.
    #[must_use]
    pub const fn not_after_unix_seconds(self) -> u64 {
        self.not_after_unix_seconds
    }
}

impl fmt::Debug for PrivacyZkX509CertificateValidityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivacyZkX509CertificateValidityV1 { <private material redacted> }")
    }
}

/// Signed update interval of one complete CRL.
///
/// `thisUpdate` is inclusive and `nextUpdate` is exclusive: a presentation
/// whose last second equals `nextUpdate` is not covered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivacyZkX509CrlUpdateIntervalV1 {
    /// Signed CRL `thisUpdate` as Unix seconds, inclusive.
    pub this_update_unix_seconds: u64,
    /// Signed CRL `nextUpdate` as Unix seconds, exclusive.
    pub next_update_unix_seconds: u64,
}

impl PrivacyZkX509CrlUpdateIntervalV1 {
    /// Wrap one parsed or governed `thisUpdate`/`nextUpdate` pair.
    #[must_use]
    pub const fn new(this_update_unix_seconds: u64, next_update_unix_seconds: u64) -> Self {
        Self {
            this_update_unix_seconds,
            next_update_unix_seconds,
        }
    }
}

impl PrivacyZkX509CrlRecordV1 {
    /// Signed update interval recorded by this governed CRL revision.
    #[must_use]
    pub const fn update_interval(&self) -> PrivacyZkX509CrlUpdateIntervalV1 {
        PrivacyZkX509CrlUpdateIntervalV1::new(
            self.this_update_unix_seconds,
            self.next_update_unix_seconds,
        )
    }
}

/// Public presentation window of one zk-X509 statement.
///
/// Both bounds are inclusive consensus seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivacyZkX509PresentationWindowV1 {
    /// Earliest consensus second at which the presentation may execute.
    pub not_before_unix_seconds: u64,
    /// Latest consensus second at which the presentation may execute.
    pub not_after_unix_seconds: u64,
}

impl PrivacyZkX509PresentationWindowV1 {
    /// Wrap one public `[start, end]` pair without validating it.
    #[must_use]
    pub const fn new(not_before_unix_seconds: u64, not_after_unix_seconds: u64) -> Self {
        Self {
            not_before_unix_seconds,
            not_after_unix_seconds,
        }
    }

    /// Check the closed window shape: `start < end` and `end - start <= 300`.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyZkX509PresentationIntervalErrorV1::InvalidWindow`] for
    /// an empty, reversed or over-wide window.
    pub const fn validate(self) -> Result<(), PrivacyZkX509PresentationIntervalErrorV1> {
        let start = self.not_before_unix_seconds;
        let end = self.not_after_unix_seconds;
        if end <= start || end - start > ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1 {
            return Err(PrivacyZkX509PresentationIntervalErrorV1::InvalidWindow {
                start,
                end,
                max_seconds: ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1,
            });
        }
        Ok(())
    }

    /// Whether one consensus second lies inside the inclusive window.
    #[must_use]
    pub const fn contains_unix_seconds(self, unix_seconds: u64) -> bool {
        self.not_before_unix_seconds <= unix_seconds && unix_seconds <= self.not_after_unix_seconds
    }

    /// Whether a block with this millisecond timestamp may execute the
    /// presentation. Admission truncates the timestamp to its whole second.
    #[must_use]
    pub const fn admits_block_timestamp_ms(self, block_timestamp_ms: u64) -> bool {
        self.contains_unix_seconds(block_timestamp_ms / MILLISECONDS_PER_SECOND_V1)
    }

    /// First block timestamp, in Unix milliseconds, admitted by this window.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyZkX509PresentationIntervalErrorV1::TimestampOverflow`]
    /// when the start does not fit Unix milliseconds.
    pub const fn first_admissible_block_timestamp_ms(
        self,
    ) -> Result<u64, PrivacyZkX509PresentationIntervalErrorV1> {
        match self
            .not_before_unix_seconds
            .checked_mul(MILLISECONDS_PER_SECOND_V1)
        {
            Some(milliseconds) => Ok(milliseconds),
            None => Err(PrivacyZkX509PresentationIntervalErrorV1::TimestampOverflow),
        }
    }

    /// Last block timestamp, in Unix milliseconds, admitted by this window:
    /// `(end + 1) * 1000 - 1`.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyZkX509PresentationIntervalErrorV1::TimestampOverflow`]
    /// when the end does not fit Unix milliseconds.
    pub const fn last_admissible_block_timestamp_ms(
        self,
    ) -> Result<u64, PrivacyZkX509PresentationIntervalErrorV1> {
        last_millisecond_of_second_v1(self.not_after_unix_seconds)
    }
}

impl IrohaZkX509StarkP256StatementV1 {
    /// Public presentation window carried by this statement.
    #[must_use]
    pub const fn presentation_window(&self) -> PrivacyZkX509PresentationWindowV1 {
        PrivacyZkX509PresentationWindowV1::new(
            self.presentation_not_before_unix_seconds,
            self.presentation_not_after_unix_seconds,
        )
    }
}

/// Inclusive bounds that signed X.509 material places on a presentation window.
///
/// The two fields are the admissible endpoints of a window, not certificate
/// fields: the earliest admissible start is the **latest** signed lower bound
/// (every `notBefore` and the CRL `thisUpdate`), and the latest admissible end
/// is the **earliest** signed upper bound (every `notAfter`, the CRL
/// `nextUpdate - 1` and `thisUpdate + 300`).
///
/// Bounds derived from a certification path are private witness material:
/// `Debug` never prints them.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivacyZkX509PresentationBoundsV1 {
    earliest_start_unix_seconds: u64,
    latest_end_unix_seconds: u64,
}

impl fmt::Debug for PrivacyZkX509PresentationBoundsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivacyZkX509PresentationBoundsV1 { <private material redacted> }")
    }
}

impl PrivacyZkX509PresentationBoundsV1 {
    /// Bounds implied by **every** certificate of one leaf-first path:
    /// `[max notBefore, min notAfter]`.
    ///
    /// The upper bound is the earliest expiry in the path. Using the latest
    /// expiry would admit a presentation after an intermediate or root
    /// certificate has expired.
    ///
    /// # Errors
    ///
    /// Rejects a path outside the closed depth range, a certificate whose
    /// validity is reversed, and a path whose certificates never overlap.
    pub fn from_certificate_path(
        certificates: &[PrivacyZkX509CertificateValidityV1],
    ) -> Result<Self, PrivacyZkX509PresentationIntervalErrorV1> {
        if certificates.len() < usize::from(ZK_X509_MIN_CHAIN_DEPTH_V1)
            || certificates.len() > usize::from(ZK_X509_MAX_CHAIN_DEPTH_V1)
        {
            return Err(PrivacyZkX509PresentationIntervalErrorV1::InvalidChainDepth);
        }
        let mut earliest_start_unix_seconds = 0;
        let mut latest_end_unix_seconds = ZK_X509_MAX_UNIX_SECONDS_V1;
        for (index, certificate) in certificates.iter().enumerate() {
            if certificate.not_after_unix_seconds < certificate.not_before_unix_seconds {
                return Err(
                    PrivacyZkX509PresentationIntervalErrorV1::InvalidCertificateValidity { index },
                );
            }
            // The latest notBefore is the earliest admissible start; the
            // earliest notAfter is the latest admissible end.
            earliest_start_unix_seconds =
                earliest_start_unix_seconds.max(certificate.not_before_unix_seconds);
            latest_end_unix_seconds =
                latest_end_unix_seconds.min(certificate.not_after_unix_seconds);
        }
        Self::checked(earliest_start_unix_seconds, latest_end_unix_seconds)
    }

    /// Bounds implied by one complete CRL:
    /// `[thisUpdate, min(nextUpdate - 1, thisUpdate + 300)]`.
    ///
    /// `nextUpdate` is exclusive and the CRL may be at most 300 seconds old at
    /// the last presentation second.
    ///
    /// # Errors
    ///
    /// Rejects a CRL whose `nextUpdate` is not after `thisUpdate`, or whose
    /// `thisUpdate` lies beyond the RFC 5280 calendar.
    pub fn from_crl(
        crl: PrivacyZkX509CrlUpdateIntervalV1,
    ) -> Result<Self, PrivacyZkX509PresentationIntervalErrorV1> {
        if crl.next_update_unix_seconds <= crl.this_update_unix_seconds {
            return Err(PrivacyZkX509PresentationIntervalErrorV1::InvalidCrlUpdateInterval);
        }
        let last_covered_second = crl.next_update_unix_seconds - 1;
        let last_fresh_second = crl
            .this_update_unix_seconds
            .saturating_add(ZK_X509_MAX_CRL_AGE_SECONDS_V1);
        Self::checked(
            crl.this_update_unix_seconds,
            last_covered_second
                .min(last_fresh_second)
                .min(ZK_X509_MAX_UNIX_SECONDS_V1),
        )
    }

    /// Bounds implied by the complete path **and** its governed CRL.
    ///
    /// This is the holder-side builder input: every admissible window lies
    /// inside the returned bounds, and every well-shaped window inside them is
    /// admissible.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::from_certificate_path`] and [`Self::from_crl`]
    /// failures and rejects signed intervals that share no second.
    pub fn from_signed_intervals(
        certificates: &[PrivacyZkX509CertificateValidityV1],
        crl: PrivacyZkX509CrlUpdateIntervalV1,
    ) -> Result<Self, PrivacyZkX509PresentationIntervalErrorV1> {
        Self::from_certificate_path(certificates)?.intersect(Self::from_crl(crl)?)
    }

    /// Intersect two independently derived bounds.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyZkX509PresentationIntervalErrorV1::DisjointIntervals`]
    /// when no second satisfies both.
    pub fn intersect(self, other: Self) -> Result<Self, PrivacyZkX509PresentationIntervalErrorV1> {
        Self::checked(
            self.earliest_start_unix_seconds
                .max(other.earliest_start_unix_seconds),
            self.latest_end_unix_seconds
                .min(other.latest_end_unix_seconds),
        )
    }

    /// Earliest admissible presentation start, inclusive: the latest signed
    /// lower bound (every `notBefore` and the CRL `thisUpdate`).
    #[must_use]
    pub const fn earliest_start_unix_seconds(self) -> u64 {
        self.earliest_start_unix_seconds
    }

    /// Latest admissible presentation end, inclusive: the earliest signed
    /// upper bound (every `notAfter`, the CRL `nextUpdate - 1` and
    /// `thisUpdate + 300`).
    #[must_use]
    pub const fn latest_end_unix_seconds(self) -> u64 {
        self.latest_end_unix_seconds
    }

    /// Whether one consensus second lies inside the inclusive bounds.
    ///
    /// For bounds from [`Self::from_crl`] this is the CRL freshness predicate
    /// at one second: `thisUpdate <= second < nextUpdate` and
    /// `second - thisUpdate <= 300`, within the RFC 5280 calendar.
    #[must_use]
    pub const fn contains_unix_seconds(self, unix_seconds: u64) -> bool {
        self.earliest_start_unix_seconds <= unix_seconds
            && unix_seconds <= self.latest_end_unix_seconds
    }

    /// Verifier predicate: the window is well shaped and lies inside the bounds.
    ///
    /// # Errors
    ///
    /// Rejects a malformed window, a start before the earliest admissible
    /// second and an end after the latest admissible second.
    pub const fn admit(
        self,
        window: PrivacyZkX509PresentationWindowV1,
    ) -> Result<(), PrivacyZkX509PresentationIntervalErrorV1> {
        if let Err(error) = window.validate() {
            return Err(error);
        }
        if window.not_before_unix_seconds < self.earliest_start_unix_seconds {
            return Err(PrivacyZkX509PresentationIntervalErrorV1::StartsBeforeBounds);
        }
        if window.not_after_unix_seconds > self.latest_end_unix_seconds {
            return Err(PrivacyZkX509PresentationIntervalErrorV1::EndsAfterBounds);
        }
        Ok(())
    }

    /// Builder: the widest admissible window that starts at the given second.
    ///
    /// A start before [`Self::earliest_start_unix_seconds`] is refused, never
    /// clamped: the caller decides whether to wait or to start at the bound.
    ///
    /// # Holder privacy
    ///
    /// The window is public; certificate validity dates are private. When a
    /// certificate, not the public CRL, is the binding bound, this builder
    /// returns `end ==` the earliest `notAfter` in the path, and a caller that
    /// starts at [`Self::earliest_start_unix_seconds`] publishes the latest
    /// `notBefore`. Either copies an exact private certificate date into the
    /// public statement. It can only happen within 300 seconds of an expiry or
    /// an issuance. [`Self::window_publishes_private_bound`] detects it; the
    /// wallet decides whether to refuse or to present a shorter window.
    ///
    /// # Errors
    ///
    /// Rejects a start outside the bounds or one that leaves no later
    /// admissible second.
    pub const fn widest_window_from(
        self,
        not_before_unix_seconds: u64,
    ) -> Result<PrivacyZkX509PresentationWindowV1, PrivacyZkX509PresentationIntervalErrorV1> {
        if not_before_unix_seconds < self.earliest_start_unix_seconds {
            return Err(PrivacyZkX509PresentationIntervalErrorV1::StartsBeforeBounds);
        }
        if not_before_unix_seconds >= self.latest_end_unix_seconds {
            return Err(PrivacyZkX509PresentationIntervalErrorV1::EndsAfterBounds);
        }
        let widest_end =
            not_before_unix_seconds.saturating_add(ZK_X509_MAX_PRESENTATION_WINDOW_SECONDS_V1);
        let not_after_unix_seconds = if widest_end < self.latest_end_unix_seconds {
            widest_end
        } else {
            self.latest_end_unix_seconds
        };
        let window =
            PrivacyZkX509PresentationWindowV1::new(not_before_unix_seconds, not_after_unix_seconds);
        match self.admit(window) {
            Ok(()) => Ok(window),
            Err(error) => Err(error),
        }
    }

    /// Whether publishing `window` publishes an exact private certificate date.
    ///
    /// `self` is the combined bounds of the path and its CRL
    /// ([`Self::from_signed_intervals`]); `public_bounds` is the bounds of the
    /// same governed CRL alone ([`Self::from_crl`]), which every observer can
    /// compute. The result is `true` when the window starts exactly at an
    /// earliest start that only the private path imposes, or ends exactly at a
    /// latest end that only the private path imposes. An endpoint that the
    /// public CRL bounds explain equally (a tie) is not flagged.
    ///
    /// The inputs must be an admitted window and correctly paired bounds. A
    /// `false` result means only that this endpoint equality was not detected;
    /// it is not a general privacy guarantee. Whether to refuse or shorten a
    /// flagged window is wallet policy.
    #[must_use]
    pub const fn window_publishes_private_bound(
        self,
        public_bounds: Self,
        window: PrivacyZkX509PresentationWindowV1,
    ) -> bool {
        let start = window.not_before_unix_seconds;
        let end = window.not_after_unix_seconds;
        // Only the private path imposes a bound that is tighter than the
        // public CRL bound on the same side.
        let private_start = self.earliest_start_unix_seconds;
        let private_end = self.latest_end_unix_seconds;
        let start_is_private = private_start > public_bounds.earliest_start_unix_seconds;
        let end_is_private = private_end < public_bounds.latest_end_unix_seconds;
        (start_is_private && start == private_start) || (end_is_private && end == private_end)
    }

    /// Holder deadline: the last block timestamp, in Unix milliseconds, at
    /// which a presentation ending at `presentation_not_after_unix_seconds`
    /// can still be admitted.
    ///
    /// For bounds from [`Self::from_signed_intervals`] this is exactly
    /// `min(thisUpdate + 301, nextUpdate, Cmin + 1, end + 1) * 1000 - 1`, with
    /// `Cmin` the **earliest** `notAfter` in the path.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyZkX509PresentationIntervalErrorV1::TimestampOverflow`]
    /// when the deadline does not fit Unix milliseconds.
    pub const fn presentation_deadline_unix_ms(
        self,
        presentation_not_after_unix_seconds: u64,
    ) -> Result<u64, PrivacyZkX509PresentationIntervalErrorV1> {
        let last_second = if presentation_not_after_unix_seconds < self.latest_end_unix_seconds {
            presentation_not_after_unix_seconds
        } else {
            self.latest_end_unix_seconds
        };
        last_millisecond_of_second_v1(last_second)
    }

    fn checked(
        earliest_start_unix_seconds: u64,
        latest_end_unix_seconds: u64,
    ) -> Result<Self, PrivacyZkX509PresentationIntervalErrorV1> {
        if earliest_start_unix_seconds > latest_end_unix_seconds {
            return Err(PrivacyZkX509PresentationIntervalErrorV1::DisjointIntervals);
        }
        Ok(Self {
            earliest_start_unix_seconds,
            latest_end_unix_seconds,
        })
    }
}

/// `(second + 1) * 1000 - 1` with overflow reported instead of wrapping.
const fn last_millisecond_of_second_v1(
    unix_seconds: u64,
) -> Result<u64, PrivacyZkX509PresentationIntervalErrorV1> {
    let Some(next_second) = unix_seconds.checked_add(1) else {
        return Err(PrivacyZkX509PresentationIntervalErrorV1::TimestampOverflow);
    };
    match next_second.checked_mul(MILLISECONDS_PER_SECOND_V1) {
        Some(milliseconds) => Ok(milliseconds - 1),
        None => Err(PrivacyZkX509PresentationIntervalErrorV1::TimestampOverflow),
    }
}
