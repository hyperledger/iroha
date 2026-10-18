//! Fixed temporal identities and integer-safe numeric operand bindings.
//!
//! These kernels require the caller to authenticate the complete DER time-node
//! census and to constrain their event selectors. A membership-only lookup or
//! a host-created list of dates is not a substitute for that census.

use super::{F, PolynomialAirFieldV1, ZkX509Rfc5280GrammarRoleV1, ZkX509Rfc5280StarkErrorV1};
use iroha_data_model::privacy::{ZK_X509_MAX_CRL_AGE_SECONDS_V1, ZK_X509_MAX_UNIX_SECONDS_V1};

pub(super) const TEMPORAL_SLOTS_V1: usize = 72;
pub(super) const DECIMAL_ROWS_PER_TIME_V1: usize = 15;
pub(super) const CALENDAR_PHASES_V1: usize = 7;
pub(super) const RELATION_SLOTS_V1: usize = 73;
pub(super) const RELATION_PHASES_V1: usize = 2;
pub(super) const RANGE_BYTES_PER_RELATION_V1: usize = 8;
/// Last RFC 5280 calendar second; the canonical interval definition owns it.
pub(super) const MAXIMUM_TIMESTAMP_V1: u64 = ZK_X509_MAX_UNIX_SECONDS_V1;
/// Public affine offset of the CRL-age relation `thisUpdate + 300 >= end`.
pub(super) const CRL_AGE_SECONDS_V1: u16 = {
    assert!(ZK_X509_MAX_CRL_AGE_SECONDS_V1 <= u16::MAX as u64);
    ZK_X509_MAX_CRL_AGE_SECONDS_V1 as u16
};
pub(super) const SLACK_BITS_V1: usize = 38;
pub(super) const TIME_NODE_DOMAIN_V1: u64 = 100;
pub(super) const TIMESTAMP_DOMAIN_V1: u64 = 101;
pub(super) const LOOKUP_LANES_V1: usize = 4;
#[cfg(test)]
pub(super) const LOOKUP_AUX_WIDTH_V1: usize = 4 * LOOKUP_LANES_V1;
pub(super) const LOOKUP_RESIDUES_V1: usize = 3 + 12 * LOOKUP_LANES_V1;
const _: () =
    assert!(MAXIMUM_TIMESTAMP_V1 + ZK_X509_MAX_CRL_AGE_SECONDS_V1 < 1_u64 << SLACK_BITS_V1);

/// One fixed semantic time slot; its instance is not a prover-chosen ordinal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TemporalSlotV1 {
    CertificateNotBefore(u8),
    CertificateNotAfter(u8),
    CrlThisUpdate,
    CrlNextUpdate,
    CrlEntry(u8),
}

pub(super) fn temporal_slot_v1(index: usize) -> Option<TemporalSlotV1> {
    match index {
        0..=2 => Some(TemporalSlotV1::CertificateNotBefore(index as u8)),
        3..=5 => Some(TemporalSlotV1::CertificateNotAfter((index - 3) as u8)),
        6 => Some(TemporalSlotV1::CrlThisUpdate),
        7 => Some(TemporalSlotV1::CrlNextUpdate),
        8..TEMPORAL_SLOTS_V1 => Some(TemporalSlotV1::CrlEntry((index - 8) as u8)),
        _ => None,
    }
}

impl TemporalSlotV1 {
    /// Document, authenticated grammar role, and role-local occurrence index.
    pub(super) fn identity_v1<A: PolynomialAirFieldV1>(self, certificate_two: A) -> [A; 3] {
        use ZkX509Rfc5280GrammarRoleV1 as Role;
        let (certificate, role, instance) = match self {
            Self::CertificateNotBefore(index) => (Some(index), Role::CertificateNotBefore, index),
            Self::CertificateNotAfter(index) => (Some(index), Role::CertificateNotAfter, index),
            Self::CrlThisUpdate => (None, Role::CrlThisUpdate, 0),
            Self::CrlNextUpdate => (None, Role::CrlNextUpdate, 0),
            Self::CrlEntry(index) => (None, Role::CrlEntryTime, index),
        };
        [
            certificate.map_or_else(
                || A::from_base(F(2)).add(certificate_two),
                |index| A::from_base(F(u64::from(index))),
            ),
            A::from_base(F(role as u64)),
            A::from_base(F(u64::from(instance))),
        ]
    }

    /// Every time except the CRL update is consumed once by a numeric relation.
    #[cfg(test)]
    pub(super) fn numeric_multiplicity_v1<A: PolynomialAirFieldV1>(self, entries: A) -> A {
        if self == Self::CrlThisUpdate {
            A::from_base(F(2)).add(entries)
        } else {
            A::ONE
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NumericOperandV1 {
    WindowStart,
    WindowEnd,
    Time {
        slot: TemporalSlotV1,
        add_seconds: u16,
    },
}

#[cfg(test)]
impl NumericOperandV1 {
    /// A private operand query removes its public affine offset before lookup.
    /// Public operands are bound directly to verifier-generated fixed cells.
    #[cfg(test)]
    pub(super) fn timestamp_tuple_v1<A: PolynomialAirFieldV1>(
        self,
        certificate_two: A,
        value: A,
    ) -> Option<[A; 12]> {
        match self {
            Self::WindowStart | Self::WindowEnd => None,
            Self::Time { slot, add_seconds } => {
                let identity = slot.identity_v1(certificate_two);
                Some(timestamp_tuple_v1(
                    identity,
                    value.sub(A::from_base(F(u64::from(add_seconds)))),
                ))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NumericActivityV1 {
    Required,
    CertificateTwo,
    Entry(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NumericRelationSlotV1 {
    pub(super) relation: u16,
    pub(super) instance: u16,
    pub(super) strict: bool,
    pub(super) activity: NumericActivityV1,
    pub(super) left: NumericOperandV1,
    pub(super) right: NumericOperandV1,
}

pub(super) fn relation_slot_v1(index: usize) -> Option<NumericRelationSlotV1> {
    use NumericOperandV1::{Time, WindowEnd, WindowStart};
    use TemporalSlotV1::{
        CertificateNotAfter, CertificateNotBefore, CrlEntry, CrlNextUpdate, CrlThisUpdate,
    };
    let time = |slot| Time {
        slot,
        add_seconds: 0,
    };
    let (relation, instance, strict, activity, left, right) = match index {
        0..=5 => {
            let certificate = (index / 2) as u8;
            let activity = if certificate == 2 {
                NumericActivityV1::CertificateTwo
            } else {
                NumericActivityV1::Required
            };
            if index % 2 == 0 {
                (
                    1,
                    u16::from(certificate),
                    false,
                    activity,
                    WindowStart,
                    time(CertificateNotBefore(certificate)),
                )
            } else {
                (
                    2,
                    u16::from(certificate),
                    false,
                    activity,
                    time(CertificateNotAfter(certificate)),
                    WindowEnd,
                )
            }
        }
        6 => (
            4,
            0,
            false,
            NumericActivityV1::Required,
            WindowStart,
            time(CrlThisUpdate),
        ),
        7 => (
            5,
            0,
            true,
            NumericActivityV1::Required,
            time(CrlNextUpdate),
            WindowEnd,
        ),
        8 => (
            6,
            0,
            false,
            NumericActivityV1::Required,
            Time {
                slot: CrlThisUpdate,
                add_seconds: CRL_AGE_SECONDS_V1,
            },
            WindowEnd,
        ),
        9..RELATION_SLOTS_V1 => {
            let entry = (index - 9) as u8;
            (
                7,
                u16::from(entry),
                false,
                NumericActivityV1::Entry(entry),
                time(CrlThisUpdate),
                time(CrlEntry(entry)),
            )
        }
        _ => return None,
    };
    Some(NumericRelationSlotV1 {
        relation,
        instance,
        strict,
        activity,
        left,
        right,
    })
}

pub(super) fn validate_window_v1(start: u64, end: u64) -> Result<(), ZkX509Rfc5280StarkErrorV1> {
    if start > end || end > MAXIMUM_TIMESTAMP_V1 {
        Err(ZkX509Rfc5280StarkErrorV1::Semantic)
    } else {
        Ok(())
    }
}

pub(super) fn timestamp_tuple_v1<A: PolynomialAirFieldV1>(identity: [A; 3], value: A) -> [A; 12] {
    let mut tuple = [A::ZERO; 12];
    tuple[0] = A::from_base(F(TIMESTAMP_DOMAIN_V1));
    tuple[1..4].copy_from_slice(&identity);
    tuple[4] = value;
    tuple
}

/// Bind the exact DER node, including time tag and content span, across the
/// source-node and calendar identity events. The complete source census must
/// emit every authenticated time-role node exactly once.
pub(super) fn time_node_tuple_v1<A: PolynomialAirFieldV1>(
    identity: [A; 3],
    ordinal: A,
    tag: A,
    content_start: A,
    content_end: A,
) -> [A; 12] {
    [
        A::from_base(F(TIME_NODE_DOMAIN_V1)),
        identity[0],
        identity[1],
        identity[2],
        ordinal,
        tag,
        content_start,
        content_end,
        A::ZERO,
        A::ZERO,
        A::ZERO,
        A::ZERO,
    ]
}

/// Affine challenge factor with a fixed constant term. This normalizes factors
/// across tuple domains: distinct nonzero tuples cannot define proportional
/// linear polynomials in the challenge coordinates. Typed event constraints
/// must still enforce each nonzero domain and every tuple coordinate.
pub(super) fn lookup_factor_v1<A: PolynomialAirFieldV1>(tuple: [A; 12], challenge: [F; 12]) -> A {
    A::ONE.add(super::compress_tuple_v1(tuple, challenge))
}

/// One selected source or consumer event. Source multiplicities are supplied
/// by the fixed slot census (CRL this-update is `2 + entry_count`).
pub(super) struct NumericLookupEventV1<A> {
    pub(super) source: A,
    pub(super) query: A,
    pub(super) multiplicity: A,
    pub(super) tuple: [A; 12],
}

/// Prefix values before this row, with one zero-safe inverse per lane.
pub(super) struct NumericLookupRowV1<A> {
    pub(super) inverse: [A; LOOKUP_LANES_V1],
    pub(super) zero: [A; LOOKUP_LANES_V1],
    pub(super) sum: [A; LOOKUP_LANES_V1],
    pub(super) zero_sum: [A; LOOKUP_LANES_V1],
}

/// Polynomial zero-safe logarithmic multiset equality. The caller separately
/// binds event selectors, tuples and multiplicities to the fixed semantics.
/// With normalized selectors/weights these residues have degree at most four,
/// including verifier-fixed first/continue/last selectors.
pub(super) fn lookup_residues_v1<A: PolynomialAirFieldV1>(
    event: &NumericLookupEventV1<A>,
    current: &NumericLookupRowV1<A>,
    next: &NumericLookupRowV1<A>,
    first: A,
    continue_row: A,
    last: A,
    challenges: &[[F; 12]; LOOKUP_LANES_V1],
) -> Vec<A> {
    let active = event.source.add(event.query);
    let weight = event.source.mul(event.multiplicity).sub(event.query);
    let mut residues = Vec::with_capacity(LOOKUP_RESIDUES_V1);
    residues.push(event.source.mul(event.source.sub(A::ONE)));
    residues.push(event.query.mul(event.query.sub(A::ONE)));
    residues.push(event.source.mul(event.query));
    for (lane, challenge) in challenges.iter().copied().enumerate() {
        let factor = lookup_factor_v1(event.tuple, challenge);
        let inverse = current.inverse[lane];
        let zero = current.zero[lane];
        let delta = weight.mul(inverse);
        let zero_delta = weight.mul(zero);
        residues.push(zero.mul(zero.sub(A::ONE)));
        residues.push(active.mul(factor.mul(inverse).sub(A::ONE.sub(zero))));
        residues.push(active.mul(factor).mul(zero));
        residues.push(zero.mul(inverse));
        residues.push(A::ONE.sub(active).mul(inverse));
        residues.push(A::ONE.sub(active).mul(zero));
        residues.push(first.mul(current.sum[lane]));
        residues.push(first.mul(current.zero_sum[lane]));
        residues.push(continue_row.mul(next.sum[lane].sub(current.sum[lane]).sub(delta)));
        residues.push(
            continue_row.mul(
                next.zero_sum[lane]
                    .sub(current.zero_sum[lane])
                    .sub(zero_delta),
            ),
        );
        residues.push(last.mul(current.sum[lane].add(delta)));
        residues.push(last.mul(current.zero_sum[lane].add(zero_delta)));
    }
    residues
}

#[cfg(test)]
#[path = "rfc5280_numeric_tests.rs"]
mod tests;
