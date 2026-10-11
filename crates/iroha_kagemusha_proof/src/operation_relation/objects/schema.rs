//! Fixed canonical body schemas; metadata is never selected by private bytes.

use iroha_plonk_gadgets::bytes::{chunk_segments, tape::SegmentSpec};

#[derive(Clone, Copy, Debug)]
pub(super) enum Atom {
    Integer(usize),
    Identifier,
    Field,
    Key,
}
impl Atom {
    pub(super) const fn len(self) -> usize {
        match self {
            Self::Integer(n) => n,
            Self::Identifier | Self::Field => 32,
            Self::Key => 65,
        }
    }
}
use Atom::{Field as P, Identifier as D, Integer as U, Key as K};

/// Canonical G1 signed-object bodies needed by operation relations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    /// Scheme-root signer certificate.
    Certificate,
    /// Enrollment or renewed wallet credential.
    Credential,
    /// Derived durable-provider receipt body.
    Receipt,
    /// Scheme policy and optional fee-schedule digest.
    SchemePolicy,
    /// Fee formula and beneficiary.
    FeeSchedule,
    /// Blacklist version/root descriptor.
    Blacklist,
    /// Quota-window root descriptor.
    QuotaShare,
    /// Wallet-bound issuer time.
    TimeAnchor,
    /// Load/unload online-charge quote.
    ChargeQuote,
    /// Receiver's exact payment Request.
    Request,
}
impl ObjectKind {
    /// Every schema, in domain-table order.
    pub const ALL: [Self; 10] = [
        Self::Certificate,
        Self::Credential,
        Self::Receipt,
        Self::SchemePolicy,
        Self::FeeSchedule,
        Self::Blacklist,
        Self::QuotaShare,
        Self::TimeAnchor,
        Self::ChargeQuote,
        Self::Request,
    ];
    pub(super) const fn schema(self) -> &'static [Atom] {
        match self {
            Self::Certificate => &[U(2), D, U(1), K, U(8)],
            Self::Credential => &[
                U(2),
                D,
                D,
                D,
                D,
                K,
                D,
                U(1),
                D,
                U(8),
                U(4),
                U(4),
                U(4),
                U(4),
                D,
                U(8),
                U(4),
                U(4),
                U(4),
                U(4),
                D,
                U(4),
                U(8),
                U(8),
                D,
                U(8),
                U(4),
                U(8),
                P,
            ],
            Self::Receipt => &[U(2), D, D, D, U(16), P, P, P, P, P, D, P],
            Self::SchemePolicy => &[U(2), D, D, U(8), U(4), P, P],
            Self::FeeSchedule => &[U(2), D, D, U(8), D, U(4), U(16), U(16), U(16), U(1), P],
            Self::Blacklist => &[U(2), D, U(8), U(8), U(4), P, P],
            Self::QuotaShare => &[U(2), D, D, D, U(8), U(8), U(8), P, U(4), P],
            Self::TimeAnchor => &[U(2), D, D, D, U(8), P],
            Self::ChargeQuote => &[U(2), D, D, D, U(1), U(16), U(16), U(16), D, U(8), P],
            Self::Request => &[
                U(2),
                D,
                D,
                D,
                D,
                D,
                D,
                U(16),
                P,
                U(16),
                P,
                U(16),
                U(8),
                P,
                U(8),
                U(8),
                P,
                P,
                D,
            ],
        }
    }
    /// Exact signed-body byte length, excluding its signature.
    pub fn body_len(self) -> usize {
        self.schema().iter().map(|atom| atom.len()).sum()
    }
    /// `P_bytes` signing domain of the body.
    pub const fn signing_domain(self) -> u64 {
        u64::from_le_bytes(match self {
            Self::Certificate => *b"kgwcert1",
            Self::Credential => *b"kgwcred1",
            Self::Receipt => *b"kgwrcpt1",
            Self::SchemePolicy => *b"kgwspol1",
            Self::FeeSchedule => *b"kgwfsch1",
            Self::Blacklist => *b"kgwblst1",
            Self::QuotaShare => *b"kgwqshr1",
            Self::TimeAnchor => *b"kgwtanc1",
            Self::ChargeQuote => *b"kgwchgq1",
            Self::Request => *b"kgwrqst1",
        })
    }
    /// `P` domain of the message/signature object digest.
    pub const fn object_domain(self) -> u64 {
        u64::from_le_bytes(match self {
            Self::Certificate => *b"kgwocrt1",
            Self::Credential => *b"kgwocrd1",
            Self::Receipt => *b"kgworcp1",
            Self::SchemePolicy => *b"kgwopol1",
            Self::FeeSchedule => *b"kgwofee1",
            Self::Blacklist => *b"kgwoblk1",
            Self::QuotaShare => *b"kgwoqsh1",
            Self::TimeAnchor => *b"kgwotim1",
            Self::ChargeQuote => *b"kgwochg1",
            Self::Request => *b"kgworeq1",
        })
    }
    /// Primary chunk layout of body followed by its 64-byte raw signature.
    pub fn primary_segments(self) -> Vec<usize> {
        let mut primary = chunk_segments(0, self.body_len());
        primary.extend(chunk_segments(0, 64));
        primary
    }
    /// Secondary semantic fields, covering every body/signature byte exactly once.
    pub fn secondary_segments(self) -> Vec<SegmentSpec> {
        let mut segments = Vec::new();
        let mut offset = 0;
        for atom in self.schema() {
            match atom {
                U(n) => segments.push(SegmentSpec::little(offset, *n)),
                D | P => {
                    segments.push(SegmentSpec::little(offset, 16));
                    segments.push(SegmentSpec::little(offset + 16, 16));
                }
                K => {
                    segments.push(SegmentSpec::little(offset, 1));
                    for i in 0..4 {
                        segments.push(SegmentSpec::big(offset + 1 + i * 16, 16));
                    }
                }
            }
            offset += atom.len();
        }
        for i in 0..4 {
            segments.push(SegmentSpec::big(offset + i * 16, 16));
        }
        segments
    }
}
