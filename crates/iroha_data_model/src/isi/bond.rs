//! Native bond-servicing kernel instructions.
//!
//! Every instruction is admitted only through the registered outer
//! [`BondInstructionBox`] (`iroha.bond`); the leaf types have no wire
//! identifiers of their own. Core performs every authority, schedule and
//! balance check (`specs/finance/bond_ops.md`).
use super::*;
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize,
    bond::{BondId, BondTerms},
};

isi! {
    /// Register the typed bond record of an existing scale-0 asset definition.
    ///
    /// Signed by the issuer, which must own the definition. Intended to be
    /// submitted in the issuer transaction that registers and mints the bond
    /// asset definition; the minted total becomes the outstanding amount and the
    /// definition's supply is locked from then on.
    #[derive(DeriveJsonSerialize, DeriveJsonDeserialize)]
    #[norito(deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::bond::RegisterBond")]
    pub struct RegisterBond {
        /// Bond asset definition.
        pub bond: BondId,
        /// Complete immutable terms including the materialised schedule.
        pub terms: BondTerms,
    }
}
isi! {
    /// Record one cash flow: snapshot investor holdings and compute the amount due.
    ///
    /// Signed by the paying agent at or after the record date. Recording the
    /// redemption cash flow freezes every further movement of the bond asset.
    #[derive(DeriveJsonSerialize, DeriveJsonDeserialize)]
    #[norito(deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::bond::RecordBondCashflow")]
    pub struct RecordBondCashflow {
        /// Bond asset definition.
        pub bond: BondId,
        /// Cash-flow index.
        pub index: u16,
    }
}
isi! {
    /// Move exactly the recorded amount due from the signer's payment-asset bucket into the vault.
    #[derive(DeriveJsonSerialize, DeriveJsonDeserialize)]
    #[norito(deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::bond::FundBondCashflow")]
    pub struct FundBondCashflow {
        /// Bond asset definition.
        pub bond: BondId,
        /// Cash-flow index.
        pub index: u16,
        /// Payment-asset bucket owned by the signing paying agent or issuer.
        pub source: AssetId,
    }
}
isi! {
    /// Pay one snapshot holder from the vault; a redemption also burns the holder's units.
    ///
    /// Signed by the holder, or by the paying agent pushing the payment; the
    /// destination is always the holder.
    #[derive(DeriveJsonSerialize, DeriveJsonDeserialize)]
    #[norito(deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::bond::ClaimBondCashflow")]
    pub struct ClaimBondCashflow {
        /// Bond asset definition.
        pub bond: BondId,
        /// Cash-flow index.
        pub index: u16,
        /// Snapshot holder receiving the payment.
        pub holder: AccountId,
    }
}
isi! {
    /// Close a fully claimed cash flow and return its rounding residual to the issuer.
    #[derive(DeriveJsonSerialize, DeriveJsonDeserialize)]
    #[norito(deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::bond::CloseBondCashflow")]
    pub struct CloseBondCashflow {
        /// Bond asset definition.
        pub bond: BondId,
        /// Cash-flow index.
        pub index: u16,
    }
}
isi! {
    /// Exercise the issuer call at a scheduled coupon payment date.
    #[derive(DeriveJsonSerialize, DeriveJsonDeserialize)]
    #[norito(deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::bond::CallBond")]
    pub struct CallBond {
        /// Bond asset definition.
        pub bond: BondId,
        /// Call date; must equal the payment date of a still scheduled coupon.
        pub call_date_ms: u64,
    }
}
isi! {
    /// Declare a payment default on an unfunded cash flow after its payment date.
    #[derive(DeriveJsonSerialize, DeriveJsonDeserialize)]
    #[norito(deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::isi::bond::DeclareBondDefault")]
    pub struct DeclareBondDefault {
        /// Bond asset definition.
        pub bond: BondId,
        /// Defaulted cash-flow index.
        pub index: u16,
        /// SHA-256 of the default evidence.
        #[norito(json = "crate::json_helpers::fixed_bytes_hex")]
        pub evidence_sha256: [u8; 32],
    }
}

impl RegisterBond {
    /// Construct a registration.
    #[must_use]
    pub fn new(bond: BondId, terms: BondTerms) -> Self {
        Self { bond, terms }
    }
}
impl RecordBondCashflow {
    /// Construct a record instruction.
    #[must_use]
    pub fn new(bond: BondId, index: u16) -> Self {
        Self { bond, index }
    }
}
impl FundBondCashflow {
    /// Construct a funding instruction.
    #[must_use]
    pub fn new(bond: BondId, index: u16, source: AssetId) -> Self {
        Self {
            bond,
            index,
            source,
        }
    }
}
impl ClaimBondCashflow {
    /// Construct a claim instruction.
    #[must_use]
    pub fn new(bond: BondId, index: u16, holder: AccountId) -> Self {
        Self {
            bond,
            index,
            holder,
        }
    }
}
impl CloseBondCashflow {
    /// Construct a close instruction.
    #[must_use]
    pub fn new(bond: BondId, index: u16) -> Self {
        Self { bond, index }
    }
}
impl CallBond {
    /// Construct a call instruction.
    #[must_use]
    pub fn new(bond: BondId, call_date_ms: u64) -> Self {
        Self { bond, call_date_ms }
    }
}
impl DeclareBondDefault {
    /// Construct a default declaration.
    #[must_use]
    pub fn new(bond: BondId, index: u16, evidence_sha256: [u8; 32]) -> Self {
        Self {
            bond,
            index,
            evidence_sha256,
        }
    }
}

impl core::fmt::Display for RegisterBond {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "BOND_REGISTER `{}` ISSUER `{}` AGENT `{}` CASHFLOWS {}",
            self.bond,
            self.terms.issuer,
            self.terms.paying_agent,
            self.terms.cashflows.len()
        )
    }
}
impl core::fmt::Display for RecordBondCashflow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BOND_RECORD `{}` #{}", self.bond, self.index)
    }
}
impl core::fmt::Display for FundBondCashflow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "BOND_FUND `{}` #{} FROM `{}`",
            self.bond, self.index, self.source
        )
    }
}
impl core::fmt::Display for ClaimBondCashflow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "BOND_CLAIM `{}` #{} HOLDER `{}`",
            self.bond, self.index, self.holder
        )
    }
}
impl core::fmt::Display for CloseBondCashflow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BOND_CLOSE `{}` #{}", self.bond, self.index)
    }
}
impl core::fmt::Display for CallBond {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BOND_CALL `{}` AT {}ms", self.bond, self.call_date_ms)
    }
}
impl core::fmt::Display for DeclareBondDefault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BOND_DEFAULT `{}` #{}", self.bond, self.index)
    }
}

impl crate::seal::Instruction for RegisterBond {}
impl crate::seal::Instruction for RecordBondCashflow {}
impl crate::seal::Instruction for FundBondCashflow {}
impl crate::seal::Instruction for ClaimBondCashflow {}
impl crate::seal::Instruction for CloseBondCashflow {}
impl crate::seal::Instruction for CallBond {}
impl crate::seal::Instruction for DeclareBondDefault {}

isi_box! {
    /// Grouping enum for the native bond-servicing kernel.
    #[norito_schema(name = "iroha_data_model::isi::bond::BondInstructionBox")]
    pub enum BondInstructionBox {
        /// Register a bond record.
        Register(RegisterBond),
        /// Record a cash flow.
        RecordCashflow(RecordBondCashflow),
        /// Fund a recorded cash flow.
        FundCashflow(FundBondCashflow),
        /// Claim a funded cash flow for one holder.
        ClaimCashflow(ClaimBondCashflow),
        /// Close a fully claimed cash flow.
        CloseCashflow(CloseBondCashflow),
        /// Exercise the issuer call.
        Call(CallBond),
        /// Declare a payment default.
        DeclareDefault(DeclareBondDefault),
    }
}
impl_into_box! {
    RegisterBond | RecordBondCashflow | FundBondCashflow | ClaimBondCashflow | CloseBondCashflow | CallBond | DeclareBondDefault => BondInstructionBox
}
impl crate::seal::Instruction for BondInstructionBox {}
impl BondInstructionBox {
    /// Stable Norito wire identifier for boxed bond instructions.
    pub const WIRE_ID: &'static str = "iroha.bond";

    /// Bond addressed by the boxed instruction.
    #[must_use]
    pub fn bond(&self) -> &BondId {
        match self {
            Self::Register(isi) => &isi.bond,
            Self::RecordCashflow(isi) => &isi.bond,
            Self::FundCashflow(isi) => &isi.bond,
            Self::ClaimCashflow(isi) => &isi.bond,
            Self::CloseCashflow(isi) => &isi.bond,
            Self::Call(isi) => &isi.bond,
            Self::DeclareDefault(isi) => &isi.bond,
        }
    }
}

impl_aos_decode_from_slice!(RegisterBond {
    bond: BondId,
    terms: BondTerms,
});
impl_aos_decode_from_slice!(RecordBondCashflow {
    bond: BondId,
    index: u16,
});
impl_aos_decode_from_slice!(FundBondCashflow {
    bond: BondId,
    index: u16,
    source: AssetId,
});
impl_aos_decode_from_slice!(ClaimBondCashflow {
    bond: BondId,
    index: u16,
    holder: AccountId,
});
impl_aos_decode_from_slice!(CloseBondCashflow {
    bond: BondId,
    index: u16,
});
impl_aos_decode_from_slice!(CallBond {
    bond: BondId,
    call_date_ms: u64,
});
impl_aos_decode_from_slice!(DeclareBondDefault {
    bond: BondId,
    index: u16,
    evidence_sha256: [u8; 32],
});

impl<'a> norito::core::DecodeFromSlice<'a> for BondInstructionBox {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = norito::core::effective_decode_flags()
            .unwrap_or_else(norito::core::default_encode_flags);
        let tag_bytes = bytes.get(..4).ok_or(norito::core::Error::LengthMismatch)?;
        let tag = u32::from_le_bytes(
            tag_bytes
                .try_into()
                .map_err(|_| norito::core::Error::LengthMismatch)?,
        );
        let mut offset = 4usize;
        macro_rules! variant {
            ($variant:ident, $ty:ty) => {
                Self::$variant(super::decode_aos_slice_field::<$ty>(
                    super::read_aos_field(bytes, &mut offset, flags)?,
                    flags,
                )?)
            };
        }
        let value = match tag {
            0 => variant!(Register, RegisterBond),
            1 => variant!(RecordCashflow, RecordBondCashflow),
            2 => variant!(FundCashflow, FundBondCashflow),
            3 => variant!(ClaimCashflow, ClaimBondCashflow),
            4 => variant!(CloseCashflow, CloseBondCashflow),
            5 => variant!(Call, CallBond),
            6 => variant!(DeclareDefault, DeclareBondDefault),
            _ => {
                return Err(norito::core::Error::Message(format!(
                    "invalid BondInstructionBox tag {tag}"
                )));
            }
        };
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((value, offset))
    }
}

#[cfg(test)]
#[path = "bond_tests.rs"]
mod tests;
