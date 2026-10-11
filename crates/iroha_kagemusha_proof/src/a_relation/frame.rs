//! Canonical `D_A` prefix and the homogeneous A-to-Omega public frame.

use ff::Field;
use iroha_pasta::Fp;
use iroha_plonk::{
    cs::InstanceType,
    frontend::{Error, Region},
};
use iroha_plonk_gadgets::{GlueChip, UintChip, Word};
use iroha_plonk_recursion::obligation::ledger::Variant;

/// Native Fp domain of the complete 52-element lineage digest.
pub const LINEAGE_DOMAIN: u64 = u64::from_le_bytes(*b"kgwomg_1");
/// Public lineage fields preceding the Pallas accumulator in `D_A`.
pub const LINEAGE_FIELDS: usize = 18;

/// Checked public lineage prefix, in canonical Lambda section 3.2 order.
/// Operation constraints additionally bind the lifecycle/policy/control packing,
/// identity continuity, head opening and monetary transition.
#[derive(Clone, Debug)]
pub struct LineagePublicCells {
    fields: [Word<Fp>; LINEAGE_FIELDS],
}

impl LineagePublicCells {
    /// Checks existing cells in this order:
    /// version, scheme(lo,hi), relation(lo,hi), head, wallet(lo,hi), credential,
    /// payment-key x(lo,hi), y(lo,hi), packed lifecycle/policy/controls, burned,
    /// pending-outgoing root, credit-digest root, Omega key digest.
    ///
    /// # Errors
    /// Layout failure; invalid version or integer widths are unsatisfiable.
    pub fn constrain(
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        fields: &[Word<Fp>; LINEAGE_FIELDS],
    ) -> Result<Self, Error> {
        GlueChip::assert_constant(region, &fields[0], Fp::ONE)?;
        for index in [1, 2, 3, 4, 6, 7, 9, 10, 11, 12, 14] {
            uint.range_check::<128>(region, &fields[index])?;
        }
        uint.range_check::<104>(region, &fields[13])?;
        Ok(Self {
            fields: fields.clone(),
        })
    }

    /// The exact prefix, preserving the original cells and canonical order.
    pub const fn fields(&self) -> &[Word<Fp>; LINEAGE_FIELDS] {
        &self.fields
    }
    /// Commitment to the lineage's wallet state.
    pub const fn head(&self) -> &Word<Fp> {
        &self.fields[5]
    }
    /// The carried artifact-set Omega verifying-key digest.
    pub const fn omega_key_digest(&self) -> &Word<Fp> {
        &self.fields[17]
    }
    /// Checked cumulative burned amount.
    pub const fn burned_total(&self) -> &Word<Fp> {
        &self.fields[14]
    }
    /// Authenticated pending-outgoing map root.
    pub const fn pending_root(&self) -> &Word<Fp> {
        &self.fields[15]
    }
    /// Authenticated credit-digest map root.
    pub const fn credit_root(&self) -> &Word<Fp> {
        &self.fields[16]
    }
}

/// Circuit-fixed interpretation of A's single Bounded instance column.
/// This describes routing, not permission to omit an operation constraint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AFramePlan {
    variant: Variant,
    part_source_k: u32,
}

impl AFramePlan {
    /// Pins the variant and forwarded sigma part's original descriptor k.
    /// Two-sigma variants require an accumulated k16 part; others retain
    /// the single sigma descriptor's k12/k14.
    ///
    /// # Errors
    /// A source k disagrees with the variant's fixed obligation schedule.
    pub fn new(variant: Variant, part_source_k: u32) -> Result<Self, Error> {
        let folded = matches!(
            variant,
            Variant::Receive | Variant::ReceiveRenewed | Variant::ArchiveReceive
        );
        if if folded {
            part_source_k != 16
        } else {
            !matches!(part_source_k, 12 | 14)
        } {
            return Err(Error::Synthesis);
        }
        Ok(Self {
            variant,
            part_source_k,
        })
    }
    /// The fixed operation relation variant.
    pub const fn variant(self) -> Variant {
        self.variant
    }
    /// Source k retained by the single sigma or fixed at sixteen after its fold.
    pub const fn part_source_k(self) -> u32 {
        self.part_source_k
    }
    /// Exactly one predecessor appears in every non-bootstrap relation.
    pub fn has_predecessor(self) -> bool {
        self.variant != Variant::Bootstrap
    }
    /// Incoming Omega appears only in these three relations.
    pub const fn has_incoming(self) -> bool {
        matches!(
            self.variant,
            Variant::Receive | Variant::ReceiveRenewed | Variant::ArchiveStatus
        )
    }
    /// Homogeneous descriptor type of the single Fp instance column.
    pub const fn instance_type() -> InstanceType {
        InstanceType::Bounded
    }
    /// `D_A` occupies index zero; the normalized part occupies 1..22.
    pub const fn part_range() -> core::ops::Range<usize> {
        1..22
    }
    /// Hard predecessor Vesta claim or explicit pinned trivial filler.
    pub const fn predecessor_range() -> core::ops::Range<usize> {
        22..42
    }
    /// Incoming Vesta claim: x/y S6, sixteen native scalars, three mode bits
    /// and four corrected x/y S6 limbs. Absent inputs use fixed trivial data.
    pub const fn incoming_range() -> core::ops::Range<usize> {
        42..69
    }
    /// Exact public-column length; no optional witness can alter it.
    pub const fn instance_length() -> usize {
        69
    }
}
