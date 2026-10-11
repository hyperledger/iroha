//! Exact basis-point fee arithmetic and Send's head-committed fee terms.

use ff::{Field, PrimeField};
use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{Bit, GlueChip, Uint, UintChip, Word};

use super::{
    ObjectKind,
    policy::PolicyCells,
    predicates::{all, equal, implies, is_constant, nonzero},
    request::RequestCells,
};
use crate::{
    operation_relation::state::{StateCells, rest_index},
    witness::core_index,
};

/// Exact fee value and its total non-overflow/body verdict.
#[derive(Clone, Debug)]
pub struct FeeCells {
    amount: Word<Fp>,
    valid: Bit<Fp>,
}
impl FeeCells {
    /// `clamp(fixed + round(amount * basis_points / 10_000), minimum, maximum)`.
    ///
    /// Uses exact quotient/remainder decompositions with bounded remainders.
    /// An overflowing sum is false even if clamping would hide the overflow.
    /// Invalid schedules select a safe arithmetic witness and retain false.
    /// No division by an unconstrained witness or field division is accepted.
    ///
    /// # Errors
    /// Wrong fixed object class or layout failure.
    pub fn compute(
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        schedule: &PolicyCells,
        amount: &Word<Fp>,
    ) -> Result<Self, Error> {
        let object = schedule.object();
        if object.kind() != ObjectKind::FeeSchedule {
            return Err(Error::Synthesis);
        }
        let amount = uint.range_check::<128>(region, amount)?;
        let (whole_amount, partial_amount) = div_10_000(uint, region, &amount)?;
        let rate =
            uint.glue()
                .select_constant(region, schedule.valid(), object.word(5)?, Fp::ZERO)?;
        let rate = uint.range_check::<14>(region, &rate)?;
        let limit = uint.constant::<14>(region, 10_000)?;
        uint.assert_le(region, &rate, &limit)?;
        let whole = uint.glue().mul(region, whole_amount.word(), rate.word())?;
        let whole = uint.range_check::<128>(region, &whole)?;
        let fraction = uint
            .glue()
            .mul(region, partial_amount.word(), rate.word())?;
        let fraction = uint.range_check::<128>(region, &fraction)?;
        let (part, remainder) = div_10_000(uint, region, &fraction)?;
        let round_up = is_constant(uint.glue(), region, object.word(9)?, 2)?;
        let has_remainder = nonzero(uint.glue(), region, core::slice::from_ref(remainder.word()))?;
        let increment = uint.glue().and(region, &round_up, &has_remainder)?;
        let proportional = uint.checked_add(region, &whole, &part)?;
        let proportional = uint
            .glue()
            .add(region, proportional.word(), increment.word())?;
        let proportional = uint.range_check::<128>(region, &proportional)?;
        let fixed = uint.range_check::<128>(region, object.word(6)?)?;
        let sum = proportional
            .value()
            .zip(fixed.value())
            .map(|(a, b)| a.overflowing_add(b));
        let raw = uint.assign::<128>(region, sum.map(|(lo, _)| lo))?;
        let carry = uint.glue().boolean(region, sum.map(|(_, carry)| carry))?;
        let joined = uint.glue().linear(
            region,
            &[
                (Fp::ONE, raw.word()),
                (Fp::from_u128(1 << 127).double(), carry.word()),
            ],
            Fp::ZERO,
        )?;
        let sum = uint.glue().add(region, proportional.word(), fixed.word())?;
        GlueChip::assert_equal(region, &sum, &joined)?;
        let fits = uint.glue().not(region, &carry)?;
        let valid = uint.glue().and(region, schedule.valid(), &fits)?;
        let min = uint.range_check::<128>(region, object.word(7)?)?;
        let max = uint.range_check::<128>(region, object.word(8)?)?;
        let below = uint.lt(region, &raw, &min)?;
        let above = uint.lt(region, &max, &raw)?;
        let lower = uint.glue().select(region, &below, min.word(), raw.word())?;
        let amount = uint.glue().select(region, &above, max.word(), &lower)?;
        Ok(Self { amount, valid })
    }
    /// Exact clamped amount when `valid` is true; an invalid body's dummy otherwise.
    pub const fn amount(&self) -> &Word<Fp> {
        &self.amount
    }
    /// Body validity and absence of overflow before clamping.
    pub const fn valid(&self) -> &Bit<Fp> {
        &self.valid
    }
}

fn div_10_000(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    amount: &Uint<Fp, 128>,
) -> Result<(Uint<Fp, 128>, Uint<Fp, 14>), Error> {
    let quotient = uint.assign::<128>(region, amount.value().map(|n| n / 10_000))?;
    let remainder = uint.assign::<14>(region, amount.value().map(|n| n % 10_000))?;
    let denominator = uint.constant::<14>(region, 10_000)?;
    uint.assert_lt(region, &remainder, &denominator)?;
    let composed = uint.glue().linear(
        region,
        &[
            (Fp::from(10_000), quotient.word()),
            (Fp::ONE, remainder.word()),
        ],
        Fp::ZERO,
    )?;
    GlueChip::assert_equal(region, amount.word(), &composed)?;
    Ok((quotient, remainder))
}

/// Bind Send fees to the sender's authenticated predecessor state.
///
/// `schedule` is a fixed witness slot: when the head permits no schedule it
/// can contain a malformed dummy and cannot introduce a fee. Otherwise the
/// exact signed object digest must equal the head's held schedule. The issuer
/// authorization occurred when that policy was installed; Send does not add
/// a receiver-supplied issuer-signature obligation.
///
/// # Errors
/// Wrong fixed schedule class or layout failure.
pub fn bind_send(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    request: &RequestCells,
    state: &StateCells,
    schedule: &PolicyCells,
) -> Result<Bit<Fp>, Error> {
    let object = request.object();
    let fee = FeeCells::compute(uint, region, schedule, object.word(9)?)?;
    let held = &state.rest()[rest_index::FEE_SCHEDULE];
    let enabled = nonzero(uint.glue(), region, core::slice::from_ref(held))?;
    let matches = uint
        .glue()
        .is_equal(region, schedule.object().digest(), held)?;
    let mut checks = vec![
        request.valid().clone(),
        uint.glue().is_equal(region, object.word(10)?, held)?,
        implies(uint.glue(), region, &enabled, &matches)?,
        implies(uint.glue(), region, &enabled, fee.valid())?,
    ];
    for (index, offset) in [(1, core_index::SCHEME), (2, core_index::ASSET)] {
        let same = equal(
            uint.glue(),
            region,
            schedule.object().identifier(index)?,
            &state.core()[offset..offset + 2],
        )?;
        checks.push(implies(uint.glue(), region, &enabled, &same)?);
    }
    let expected = uint
        .glue()
        .select_constant(region, &enabled, fee.amount(), Fp::ZERO)?;
    checks.push(uint.glue().is_equal(region, object.word(11)?, &expected)?);
    let requested_epoch = uint.range_check::<64>(region, object.word(12)?)?;
    let installed_epoch =
        uint.range_check::<64>(region, &state.core()[core_index::POLICY_EPOCH])?;
    let future_epoch = uint.lt(region, &installed_epoch, &requested_epoch)?;
    checks.push(uint.glue().not(region, &future_epoch)?);
    let same_epoch =
        uint.glue()
            .is_equal(region, requested_epoch.word(), installed_epoch.word())?;
    let same_policy = uint.glue().is_equal(
        region,
        object.word(13)?,
        &state.rest()[rest_index::SCHEME_POLICY],
    )?;
    checks.push(implies(uint.glue(), region, &same_epoch, &same_policy)?);
    all(uint.glue(), region, &checks)
}
