//! Signed policy body validity and fixed refresh-field projections.

use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{Bit, UintChip, Word};

use super::{
    ObjectKind, SignedObjectCells,
    predicates::{all, bits32, implies, is_constant, nonzero, sum_fits128},
};
use crate::operation_relation::refresh::RefreshUpdate;

fn at_most<const N: usize>(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    word: &Word<Fp>,
    bound: u128,
) -> Result<Bit<Fp>, Error> {
    let value = uint.range_check::<N>(region, word)?;
    let bound = uint.constant::<N>(region, bound)?;
    let greater = uint.lt(region, &bound, &value)?;
    uint.glue().not(region, &greater)
}
fn le128(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    a: &Word<Fp>,
    b: &Word<Fp>,
) -> Result<Bit<Fp>, Error> {
    let a = uint.range_check::<128>(region, a)?;
    let b = uint.range_check::<128>(region, b)?;
    let greater = uint.lt(region, &b, &a)?;
    uint.glue().not(region, &greater)
}
fn tag_pair(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    word: &Word<Fp>,
) -> Result<(Bit<Fp>, Bit<Fp>), Error> {
    let first = is_constant(uint.glue(), region, word, 1)?;
    let second = is_constant(uint.glue(), region, word, 2)?;
    let sum = uint.glue().add(region, first.word(), second.word())?;
    Ok((is_constant(uint.glue(), region, &sum, 1)?, second))
}

/// An issuer-owned object with a total body-validity predicate.
/// Authentication under its certificate is supplied by `issuer::authenticate`.
#[derive(Clone, Debug)]
pub struct PolicyCells {
    object: SignedObjectCells,
    valid: Bit<Fp>,
}
impl PolicyCells {
    /// Validate one policy, fee schedule, quota share, blacklist, time anchor,
    /// or charge quote against native self-contained body rules.
    ///
    /// Full windows/blacklist data, fee evaluation and operation/finality
    /// bindings are distinct relations; this method does not authenticate them.
    ///
    /// # Errors
    /// A different fixed class or layout failure. Invalid body fields return false.
    pub fn check(
        uint: &mut UintChip<'_, Fp>,
        region: &mut Region<'_, Fp>,
        object: &SignedObjectCells,
    ) -> Result<Self, Error> {
        let (identifiers, nonzero_fields): (&[usize], &[usize]) = match object.kind() {
            ObjectKind::SchemePolicy => (&[1, 2], &[3, 6]),
            ObjectKind::FeeSchedule => (&[1, 2, 4], &[10]),
            ObjectKind::Blacklist => (&[1], &[2, 5, 6]),
            ObjectKind::QuotaShare => (&[1, 2, 3], &[4, 7, 8, 9]),
            ObjectKind::TimeAnchor => (&[1, 2, 3], &[5]),
            ObjectKind::ChargeQuote => (&[1, 2, 3, 8], &[7, 10]),
            _ => return Err(Error::Synthesis),
        };
        let mut checks = vec![object.structural_valid().clone()];
        for index in identifiers {
            checks.push(nonzero(uint.glue(), region, object.identifier(*index)?)?);
        }
        for index in nonzero_fields {
            checks.push(nonzero(
                uint.glue(),
                region,
                core::slice::from_ref(object.word(*index)?),
            )?);
        }
        match object.kind() {
            ObjectKind::SchemePolicy => {
                let mask = bits32(uint, region, object.word(4)?)?;
                for bit in &mask[3..] {
                    checks.push(uint.glue().not(region, bit)?);
                }
            }
            ObjectKind::FeeSchedule => {
                checks.push(at_most::<32>(uint, region, object.word(5)?, 10_000)?);
                checks.push(le128(uint, region, object.word(7)?, object.word(8)?)?);
                checks.push(tag_pair(uint, region, object.word(9)?)?.0);
            }
            ObjectKind::Blacklist => {
                checks.push(at_most::<32>(uint, region, object.word(4)?, 65_535)?);
            }
            ObjectKind::QuotaShare => {
                let issued = uint.range_check::<64>(region, object.word(5)?)?;
                let expires = uint.range_check::<64>(region, object.word(6)?)?;
                checks.push(uint.lt(region, &issued, &expires)?);
                checks.push(at_most::<32>(uint, region, object.word(8)?, 64)?);
            }
            ObjectKind::ChargeQuote => {
                let (valid, unload) = tag_pair(uint, region, object.word(4)?)?;
                checks.push(valid);
                let load = is_constant(uint.glue(), region, object.word(4)?, 1)?;
                let fits = sum_fits128(uint, region, object.word(6)?, object.word(7)?)?;
                checks.push(implies(uint.glue(), region, &load, &fits)?);
                let positive =
                    nonzero(uint.glue(), region, core::slice::from_ref(object.word(6)?))?;
                let affordable = le128(uint, region, object.word(7)?, object.word(6)?)?;
                checks.push(implies(uint.glue(), region, &unload, &positive)?);
                checks.push(implies(uint.glue(), region, &unload, &affordable)?);
            }
            ObjectKind::TimeAnchor => {}
            _ => return Err(Error::Synthesis),
        }
        let valid = all(uint.glue(), region, &checks)?;
        Ok(Self {
            object: object.clone(),
            valid,
        })
    }
    /// Same-tape object used in issuer authorization.
    pub const fn object(&self) -> &SignedObjectCells {
        &self.object
    }
    /// Body validity, to require together with its issuer signature verdict.
    pub const fn valid(&self) -> &Bit<Fp> {
        &self.valid
    }

    /// Project exact signed fields into the operation's refresh-state relation.
    /// The caller must require `valid` and authenticate the issuer. Quota refresh
    /// must also bind field8 to its exact real-window count and field5 to issue time.
    ///
    /// # Errors
    /// This object has no fixed refresh variant, or a schema inconsistency.
    pub fn refresh_update(&self) -> Result<RefreshUpdate<'_>, Error> {
        let o = &self.object;
        Ok(match o.kind() {
            ObjectKind::SchemePolicy => RefreshUpdate::SchemePolicy {
                digest: o.digest(),
                scheme: o.identifier(1)?,
                asset: o.identifier(2)?,
                epoch: o.word(3)?,
                controls: o.word(4)?,
                fee: o.word(5)?,
            },
            ObjectKind::Blacklist => RefreshUpdate::Blacklist {
                digest: o.digest(),
                scheme: o.identifier(1)?,
                version: o.word(2)?,
                root: o.word(5)?,
                issued: o.word(3)?,
            },
            ObjectKind::QuotaShare => RefreshUpdate::QuotaShare {
                digest: o.digest(),
                scheme: o.identifier(1)?,
                asset: o.identifier(2)?,
                wallet: o.identifier(3)?,
                id: o.word(4)?,
                issued: o.word(5)?,
                expires: o.word(6)?,
                windows: o.word(7)?,
            },
            ObjectKind::TimeAnchor => RefreshUpdate::TimeAnchor {
                digest: o.digest(),
                scheme: o.identifier(1)?,
                wallet: o.identifier(2)?,
                issued: o.word(4)?,
            },
            _ => return Err(Error::Synthesis),
        })
    }
}
