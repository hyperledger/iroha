//! Fixed phase encodings for the compact shared arithmetic lane.
//!
//! Phase bits and payloads are circuit-fixed metadata, never advice or witness
//! branch selectors. Two bits distinguish standard Glue, ECC, ordinary
//! Poseidon rounds and paired Poseidon rounds. Six payload columns are reused
//! as Glue coefficients, ECC enables or Poseidon round constants. Callers must
//! allocate disjoint row spans to the phase owners. The recursive interpreter
//! reserves these spans explicitly; its complete row qualification remains open.

use iroha_pasta::PastaField;
use iroha_plonk::{
    cs::{Column, ConstraintSystem, Expression, Fixed, Rotation, Selector, VirtualCells},
    frontend::{Error, Region},
};

/// Highest gate degree in the shared phase layout, including phase enables.
pub const MAX_COMPACT_GATE_DEGREE: usize = 9;

/// Eight shared fixed columns: two phase bits and six coefficient payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhaseColumns {
    bits: [Column<Fixed>; 2],
    payload: [Column<Fixed>; 6],
    idle_ecc: bool,
}

impl PhaseColumns {
    /// Allocates the fixed columns. Every participating chip must receive the
    /// same bundle and own a disjoint, circuit-fixed row interval.
    pub fn allocate<F: PastaField>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            bits: core::array::from_fn(|_| meta.fixed_column()),
            payload: core::array::from_fn(|_| meta.fixed_column()),
            idle_ecc: false,
        }
    }

    /// Allocates the experimental encoding whose zero fixed bits denote ECC.
    /// Logical phase identifiers stay unchanged; all owners translate them
    /// through this bundle. This permits linear spare-digit enables to vanish
    /// on the unassigned and blinding rows without another fixed column.
    pub fn allocate_with_idle_ecc<F: PastaField>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            idle_ecc: true,
            ..Self::allocate(meta)
        }
    }

    pub(crate) const fn has_idle_ecc(self) -> bool {
        self.idle_ecc
    }

    const fn encoded(self, phase: u8) -> u8 {
        phase ^ self.idle_ecc as u8
    }

    /// The six columns in coefficient/round-constant order.
    #[must_use]
    pub const fn coefficients(self) -> [Column<Fixed>; 6] {
        self.payload
    }

    pub(crate) const fn bits(self) -> [Column<Fixed>; 2] {
        self.bits
    }

    pub(crate) fn expect<F: PastaField>(
        self,
        region: &mut Region<'_, F>,
        row: usize,
        phase: u8,
    ) -> Result<(), Error> {
        let encoded = self.encoded(phase);
        for (index, column) in self.bits.iter().enumerate() {
            region.expect_fixed(*column, row, F::from(u64::from((encoded >> index) & 1)))?;
        }
        Ok(())
    }

    pub(crate) const fn enable(self, phase: u8, payload: Option<(usize, u8, u8)>) -> Enable {
        Enable::Phase {
            columns: self,
            phase,
            payload,
        }
    }
}

/// Either the retained layout's selector or the compact fixed phase code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Enable {
    Selector(Selector),
    Phase {
        columns: PhaseColumns,
        phase: u8,
        payload: Option<(usize, u8, u8)>,
    },
}

impl From<Selector> for Enable {
    fn from(selector: Selector) -> Self {
        Self::Selector(selector)
    }
}

impl Enable {
    pub(crate) fn query<F: PastaField>(self, cells: &mut VirtualCells<'_, F>) -> Expression<F> {
        match self {
            Self::Selector(selector) => cells.query_selector(selector),
            Self::Phase {
                columns,
                phase,
                payload,
            } => {
                let phase = columns.encoded(phase);
                let mut enabled = Expression::Constant(F::ONE);
                for (index, column) in columns.bits.iter().enumerate() {
                    let bit = cells.query_fixed(*column, Rotation::cur());
                    enabled = enabled
                        * if phase & (1 << index) == 0 {
                            Expression::Constant(F::ONE) - bit
                        } else {
                            bit
                        };
                }
                if let Some((index, code, largest)) = payload {
                    let value = cells.query_fixed(columns.payload[index], Rotation::cur());
                    let mut denominator = F::ONE;
                    for other in 0..=largest {
                        if other != code {
                            enabled = enabled
                                * (value.clone() - Expression::Constant(F::from(u64::from(other))));
                            denominator *= F::from(u64::from(code)) - F::from(u64::from(other));
                        }
                    }
                    enabled = enabled * denominator.invert().expect("distinct fixed small roots");
                }
                enabled
            }
        }
    }

    pub(crate) fn enable<F: PastaField>(
        self,
        region: &mut Region<'_, F>,
        row: usize,
    ) -> Result<(), Error> {
        match self {
            Self::Selector(selector) => selector.enable(region, row),
            Self::Phase {
                columns,
                phase,
                payload,
            } => {
                let phase = columns.encoded(phase);
                for (index, column) in columns.bits.iter().enumerate() {
                    region.assign_fixed(*column, row, F::from(u64::from((phase >> index) & 1)))?;
                }
                if let Some((index, code, _)) = payload {
                    region.assign_fixed(columns.payload[index], row, F::from(u64::from(code)))?;
                }
                Ok(())
            }
        }
    }
}
