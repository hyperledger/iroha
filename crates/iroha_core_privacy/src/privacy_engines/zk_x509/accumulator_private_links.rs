//! Closed translations between original CA and MAIN auxiliary polynomials.
//!
//! The 104 SHA links are multiplicative endpoint identities; four more bind
//! the root SPKI. All CA SHA calls end at a memory row with no call-bus event.
//! Consequently the original before-row accumulator equals its after-row value
//! at that precise native endpoint. No private product is inverted.

/// Independent supplemental batching after both complete DEEP records.
pub const CA_EXTRA_MIX_LABEL_V1: &[u8] = b"iroha:privacy:zk-x509:ca-original-auxiliary-deep-mix:v1";

use super::super::accumulator_air::ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1;
use super::super::sha_call_bus_stark::{
    ZK_X509_SHA_DIGEST_PRODUCTS_V1, ZK_X509_SHA_INPUT_PRODUCTS_V1, ZK_X509_SHA_SEGMENT_COUNT_V1,
    ZK_X509_SHA_SEGMENT_ROWS_V1,
};
use super::*;
use crate::privacy_engines::transparent_stark::GOLDILOCKS_GENERATOR_V1;

/// One quotient for every CA source/digest lane and root-SPKI lane.
pub const CA_MAIN_LINK_COUNT_V1: usize = 108;
/// The three physical SHA segments each need two families and four lanes.
pub const CA_MAIN_EXTRA_OPENINGS_V1: usize = 24;
/// Each native CA row/column translation is distinct within its column.
pub const CA_EXTRA_OPENINGS_V1: usize = 108;
const MAIN_LOG_V1: u8 = 19;
const MAIN_ROWS_V1: usize = 1 << MAIN_LOG_V1;
const CA_TO_MAIN_STRIDE_V1: usize = 1 << (MAIN_LOG_V1 - ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1);
const DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:credential-private-ca-links:v1";
const DESCRIPTOR_V1: &[u8] = b"13-required-ca-calls:source+digest:4-independent-lanes:104-multiplicative-endpoint-quotients+4-governed-root-spki-quotients:original-auxiliary-polynomials:24-main+108-ca-translated-deep-values:both-auxiliary-roots-before-link-alphas:both-composition-and-fri-mask-roots-before-shared-deep-point:no-private-product-inversion";

/// Original MAIN auxiliary owner and its local column, never caller-selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainCaColumnV1 {
    /// One of the original four physical SHA registrations.
    Sha {
        /// Physical segment identifier.
        segment: u8,
        /// Auxiliary column local to that registration.
        column: u16,
    },
    /// Original RFC auxiliary column local to its registration.
    Rfc {
        /// Governed-root consumer product column.
        column: u16,
    },
}
/// A separately authenticated evaluation of an original MAIN auxiliary column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MainCaExtraOpeningV1 {
    /// Original owner and local auxiliary column.
    pub(crate) column: MainCaColumnV1,
    /// Native-root multiplier applied to the shared DEEP point.
    pub(crate) multiplier: F,
}
/// A separately authenticated evaluation of an original CA auxiliary column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaExtraOpeningV1 {
    /// Original CA auxiliary column.
    pub(crate) column: u16,
    /// Native-root multiplier applied to the shared DEEP point.
    pub(crate) multiplier: F,
}
/// Public quotient coordinates. The optional start is absent only for root SPKI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaMainLinkV1 {
    /// Original MAIN auxiliary owner evaluated at the shared point.
    pub(crate) main: MainCaColumnV1,
    /// Index of the separately authenticated MAIN start opening.
    pub(crate) main_start: Option<usize>,
    /// Index of the separately authenticated CA opening.
    pub(crate) ca: usize,
    /// Native MAIN endpoint, the root of this quotient's linear divisor.
    pub(crate) endpoint: F,
    /// Public SHA leaf constants; one for other source/digest/root links.
    pub(crate) public_factor: F,
}

/// The closed source plan contains only public topology and challenge constants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaMainPrivateLinkPlanV1 {
    links: [CaMainLinkV1; CA_MAIN_LINK_COUNT_V1],
    main_openings: [MainCaExtraOpeningV1; CA_MAIN_EXTRA_OPENINGS_V1],
    ca_openings: [CaExtraOpeningV1; CA_EXTRA_OPENINGS_V1],
}
impl CaMainPrivateLinkPlanV1 {
    /// Derive every source/point from the sole native schedules and SHA challenges.
    pub(crate) fn new_v1(
        schedule: &ZkX509ShaCallScheduleV1,
        challenges: ZkX509ShaCallBusChallengesV1,
    ) -> Result<Self, ZkX509CaAccumulatorProofErrorV1> {
        validate_ca_proof_schedule_v1(schedule)?;
        challenges
            .validate()
            .map_err(|_| ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)?;
        if MAIN_ROWS_V1 != ZK_X509_SHA_SEGMENT_ROWS_V1 {
            return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
        }
        let root =
            goldilocks_primitive_root_v1(MAIN_LOG_V1).map_err(map_transparent_proof_error_v1)?;
        let placeholder = MainCaColumnV1::Rfc { column: 0 };
        let mut plan = Self {
            links: [CaMainLinkV1 {
                main: placeholder,
                main_start: None,
                ca: 0,
                endpoint: F::ONE,
                public_factor: F::ONE,
            }; CA_MAIN_LINK_COUNT_V1],
            main_openings: [MainCaExtraOpeningV1 {
                column: placeholder,
                multiplier: F::ONE,
            }; CA_MAIN_EXTRA_OPENINGS_V1],
            ca_openings: [CaExtraOpeningV1 {
                column: 0,
                multiplier: F::ONE,
            }; CA_EXTRA_OPENINGS_V1],
        };
        let mut extra_count = 0;
        let mut link_count = 0;
        let ca_io_end = ZK_X509_CA_ACCUMULATOR_NONPADDING_ROWS_V1 - 1;
        for row in 0..ZK_X509_CA_ACCUMULATOR_ACTIVE_ROWS_V1 {
            let call = schedule
                .call(ZK_X509_SHA_CA_LEAF_CALL_V1 + row)
                .map_err(|_| ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness)?;
            let segment = call.first_logical_row / MAIN_ROWS_V1;
            let first = call.first_logical_row % MAIN_ROWS_V1;
            let last = first
                .checked_add(call.maximum_logical_rows())
                .and_then(|end| end.checked_sub(1))
                .filter(|last| *last < MAIN_ROWS_V1)
                .ok_or(ZkX509CaAccumulatorProofErrorV1::Resource)?;
            if segment >= ZK_X509_SHA_SEGMENT_COUNT_V1
                || call.maximum_blocks != 3
                || call.maximum_logical_rows() != 9_632
                || call.activation != ZkX509ShaCallActivationV1::Required
            {
                return Err(ZkX509CaAccumulatorProofErrorV1::InvalidStatementOrWitness);
            }
            let gamma = root.pow(((first + MAIN_ROWS_V1 - last) % MAIN_ROWS_V1) as u128);
            for family in 0..2 {
                let ca_row = if row == 0 && family == 0 {
                    ca_io_end
                } else {
                    row
                };
                let eta = root.pow(
                    ((CA_TO_MAIN_STRIDE_V1 * ca_row + MAIN_ROWS_V1 - last) % MAIN_ROWS_V1) as u128,
                );
                for lane in 0..ZK_X509_SHA_BUS_LANES_V1 {
                    let column = if family == 0 {
                        ZK_X509_SHA_INPUT_PRODUCTS_V1
                    } else {
                        ZK_X509_SHA_DIGEST_PRODUCTS_V1
                    } + lane;
                    let main = MainCaColumnV1::Sha {
                        segment: segment as u8,
                        column: column as u16,
                    };
                    let opening = MainCaExtraOpeningV1 {
                        column: main,
                        multiplier: gamma,
                    };
                    let main_start = if let Some(index) = plan.main_openings[..extra_count]
                        .iter()
                        .position(|candidate| *candidate == opening)
                    {
                        index
                    } else {
                        if extra_count >= CA_MAIN_EXTRA_OPENINGS_V1 {
                            return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
                        }
                        plan.main_openings[extra_count] = opening;
                        extra_count += 1;
                        extra_count - 1
                    };
                    let ca_column = if row == 0 && family == 0 {
                        serialized_sha_product_cell_v1(lane)
                    } else if family == 0 {
                        source_aux_cell_v1(SOURCE_STATES_V1 - 1, lane)
                    } else {
                        digest_aux_cell_v1(DIGEST_STATES_V1 - 1, lane)
                    };
                    let factor = if row == 0 && family == 0 {
                        leaf_constant_source_product_v1(lane, challenges)
                            .map_err(ZkX509CaAccumulatorProofErrorV1::from)?
                    } else {
                        F::ONE
                    };
                    plan.ca_openings[link_count] = CaExtraOpeningV1 {
                        column: ca_column as u16,
                        multiplier: eta,
                    };
                    plan.links[link_count] = CaMainLinkV1 {
                        main,
                        main_start: Some(main_start),
                        ca: link_count,
                        endpoint: root.pow(last as u128),
                        public_factor: factor,
                    };
                    link_count += 1;
                }
            }
        }
        let endpoint = root.pow((MAIN_ROWS_V1 - 1) as u128);
        let eta = root.pow(((CA_TO_MAIN_STRIDE_V1 * ca_io_end + 1) % MAIN_ROWS_V1) as u128);
        // The RFC role accessor is authored beside its actual auxiliary layout.
        let root_columns = super::super::rfc5280_stark::zk_x509_rfc_governed_root_columns_v1();
        for (lane, column) in root_columns.into_iter().enumerate() {
            plan.ca_openings[link_count] = CaExtraOpeningV1 {
                column: root_spki_io_product_cell_v1(lane) as u16,
                multiplier: eta,
            };
            plan.links[link_count] = CaMainLinkV1 {
                main: MainCaColumnV1::Rfc {
                    column: column as u16,
                },
                main_start: None,
                ca: link_count,
                endpoint,
                public_factor: F::ONE,
            };
            link_count += 1;
        }
        if link_count != CA_MAIN_LINK_COUNT_V1 || extra_count != CA_MAIN_EXTRA_OPENINGS_V1 {
            return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
        }
        Ok(plan)
    }

    /// Ordered quotient coordinates, including the four public leaf factors.
    pub(crate) const fn links_v1(&self) -> &[CaMainLinkV1; CA_MAIN_LINK_COUNT_V1] {
        &self.links
    }
    /// Ordered deduplicated MAIN translated openings.
    pub(crate) const fn main_openings_v1(
        &self,
    ) -> &[MainCaExtraOpeningV1; CA_MAIN_EXTRA_OPENINGS_V1] {
        &self.main_openings
    }
    /// Ordered CA translated openings.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(crate) const fn ca_openings_v1(&self) -> &[CaExtraOpeningV1; CA_EXTRA_OPENINGS_V1] {
        &self.ca_openings
    }

    /// Reject every native or commitment/query domain reached by these translations.
    /// The shared sampler must also apply the MAIN key/digest power-map predicate.
    pub(crate) fn admissible_v1(&self, point: E) -> Result<bool, ZkX509CaAccumulatorProofErrorV1> {
        if point == E::ZERO || !point.is_canonical() {
            return Ok(false);
        }
        let allowed = |candidate: E, native_rows: usize, lde_rows: usize| {
            candidate.pow(native_rows as u128) != E::ONE
                && candidate.pow(lde_rows as u128)
                    != E::from_base(F(GOLDILOCKS_GENERATOR_V1).pow(lde_rows as u128))
        };
        let ca_root = goldilocks_primitive_root_v1(ZK_X509_CA_ACCUMULATOR_TRACE_LOG2_V1)
            .map_err(map_transparent_proof_error_v1)?;
        let main_root =
            goldilocks_primitive_root_v1(MAIN_LOG_V1).map_err(map_transparent_proof_error_v1)?;
        for candidate in [point, point.mul_base(main_root)].into_iter().chain(
            self.main_openings
                .iter()
                .map(|opening| point.mul_base(opening.multiplier)),
        ) {
            if !allowed(candidate, MAIN_ROWS_V1, 1 << 22) {
                return Ok(false);
            }
        }
        for candidate in [point, point.mul_base(ca_root)].into_iter().chain(
            self.ca_openings
                .iter()
                .map(|opening| point.mul_base(opening.multiplier)),
        ) {
            if !allowed(
                candidate,
                ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1,
                1 << ZK_X509_CA_FRI_LDE_LOG2_V1,
            ) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Attach each CA translated value to its own original auxiliary FRI column.
    /// The caller samples the mixes only after absorbing both proofs' openings.
    pub(crate) fn ca_supplemental_v1(
        &self,
        point: E,
        values: &[E],
        mixes: &[E],
    ) -> Result<Vec<aggregate::AggregateSupplementalDeepOpeningV1>, ZkX509CaAccumulatorProofErrorV1>
    {
        if values.len() != CA_EXTRA_OPENINGS_V1
            || mixes.len() != CA_EXTRA_OPENINGS_V1
            || values
                .iter()
                .chain(mixes)
                .any(|value| !value.is_canonical())
            || !self.admissible_v1(point)?
        {
            return Err(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening);
        }
        let mut result = Vec::new();
        result
            .try_reserve_exact(CA_EXTRA_OPENINGS_V1)
            .map_err(|_| ZkX509CaAccumulatorProofErrorV1::Resource)?;
        if result.capacity() != CA_EXTRA_OPENINGS_V1 {
            return Err(ZkX509CaAccumulatorProofErrorV1::Resource);
        }
        for (index, opening) in self.ca_openings.iter().enumerate() {
            result.push(aggregate::AggregateSupplementalDeepOpeningV1 {
                group: 0,
                column: aggregate::AggregateSupplementalColumnV1::Auxiliary(usize::from(
                    opening.column,
                )),
                point: point.mul_base(opening.multiplier),
                value: values[index],
                mix: mixes[index],
            });
        }
        Ok(result)
    }

    /// Bind the complete closed source-coordinate plan in each local transcript.
    pub(crate) fn absorb_registration_v1(
        &self,
        transcript: &mut TransparentTranscriptV1,
    ) -> Result<(), ZkX509CaAccumulatorProofErrorV1> {
        transcript
            .absorb(DOMAIN_V1, &[DESCRIPTOR_V1])
            .map_err(map_transparent_proof_error_v1)?;
        let encode_main = |column: MainCaColumnV1| -> [u8; 4] {
            let (kind, segment, column) = match column {
                MainCaColumnV1::Sha { segment, column } => (0, segment, column),
                MainCaColumnV1::Rfc { column } => (1, 0, column),
            };
            [
                kind,
                segment,
                column.to_be_bytes()[0],
                column.to_be_bytes()[1],
            ]
        };
        for link in self.links {
            let mut record = [0_u8; 24];
            record[..4].copy_from_slice(&encode_main(link.main));
            record[4..6].copy_from_slice(
                &(link.main_start.map_or(u16::MAX, |index| index as u16)).to_be_bytes(),
            );
            record[6..8].copy_from_slice(&(link.ca as u16).to_be_bytes());
            record[8..16].copy_from_slice(&link.endpoint.0.to_be_bytes());
            record[16..].copy_from_slice(&link.public_factor.0.to_be_bytes());
            transcript
                .absorb(DOMAIN_V1, &[&record])
                .map_err(map_transparent_proof_error_v1)?;
        }
        for opening in self.main_openings {
            transcript
                .absorb(
                    DOMAIN_V1,
                    &[
                        &encode_main(opening.column),
                        &opening.multiplier.0.to_be_bytes(),
                    ],
                )
                .map_err(map_transparent_proof_error_v1)?;
        }
        for opening in self.ca_openings {
            transcript
                .absorb(
                    DOMAIN_V1,
                    &[
                        &opening.column.to_be_bytes(),
                        &opening.multiplier.0.to_be_bytes(),
                    ],
                )
                .map_err(map_transparent_proof_error_v1)?;
        }
        Ok(())
    }

    /// Bind every original coordinate and point before sampling link randomness.
    /// The staged owner must already have absorbed both original auxiliary roots.
    pub(crate) fn derive_alphas_v1(
        &self,
        transcript: &mut TransparentTranscriptV1,
    ) -> Result<[E; CA_MAIN_LINK_COUNT_V1], ZkX509CaAccumulatorProofErrorV1> {
        self.absorb_registration_v1(transcript)?;
        let mut result = [E::ZERO; CA_MAIN_LINK_COUNT_V1];
        for alpha in &mut result {
            *alpha = transcript
                .challenge_fp4(DOMAIN_V1)
                .map_err(map_transparent_proof_error_v1)?;
        }
        Ok(result)
    }

    /// Recompose all cross-proof quotients after both proofs authenticate extras.
    /// `main_current` must resolve the original committed MAIN auxiliary column.
    pub(crate) fn evaluate_v1(
        &self,
        point: E,
        alphas: &[E],
        main_extra: &[E],
        ca_extra: &[E],
        main_current: impl Fn(MainCaColumnV1) -> Result<E, ZkX509CaAccumulatorProofErrorV1>,
    ) -> Result<E, ZkX509CaAccumulatorProofErrorV1> {
        if point == E::ZERO
            || !point.is_canonical()
            || alphas.len() != CA_MAIN_LINK_COUNT_V1
            || main_extra.len() != CA_MAIN_EXTRA_OPENINGS_V1
            || ca_extra.len() != CA_EXTRA_OPENINGS_V1
            || alphas
                .iter()
                .chain(main_extra)
                .chain(ca_extra)
                .any(|value| !value.is_canonical())
        {
            return Err(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening);
        }
        let mut result = E::ZERO;
        for (alpha, link) in alphas.iter().zip(&self.links) {
            let source = main_current(link.main)?;
            if !source.is_canonical() {
                return Err(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening);
            }
            let start = link.main_start.map_or(E::ONE, |index| main_extra[index]);
            let numerator = source.sub(start.mul(ca_extra[link.ca]).mul_base(link.public_factor));
            let inverse = point
                .sub(E::from_base(link.endpoint))
                .inv()
                .ok_or(ZkX509CaAccumulatorProofErrorV1::ConstraintOpening)?;
            result = result.add(alpha.mul(numerator).mul(inverse));
        }
        Ok(result)
    }
}

#[cfg(test)]
#[path = "accumulator_private_links_tests.rs"]
mod tests;
