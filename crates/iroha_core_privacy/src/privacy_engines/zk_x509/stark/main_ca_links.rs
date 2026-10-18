//! Closed MAIN coordinates and original-polynomial DEEP terms for private CA links.
//! Both subproofs must bind their trace and composition roots before the shared
//! point, and absorb both opening families before independently sampling mixes.

use super::super::super::{
    accumulator_stark::private_links::{
        CA_EXTRA_OPENINGS_V1, CA_MAIN_EXTRA_OPENINGS_V1, CA_MAIN_LINK_COUNT_V1,
        CaMainPrivateLinkPlanV1, MainCaColumnV1,
    },
    sha_call_bus_stark::ZkX509ShaCallScheduleV1,
};
use super::*;

const DOMAIN_V1: &[u8] = b"zk-x509-main-ca-private-original-columns-v1";
const NATIVE_LOG_V1: u8 = 19;
const NATIVE_ROWS_V1: usize = 1 << NATIVE_LOG_V1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ColumnV1 {
    group: usize,
    column: usize,
}

/// Only public closed-plan metadata is retained here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct MainCaPrivatePlanV1 {
    shared: CaMainPrivateLinkPlanV1,
    current: [ColumnV1; CA_MAIN_LINK_COUNT_V1],
    extra: [ColumnV1; CA_MAIN_EXTRA_OPENINGS_V1],
    endpoint_rows: [usize; CA_MAIN_LINK_COUNT_V1],
}
impl MainCaPrivatePlanV1 {
    pub(super) fn new_v1(
        layout: &AggregateProofLayoutV1,
        schedule: &ZkX509ShaCallScheduleV1,
        challenges: ZkX509ShaCallBusChallengesV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        layout.validate_exact_full_profile_registration_v1()?;
        let shared = CaMainPrivateLinkPlanV1::new_v1(schedule, challenges)
            .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
        let mut current = [ColumnV1 {
            group: 0,
            column: 0,
        }; CA_MAIN_LINK_COUNT_V1];
        let mut extra = [ColumnV1 {
            group: 0,
            column: 0,
        }; CA_MAIN_EXTRA_OPENINGS_V1];
        let resolve = |source: MainCaColumnV1| {
            let (adapter, segment, local) = match source {
                MainCaColumnV1::Sha { segment, column } => (
                    SegmentAdapterIdV1::Sha256CallBus,
                    u16::from(segment),
                    usize::from(column),
                ),
                MainCaColumnV1::Rfc { column } => {
                    (SegmentAdapterIdV1::Rfc5280, 0, usize::from(column))
                }
            };
            let registration = layout.registered_segment(adapter, segment)?;
            if registration.segment.trace_log2 != NATIVE_LOG_V1
                || local >= registration.segment.aux_width
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            Ok(ColumnV1 {
                group: registration.trace_group,
                column: registration
                    .aux_start
                    .checked_add(local)
                    .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
            })
        };
        for (target, link) in current.iter_mut().zip(shared.links_v1()) {
            *target = resolve(link.main)?;
        }
        for (target, opening) in extra.iter_mut().zip(shared.main_openings_v1()) {
            *target = resolve(opening.column)?;
        }
        let root = goldilocks_primitive_root_v1(NATIVE_LOG_V1).map_err(map_transparent_error_v1)?;
        let mut endpoint_rows = [NATIVE_ROWS_V1 - 1; CA_MAIN_LINK_COUNT_V1];
        for (index, link) in shared.links_v1().iter().enumerate() {
            if index < 104 {
                let call = schedule
                    .call(16 + index / 8)
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
                endpoint_rows[index] =
                    call.first_logical_row % NATIVE_ROWS_V1 + call.maximum_logical_rows() - 1;
            }
            if endpoint_rows[index] >= NATIVE_ROWS_V1
                || root.pow(endpoint_rows[index] as u128) != link.endpoint
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
        }
        Ok(Self {
            shared,
            current,
            extra,
            endpoint_rows,
        })
    }

    /// Canonical global coordinates are bound along with local plan metadata.
    pub(super) fn derive_alphas_v1(
        &self,
        transcript: &mut TransparentTranscriptV1,
    ) -> Result<[E; CA_MAIN_LINK_COUNT_V1], ZkX509StarkErrorV1> {
        for source in self.current.iter().chain(&self.extra) {
            let group =
                u64::try_from(source.group).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            let column =
                u64::try_from(source.column).map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
            transcript
                .absorb(DOMAIN_V1, &[&group.to_be_bytes(), &column.to_be_bytes()])
                .map_err(map_transparent_error_v1)?;
        }
        for row in self.endpoint_rows {
            transcript
                .absorb(DOMAIN_V1, &[&(row as u64).to_be_bytes()])
                .map_err(map_transparent_error_v1)?;
        }
        self.shared
            .derive_alphas_v1(transcript)
            .map_err(|_| ZkX509StarkErrorV1::ConstraintOpening)
    }

    /// Shared CA translations must avoid both original LDE and native domains.
    pub(super) fn admissible_v1(&self, point: E) -> Result<bool, ZkX509StarkErrorV1> {
        self.shared
            .admissible_v1(point)
            .map_err(|_| ZkX509StarkErrorV1::ConstraintOpening)
    }

    pub(super) fn evaluate_v1(
        &self,
        groups: &[aggregate::AggregateOpenedDeepTraceGroupV1],
        z: E,
        alphas: &[E],
        main_values: &[E],
        ca_values: &[E],
    ) -> Result<E, ZkX509StarkErrorV1> {
        self.shared.evaluate_v1(z, alphas, main_values, ca_values, |source| {
            let index = self.shared.links_v1().iter().position(|link| link.main == source)
                .ok_or(super::super::super::accumulator_stark::ZkX509CaAccumulatorProofErrorV1::ConstraintOpening)?;
            let source = self.current[index];
            groups.get(source.group).and_then(|group| group.aux_current.get(source.column)).copied()
                .ok_or(super::super::super::accumulator_stark::ZkX509CaAccumulatorProofErrorV1::ConstraintOpening)
        }).map_err(|_| ZkX509StarkErrorV1::ConstraintOpening)
    }

    pub(super) fn supplemental_v1(
        &self,
        z: E,
        values: &[E],
        mixes: &[E],
    ) -> Result<Vec<aggregate::AggregateSupplementalDeepOpeningV1>, ZkX509StarkErrorV1> {
        if values.len() != CA_MAIN_EXTRA_OPENINGS_V1
            || mixes.len() != CA_MAIN_EXTRA_OPENINGS_V1
            || values
                .iter()
                .chain(mixes)
                .any(|value| !value.is_canonical())
            || !self
                .shared
                .admissible_v1(z)
                .map_err(|_| ZkX509StarkErrorV1::ConstraintOpening)?
        {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        let mut result = Vec::new();
        result
            .try_reserve_exact(CA_MAIN_EXTRA_OPENINGS_V1)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if result.capacity() != CA_MAIN_EXTRA_OPENINGS_V1 {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        for (index, column) in self.extra.iter().enumerate() {
            result.push(aggregate::AggregateSupplementalDeepOpeningV1 {
                group: column.group,
                column: aggregate::AggregateSupplementalColumnV1::Auxiliary(column.column),
                point: z.mul_base(self.shared.main_openings_v1()[index].multiplier),
                value: values[index],
                mix: mixes[index],
            });
        }
        Ok(result)
    }

    /// Bind ordered reference values in an isolated single-transcript component control.
    #[cfg(test)]
    pub(super) fn absorb_openings_v1(
        main: &[E],
        ca: &[E],
        transcript: &mut TransparentTranscriptV1,
    ) -> Result<(), ZkX509StarkErrorV1> {
        if main.len() != CA_MAIN_EXTRA_OPENINGS_V1
            || ca.len() != CA_EXTRA_OPENINGS_V1
            || main.iter().chain(ca).any(|value| !value.is_canonical())
        {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        transcript
            .absorb(DOMAIN_V1, &[b"ordered-main24-ca108-openings"])
            .map_err(map_transparent_error_v1)?;
        for value in main.iter().chain(ca) {
            transcript
                .absorb(DOMAIN_V1, &[&value.to_be_bytes()])
                .map_err(map_transparent_error_v1)?;
        }
        Ok(())
    }

    pub(super) fn derive_mixes_v1(
        transcript: &mut TransparentTranscriptV1,
    ) -> Result<([E; CA_MAIN_EXTRA_OPENINGS_V1], [E; CA_EXTRA_OPENINGS_V1]), ZkX509StarkErrorV1>
    {
        let mut main = [E::ZERO; CA_MAIN_EXTRA_OPENINGS_V1];
        let mut ca = [E::ZERO; CA_EXTRA_OPENINGS_V1];
        for mix in &mut main {
            *mix = transcript
                .challenge_fp4(b"zk-x509-main-ca-main-extra-mix-v1")
                .map_err(map_transparent_error_v1)?;
        }
        for mix in &mut ca {
            *mix = transcript
                .challenge_fp4(b"zk-x509-main-ca-ca-extra-mix-v1")
                .map_err(map_transparent_error_v1)?;
        }
        Ok((main, ca))
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainCaPrivatePlanV1 {
    // Direct DEEP replay borrows the retained original coefficients and owns
    // only a deferred extension column and bounded public opening metadata.
    const DEEP_PRIVATE_BYTES_V1: usize = (NATIVE_ROWS_V1 + MASK_DEGREE + 1) * 32 + 4096;

    fn replay_v1(
        column: ColumnV1,
        layout: &AggregateProofLayoutV1,
        polynomials: &MainTracePolynomialSetV1,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
        policy: main_bounded_transform::MainBoundedTransformPolicyV1,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        let mut generated = polynomials.replay_columns_coefficients_v1(
            layout,
            MainTraceColumnKindV1::Aux,
            column.group,
            column.column..column.column + 1,
            sources,
            policy,
        )?;
        if generated.len() != 1 || generated.capacity() != 1 {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        let result = generated
            .pop()
            .ok_or(ZkX509StarkErrorV1::InternalInvariant)?;
        if result.len() != NATIVE_ROWS_V1 + MASK_DEGREE + 1 || result.0.capacity() != result.len() {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        Ok(result)
    }

    /// Retain each of the24 original SHA columns once across quotient and DEEP.
    pub(super) fn retain_original_auxiliary_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        polynomials: &MainTracePolynomialSetV1,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
        ca: &super::super::super::accumulator_stark::stages::CaAwaitingMainAuxiliaryV1,
        policy: main_bounded_transform::MainBoundedTransformPolicyV1,
    ) -> Result<MainCaOriginalAuxiliaryV1, ZkX509StarkErrorV1> {
        ca.validate_source_plan_v1(&self.shared)
            .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
        let reserved = MainCaOriginalAuxiliaryV1::payload_bound_v1()
            .checked_add(8 * NATIVE_ROWS_V1 * 8 + 8192)
            .and_then(|bytes| {
                ca.allocated_payload_bytes_v1()
                    .ok()
                    .and_then(|ca| bytes.checked_add(ca))
            })
            .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?;
        let policy = policy.reserve_additional_v1(reserved)?;
        let mut columns = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1::<Vec<F>>);
        columns
            .try_reserve_exact(CA_MAIN_EXTRA_OPENINGS_V1)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if columns.capacity() != CA_MAIN_EXTRA_OPENINGS_V1 {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        for column in self.extra {
            let coefficients = Self::replay_v1(column, layout, polynomials, sources, policy)?;
            if coefficients.iter().any(|value| !value.is_canonical()) {
                return Err(ZkX509StarkErrorV1::NonCanonicalField);
            }
            columns.push(coefficients.into_vec_v1());
        }
        main_bounded_transform::check_completion_v1(
            fastpq_prover::goldilocks_transform::goldilocks_transform_completion_uncertain_v1(),
        )?;
        let retained = MainCaOriginalAuxiliaryV1 {
            coordinates: self.extra,
            columns,
        };
        retained.validate_v1(self)?;
        Ok(retained)
    }

    pub(super) fn open_v1(
        &self,
        retained: &MainCaOriginalAuxiliaryV1,
        z: E,
    ) -> Result<[E; CA_MAIN_EXTRA_OPENINGS_V1], ZkX509StarkErrorV1> {
        retained.validate_v1(self)?;
        if !self
            .shared
            .admissible_v1(z)
            .map_err(|_| ZkX509StarkErrorV1::ConstraintOpening)?
        {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        let mut values = [E::ZERO; CA_MAIN_EXTRA_OPENINGS_V1];
        for (index, coefficients) in retained.columns.iter().enumerate() {
            let point = z.mul_base(self.shared.main_openings_v1()[index].multiplier);
            values[index] = coefficients.iter().rev().fold(E::ZERO, |sum, coefficient| {
                sum.mul(point).add(E::from_base(*coefficient))
            });
        }
        Ok(values)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn accumulate_deep_v1(
        &self,
        retained: &MainCaOriginalAuxiliaryV1,
        z: E,
        values: &[E],
        mixes: &[E],
        policy: main_bounded_transform::MainBoundedTransformPolicyV1,
        accumulator: &mut [E],
    ) -> Result<(), ZkX509StarkErrorV1> {
        retained.validate_v1(self)?;
        self.supplemental_v1(z, values, mixes)?;
        // The parent's policy has already charged the CA stage and common FRI
        // owners; count the actual retained MAIN cache and deferred polynomial.
        let _reserved = policy.reserve_additional_v1(
            Self::DEEP_PRIVATE_BYTES_V1
                .checked_add(retained.allocated_payload_bytes_v1()?)
                .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?,
        )?;
        let count = NATIVE_ROWS_V1 + MASK_DEGREE + 1;
        if accumulator.len() < count {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut deferred = ZeroizingExtensionColumnV1(Vec::new());
        deferred
            .0
            .try_reserve_exact(count)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if deferred.0.capacity() != count {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        deferred.0.resize(count, E::ZERO);
        for (index, coefficients) in retained.columns.iter().enumerate() {
            let target = z.mul_base(self.shared.main_openings_v1()[index].multiplier);
            let mut carry = zeroize::Zeroizing::new(E::ZERO);
            for (degree, coefficient) in coefficients.iter().enumerate().rev() {
                deferred.0[degree] = deferred.0[degree].add((*carry).mul(mixes[index]));
                *carry = E::from_base(*coefficient).add((*carry).mul(target));
            }
            if *carry != values[index] {
                return Err(ZkX509StarkErrorV1::ConstraintOpening);
            }
        }
        for (target, contribution) in accumulator.iter_mut().zip(&deferred.0) {
            *target = target.add(*contribution);
        }
        Ok(())
    }
}

// TODO: qualify the complete native joint proof and its resource measurements;
// the staged callers now consume these original-polynomial quotient/DEEP owners.

#[cfg(test)]
#[path = "main_ca_links_tests.rs"]
mod tests;

#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainCaPrivatePlanV1 {
    const QUOTIENT_LOG_V1: u8 = 20;
    const QUOTIENT_ROWS_V1: usize = 1 << Self::QUOTIENT_LOG_V1;
    const COEFFICIENT_COUNT_V1: usize = NATIVE_ROWS_V1 + MASK_DEGREE + 1;
    const CA_COEFFICIENT_COUNT_V1: usize =
        super::super::super::accumulator_air::ZK_X509_CA_ACCUMULATOR_TRACE_ROWS_V1
            + super::super::super::profile::ZK_X509_CA_TRACE_MASK_DEGREE_V1 as usize
            + 1;
    pub(super) const MAXIMUM_QUOTIENT_DEGREE_V1: usize =
        Self::COEFFICIENT_COUNT_V1 + Self::CA_COEFFICIENT_COUNT_V1 - 3;

    /// Charge disjoint replay/inverse/chunk phases; the retained CA owner is
    /// charged separately by its actual capacity at the call below.
    pub(super) const fn quotient_private_bytes_v1() -> usize {
        let extension = Self::QUOTIENT_ROWS_V1 * 32;
        let replay = extension + Self::COEFFICIENT_COUNT_V1 * 8 + (7 + 8 + 2) * NATIVE_ROWS_V1 * 8;
        let inverse = 2 * extension;
        // This quotient fits the first original chunk. Transfer its IFFT owner
        // directly; only a possible target growth overlap and six Vec headers
        // coexist. No six-chunk zero matrix is allocated for this contribution.
        let split =
            extension + 589_824 * 32 + COMPOSITION_DEGREE_CHUNKS * core::mem::size_of::<Vec<E>>();
        let peak = if replay > inverse { replay } else { inverse };
        let peak = if peak > split { peak } else { split };
        peak + 8192
    }

    /// Build all108 exact cross-proof quotients from original masked polynomials.
    /// Each native identity is checked separately before any coefficient is
    /// published. One MAIN source is replayed once for all calls using it.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub(super) fn accumulate_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        polynomials: &MainTracePolynomialSetV1,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
        ca: &super::super::super::accumulator_stark::stages::CaAwaitingMainAuxiliaryV1,
        retained: &MainCaOriginalAuxiliaryV1,
        alphas: &[E],
        policy: main_bounded_transform::MainBoundedTransformPolicyV1,
        accumulator: &mut [Vec<Vec<E>>],
    ) -> Result<(), ZkX509StarkErrorV1> {
        use fastpq_prover::goldilocks_transform::{
            goldilocks_transform_completion_uncertain_v1, transform_goldilocks_columns_v1,
        };
        ca.validate_source_plan_v1(&self.shared)
            .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
        retained.validate_v1(self)?;
        if alphas.len() != CA_MAIN_LINK_COUNT_V1
            || alphas.iter().any(|alpha| !alpha.is_canonical())
            || Self::MAXIMUM_QUOTIENT_DEGREE_V1 != 532_297
            || SECURITY_LANES != 1
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let allowance = Self::quotient_private_bytes_v1()
            .checked_add(
                ca.allocated_payload_bytes_v1()
                    .map_err(|_| ZkX509StarkErrorV1::ProofTooLarge)?,
            )
            .and_then(|bytes| {
                retained
                    .allocated_payload_bytes_v1()
                    .ok()
                    .and_then(|cache| bytes.checked_add(cache))
            })
            .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?;
        let policy = policy.reserve_additional_v1(allowance)?;
        let shared = layout.as_shared()?;
        let cap = shared
            .fri_degree_cap(AGGREGATE_PARAMETERS_V1)
            .map_err(map_aggregate_error_v1)?;
        if cap != 589_824 {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut quotient = ZeroizingExtensionColumnV1(Vec::new());
        quotient
            .0
            .try_reserve_exact(Self::QUOTIENT_ROWS_V1)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if quotient.0.capacity() != Self::QUOTIENT_ROWS_V1 {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        quotient.0.resize(Self::QUOTIENT_ROWS_V1, E::ZERO);
        let evaluate = |coefficients: &[F], point: F| {
            coefficients
                .iter()
                .rev()
                .fold(F::ZERO, |sum, coefficient| sum.mul(point).add(*coefficient))
        };
        let denominators = [
            CaEndpointDenominatorsV1::new_v1(main_quotient_stripes::MainQuotientStripeV1::new_v1(
                NATIVE_LOG_V1,
                Self::QUOTIENT_LOG_V1,
                0,
            )?)?,
            CaEndpointDenominatorsV1::new_v1(main_quotient_stripes::MainQuotientStripeV1::new_v1(
                NATIVE_LOG_V1,
                Self::QUOTIENT_LOG_V1,
                1,
            )?)?,
        ];
        let mut original_count = 0;
        for first in 0..CA_MAIN_LINK_COUNT_V1 {
            let column = self.current[first];
            if self.current[..first].contains(&column) {
                continue;
            }
            original_count += 1;
            let mut indices = [0_usize; 5];
            let mut count = 0;
            for index in first..CA_MAIN_LINK_COUNT_V1 {
                if self.current[index] == column {
                    if count == indices.len() {
                        return Err(ZkX509StarkErrorV1::ProfileMismatch);
                    }
                    indices[count] = index;
                    count += 1;
                }
            }
            let indices = &indices[..count];
            let cached_index = retained
                .coordinates
                .iter()
                .position(|cached| *cached == column);
            let replayed = if cached_index.is_none() {
                Some(Self::replay_v1(
                    column,
                    layout,
                    polynomials,
                    sources,
                    policy,
                )?)
            } else {
                None
            };
            let source: &[F] = if let Some(index) = cached_index {
                &retained.columns[index]
            } else {
                replayed
                    .as_deref()
                    .ok_or(ZkX509StarkErrorV1::InternalInvariant)?
            };
            let first_link = &self.shared.links_v1()[first];
            let gamma = first_link
                .main_start
                .map(|index| self.shared.main_openings_v1()[index].multiplier);
            for &index in indices {
                let link = &self.shared.links_v1()[index];
                if link
                    .main_start
                    .map(|index| self.shared.main_openings_v1()[index].multiplier)
                    != gamma
                {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                let target = &self.shared.ca_openings_v1()[link.ca];
                let coefficients = ca
                    .link_column_v1(usize::from(target.column))
                    .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
                if coefficients.len() != Self::CA_COEFFICIENT_COUNT_V1 {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
                let mut endpoint = zeroize::Zeroizing::new([F::ZERO; 3]);
                endpoint[0] = evaluate(source, link.endpoint);
                endpoint[1] =
                    gamma.map_or(F::ONE, |gamma| evaluate(source, gamma.mul(link.endpoint)));
                endpoint[2] = evaluate(coefficients, target.multiplier.mul(link.endpoint));
                if endpoint[0] != endpoint[1].mul(endpoint[2]).mul(link.public_factor) {
                    return Err(ZkX509StarkErrorV1::ConstraintOpening);
                }
            }
            let mut batch = PrivateTableV1::new(Vec::new(), zeroize_field_rows_v1::<Vec<F>>);
            batch
                .try_reserve_exact(2 + count)
                .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
            if batch.capacity() != 2 + count {
                return Err(ZkX509StarkErrorV1::ProofTooLarge);
            }
            for _ in 0..2 + count {
                batch.push(zeroed_main_trace_column_v1(NATIVE_ROWS_V1)?.into_vec_v1());
            }
            if batch
                .iter()
                .any(|column| column.capacity() != NATIVE_ROWS_V1)
            {
                return Err(ZkX509StarkErrorV1::ProofTooLarge);
            }
            for ordinal in 0..2 {
                let stripe = main_quotient_stripes::MainQuotientStripeV1::new_v1(
                    NATIVE_LOG_V1,
                    Self::QUOTIENT_LOG_V1,
                    ordinal,
                )?;
                let inverse = &denominators[ordinal];
                stripe.fold_into_v1(source, &mut batch[0])?;
                batch[1].fill(F::ZERO);
                if let Some(gamma) = gamma {
                    let mut translated = stripe;
                    translated.shift = translated.shift.mul(gamma);
                    translated.fold_into_v1(source, &mut batch[1])?;
                } else {
                    batch[1][0] = F::ONE;
                }
                for (offset, &index) in indices.iter().enumerate() {
                    let opening = &self.shared.ca_openings_v1()[self.shared.links_v1()[index].ca];
                    let coefficients = ca
                        .link_column_v1(usize::from(opening.column))
                        .map_err(|_| ZkX509StarkErrorV1::ProfileMismatch)?;
                    let mut translated = stripe;
                    translated.shift = translated.shift.mul(opening.multiplier);
                    translated.fold_into_v1(coefficients, &mut batch[2 + offset])?;
                }
                main_bounded_transform::check_completion_v1(
                    goldilocks_transform_completion_uncertain_v1(),
                )?;
                policy.forward_with_v1(
                    &mut batch,
                    stripe.root,
                    &mut |words: &mut [Vec<u64>], root, direction| {
                        transform_goldilocks_columns_v1(
                            words,
                            root,
                            direction,
                            fastpq_prover::ExecutionMode::Auto,
                        )
                    },
                    &mut goldilocks_transform_completion_uncertain_v1,
                )?;
                for (offset, &index) in indices.iter().enumerate() {
                    let link = &self.shared.links_v1()[index];
                    let endpoint_inverse = link
                        .endpoint
                        .inv()
                        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
                    quotient
                        .0
                        .par_chunks_mut(2)
                        .enumerate()
                        .for_each(|(row, values)| {
                            let denominator = endpoint_inverse.mul(
                                inverse.values[(row + NATIVE_ROWS_V1 - self.endpoint_rows[index])
                                    % NATIVE_ROWS_V1],
                            );
                            let numerator = batch[0][row].sub(
                                batch[1][row]
                                    .mul(batch[2 + offset][row])
                                    .mul(link.public_factor),
                            );
                            values[ordinal] = values[ordinal]
                                .add(alphas[index].mul_base(numerator.mul(denominator)));
                        });
                }
            }
        }
        drop(denominators);
        if original_count != 28 {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        main_bounded_transform::check_completion_v1(goldilocks_transform_completion_uncertain_v1())?;
        let coefficients = fp4_coset_coefficients_v1(&quotient, Self::QUOTIENT_LOG_V1)?;
        drop(quotient);
        if coefficients.0.capacity() != Self::QUOTIENT_ROWS_V1 {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        Self::add_original_first_chunk_v1(coefficients, &shared, accumulator)
    }

    /// The exact quotient degree is below the original chunk stride. Preserve
    /// atomic validation and the existing sink while transferring its one owner.
    fn add_original_first_chunk_v1(
        mut coefficients: ZeroizingExtensionColumnV1,
        shared: &aggregate::AggregateProofLayoutV1,
        accumulator: &mut [Vec<Vec<E>>],
    ) -> Result<(), ZkX509StarkErrorV1> {
        let geometry = super::super::super::composition_masking::QuotientChunkGeometryV1::new_v1(
            shared,
            AGGREGATE_PARAMETERS_V1,
        )
        .map_err(map_aggregate_error_v1)?;
        let cap = shared
            .fri_degree_cap(AGGREGATE_PARAMETERS_V1)
            .map_err(map_aggregate_error_v1)?;
        let count = Self::MAXIMUM_QUOTIENT_DEGREE_V1 + 1;
        if cap != 589_824
            || geometry.stride_v1() != 589_687
            || count > geometry.stride_v1()
            || coefficients.len() != Self::QUOTIENT_ROWS_V1
            || coefficients.0.capacity() != Self::QUOTIENT_ROWS_V1
            || coefficients.iter().any(|value| !value.is_canonical())
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        if coefficients[count..].iter().any(|value| *value != E::ZERO) {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        // The tail has been checked zero, but explicitly erase every original
        // initialized cell before the public degree bound removes it from Drop.
        super::super::super::private_table::zeroize_words_v1(&mut coefficients.0[count..]);
        let mut lane = vec![Vec::new(); COMPOSITION_DEGREE_CHUNKS];
        lane[0] = core::mem::take(&mut coefficients.0);
        lane[0].truncate(count);
        let contribution = ZeroizingExtensionLanesV1::new(vec![lane], zeroize_extension_lanes_v1);
        add_main_composition_coefficient_chunks_v1(accumulator, &contribution, cap)
    }
}

/// One public stripe table supplies all108 native endpoint inverses by rotation.
#[cfg(any(test, feature = "privacy-release-evidence"))]
struct CaEndpointDenominatorsV1 {
    values: Vec<F>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl CaEndpointDenominatorsV1 {
    fn new_v1(
        stripe: main_quotient_stripes::MainQuotientStripeV1,
    ) -> Result<Self, ZkX509StarkErrorV1> {
        let expected =
            main_quotient_stripes::MainQuotientStripeV1::new_v1(NATIVE_LOG_V1, 20, stripe.ordinal)?;
        if stripe.rows != expected.rows
            || stripe.count != expected.count
            || stripe.root != expected.root
            || stripe.shift != expected.shift
            || stripe.next_stride != expected.next_stride
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(NATIVE_ROWS_V1)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if values.capacity() != NATIVE_ROWS_V1 {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        let mut product = F::ONE;
        let mut point = stripe.shift;
        for _ in 0..NATIVE_ROWS_V1 {
            product = product.mul(point.sub(F::ONE));
            values.push(product);
            point = point.mul(stripe.root);
        }
        let mut inverse = product.inv().ok_or(ZkX509StarkErrorV1::ConstraintOpening)?;
        let root_inverse = stripe
            .root
            .inv()
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        point = stripe.shift.mul(root_inverse);
        for row in (0..NATIVE_ROWS_V1).rev() {
            let prefix = if row == 0 { F::ONE } else { values[row - 1] };
            values[row] = inverse.mul(prefix);
            inverse = inverse.mul(point.sub(F::ONE));
            point = point.mul(root_inverse);
        }
        if inverse != F::ONE {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        Ok(Self { values })
    }
}

/// Selected original SHA polynomials, retained through the shared DEEP phase.
/// The constructor is the only path from the original committed mask replay.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) struct MainCaOriginalAuxiliaryV1 {
    coordinates: [ColumnV1; CA_MAIN_EXTRA_OPENINGS_V1],
    columns: PrivateTableV1<Vec<F>>,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl core::fmt::Debug for MainCaOriginalAuxiliaryV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MainCaOriginalAuxiliaryV1 { <original coefficients redacted> }")
    }
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
impl MainCaOriginalAuxiliaryV1 {
    pub(super) fn payload_bound_v1() -> usize {
        CA_MAIN_EXTRA_OPENINGS_V1
            * ((NATIVE_ROWS_V1 + MASK_DEGREE + 1) * 8 + core::mem::size_of::<Vec<F>>())
            + core::mem::size_of::<Self>()
    }
    pub(super) fn allocated_payload_bytes_v1(&self) -> Result<usize, ZkX509StarkErrorV1> {
        self.columns.iter().try_fold(
            core::mem::size_of::<Self>() + self.columns.capacity() * core::mem::size_of::<Vec<F>>(),
            |total, column| {
                column
                    .capacity()
                    .checked_mul(8)
                    .and_then(|bytes| total.checked_add(bytes))
                    .ok_or(ZkX509StarkErrorV1::ProofTooLarge)
            },
        )
    }
    fn validate_v1(&self, plan: &MainCaPrivatePlanV1) -> Result<(), ZkX509StarkErrorV1> {
        if self.coordinates != plan.extra
            || self.columns.len() != CA_MAIN_EXTRA_OPENINGS_V1
            || self.columns.capacity() != CA_MAIN_EXTRA_OPENINGS_V1
            || self.columns.iter().any(|column| {
                column.len() != NATIVE_ROWS_V1 + MASK_DEGREE + 1
                    || column.capacity() != column.len()
            })
            || self.allocated_payload_bytes_v1()? != Self::payload_bound_v1()
        {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(())
    }
}
