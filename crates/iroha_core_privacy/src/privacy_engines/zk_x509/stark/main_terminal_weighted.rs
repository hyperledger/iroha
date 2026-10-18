// Four native-domain interpolations of the exact original masked link quotients.
// This module is included by main_terminal_links so the closed endpoint plan
// remains the only production caller. Public roots/points determine every loop.

use super::super::super::super::private_table::{zeroize_field_rows_v1, zeroize_words_v1};
use super::*;
use fastpq_prover::goldilocks_transform::{
    GoldilocksTransformBackendV1 as Backend, GoldilocksTransformDirectionV1 as Direction,
    GoldilocksTransformErrorV1 as TransformError, goldilocks_transform_completion_uncertain_v1,
    transform_goldilocks_columns_v1,
};

type Fields = PrivateTableV1<F>;
type Extensions = PrivateTableV1<E>;
type Matrix = PrivateTableV1<Vec<F>>;
const METADATA_BYTES: usize = 16 * 1024;
const MAX_POINTS: usize = 3;

fn fields_v1(length: usize) -> Result<Fields, ZkX509StarkErrorV1> {
    let mut owner = Fields::new(Vec::new(), zeroize_fields_v1);
    before_allocation_v1()?;
    owner
        .try_reserve_exact(length)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    if owner.capacity() != length {
        return Err(ZkX509StarkErrorV1::ProofTooLarge);
    }
    owner.resize(length, F::ZERO);
    Ok(owner)
}
fn extensions_v1(length: usize) -> Result<Extensions, ZkX509StarkErrorV1> {
    let mut owner = Extensions::new(Vec::new(), zeroize_words_v1);
    before_allocation_v1()?;
    owner
        .try_reserve_exact(length)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    if owner.capacity() != length {
        return Err(ZkX509StarkErrorV1::ProofTooLarge);
    }
    owner.resize(length, E::ZERO);
    Ok(owner)
}
fn matrix_v1(rows: usize) -> Result<Matrix, ZkX509StarkErrorV1> {
    let mut owner = Matrix::new(Vec::new(), zeroize_field_rows_v1::<Vec<F>>);
    before_allocation_v1()?;
    owner
        .try_reserve_exact(4)
        .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
    if owner.capacity() != 4 {
        return Err(ZkX509StarkErrorV1::ProofTooLarge);
    }
    for _ in 0..4 {
        let column = fields_v1(rows)?;
        // Reserved push is infallible; the inner owner transfers directly into
        // the clearing matrix, with no fallible operation between them.
        owner.push(column.into_vec());
    }
    Ok(owner)
}

/// Entire simultaneous caller payload, additional to the unchanged MAIN plan.
/// Twelve base columns cover four weighted columns, the in-place public inverse
/// prefix/table and at most seven native source columns. Each side retains at
/// most three columns after its current column has been consumed and dropped. Two extension columns cover the private
/// result and mask quotient; the original masks are borrowed, never resampled.
fn payload_v1(rows: usize, masks: usize, links: usize) -> Result<usize, ZkX509StarkErrorV1> {
    let metadata = 8 * core::mem::size_of::<Fields>()
        + 4 * core::mem::size_of::<Extensions>()
        + 2 * core::mem::size_of::<E>()
        + core::mem::size_of::<Matrix>()
        + 4 * core::mem::size_of::<Vec<F>>()
        + 2 * core::mem::size_of::<NativeFamilyCacheV1>()
        + core::mem::size_of::<[u8; 2 * LINK_COUNT_V1]>()
        + 2 * core::mem::size_of::<Vec<ZeroizingMainTraceColumnV1>>()
        + 17 * core::mem::size_of::<ZeroizingMainTraceColumnV1>()
        + core::mem::size_of::<[bool; 2 * LINK_COUNT_V1]>()
        + core::mem::size_of::<[F; MAX_POINTS]>()
        + 2048; // bounded borrowed descriptors and scalar loop/field temporaries
    if metadata > METADATA_BYTES {
        return Err(ZkX509StarkErrorV1::ProofTooLarge);
    }
    rows.checked_mul(12)
        .and_then(|n| links.checked_mul(2).and_then(|l| n.checked_add(l)))
        .and_then(|n| n.checked_add(4))
        .and_then(|n| n.checked_mul(core::mem::size_of::<F>()))
        .and_then(|n| {
            rows.checked_add(masks)
                .and_then(|c| c.checked_mul(2))
                .and_then(|c| c.checked_add(masks))
                .and_then(|c| c.checked_mul(core::mem::size_of::<E>()))
                .and_then(|c| n.checked_add(c))
        })
        .and_then(|n| n.checked_add(METADATA_BYTES))
        .ok_or(ZkX509StarkErrorV1::ProofTooLarge)
}

/// Build 1/(x-a) in one allocation. The endpoint is the single public zero.
/// Prefix products are replaced in place, so there is no hidden second N table.
fn inverse_table_v1(table: &mut [F], root: F, point: F) -> Result<usize, ZkX509StarkErrorV1> {
    let rows = table.len();
    if rows < 2
        || !rows.is_power_of_two()
        || !point.is_canonical()
        || !root.is_canonical()
        || point.pow(rows as u128) != F::ONE
        || root.pow(rows as u128) != F::ONE
        || root.pow((rows / 2) as u128) == F::ONE
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let mut product = F::ONE;
    let mut x = F::ONE;
    let mut endpoint = None;
    for (index, slot) in table.iter_mut().enumerate() {
        *slot = product;
        if x == point {
            if endpoint.replace(index).is_some() {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
        } else {
            product = product.mul(x.sub(point));
        }
        x = x.mul(root);
    }
    let endpoint = endpoint.ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    // All inverted values depend only on the public native domain and point.
    let mut inverse = product.inv().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    let root_inverse = root.inv().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
    x = root_inverse;
    for (index, slot) in table.iter_mut().enumerate().rev() {
        if index == endpoint {
            *slot = F::ZERO;
        } else {
            let prefix = *slot;
            *slot = inverse.mul(prefix);
            inverse = inverse.mul(x.sub(point));
        }
        x = x.mul(root_inverse);
    }
    Ok(endpoint)
}

/// Divide a weighted original-mask polynomial r(X)(X^N-1) by X-a.
/// The high-to-low synthetic division handles overlapping mask tails M>N.
fn mask_quotient_v1(
    masks: &[E],
    rows: usize,
    point: F,
    output: &mut [E],
) -> Result<(), ZkX509StarkErrorV1> {
    if output.len()
        < rows
            .checked_add(masks.len())
            .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?
        || rows < 2
        || !rows.is_power_of_two()
        || !point.is_canonical()
        || masks.is_empty()
        || masks.iter().any(|value| !value.is_canonical())
        || point.pow(rows as u128) != F::ONE
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    output.fill(E::ZERO);
    for (index, value) in masks.iter().copied().enumerate() {
        output[index] = output[index].sub(value);
        output[index + rows] = output[index + rows].add(value);
    }
    // The temporary carry is itself clearing-owned, including error/unwind.
    let mut carry = extensions_v1(2)?;
    for index in (0..output.len()).rev() {
        carry[1] = output[index];
        output[index] = carry[0];
        carry[0] = carry[1].add(carry[0].mul_base(point));
    }
    if carry[0] != E::ZERO {
        return Err(ZkX509StarkErrorV1::ConstraintOpening);
    }
    Ok(())
}

/// Width-four requests are restricted to the existing grouped arithmetic/value
/// sources and one exact public family. Width one already computes every lane of
/// that family; changing the copied columns introduces no new source recurrence.
fn family_widths_v1(
    plan: &MainTerminalLinkPlanV1,
    layout: &AggregateProofLayoutV1,
) -> Result<[u8; 2 * LINK_COUNT_V1], ZkX509StarkErrorV1> {
    use super::super::super::super::p256_aggregate_adapter::{
        P256PrivateLinkFamilyV1 as Family, p256_private_link_columns_v1,
    };
    let mut widths = [1; 2 * LINK_COUNT_V1];
    for (index, link) in plan.links.iter().enumerate() {
        for (side, column) in [Some(link.left), link.right].into_iter().enumerate() {
            let Some(column) = column else { continue };
            let (registration, local) = registered_main_group_column_v1(
                layout,
                column.group,
                MainTraceColumnKindV1::Aux,
                column.column,
            )?;
            if !matches!(
                registration.segment.adapter,
                SegmentAdapterIdV1::P256Arithmetic | SegmentAdapterIdV1::P256ValueBus
            ) {
                continue;
            }
            let identity = p256_main_registration_from_main_layout_v1(registration)?;
            // BindingSink shares the ValueBus segment tag at local two but its
            // source is scalar; it must not acquire later-lane errors eagerly.
            if !matches!(
                (identity.adapter_v1(), identity.local_instance_v1()),
                (P256MainAdapterV1::Arithmetic, 0) | (P256MainAdapterV1::ValueBus, 0 | 1)
            ) {
                continue;
            }
            let is_family = [
                Family::Value,
                Family::Copy,
                Family::ArithmeticScalar,
                Family::WindowScalar,
                Family::ChainStart,
                Family::ChainTerminal,
            ]
            .into_iter()
            .any(|family| {
                p256_private_link_columns_v1(identity, family)
                    .is_ok_and(|columns| columns == core::array::from_fn(|lane| local + lane))
            });
            if is_family && contiguous_family_v1(&plan.links, index, side) {
                widths[2 * index + side] = 4;
            }
        }
    }
    Ok(widths)
}

/// Public link order, point, native geometry and group must all stay identical.
fn contiguous_family_v1(links: &[LinkV1], first: usize, side: usize) -> bool {
    let Some(family) = first.checked_add(4).and_then(|end| links.get(first..end)) else {
        return false;
    };
    let column = |link: &LinkV1| match side {
        0 => Some(link.left),
        1 => link.right,
        _ => None,
    };
    let Some(start) = column(&family[0]) else {
        return false;
    };
    family.iter().enumerate().all(|(lane, link)| {
        link.point == family[0].point
            && column(link).is_some_and(|current| {
                current.group == start.group
                    && current.native_log2 == start.native_log2
                    && start.column.checked_add(lane) == Some(current.column)
            })
    })
}

/// A FIFO of source-owned columns, never of private endpoint/equality results.
/// Removing the current owner before the other side fills bounds simultaneous
/// storage by three retained columns plus four newly produced columns.
#[derive(Default)]
struct NativeFamilyCacheV1 {
    next: Option<(usize, ColumnV1)>,
    columns: Vec<ZeroizingMainTraceColumnV1>,
}
impl NativeFamilyCacheV1 {
    fn take_v1(
        &mut self,
        index: usize,
        column: ColumnV1,
        width: usize,
        native: &mut impl FnMut(
            ColumnV1,
            usize,
        ) -> Result<Vec<ZeroizingMainTraceColumnV1>, ZkX509StarkErrorV1>,
    ) -> Result<ZeroizingMainTraceColumnV1, ZkX509StarkErrorV1> {
        if self.columns.is_empty() {
            if self.next.is_some() || !matches!(width, 1 | 4) {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            self.columns = native(column, width)?;
            if self.columns.len() != width || self.columns.capacity() != width {
                return Err(ZkX509StarkErrorV1::ProofTooLarge);
            }
        } else if self.next != Some((index, column)) {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let value = self.columns.remove(0);
        self.next = if self.columns.is_empty() {
            None
        } else {
            Some((
                index
                    .checked_add(1)
                    .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
                ColumnV1 {
                    column: column
                        .column
                        .checked_add(1)
                        .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
                    ..column
                },
            ))
        };
        Ok(value)
    }
}

pub(super) fn accumulate_v1(
    plan: &MainTerminalLinkPlanV1,
    layout: &AggregateProofLayoutV1,
    polynomials: &MainTracePolynomialSetV1,
    sources: &MainTraceReplaySourcesV1<'_, '_>,
    alphas: &[E],
    policy: main_bounded_transform::MainBoundedTransformPolicyV1,
    chunk: &mut Vec<E>,
) -> Result<(), ZkX509StarkErrorV1> {
    polynomials.validate_v1(layout, MainTraceColumnKindV1::Aux)?;
    let widths = family_widths_v1(plan, layout)?;
    accumulate_with_batches_v1(
        &plan.links,
        &widths,
        alphas,
        MASK_DEGREE + 1,
        policy,
        chunk,
        |column, width| {
            sources.native_columns_v1(
                layout,
                MainTraceColumnKindV1::Aux,
                column.group,
                column.column..column.column + width,
            )
        },
        |column| {
            let masks = polynomials.original_masks_v1(
                layout,
                MainTraceColumnKindV1::Aux,
                column.group,
                column.column..column.column + 1,
            )?;
            if masks.len() != 1 {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            Ok(masks[0].coefficients())
        },
        |words, root, direction| {
            transform_goldilocks_columns_v1(
                words,
                root,
                direction,
                fastpq_prover::ExecutionMode::Auto,
            )
        },
        goldilocks_transform_completion_uncertain_v1,
    )
}

// The one-column callback remains a test oracle for the same accumulator.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn accumulate_with_v1<'a>(
    links: &[LinkV1],
    alphas: &[E],
    masks: usize,
    policy: main_bounded_transform::MainBoundedTransformPolicyV1,
    chunk: &mut Vec<E>,
    mut native: impl FnMut(ColumnV1) -> Result<Vec<ZeroizingMainTraceColumnV1>, ZkX509StarkErrorV1>,
    original_mask: impl FnMut(ColumnV1) -> Result<&'a [F], ZkX509StarkErrorV1>,
    transform: impl FnMut(&mut [Vec<u64>], u64, Direction) -> Result<Backend, TransformError>,
    uncertain: impl FnMut() -> bool,
) -> Result<(), ZkX509StarkErrorV1> {
    accumulate_with_batches_v1(
        links,
        &[1; 2 * LINK_COUNT_V1],
        alphas,
        masks,
        policy,
        chunk,
        |column, width| {
            assert_eq!(width, 1);
            native(column)
        },
        original_mask,
        transform,
        uncertain,
    )
}

#[allow(clippy::too_many_arguments)]
fn accumulate_with_batches_v1<'a>(
    links: &[LinkV1],
    widths: &[u8; 2 * LINK_COUNT_V1],
    alphas: &[E],
    masks: usize,
    policy: main_bounded_transform::MainBoundedTransformPolicyV1,
    chunk: &mut Vec<E>,
    mut native: impl FnMut(
        ColumnV1,
        usize,
    ) -> Result<Vec<ZeroizingMainTraceColumnV1>, ZkX509StarkErrorV1>,
    mut original_mask: impl FnMut(ColumnV1) -> Result<&'a [F], ZkX509StarkErrorV1>,
    mut transform: impl FnMut(&mut [Vec<u64>], u64, Direction) -> Result<Backend, TransformError>,
    mut uncertain: impl FnMut() -> bool,
) -> Result<(), ZkX509StarkErrorV1> {
    if links.is_empty()
        || links.len() > LINK_COUNT_V1
        || alphas.len() != links.len()
        || alphas.iter().any(|value| !value.is_canonical())
        || masks == 0
        || masks > MASK_DEGREE + 1
        || chunk.iter().any(|value| !value.is_canonical())
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    for index in 0..links.len() {
        for side in 0..2 {
            match widths[2 * index + side] {
                1 => {}
                4 if contiguous_family_v1(links, index, side) => {}
                _ => return Err(ZkX509StarkErrorV1::ProfileMismatch),
            }
        }
    }
    let mut points = [F::ZERO; MAX_POINTS];
    let mut point_count = 0;
    let mut max_log = 0;
    for link in links {
        if !link.point.is_canonical() {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        if !points[..point_count].contains(&link.point) {
            if point_count == MAX_POINTS {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            points[point_count] = link.point;
            point_count += 1;
        }
        for column in [Some(link.left), link.right].into_iter().flatten() {
            if column.native_log2 == 0
                || column.native_log2 > ZK_X509_MAX_NATIVE_TRACE_LOG2_V1
                || link.point.pow(1_u128 << column.native_log2) != F::ONE
            {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            max_log = max_log.max(column.native_log2);
        }
    }
    let max_rows = 1_usize << max_log;
    let count = max_rows
        .checked_add(masks)
        .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?;
    let charge = payload_v1(max_rows, masks, links.len())?;
    let policy = policy.reserve_additional_v1(charge)?;
    if chunk.capacity() < count - 1 {
        return Err(ZkX509StarkErrorV1::ProofTooLarge);
    }
    main_bounded_transform::check_completion_v1(uncertain())?;
    // Publication is deferred until every individual endpoint has passed and all
    // transforms have completed. These additional buffers are fully charged.
    let mut result = extensions_v1(count)?;
    let mut quotient = extensions_v1(count)?;
    let mut weighted_mask = extensions_v1(masks)?;
    let mut endpoints = fields_v1(2 * links.len())?;
    let mut seen = [false; 2 * LINK_COUNT_V1];
    let mut scalar = fields_v1(4)?;
    for (index, link) in links.iter().enumerate() {
        if link.right.is_none() {
            endpoints[2 * index + 1] = F::ONE;
            seen[2 * index + 1] = true;
        }
    }
    for log in 1..=max_log {
        if !links
            .iter()
            .flat_map(|link| [Some(link.left), link.right])
            .flatten()
            .any(|column| column.native_log2 == log)
        {
            continue;
        }
        let rows = 1_usize << log;
        let root = goldilocks_primitive_root_v1(log).map_err(map_transparent_error_v1)?;
        let mut weighted = matrix_v1(rows)?;
        let mut inverse = fields_v1(rows)?;
        for &point in &points[..point_count] {
            if !links.iter().any(|link| {
                link.point == point
                    && [Some(link.left), link.right]
                        .into_iter()
                        .flatten()
                        .any(|column| column.native_log2 == log)
            }) {
                continue;
            }
            let endpoint = inverse_table_v1(&mut inverse, root, point)?;
            let point_inverse = point.inv().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
            let diagonal = F((rows - 1) as u64)
                .mul(F(2).inv().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?)
                .mul(point_inverse);
            weighted_mask.fill(E::ZERO);
            let mut caches: [NativeFamilyCacheV1; 2] = core::array::from_fn(|_| NativeFamilyCacheV1::default());
            for (index, (link, &alpha)) in links.iter().zip(alphas).enumerate() {
                if link.point != point {
                    continue;
                }
                for (side, column) in [Some(link.left), link.right].into_iter().enumerate() {
                    let Some(column) = column.filter(|column| column.native_log2 == log) else {
                        continue;
                    };
                    main_bounded_transform::check_completion_v1(uncertain())?;
                    let values = caches[side].take_v1(
                        index,
                        column,
                        usize::from(widths[2 * index + side]),
                        &mut native,
                    )?;
                    // Validate only this original link/side now. A later cached
                    // lane must not outrank the other side's mask or endpoint.
                    if values.len() != rows || values.0.capacity() != rows {
                        return Err(ZkX509StarkErrorV1::ProofTooLarge);
                    }
                    if values.iter().any(|value| !value.is_canonical()) {
                        return Err(ZkX509StarkErrorV1::ProfileMismatch);
                    }
                    let mask = original_mask(column)?;
                    if mask.len() != masks || mask.iter().any(|value| !value.is_canonical()) {
                        return Err(ZkX509StarkErrorV1::ProfileMismatch);
                    }
                    scalar[0] = values[endpoint];
                    endpoints[2 * index + side] = scalar[0];
                    seen[2 * index + side] = true;
                    if seen[2 * index]
                        && seen[2 * index + 1]
                        && endpoints[2 * index] != endpoints[2 * index + 1]
                    {
                        return Err(ZkX509StarkErrorV1::ConstraintOpening);
                    }
                    let scale = if side == 0 { alpha } else { E::ZERO.sub(alpha) };
                    scalar[1] = scalar[0].mul(diagonal);
                    let mut x = F::ONE;
                    for row in 0..rows {
                        if row != endpoint {
                            scalar[2] = values[row].sub(scalar[0]).mul(inverse[row]);
                            // L_i'(a) = -x_i/(a*(x_i-a)); only public inversion.
                            scalar[1] = scalar[1]
                                .sub(values[row].mul(x).mul(inverse[row]).mul(point_inverse));
                            for lane in 0..4 {
                                weighted[lane][row] = weighted[lane][row]
                                    .add(scale.coefficients()[lane].mul(scalar[2]));
                            }
                        }
                        x = x.mul(root);
                    }
                    for lane in 0..4 {
                        weighted[lane][endpoint] =
                            weighted[lane][endpoint].add(scale.coefficients()[lane].mul(scalar[1]));
                    }
                    for (target, &value) in weighted_mask.iter_mut().zip(mask) {
                        *target = target.add(scale.mul_base(value));
                    }
                    scalar.fill(F::ZERO);
                    // Drop this owner before the next side can allocate its batch.
                }
            }
            if caches
                .iter()
                .any(|cache| !cache.columns.is_empty() || cache.next.is_some())
            {
                return Err(ZkX509StarkErrorV1::InternalInvariant);
            }
            drop(caches);
            mask_quotient_v1(&weighted_mask, rows, point, &mut quotient)?;
            for (target, &value) in result.iter_mut().zip(quotient.iter()) {
                *target = target.add(value);
            }
            quotient.fill(E::ZERO);
            weighted_mask.fill(E::ZERO);
        }
        policy.inverse_with_v1(&mut weighted, root, &mut transform, &mut uncertain)?;
        for row in 0..rows {
            result[row] = result[row].add(
                E::from_coefficients(core::array::from_fn(|lane| weighted[lane][row]))
                    .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
            );
        }
    }
    if seen[..2 * links.len()].iter().any(|seen| !seen) {
        return Err(ZkX509StarkErrorV1::InternalInvariant);
    }
    for index in 0..links.len() {
        if endpoints[2 * index] != endpoints[2 * index + 1] {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
    }
    main_bounded_transform::check_completion_v1(uncertain())?;
    if result[count - 1] != E::ZERO {
        return Err(ZkX509StarkErrorV1::ConstraintOpening);
    }
    // Infallible publication only: the caller's existing admitted allocation is
    // unchanged on every earlier error or unwind, including device uncertainty.
    if chunk.len() < count - 1 {
        chunk.resize(count - 1, E::ZERO);
    }
    for (target, &value) in chunk.iter_mut().zip(&result[..count - 1]) {
        *target = target.add(value);
    }
    Ok(())
}

fn before_allocation_v1() -> Result<(), ZkX509StarkErrorV1> {
    #[cfg(test)]
    allocation_failure::step_v1()?;
    Ok(())
}

#[cfg(test)]
mod allocation_failure {
    use super::*;
    thread_local! { static REMAINING: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) }; }
    pub(super) fn step_v1() -> Result<(), ZkX509StarkErrorV1> {
        REMAINING.with(|remaining| match remaining.get() {
            None => Ok(()),
            Some(0) => Err(ZkX509StarkErrorV1::AllocationFailure),
            Some(n) => {
                remaining.set(Some(n - 1));
                Ok(())
            }
        })
    }
    pub(super) fn at_v1<T>(index: usize, run: impl FnOnce() -> T) -> T {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                REMAINING.with(|remaining| remaining.set(None));
            }
        }
        REMAINING.with(|remaining| {
            assert!(remaining.get().is_none());
            remaining.set(Some(index));
        });
        let _reset = Reset;
        run()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::transparent_stark::{
        goldilocks_ifft_v1, masked_trace_coefficients_with_mask_v1, sample_trace_mask_v1,
    };
    use crate::privacy_engines::zk_x509::private_table::inspection::observe_v1;
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    fn plan_v1(logs: [u8; 3]) -> MainTerminalLinkPlanV1 {
        let points = [
            F::ONE,
            F::ZERO.sub(F::ONE),
            goldilocks_primitive_root_v1(logs[0]).unwrap(),
        ];
        let links = core::array::from_fn(|index| {
            let left = ColumnV1 {
                group: 0,
                column: 2 * index,
                native_log2: logs[index % 3],
            };
            let right = ColumnV1 {
                column: 2 * index + 1,
                native_log2: logs[(index + 1) % 3],
                ..left
            };
            LinkV1 {
                left,
                right: (index % 5 != 0).then_some(right),
                point: points[index % 3],
            }
        });
        MainTerminalLinkPlanV1 { links }
    }
    fn native_v1(
        plan: &MainTerminalLinkPlanV1,
        column: ColumnV1,
    ) -> Vec<ZeroizingMainTraceColumnV1> {
        let point = plan.links[column.column / 2].point;
        let root = goldilocks_primitive_root_v1(column.native_log2).unwrap();
        let mut x = F::ONE;
        let slope = F(3 + column.column as u64);
        let values = (0..1_usize << column.native_log2)
            .map(|_| {
                let value = F::ONE
                    .add(x.sub(point).mul(slope))
                    .add(x.sub(point).mul(x).mul(F(7)));
                x = x.mul(root);
                value
            })
            .collect::<Vec<_>>();
        vec![ZeroizingMainTraceColumnV1(values)]
    }
    fn masks_v1() -> Vec<Vec<F>> {
        (0..2 * LINK_COUNT_V1)
            .map(|column| {
                (0..MASK_DEGREE + 1)
                    .map(|i| F((17 * column + 31 * i + 1) as u64))
                    .collect()
            })
            .collect()
    }
    fn alphas_v1() -> [E; LINK_COUNT_V1] {
        core::array::from_fn(|index| E::canonical([index as u64 + 1, 7, 11, 13]).unwrap())
    }
    fn cpu_adapter_v1(
        words: &mut [Vec<u64>],
        root: u64,
        direction: Direction,
    ) -> Result<Backend, TransformError> {
        assert_eq!(direction, Direction::Inverse);
        for column in words {
            let mut fields = column.iter().copied().map(F).collect::<Vec<_>>();
            goldilocks_ifft_v1(&mut fields, F(root)).unwrap();
            for (word, value) in column.iter_mut().zip(fields) {
                *word = value.0;
            }
        }
        Ok(Backend::Cpu)
    }
    fn policy_v1() -> main_bounded_transform::MainBoundedTransformPolicyV1 {
        main_bounded_transform::MainBoundedTransformPolicyV1::for_test_v1(1 << 19, 8)
    }
    fn oracle_v1(plan: &MainTerminalLinkPlanV1, masks: &[Vec<F>], alphas: &[E]) -> Vec<E> {
        let count = (1_usize
            << plan
                .links
                .iter()
                .flat_map(|link| [Some(link.left), link.right])
                .flatten()
                .map(|column| column.native_log2)
                .max()
                .unwrap())
            + MASK_DEGREE
            + 1;
        let mut output = vec![E::canonical([2, 3, 5, 7]).unwrap(); count - 1];
        plan.accumulate_with_v1(alphas, policy_v1(), &mut output, |column, _| {
            Ok(vec![ZeroizingMainTraceColumnV1(
                masked_trace_coefficients_with_mask_v1(
                    &native_v1(plan, column)[0],
                    column.native_log2,
                    &masks[column.column],
                )
                .unwrap(),
            )])
        })
        .unwrap();
        output
    }
    fn run_v1(
        plan: &MainTerminalLinkPlanV1,
        masks: &[Vec<F>],
        alphas: &[E],
        output: &mut Vec<E>,
    ) -> Result<(), ZkX509StarkErrorV1> {
        accumulate_with_v1(
            &plan.links,
            alphas,
            MASK_DEGREE + 1,
            policy_v1(),
            output,
            |column| Ok(native_v1(plan, column)),
            |column| Ok(&masks[column.column]),
            cpu_adapter_v1,
            || false,
        )
    }

    #[test]
    fn weighted_native_quotients_match_serial_masked_coefficients_for_mixed_domains_and_long_tails()
    {
        let masks = masks_v1();
        for logs in [[1, 2, 3], [2, 3, 4], [3, 4, 5]] {
            let plan = plan_v1(logs);
            let expected = oracle_v1(&plan, &masks, &alphas_v1());
            for threads in [1, 4] {
                let mut actual = vec![E::canonical([2, 3, 5, 7]).unwrap(); expected.len()];
                rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .unwrap()
                    .install(|| {
                        run_v1(&plan, &masks, &alphas_v1(), &mut actual).unwrap();
                    });
                assert_eq!(actual, expected, "logs {logs:?}, threads {threads}");
            }
        }
    }

    #[test]
    fn public_inverse_derivative_rows_match_independent_monomial_derivatives_at_every_native_point()
    {
        for log in 1..=6 {
            let rows = 1_usize << log;
            let root = goldilocks_primitive_root_v1(log).unwrap();
            for exponent in 0..rows {
                let point = root.pow(exponent as u128);
                let mut inverse = vec![F::ZERO; rows];
                let endpoint = inverse_table_v1(&mut inverse, root, point).unwrap();
                assert_eq!(endpoint, exponent);
                let ai = point.inv().unwrap();
                for degree in 0..rows {
                    let mut derivative = point
                        .pow(degree as u128)
                        .mul(F((rows - 1) as u64))
                        .mul(F(2).inv().unwrap())
                        .mul(ai);
                    let mut x = F::ONE;
                    for (row, value) in inverse.iter().copied().enumerate() {
                        if row == endpoint {
                            assert_eq!(value, F::ZERO);
                        } else {
                            assert_eq!(value.mul(x.sub(point)), F::ONE);
                            derivative =
                                derivative.sub(x.pow(degree as u128).mul(x).mul(value).mul(ai));
                        }
                        x = x.mul(root);
                    }
                    let expected = if degree == 0 {
                        F::ZERO
                    } else {
                        F(degree as u64).mul(point.pow((degree - 1) as u128))
                    };
                    assert_eq!(derivative, expected);
                }
            }
        }
        assert!(inverse_table_v1(&mut [], F::ONE, F::ONE).is_err());
        assert!(inverse_table_v1(&mut [F::ZERO; 4], F::ONE, F::ONE).is_err());
        assert!(
            inverse_table_v1(
                &mut [F::ZERO; 4],
                goldilocks_primitive_root_v1(2).unwrap(),
                F(7)
            )
            .is_err()
        );
    }

    #[test]
    fn weighted_masks_overlap_and_cancel_without_truncating_high_coefficients() {
        for rows in [2, 4, 8, 32] {
            for count in [1, rows - 1, rows + 5] {
                let mask = (0..count)
                    .map(|index| E::canonical([index as u64 + 1, 3, 5, 7]).unwrap())
                    .collect::<Vec<_>>();
                for point in [F::ONE, F::ZERO.sub(F::ONE)] {
                    let mut quotient = vec![E::ZERO; rows + count];
                    mask_quotient_v1(&mask, rows, point, &mut quotient).unwrap();
                    let mut reconstructed = vec![E::ZERO; rows + count + 1];
                    for (index, &value) in quotient.iter().enumerate() {
                        reconstructed[index] = reconstructed[index].sub(value.mul_base(point));
                        reconstructed[index + 1] = reconstructed[index + 1].add(value);
                    }
                    let mut expected = vec![E::ZERO; rows + count + 1];
                    for (index, &value) in mask.iter().enumerate() {
                        expected[index] = expected[index].sub(value);
                        expected[index + rows] = expected[index + rows].add(value);
                    }
                    assert_eq!(reconstructed, expected);
                    assert_eq!(quotient[rows + count - 1], E::ZERO);
                }
            }
        }
    }

    #[test]
    fn individual_endpoint_rejection_survives_zero_alphas_and_cancelling_link_mutations() {
        let plan = plan_v1([1, 2, 3]);
        let masks = masks_v1();
        for alphas in [[E::ZERO; LINK_COUNT_V1], [E::ONE; LINK_COUNT_V1]] {
            let mut output = vec![E::ONE; 8 + MASK_DEGREE];
            let before = output.clone();
            let result = accumulate_with_v1(
                &plan.links,
                &alphas,
                MASK_DEGREE + 1,
                policy_v1(),
                &mut output,
                |column| {
                    let mut values = native_v1(&plan, column);
                    // Opposite endpoint offsets on two left columns would cancel
                    // in a weighted remainder. Each individual equality must fail.
                    if column.column == 2 || column.column == 8 {
                        let delta = if column.column == 2 {
                            F::ONE
                        } else {
                            F::ZERO.sub(F::ONE)
                        };
                        for value in values[0].iter_mut() {
                            *value = value.add(delta);
                        }
                    }
                    Ok(values)
                },
                |column| Ok(&masks[column.column]),
                cpu_adapter_v1,
                || false,
            );
            assert_eq!(result, Err(ZkX509StarkErrorV1::ConstraintOpening));
            assert_eq!(output, before);
        }
    }

    #[test]
    fn shape_source_mask_completion_and_unwind_failures_preserve_chunk_and_clear_all_private_owners()
     {
        let plan = plan_v1([1, 2, 3]);
        let masks = masks_v1();
        for failure in 0..8 {
            let mut output = vec![E::ONE; 8 + MASK_DEGREE];
            let before = output.clone();
            let calls = std::cell::Cell::new(0);
            let transformed = std::cell::Cell::new(false);
            let (result, observations) = observe_v1(|| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    accumulate_with_v1(
                        &plan.links,
                        &alphas_v1(),
                        MASK_DEGREE + 1,
                        policy_v1(),
                        &mut output,
                        |column| {
                            calls.set(calls.get() + 1);
                            let mut values = native_v1(&plan, column);
                            if calls.get() == 3 {
                                match failure {
                                    0 => return Err(ZkX509StarkErrorV1::AllocationFailure),
                                    1 => {
                                        values[0].0.pop();
                                    }
                                    2 => values[0].0[0] = F(u64::MAX),
                                    3 => values.push(ZeroizingMainTraceColumnV1(vec![F::ONE; 2])),
                                    4 => panic!("injected terminal replay source unwind"),
                                    _ => {}
                                }
                            }
                            Ok(values)
                        },
                        |column| {
                            if failure == 5 && calls.get() == 3 {
                                Ok(&masks[column.column][1..])
                            } else {
                                Ok(&masks[column.column])
                            }
                        },
                        |words, root, direction| {
                            transformed.set(true);
                            if failure == 6 {
                                return Err(TransformError::DeviceUnavailable);
                            }
                            cpu_adapter_v1(words, root, direction)
                        },
                        || failure == 7 && transformed.get(),
                    )
                }))
            });
            if failure == 4 {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err(), "failure {failure}");
                assert_eq!(output, before);
            }
            assert!(observations.iter().any(|row| row.nonzero_before != 0));
            assert!(observations.iter().all(|row| row.nonzero_after == 0));
        }
    }

    #[test]
    fn every_allocation_boundary_refuses_atomically_and_clears_prior_allocations() {
        let plan = plan_v1([1, 2, 3]);
        let masks = masks_v1();
        let mut failures = 0;
        for index in 0..80 {
            let mut output = vec![E::ONE; 8 + MASK_DEGREE];
            let before = output.clone();
            let (result, observations) = observe_v1(|| {
                allocation_failure::at_v1(index, || {
                    run_v1(&plan, &masks, &alphas_v1(), &mut output)
                })
            });
            assert!(observations.iter().all(|row| row.nonzero_after == 0));
            if result.is_ok() {
                assert!(failures >= 28);
                break;
            }
            assert_eq!(result, Err(ZkX509StarkErrorV1::AllocationFailure));
            assert_eq!(output, before);
            failures += 1;
        }
        assert!(failures >= 28 && failures < 80);
        assert!(fields_v1(usize::MAX).is_err());
        assert!(extensions_v1(usize::MAX).is_err());
        assert!(payload_v1(usize::MAX, 1, 1).is_err());
    }

    #[test]
    fn replay_borrows_sampled_masks_without_consuming_next_blinding_entropy() {
        let plan = plan_v1([1, 2, 3]);
        let mut rng = StdRng::from_seed([93; 32]);
        let masks = (0..2 * LINK_COUNT_V1)
            .map(|_| sample_trace_mask_v1(MASK_DEGREE, &mut rng).unwrap())
            .collect::<Vec<_>>();
        let mut untouched = rng.clone();
        let mut actual = vec![E::ZERO; 8 + MASK_DEGREE];
        accumulate_with_v1(
            &plan.links,
            &alphas_v1(),
            MASK_DEGREE + 1,
            policy_v1(),
            &mut actual,
            |column| Ok(native_v1(&plan, column)),
            |column| Ok(masks[column.column].coefficients()),
            cpu_adapter_v1,
            || false,
        )
        .unwrap();
        // This is the exact next entropy cursor used by the unchanged caller's
        // canonical quotient blinding; no private mask is copied or resampled.
        for _ in 0..(6 - 1) * 137 * 4 {
            assert_eq!(rng.next_u64(), untouched.next_u64());
        }
    }

    #[test]
    fn full_domain_census_and_owner_plus_device_budget_fit_existing_admission() {
        let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
        let plan = MainTerminalLinkPlanV1::new_v1(&layout).unwrap();
        let mut groups = std::collections::BTreeMap::new();
        for link in plan.links {
            for column in [Some(link.left), link.right].into_iter().flatten() {
                *groups
                    .entry((column.native_log2, link.point.0))
                    .or_insert(0) += 1;
            }
        }
        assert_eq!(groups.len(), 7);
        assert_eq!(groups.values().sum::<usize>(), 364);
        assert_eq!(
            groups
                .keys()
                .map(|(log, _)| *log)
                .collect::<std::collections::BTreeSet<_>>(),
            [5, 8, 16, 19].into_iter().collect()
        );
        let payload = payload_v1(1 << 19, MASK_DEGREE + 1, LINK_COUNT_V1).unwrap();
        let independent =
            (12 * (1 << 19) + 384 + 4) * 8 + (2 * ((1 << 19) + 1816) + 1816) * 32 + 16 * 1024;
        assert_eq!(payload, independent);
        let policy = main_bounded_transform::MainBoundedTransformPolicyV1::for_assembly_v1(
            &layout,
            288_345_698,
        )
        .unwrap();
        let adjusted = policy.reserve_additional_v1(payload).unwrap();
        // Backend-independent resource admission is exercised even on CPU hosts.
        // The required four-column device payload remains below the free budget.
        adjusted.reserve_additional_v1(119_095_420).unwrap();
        assert!(policy.reserve_additional_v1(usize::MAX).is_err());
    }

    #[test]
    #[ignore = "requires actual Metal device; compare all four native sizes with CPU coefficients"]
    fn required_metal_four_native_domains_match_cpu_coefficients_without_entropy_changes() {
        assert_eq!(
            fastpq_prover::goldilocks_transform::available_goldilocks_transform_backend_v1(),
            Some(Backend::Metal)
        );
        for (log, endpoint_row) in [
            (5, 0),
            (8, 170),
            (16, 0),
            (16, 170 << 8),
            (19, 0),
            (19, (1 << 19) - 1),
            (19, 170 << 11),
        ] {
            let point = goldilocks_primitive_root_v1(log).unwrap().pow(endpoint_row);
            let left = ColumnV1 {
                group: 0,
                column: 0,
                native_log2: log,
            };
            let right = ColumnV1 { column: 1, ..left };
            let plan = MainTerminalLinkPlanV1 {
                links: [LinkV1 {
                    left,
                    right: Some(right),
                    point,
                }; LINK_COUNT_V1],
            };
            let masks = masks_v1();
            let rows = 1_usize << log;
            let alphas = [E::canonical([3, 5, 7, 11]).unwrap(); 1];
            let mut expected = vec![E::ZERO; rows + MASK_DEGREE];
            let mut actual = expected.clone();
            let mut device_columns = 0;
            for device in [false, true] {
                accumulate_with_v1(
                    &plan.links[..1],
                    &alphas,
                    MASK_DEGREE + 1,
                    main_bounded_transform::MainBoundedTransformPolicyV1::for_test_v1(1 << 19, 8),
                    if device { &mut actual } else { &mut expected },
                    |column| Ok(native_v1(&plan, column)),
                    |column| Ok(&masks[column.column]),
                    |words, root, direction| {
                        let backend = transform_goldilocks_columns_v1(
                            words,
                            root,
                            direction,
                            if device {
                                fastpq_prover::ExecutionMode::Gpu
                            } else {
                                fastpq_prover::ExecutionMode::Cpu
                            },
                        )?;
                        if device {
                            assert_eq!(backend, Backend::Metal);
                            device_columns += words.len();
                        }
                        Ok(backend)
                    },
                    goldilocks_transform_completion_uncertain_v1,
                )
                .unwrap();
            }
            assert_eq!(device_columns, 4);
            assert_eq!(actual, expected, "native log {log}");
            let mut difference =
                masked_trace_coefficients_with_mask_v1(&native_v1(&plan, left)[0], log, &masks[0])
                    .unwrap();
            let other =
                masked_trace_coefficients_with_mask_v1(&native_v1(&plan, right)[0], log, &masks[1])
                    .unwrap();
            for (left, right) in difference.iter_mut().zip(other) {
                *left = left.sub(right);
            }
            divide_linear_in_place_v1(&mut difference, point).unwrap();
            assert_eq!(
                actual,
                difference[..rows + MASK_DEGREE]
                    .iter()
                    .map(|value| alphas[0].mul_base(*value))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn malformed_public_admission_refuses_before_any_source_or_transform() {
        let masks = masks_v1();
        for variant in 0..6 {
            let mut plan = plan_v1([1, 2, 3]);
            let mut output = vec![E::ONE; 8 + MASK_DEGREE];
            let before = output.clone();
            let mut alphas = alphas_v1().to_vec();
            let mut policy = policy_v1();
            let mut count = MASK_DEGREE + 1;
            match variant {
                0 => {
                    alphas.pop();
                }
                1 => plan.links[0].left.native_log2 = u8::MAX,
                2 => plan.links[0].point = F(7),
                3 => policy = main_bounded_transform::MainBoundedTransformPolicyV1::cpu_v1(),
                4 => count = 0,
                _ => {
                    output = vec![E::ONE];
                }
            }
            let previous = if variant == 5 { output.clone() } else { before };
            let result = accumulate_with_v1(
                &plan.links,
                &alphas,
                count,
                policy,
                &mut output,
                |_| panic!("invalid public admission must not replay"),
                |column| Ok(&masks[column.column]),
                |_, _, _| panic!("invalid public admission must not dispatch"),
                || false,
            );
            assert!(result.is_err());
            assert_eq!(output, previous);
        }
    }

    #[test]
    fn funded_cpu_fallback_matches_serial_without_device_dispatch() {
        let plan = plan_v1([1, 2, 3]);
        let masks = masks_v1();
        let expected = oracle_v1(&plan, &masks, &alphas_v1());
        let mut actual = vec![E::canonical([2, 3, 5, 7]).unwrap(); expected.len()];
        // This policy funds private owners but, after their reservation, cannot
        // fit even the minimum complete Metal pool/table allowance. CPU runs
        // on the already admitted four F columns with the same exact result.
        let policy = main_bounded_transform::MainBoundedTransformPolicyV1::for_test_v1(32, 1);
        let adjusted = policy
            .reserve_additional_v1(payload_v1(8, MASK_DEGREE + 1, LINK_COUNT_V1).unwrap())
            .unwrap();
        assert_eq!(adjusted.columns_v1(8), 0);
        accumulate_with_v1(
            &plan.links,
            &alphas_v1(),
            MASK_DEGREE + 1,
            policy,
            &mut actual,
            |column| Ok(native_v1(&plan, column)),
            |column| Ok(&masks[column.column]),
            |_, _, _| panic!("CPU fallback must not dispatch device"),
            || false,
        )
        .unwrap();
        assert_eq!(actual, expected);
    }
}

#[cfg(test)]
mod family_batch_tests {
    //! Ordered, clearing-owned family replay controls.
    include!("main_terminal_family_batch_tests.rs");
}
