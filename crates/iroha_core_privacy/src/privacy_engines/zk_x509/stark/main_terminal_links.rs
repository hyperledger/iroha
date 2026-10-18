//! Private cross-registration endpoints enforced by linear polynomial quotients.
//!
//! The closed verifier plan selects existing masked auxiliary columns. Equality
//! is required at one native point, never between independently masked entire
//! polynomials. No terminal value enters the public proof or transcript.

#[cfg(any(test, feature = "privacy-release-evidence"))]
use super::super::super::private_table::{PrivateTableV1, zeroize_fields_v1};
use super::*;

const LINK_DOMAIN_V1: &[u8] = b"iroha:privacy:zk-x509:main-private-terminal-links:v1";
const LINK_DESCRIPTOR_V1: &[u8] = b"der-rfc8:p256-buses80:p256-chain104:native19-last,one,native8-row170:linear-quotient:original-independent-masks";
pub(super) const LINK_COUNT_V1: usize = 192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ColumnV1 {
    group: usize,
    column: usize,
    native_log2: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinkV1 {
    left: ColumnV1,
    right: Option<ColumnV1>,
    point: F,
}

/// Exact public registration/column plan; private endpoints are never fields.
pub(super) struct MainTerminalLinkPlanV1 {
    links: [LinkV1; LINK_COUNT_V1],
}

impl MainTerminalLinkPlanV1 {
    /// Conservative public stack/heap charge retained during all MAIN device phases.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(super) const fn public_owner_charge_v1() -> usize {
        3 * core::mem::size_of::<Self>()
            + 64
            + core::mem::size_of::<Vec<E>>()
            + LINK_COUNT_V1 * core::mem::size_of::<E>()
    }

    pub(super) fn new_v1(layout: &AggregateProofLayoutV1) -> Result<Self, ZkX509StarkErrorV1> {
        use super::super::super::p256_aggregate_adapter::{
            P256PrivateLinkFamilyV1 as Family, p256_private_link_columns_v1,
        };
        layout.validate_exact_full_profile_registration_v1()?;
        let public_registration = |adapter| {
            let mut found = layout
                .registered_segments
                .iter()
                .copied()
                .filter(|item| item.segment.adapter == adapter && item.segment.instance == 0);
            let result = found.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
            if found.next().is_some() || result.segment.trace_log2 != 19 {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            Ok(result)
        };
        let column = |registration: RegisteredSegmentLayoutV1, local: usize| {
            if local >= registration.segment.aux_width {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            Ok(ColumnV1 {
                group: registration.trace_group,
                column: registration
                    .aux_start
                    .checked_add(local)
                    .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?,
                native_log2: registration.segment.trace_log2,
            })
        };
        let p256 = |signature, adapter, local, family| {
            let identity = P256MainRegistrationV1::new_v1(signature, adapter, local)?;
            let mut found = layout
                .registered_segments
                .iter()
                .copied()
                .filter(|registration| {
                    p256_main_registration_from_main_layout_v1(*registration).ok() == Some(identity)
                });
            let registration = found.next().ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
            if found.next().is_some() {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            let columns = p256_private_link_columns_v1(identity, family)?;
            let mut resolved = [column(registration, columns[0])?; 4];
            for lane in 1..4 {
                resolved[lane] = column(registration, columns[lane])?;
            }
            Ok::<[ColumnV1; 4], ZkX509StarkErrorV1>(resolved)
        };
        let der = public_registration(SegmentAdapterIdV1::StrictDer)?;
        let rfc = public_registration(SegmentAdapterIdV1::Rfc5280)?;
        let der_columns = super::super::super::der_stark::zk_x509_der_terminal_columns_v1();
        let rfc_columns = super::super::super::rfc5280_stark::zk_x509_rfc_der_terminal_columns_v1();
        let last = goldilocks_primitive_root_v1(19)
            .map_err(map_transparent_error_v1)?
            .pow((1_u128 << 19) - 1);
        let scalar = goldilocks_primitive_root_v1(8)
            .map_err(map_transparent_error_v1)?
            .pow(170);
        let dummy = LinkV1 {
            left: column(der, der_columns[0])?,
            right: None,
            point: F::ONE,
        };
        let mut links = [dummy; LINK_COUNT_V1];
        let mut cursor = 0;
        let mut push = |left: ColumnV1, right: Option<ColumnV1>, point: F| {
            for endpoint in [Some(left), right].into_iter().flatten() {
                if point.pow(1_u128 << endpoint.native_log2) != F::ONE {
                    return Err(ZkX509StarkErrorV1::ProfileMismatch);
                }
            }
            *links
                .get_mut(cursor)
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)? = LinkV1 { left, right, point };
            cursor += 1;
            Ok(())
        };
        for index in 0..8 {
            push(
                column(der, der_columns[index])?,
                Some(column(rfc, rfc_columns[index])?),
                last,
            )?;
        }
        for signature in 0..P256_SIGNATURE_COUNT_V1 {
            use P256MainAdapterV1 as Adapter;
            for (
                left_adapter,
                left_local,
                left_family,
                right_adapter,
                right_local,
                right_family,
                point,
            ) in [
                (
                    Adapter::ValueBus,
                    0,
                    Family::Value,
                    Adapter::ValueBus,
                    1,
                    Family::Value,
                    last,
                ),
                (
                    Adapter::ValueBus,
                    0,
                    Family::Copy,
                    Adapter::Arithmetic,
                    0,
                    Family::Copy,
                    F::ONE,
                ),
                (
                    Adapter::Arithmetic,
                    0,
                    Family::ArithmeticScalar,
                    Adapter::ScalarBitBus,
                    0,
                    Family::ArithmeticScalar,
                    scalar,
                ),
                (
                    Adapter::WindowBatch,
                    0,
                    Family::WindowScalar,
                    Adapter::ScalarBitBus,
                    0,
                    Family::WindowScalar,
                    scalar,
                ),
            ] {
                let left = p256(signature, left_adapter, left_local, left_family)?;
                let right = p256(signature, right_adapter, right_local, right_family)?;
                for lane in 0..4 {
                    push(left[lane], Some(right[lane]), point)?;
                }
            }
            let writer = p256(signature, Adapter::ValueBus, 0, Family::ChainStart)?;
            for endpoint in writer {
                push(endpoint, None, F::ONE)?;
            }
            let mut previous = p256(signature, Adapter::ValueBus, 0, Family::ChainTerminal)?;
            let sources = [
                (Adapter::WindowBatch, 0),
                (Adapter::Reduction, 0),
                (Adapter::Reduction, 1),
                (Adapter::WalletLowS, 0),
            ];
            let count = if signature == P256_SIGNATURE_COUNT_V1 - 1 {
                4
            } else {
                3
            };
            for &(adapter, local) in &sources[..count] {
                let start = p256(signature, adapter, local, Family::ChainStart)?;
                for lane in 0..4 {
                    push(start[lane], Some(previous[lane]), F::ONE)?;
                }
                previous = p256(signature, adapter, local, Family::ChainTerminal)?;
            }
            let sink = p256(signature, Adapter::BindingSink, 0, Family::ChainTerminal)?;
            for lane in 0..4 {
                push(previous[lane], Some(sink[lane]), F::ONE)?;
            }
        }
        if cursor != LINK_COUNT_V1 {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        Ok(Self { links })
    }

    /// Derive one extension-field coefficient per ordered link after auxiliary roots.
    pub(super) fn derive_alphas_v1(
        &self,
        transcript: &mut TransparentTranscriptV1,
    ) -> Result<Vec<E>, ZkX509StarkErrorV1> {
        transcript
            .absorb(LINK_DOMAIN_V1, &[LINK_DESCRIPTOR_V1])
            .map_err(map_transparent_error_v1)?;
        for link in self.links {
            let mut record = [0_u8; 44];
            for (position, endpoint) in [Some(link.left), link.right].into_iter().enumerate() {
                let offset = position * 17;
                if let Some(column) = endpoint {
                    record[offset] = 1;
                    record[offset + 1..offset + 9]
                        .copy_from_slice(&(column.group as u64).to_be_bytes());
                    record[offset + 9..offset + 17]
                        .copy_from_slice(&(column.column as u64).to_be_bytes());
                }
            }
            record[34..42].copy_from_slice(&link.point.0.to_be_bytes());
            record[42] = link.left.native_log2;
            record[43] = link.right.map_or(0, |column| column.native_log2);
            transcript
                .absorb(LINK_DOMAIN_V1, &[&record])
                .map_err(map_transparent_error_v1)?;
        }
        // A fallible iterator collect may grow beyond the exact public owner
        // charge. Reserve the entire bounded vector before the first draw.
        let mut alphas = Vec::new();
        alphas
            .try_reserve_exact(LINK_COUNT_V1)
            .map_err(|_| ZkX509StarkErrorV1::ProofTooLarge)?;
        if alphas.capacity() != LINK_COUNT_V1 {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        for _ in &self.links {
            alphas.push(
                transcript
                    .challenge_fp4(LINK_DOMAIN_V1)
                    .map_err(map_transparent_error_v1)?,
            );
        }
        Ok(alphas)
    }

    /// Evaluate exactly the same quotients from authenticated current OOD values.
    pub(super) fn evaluate_v1(
        &self,
        groups: &[aggregate::AggregateOpenedDeepTraceGroupV1],
        point: E,
        alphas: &[E],
    ) -> Result<E, ZkX509StarkErrorV1> {
        self.evaluate_with_v1(point, alphas, |column| {
            groups
                .get(column.group)
                .and_then(|group| group.aux_current.get(column.column))
                .copied()
                .ok_or(ZkX509StarkErrorV1::ConstraintOpening)
        })
    }
    #[cfg(test)]
    pub(super) fn evaluate_base_v1(
        &self,
        groups: &[aggregate::AggregateOpenedTraceGroupV1],
        point: F,
        alphas: &[E],
    ) -> Result<E, ZkX509StarkErrorV1> {
        if !point.is_canonical() {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        self.evaluate_with_v1(E::from_base(point), alphas, |column| {
            let value = groups
                .get(column.group)
                .and_then(|group| group.aux_current.get(column.column))
                .copied()
                .ok_or(ZkX509StarkErrorV1::ConstraintOpening)?;
            if !value.is_canonical() {
                return Err(ZkX509StarkErrorV1::ConstraintOpening);
            }
            Ok(E::from_base(value))
        })
    }
    fn evaluate_with_v1(
        &self,
        point: E,
        alphas: &[E],
        value: impl Fn(ColumnV1) -> Result<E, ZkX509StarkErrorV1>,
    ) -> Result<E, ZkX509StarkErrorV1> {
        if !point.is_canonical()
            || alphas.len() != self.links.len()
            || alphas.iter().any(|alpha| !alpha.is_canonical())
        {
            return Err(ZkX509StarkErrorV1::ConstraintOpening);
        }
        self.links
            .iter()
            .zip(alphas)
            .try_fold(E::ZERO, |sum, (link, alpha)| {
                let left = value(link.left)?;
                let right = link.right.map(&value).transpose()?.unwrap_or(E::ONE);
                if !left.is_canonical() || !right.is_canonical() {
                    return Err(ZkX509StarkErrorV1::ConstraintOpening);
                }
                let inverse = point
                    .sub(E::from_base(link.point))
                    .inv()
                    .ok_or(ZkX509StarkErrorV1::ConstraintOpening)?;
                Ok(sum.add(alpha.mul(left.sub(right)).mul(inverse)))
            })
    }

    /// Recheck the exact canonical endpoints through real native-column custody.
    /// Test-only: the proof path uses original masked coefficients above the domain.
    #[cfg(test)]
    pub(super) fn check_native_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
    ) -> Result<usize, ZkX509StarkErrorV1> {
        let value = |column: ColumnV1, point: F| {
            let root = goldilocks_primitive_root_v1(column.native_log2)
                .map_err(map_transparent_error_v1)?;
            let rows = 1_usize << column.native_log2;
            // Public points only. Exact traversal avoids assuming a coordinate
            // convention when a scalar row is embedded in a larger subgroup.
            let mut x = F::ONE;
            let row = (0..rows)
                .find(|_| {
                    let found = x == point;
                    x = x.mul(root);
                    found
                })
                .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
            let values = sources.native_columns_v1(
                layout,
                MainTraceColumnKindV1::Aux,
                column.group,
                column.column..column.column + 1,
            )?;
            if values.len() != 1 || values[0].len() != rows {
                return Err(ZkX509StarkErrorV1::ProfileMismatch);
            }
            Ok::<F, ZkX509StarkErrorV1>(values[0][row])
        };
        for link in self.links {
            let left = value(link.left, link.point)?;
            let right = link
                .right
                .map(|column| value(column, link.point))
                .transpose()?
                .unwrap_or(F::ONE);
            if left != right {
                return Err(ZkX509StarkErrorV1::ConstraintOpening);
            }
        }
        Ok(self.links.len())
    }

    /// Accumulate the same masked linear quotients with four native-domain transforms.
    /// Original masks and the transcript are unchanged; no entropy is sampled here.
    #[cfg(any(test, feature = "privacy-release-evidence"))]
    pub(super) fn accumulate_v1(
        &self,
        layout: &AggregateProofLayoutV1,
        polynomials: &MainTracePolynomialSetV1,
        sources: &MainTraceReplaySourcesV1<'_, '_>,
        alphas: &[E],
        policy: main_bounded_transform::MainBoundedTransformPolicyV1,
        chunk: &mut Vec<E>,
    ) -> Result<(), ZkX509StarkErrorV1> {
        weighted_replay::accumulate_v1(self, layout, polynomials, sources, alphas, policy, chunk)
    }

    /// Serial original-mask replay retained only as the exact coefficient test oracle.
    #[cfg(test)]
    fn accumulate_with_v1(
        &self,
        alphas: &[E],
        policy: main_bounded_transform::MainBoundedTransformPolicyV1,
        chunk: &mut Vec<E>,
        mut replay_column: impl FnMut(
            ColumnV1,
            main_bounded_transform::MainBoundedTransformPolicyV1,
        )
            -> Result<Vec<ZeroizingMainTraceColumnV1>, ZkX509StarkErrorV1>,
    ) -> Result<(), ZkX509StarkErrorV1> {
        if alphas.len() != self.links.len() || alphas.iter().any(|value| !value.is_canonical()) {
            return Err(ZkX509StarkErrorV1::ProfileMismatch);
        }
        let native_log2 = self
            .links
            .iter()
            .flat_map(|link| [Some(link.left), link.right])
            .flatten()
            .map(|column| column.native_log2)
            .max()
            .ok_or(ZkX509StarkErrorV1::ProfileMismatch)?;
        let coefficient_count = 1_usize
            .checked_shl(u32::from(native_log2))
            .and_then(|count| count.checked_add(MASK_DEGREE + 1))
            .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?;
        let payload = coefficient_count
            .checked_mul(2 * core::mem::size_of::<F>())
            .and_then(|n| n.checked_add(2 * core::mem::size_of::<PrivateTableV1<F>>()))
            .and_then(|n| n.checked_add(core::mem::size_of::<Vec<ZeroizingMainTraceColumnV1>>()))
            .and_then(|n| n.checked_add(core::mem::size_of::<ZeroizingMainTraceColumnV1>()))
            .ok_or(ZkX509StarkErrorV1::ProofTooLarge)?;
        let policy = policy.reserve_additional_v1(payload)?;
        if chunk.capacity() < coefficient_count - 1 || chunk.len() > chunk.capacity() {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        if chunk.len() < coefficient_count - 1 {
            chunk.resize(coefficient_count - 1, E::ZERO);
        }
        let mut difference = PrivateTableV1::new(Vec::new(), zeroize_fields_v1);
        difference
            .try_reserve_exact(coefficient_count)
            .map_err(|_| ZkX509StarkErrorV1::AllocationFailure)?;
        if difference.capacity() != coefficient_count {
            return Err(ZkX509StarkErrorV1::ProofTooLarge);
        }
        difference.resize(coefficient_count, F::ZERO);
        for (link, alpha) in self.links.iter().zip(alphas) {
            main_bounded_transform::check_completion_v1(
                fastpq_prover::goldilocks_transform::goldilocks_transform_completion_uncertain_v1(),
            )?;
            difference.fill(F::ZERO);
            if link.right.is_none() {
                difference[0] = F::ZERO.sub(F::ONE);
            }
            for (column, subtract) in [(Some(link.left), false), (link.right, true)] {
                let Some(column) = column else {
                    continue;
                };
                let replay = replay_column(column, policy)?;
                if replay.len() != 1
                    || replay.capacity() != 1
                    || replay[0].len() != (1_usize << column.native_log2) + MASK_DEGREE + 1
                    || replay[0].0.capacity() != replay[0].len()
                    || replay[0].len() > difference.len()
                {
                    return Err(ZkX509StarkErrorV1::ProofTooLarge);
                }
                if replay[0].iter().any(|value| !value.is_canonical()) {
                    return Err(ZkX509StarkErrorV1::NonCanonicalField);
                }
                for (target, value) in difference.iter_mut().zip(replay[0].iter()) {
                    *target = if subtract {
                        target.sub(*value)
                    } else {
                        target.add(*value)
                    };
                }
                // Each replay owner drops before constructing the other side.
            }
            divide_linear_in_place_v1(&mut difference, link.point)?;
            for (target, coefficient) in chunk.iter_mut().zip(difference.iter()) {
                *target = target.add(alpha.mul_base(*coefficient));
            }
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
mod weighted_replay {
    include!("main_terminal_weighted.rs");
}

/// Replace coefficients with the quotient and a final zero; reject nonzero remainder.
#[cfg(test)]
fn divide_linear_in_place_v1(coefficients: &mut [F], point: F) -> Result<(), ZkX509StarkErrorV1> {
    if coefficients.is_empty()
        || !point.is_canonical()
        || coefficients
            .iter()
            .any(|coefficient| !coefficient.is_canonical())
    {
        return Err(ZkX509StarkErrorV1::ProfileMismatch);
    }
    let last = coefficients.len() - 1;
    let mut carry = coefficients[last];
    coefficients[last] = F::ZERO;
    for index in (0..last).rev() {
        let previous = coefficients[index];
        coefficients[index] = carry;
        carry = previous.add(point.mul(carry));
    }
    if carry != F::ZERO {
        return Err(ZkX509StarkErrorV1::ConstraintOpening);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_division_preserves_exact_high_coefficients_and_zero_endpoint() {
        for point in [F::ZERO, F::ONE, F(7)] {
            let expected = [F(3), F(5), F::ZERO, F(11), F(13)];
            let mut coefficients = vec![F::ZERO; expected.len() + 1];
            for (index, coefficient) in expected.iter().copied().enumerate() {
                coefficients[index] = coefficients[index].sub(point.mul(coefficient));
                coefficients[index + 1] = coefficients[index + 1].add(coefficient);
            }
            divide_linear_in_place_v1(&mut coefficients, point).unwrap();
            assert_eq!(&coefficients[..expected.len()], &expected);
            assert_eq!(coefficients[expected.len()], F::ZERO);
        }
    }

    #[test]
    fn linear_division_rejects_nonzero_remainder_empty_and_noncanonical() {
        assert!(divide_linear_in_place_v1(&mut [], F::ONE).is_err());
        assert!(divide_linear_in_place_v1(&mut [F::ONE], F::ONE).is_err());
        assert!(divide_linear_in_place_v1(&mut [F(u64::MAX)], F::ONE).is_err());
        assert!(divide_linear_in_place_v1(&mut [F::ZERO], F(u64::MAX)).is_err());
        assert_eq!(divide_linear_in_place_v1(&mut [F::ZERO], F::ONE), Ok(()));
    }
    #[test]
    fn canonical_plan_covers_192_links_364_replays_and_exact_native_coordinates() {
        let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
        let plan = MainTerminalLinkPlanV1::new_v1(&layout).unwrap();
        let mut points = std::collections::BTreeMap::new();
        let mut native_counts = std::collections::BTreeMap::new();
        let mut pairs = std::collections::BTreeSet::new();
        let mut constants = 0;
        for link in plan.links {
            *points.entry(link.point.0).or_insert(0) += 1;
            constants += usize::from(link.right.is_none());
            assert!(pairs.insert((
                link.left.group,
                link.left.column,
                link.right.map(|right| (right.group, right.column)),
                link.point.0
            )));
            for column in [Some(link.left), link.right].into_iter().flatten() {
                *native_counts.entry(column.native_log2).or_insert(0) += 1;
                assert_eq!(link.point.pow(1_u128 << column.native_log2), F::ONE);
                let owners = layout
                    .registered_segments
                    .iter()
                    .filter(|owner| {
                        owner.trace_group == column.group
                            && owner.aux_start <= column.column
                            && column.column < owner.aux_end().unwrap()
                    })
                    .collect::<Vec<_>>();
                assert_eq!(owners.len(), 1);
                assert_eq!(owners[0].segment.trace_log2, column.native_log2);
            }
        }
        let root19 = goldilocks_primitive_root_v1(19).unwrap();
        let scalar = goldilocks_primitive_root_v1(8).unwrap().pow(170);
        assert_eq!(
            points,
            std::collections::BTreeMap::from([
                (F::ONE.0, 124),
                (root19.pow((1 << 19) - 1).0, 28),
                (scalar.0, 40),
            ])
        );
        assert_eq!(
            native_counts,
            std::collections::BTreeMap::from([(5, 88), (8, 40), (16, 80), (19, 156)])
        );
        assert_eq!(constants, 20);
        assert_eq!(native_counts.values().sum::<usize>(), 364);
        for log in [8, 16, 19] {
            assert_eq!(
                goldilocks_primitive_root_v1(log)
                    .unwrap()
                    .pow(170_u128 << (log - 8)),
                scalar
            );
        }
        let mut wrong = layout.clone();
        wrong.registered_segments.swap(0, 1);
        assert!(MainTerminalLinkPlanV1::new_v1(&wrong).is_err());
        let mut wrong = layout;
        wrong.registered_segments[0].segment.aux_width += 1;
        assert!(MainTerminalLinkPlanV1::new_v1(&wrong).is_err());
    }

    #[test]
    fn every_join_uses_authenticated_values_and_preserves_zero_endpoints() {
        let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
        let plan = MainTerminalLinkPlanV1::new_v1(&layout).unwrap();
        let z = E::from_base(F(7));
        let roots = [
            F::ONE,
            goldilocks_primitive_root_v1(19).unwrap().pow((1 << 19) - 1),
            goldilocks_primitive_root_v1(8).unwrap().pow(170),
        ];
        let vanishing = roots.into_iter().fold(E::ONE, |product, root| {
            product.mul(z.sub(E::from_base(root)))
        });
        let slope = |column: ColumnV1| {
            E::from_base(F(1 + column.group as u64 * 100_000 + column.column as u64))
        };
        for (index, link) in plan.links.iter().enumerate() {
            let mut alphas = [E::ZERO; LINK_COUNT_V1];
            alphas[index] = E::ONE;
            let inverse = z.sub(E::from_base(link.point)).inv().unwrap();
            let expected = slope(link.left)
                .sub(link.right.map(&slope).unwrap_or(E::ZERO))
                .mul(vanishing)
                .mul(inverse);
            assert_eq!(
                plan.evaluate_with_v1(z, &alphas, |column| Ok(
                    E::ONE.add(slope(column).mul(vanishing))
                ))
                .unwrap(),
                expected
            );
            let changed = plan
                .evaluate_with_v1(z, &alphas, |column| {
                    Ok(E::ONE
                        .add(slope(column).mul(vanishing))
                        .add(if column == link.left { E::ONE } else { E::ZERO }))
                })
                .unwrap();
            assert_eq!(changed, expected.add(inverse), "one-sided link {index}");
            if link.right.is_some() {
                assert_eq!(
                    plan.evaluate_with_v1(z, &alphas, |_| Ok(E::ZERO)).unwrap(),
                    E::ZERO,
                    "zero products remain legal; no private inverse for link {index}"
                );
            }
        }
    }

    #[test]
    fn link_ood_validation_rejects_missing_noncanonical_and_singular_inputs() {
        let plan =
            MainTerminalLinkPlanV1::new_v1(&AggregateProofLayoutV1::for_full_profile_v1().unwrap())
                .unwrap();
        let alphas = [E::ONE; LINK_COUNT_V1];
        let calls = std::cell::Cell::new(0);
        let value = |_| {
            calls.set(calls.get() + 1);
            Ok(E::ONE)
        };
        assert!(
            plan.evaluate_with_v1(E::from_base(F(7)), &alphas[..191], value)
                .is_err()
        );
        assert_eq!(calls.get(), 0);
        let mut malformed = alphas;
        malformed[191] = E::noncanonical_fixture_v1();
        assert!(
            plan.evaluate_with_v1(E::from_base(F(7)), &malformed, |_| Ok(E::ONE))
                .is_err()
        );
        assert!(
            plan.evaluate_with_v1(E::noncanonical_fixture_v1(), &alphas, |_| Ok(E::ONE))
                .is_err()
        );
        assert!(
            plan.evaluate_with_v1(E::from_base(F(7)), &alphas, |_| Ok(
                E::noncanonical_fixture_v1()
            ))
            .is_err()
        );
        assert!(plan.evaluate_v1(&[], E::from_base(F(7)), &alphas).is_err());
        assert!(plan.evaluate_base_v1(&[], F(7), &alphas).is_err());
        let base_plan = small_plan_v1();
        let mut base_groups = [aggregate::AggregateOpenedTraceGroupV1 {
            base_current: Vec::new(),
            base_next: Vec::new(),
            aux_current: vec![F::ONE; 2],
            aux_next: Vec::new(),
        }];
        assert_eq!(
            base_plan.evaluate_base_v1(&base_groups, F(7), &alphas),
            Ok(E::ZERO)
        );
        assert_eq!(
            base_plan.evaluate_base_v1(&base_groups, F(u64::MAX), &alphas),
            Err(ZkX509StarkErrorV1::ConstraintOpening)
        );
        base_groups[0].aux_current[0] = F(u64::MAX);
        assert_eq!(
            base_plan.evaluate_base_v1(&base_groups, F(7), &alphas),
            Err(ZkX509StarkErrorV1::ConstraintOpening)
        );
        for point in plan
            .links
            .iter()
            .map(|link| link.point.0)
            .collect::<std::collections::BTreeSet<_>>()
        {
            assert!(
                plan.evaluate_with_v1(E::from_base(F(point)), &alphas, |_| Ok(E::ONE))
                    .is_err()
            );
        }
    }

    #[test]
    fn transcript_binds_link_order_columns_points_and_both_native_geometries() {
        let layout = AggregateProofLayoutV1::for_full_profile_v1().unwrap();
        let base = || {
            new_main_transcript_after_profile_validation_v1(
                TEST_PROOF_INSTANCE_V1,
                &[7; 32],
                [8; 32],
            )
            .unwrap()
        };
        let expected = MainTerminalLinkPlanV1::new_v1(&layout)
            .unwrap()
            .derive_alphas_v1(&mut base())
            .unwrap();
        assert_eq!(expected.len(), LINK_COUNT_V1);
        assert_eq!(expected.capacity(), LINK_COUNT_V1);
        assert_eq!(
            expected,
            MainTerminalLinkPlanV1::new_v1(&layout)
                .unwrap()
                .derive_alphas_v1(&mut base())
                .unwrap()
        );
        for variant in 0..5 {
            let mut plan = MainTerminalLinkPlanV1::new_v1(&layout).unwrap();
            match variant {
                0 => plan.links.swap(0, 1),
                1 => plan.links[0].left.column += 1,
                2 => plan.links[0].point = F::ONE,
                3 => plan.links[0].left.native_log2 -= 1,
                _ => plan.links[0].right.as_mut().unwrap().native_log2 -= 1,
            }
            assert_ne!(plan.derive_alphas_v1(&mut base()).unwrap(), expected);
        }
    }

    #[test]
    fn terminal_challenges_match_serial_transcript_and_exact_owner_capacity() {
        let plan =
            MainTerminalLinkPlanV1::new_v1(&AggregateProofLayoutV1::for_full_profile_v1().unwrap())
                .unwrap();
        let mut actual_transcript = new_main_transcript_after_profile_validation_v1(
            TEST_PROOF_INSTANCE_V1,
            &[7; 32],
            [8; 32],
        )
        .unwrap();
        let mut reference = actual_transcript;
        reference
            .absorb(LINK_DOMAIN_V1, &[LINK_DESCRIPTOR_V1])
            .unwrap();
        for link in &plan.links {
            // Independent field-by-field encoder of the fixed44-byte record.
            let mut record = Vec::new();
            for endpoint in [Some(link.left), link.right] {
                match endpoint {
                    Some(column) => {
                        record.push(1);
                        record.extend_from_slice(&(column.group as u64).to_be_bytes());
                        record.extend_from_slice(&(column.column as u64).to_be_bytes());
                    }
                    None => record.extend_from_slice(&[0; 17]),
                }
            }
            record.extend_from_slice(&link.point.0.to_be_bytes());
            record.push(link.left.native_log2);
            record.push(link.right.map_or(0, |column| column.native_log2));
            assert_eq!(record.len(), 44);
            reference.absorb(LINK_DOMAIN_V1, &[&record]).unwrap();
        }
        let expected = challenge_vector_v1(&mut reference, LINK_DOMAIN_V1, LINK_COUNT_V1).unwrap();
        let actual = plan.derive_alphas_v1(&mut actual_transcript).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), LINK_COUNT_V1);
        assert_eq!(actual.capacity(), LINK_COUNT_V1);
        assert_eq!(actual.capacity() * core::mem::size_of::<E>(), 192 * 32);
        assert_eq!(
            actual_transcript
                .challenge_fp4(b"after-terminal-links")
                .unwrap(),
            reference.challenge_fp4(b"after-terminal-links").unwrap(),
        );
    }
    fn small_plan_v1() -> MainTerminalLinkPlanV1 {
        let left = ColumnV1 {
            group: 0,
            column: 0,
            native_log2: 1,
        };
        MainTerminalLinkPlanV1 {
            links: [LinkV1 {
                left,
                right: Some(ColumnV1 { column: 1, ..left }),
                point: F::ONE,
            }; LINK_COUNT_V1],
        }
    }
    fn fixture_replay_v1(column: ColumnV1) -> Vec<ZeroizingMainTraceColumnV1> {
        let count = (1 << column.native_log2) + MASK_DEGREE + 1;
        let mut coefficients = vec![F::ZERO; count];
        coefficients[0] = F(11);
        if column.column == 0 {
            coefficients[count - 1] = F::ONE;
            coefficients[count - 2] = F::ZERO.sub(F::ONE);
        }
        vec![ZeroizingMainTraceColumnV1(coefficients)]
    }

    #[test]
    fn serial_replay_keeps_high_mask_coefficients_and_clears_private_owners() {
        use crate::privacy_engines::zk_x509::private_table::inspection::observe_v1;
        let count = 2 + MASK_DEGREE + 1;
        let mut chunk = Vec::with_capacity(count - 1);
        let mut alphas = [E::ZERO; LINK_COUNT_V1];
        alphas[0] = E::ONE;
        let mut order = Vec::new();
        let (result, erased) = observe_v1(|| {
            small_plan_v1().accumulate_with_v1(
                &alphas,
                main_bounded_transform::MainBoundedTransformPolicyV1::for_test_v1(1 << 19, 8),
                &mut chunk,
                |column, _| {
                    order.push(column.column);
                    Ok(fixture_replay_v1(column))
                },
            )
        });
        result.unwrap();
        assert_eq!(chunk.len(), count - 1);
        assert!(chunk[..count - 2].iter().all(|value| *value == E::ZERO));
        assert_eq!(
            chunk[count - 2],
            E::ONE,
            "above native degree masked tail retained"
        );
        assert_eq!(order, [0, 1].repeat(LINK_COUNT_V1));
        assert_eq!(erased.len(), 2 * LINK_COUNT_V1 + 1);
        assert!(
            erased
                .iter()
                .all(|record| record.cells == count && record.nonzero_after == 0)
        );
        assert!(erased.iter().any(|record| record.nonzero_before != 0));
    }

    #[test]
    fn replay_rejects_bad_shape_nonzero_remainder_partial_error_and_clears() {
        use crate::privacy_engines::zk_x509::private_table::inspection::observe_v1;
        let count = 2 + MASK_DEGREE + 1;
        for failure in 0..5 {
            let mut chunk = Vec::with_capacity(count - 1);
            let mut calls = 0;
            let (result, erased) = observe_v1(|| {
                small_plan_v1().accumulate_with_v1(
                    &[E::ONE; LINK_COUNT_V1],
                    main_bounded_transform::MainBoundedTransformPolicyV1::for_test_v1(1 << 19, 8),
                    &mut chunk,
                    |column, _| {
                        calls += 1;
                        let mut output = fixture_replay_v1(column);
                        if calls == 2 {
                            match failure {
                                0 => return Err(ZkX509StarkErrorV1::AllocationFailure),
                                1 => {
                                    output[0].0.pop();
                                }
                                2 => output[0].0[0] = F(12),
                                3 => output[0].0[0] = F(u64::MAX),
                                _ => {
                                    output.push(ZeroizingMainTraceColumnV1(vec![F(9); count]));
                                }
                            }
                        }
                        Ok(output)
                    },
                )
            });
            assert!(result.is_err(), "failure {failure}");
            assert_eq!(calls, 2, "stop further private replay");
            assert!(erased.iter().any(|record| record.nonzero_before != 0));
            assert!(erased.iter().all(|record| record.nonzero_after == 0));
        }
    }

    #[test]
    fn link_resource_and_shape_admission_precedes_replay() {
        let plan = small_plan_v1();
        let count = 2 + MASK_DEGREE + 1;
        let policy = main_bounded_transform::MainBoundedTransformPolicyV1::for_test_v1(1 << 19, 8);
        let calls = std::cell::Cell::new(0);
        for variant in 0..4 {
            let mut chunk = Vec::with_capacity(if variant == 0 { 0 } else { count - 1 });
            let alphas = [E::ONE; LINK_COUNT_V1];
            let p = if variant == 1 {
                main_bounded_transform::MainBoundedTransformPolicyV1::cpu_v1()
            } else {
                policy
            };
            let mut bad_plan = small_plan_v1();
            if variant == 3 {
                bad_plan.links[0].left.native_log2 = u8::MAX;
            }
            assert!(
                bad_plan
                    .accumulate_with_v1(
                        if variant == 2 {
                            &alphas[..191]
                        } else {
                            &alphas
                        },
                        p,
                        &mut chunk,
                        |column, _| {
                            calls.set(calls.get() + 1);
                            Ok(fixture_replay_v1(column))
                        }
                    )
                    .is_err()
            );
        }
        assert_eq!(calls.get(), 0);
        assert!(policy.reserve_additional_v1(usize::MAX).is_err());
        assert!(policy.reserve_additional_v1(0).is_ok());
        assert!(
            MainTerminalLinkPlanV1::public_owner_charge_v1()
                >= 3 * core::mem::size_of_val(&plan) + LINK_COUNT_V1 * core::mem::size_of::<E>()
        );
    }
}
