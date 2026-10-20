//! Compiled operation schedules shared by native source construction and artifact identity.
//!
//! These fixed partitions grant no proof or installation authority. Concrete Plan owners
//! still authenticate source descriptors, complete Q keys, original objects and parameters.

use iroha_plonk::frontend::Error;
use iroha_plonk_recursion::obligation::ledger::Variant;

use crate::a_relation::{
    AProofPlan,
    context::{ContextObjectSpec, ContextPlan},
    schedule::OperationTask,
};

/// One exact compiled owner/Q schedule, independent of witnesses and artifact keys.
#[derive(Clone, Debug)]
pub struct OperationSchedule {
    variant: Variant,
    q: Vec<Vec<usize>>,
    tasks: Vec<Vec<OperationTask>>,
    predecessor: Option<usize>,
}
impl OperationSchedule {
    /// Select the sole current source schedule for an operation variant.
    #[must_use]
    pub fn for_variant(variant: Variant) -> Self {
        use OperationTask::*;
        let (q, tasks) = match variant {
            // Lean: one unsplit terminal A proves the zero state, the issuer and
            // the own receipt on its single signature Q; no W follows it.
            Variant::Bootstrap => (
                vec![vec![0]],
                vec![vec![BootstrapState, BootstrapAuthorization]],
            ),
            // Lean, one terminal A: the hard predecessor, the recovery and the own
            // receipt on its single signature Q; no W follows it.
            Variant::Load => (vec![vec![0]], vec![vec![LoadRecovery, LoadReceipt]]),
            // Lean: A1 proves the transition and its objects beside the hard predecessor,
            // A2 both map insertions, A3 the own receipt. The two-stage packing (maps in
            // A1) exceeds k16's usable rows once A1 verifies the real Omega predecessor.
            Variant::Send => (
                vec![vec![], vec![], vec![0]],
                vec![
                    vec![SendObjects, SendTransition],
                    vec![SendPending, SendFeeAndCarry],
                    vec![SendAuthorization],
                ],
            ),
            // Lean, repacked into five stages: A1 proves the transition and both map
            // effects beside the hard predecessor; A2 verifies Q0, the incoming-only
            // Q_sigma; A3 checks the payer's proofs and the signed objects; A4 verifies
            // Q1, the merged signature leaf (own receipt hard, incoming slots soft), owned
            // by Authorization and projected by Signatures; the terminal A5 searches the
            // consumed-credit map, hashes both proof tapes and applies the effects.
            Variant::Receive | Variant::ReceiveRenewed => (
                vec![vec![], vec![0], vec![], vec![1], vec![]],
                vec![
                    vec![
                        ReceiveConsumedEffects,
                        ReceiveCreditEffects,
                        ReceiveTransition,
                    ],
                    vec![],
                    vec![ReceiveProofs, ReceiveObjects],
                    vec![ReceiveSignatures, ReceiveAuthorization],
                    vec![ReceiveNonmembership, ReceiveEffects, ReceiveProofDigest],
                ],
            ),
            // Lean: A already proves sigma_archive's relation (LineagePending runs the
            // administrative archive rule). Q1 (Q0 for Status) is the merged signature
            // leaf; ArchiveReceive's Q0 is the incoming-only Q_sigma.
            Variant::ArchiveReceive => (
                vec![
                    vec![],
                    vec![],
                    vec![1],
                    vec![],
                    vec![],
                    vec![0],
                    vec![],
                    vec![],
                    vec![],
                ],
                vec![
                    vec![ArchiveCorePending],
                    vec![ArchiveRetainedProofs],
                    vec![ArchiveSignatures, ArchiveAuthorization],
                    vec![ArchiveLineagePending],
                    vec![ArchiveProofs],
                    vec![],
                    vec![ArchiveEvidence],
                    vec![ArchiveRetainedPayment],
                    vec![ArchiveEffects],
                ],
            ),
            Variant::ArchiveStatus => (
                vec![
                    vec![],
                    vec![],
                    vec![0],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                ],
                vec![
                    vec![ArchiveCorePending],
                    vec![ArchiveRetainedProofs],
                    vec![ArchiveSignatures, ArchiveAuthorization],
                    vec![ArchiveLineagePending],
                    vec![ArchiveProofs],
                    vec![ArchiveEvidence],
                    vec![ArchiveRetainedPayment],
                    vec![ArchiveEffects],
                ],
            ),
            // Lean, one terminal A: the transition beside the hard predecessor and the
            // own-receipt leaf; no W follows it.
            Variant::Unload | Variant::Retiring => (
                vec![vec![0]],
                vec![vec![
                    if variant == Variant::Unload {
                        UnloadRecovery
                    } else {
                        RetiringState
                    },
                    UnloadAuthorization,
                ]],
            ),
            Variant::RefreshQuotaShare => (
                vec![vec![], vec![], vec![], vec![0], vec![1], vec![2], vec![]],
                vec![
                    vec![RefreshEffects, RefreshQuotaPreviousRoot],
                    vec![RefreshQuotaWindowRoot],
                    vec![RefreshQuotaUsageRoot],
                    vec![],
                    vec![RefreshUpdateAuthorization],
                    vec![RefreshCurrentAuthorization],
                    vec![RefreshQuotaMerge],
                ],
            ),
            Variant::RefreshCredential
            | Variant::RefreshSchemePolicy
            | Variant::RefreshTimeAnchor => (
                vec![vec![], vec![0], vec![1], vec![2]],
                vec![
                    vec![RefreshEffects],
                    vec![],
                    vec![RefreshUpdateAuthorization],
                    vec![RefreshCurrentAuthorization],
                ],
            ),
        };
        Self {
            variant,
            q,
            tasks,
            predecessor: (variant != Variant::Bootstrap).then_some(0),
        }
    }

    /// Bind these exact partitions to the actual fixed Q keys and object schema.
    /// # Errors
    /// Another operation variant, omitted/reordered Q or mandatory owner, or invalid schema.
    pub fn bind(
        self,
        operation: AProofPlan,
        objects: Vec<ContextObjectSpec>,
    ) -> Result<ContextPlan, Error> {
        if operation.frame().variant() != self.variant {
            return Err(Error::Synthesis);
        }
        ContextPlan::with_schedule(operation, self.q, self.predecessor, objects)?
            .with_operation_tasks(self.tasks)
    }

    /// Number of source A stages; exactly one W joins consecutive stages, and a
    /// single stage is the unsplit terminal A.
    #[must_use]
    pub fn stage_count(&self) -> usize {
        self.q.len()
    }

    /// Exact ordered Q owners, before any witness or key is supplied.
    #[must_use]
    pub fn q_partitions(&self) -> &[Vec<usize>] {
        &self.q
    }

    /// Exact ordered semantic owners in the same stage order.
    #[must_use]
    pub fn tasks(&self) -> &[Vec<OperationTask>] {
        &self.tasks
    }
}

/// One required logical producer route, before grouping exact source classes.
/// Routes may share artifacts only after their complete compiled source and VK
/// identities agree. A descriptor match alone never establishes that equality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationRoute {
    /// Exact semantic variant; renewed Receive and each Refresh remain distinct.
    pub variant: Variant,
    /// Global own sigma selector in [`super::SIGMA_SELECTORS`].
    pub own: u8,
    /// Incoming sigma selector, present only for Receive and `ArchiveReceive`.
    pub incoming: Option<u8>,
}

/// Complete ordered dispatch domain for every control and incoming sigma selector.
/// The list does not presume how many exact descriptor/source classes or terminal
/// keys the authenticated inventory will require.
#[must_use]
pub fn compiled_routes() -> Vec<OperationRoute> {
    let mut routes = Vec::new();
    for variant in Variant::ALL {
        let (own_tag, incoming_tag) = match variant {
            Variant::Bootstrap => (1, None),
            Variant::Load => (2, None),
            Variant::Send => (3, None),
            Variant::Receive | Variant::ReceiveRenewed => (4, Some(3)),
            Variant::ArchiveReceive => (5, Some(4)),
            Variant::ArchiveStatus => (5, None),
            Variant::Unload => (6, None),
            Variant::RefreshCredential
            | Variant::RefreshSchemePolicy
            | Variant::RefreshQuotaShare
            | Variant::RefreshTimeAnchor => (7, None),
            Variant::Retiring => (8, None),
        };
        for (own, (tag, _)) in (0_u8..).zip(super::SIGMA_SELECTORS) {
            if tag != own_tag {
                continue;
            }
            if let Some(incoming_tag) = incoming_tag {
                for (incoming, (tag, _)) in (0_u8..).zip(super::SIGMA_SELECTORS) {
                    if tag == incoming_tag {
                        routes.push(OperationRoute {
                            variant,
                            own,
                            incoming: Some(incoming),
                        });
                    }
                }
            } else {
                routes.push(OperationRoute {
                    variant,
                    own,
                    incoming: None,
                });
            }
        }
    }
    routes
}

#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.native.operation_route.v1")]
struct RouteRecord {
    variant: u8,
    own: u8,
    incoming: Option<u8>,
}

#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.native.operation_schedule.v1")]
struct Record {
    variant: u8,
    predecessor: Option<u32>,
    q: Vec<Vec<u32>>,
    tasks: Vec<Vec<u8>>,
}
#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.native.operation_schedules.v1")]
struct Policy {
    version: u16,
    records: Vec<Record>,
    routes: Vec<RouteRecord>,
}

/// Canonical compiled schedule preimage for the common native artifact profile.
/// It contains every variant, not caller-selected partitions or witness verdicts.
/// # Errors
/// Integer overflow or canonical Norito encoding failure.
pub fn compiled_schedule_transcript() -> Result<Vec<u8>, Error> {
    let records = Variant::ALL
        .into_iter()
        .enumerate()
        .map(|(index, variant)| {
            let s = OperationSchedule::for_variant(variant);
            Ok(Record {
                variant: u8::try_from(index + 1).map_err(|_| Error::BoundsFailure)?,
                predecessor: s
                    .predecessor
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| Error::BoundsFailure)?,
                q: s.q
                    .into_iter()
                    .map(|part| {
                        part.into_iter()
                            .map(|index| u32::try_from(index).map_err(|_| Error::BoundsFailure))
                            .collect()
                    })
                    .collect::<Result<_, _>>()?,
                tasks: s
                    .tasks
                    .into_iter()
                    .map(|part| part.into_iter().map(OperationTask::code).collect())
                    .collect(),
            })
        })
        .collect::<Result<_, Error>>()?;
    norito::encode_canonical(&Policy {
        version: 1,
        records,
        routes: compiled_routes()
            .into_iter()
            .map(|route| {
                let variant = Variant::ALL
                    .iter()
                    .position(|v| *v == route.variant)
                    .and_then(|i| u8::try_from(i + 1).ok())
                    .ok_or(Error::Synthesis)?;
                Ok(RouteRecord {
                    variant,
                    own: route.own,
                    incoming: route.incoming,
                })
            })
            .collect::<Result<_, Error>>()?,
    })
    .map_err(|_| Error::Synthesis)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_schedule_has_every_q_and_mandatory_owner_once() {
        // Every route except Refresh is lean: no own Q_sigma. Bootstrap, Load, Send,
        // Unload, Retiring and ArchiveStatus have one signature leaf; Receive and
        // ArchiveReceive add the incoming-only Q_sigma.
        let expected = [1, 1, 3, 5, 5, 9, 8, 1, 1, 4, 4, 7, 4];
        for (variant, count) in Variant::ALL.into_iter().zip(expected) {
            let schedule = OperationSchedule::for_variant(variant);
            assert_eq!(schedule.stage_count(), count);
            assert_eq!(schedule.tasks().len(), count);
            OperationTask::validate(variant, schedule.tasks()).unwrap();
            let mut q: Vec<_> = schedule.q_partitions().iter().flatten().copied().collect();
            q.sort_unstable();
            let expected_q = match variant {
                Variant::Bootstrap
                | Variant::Load
                | Variant::Send
                | Variant::Unload
                | Variant::Retiring
                | Variant::ArchiveStatus => 1,
                Variant::Receive | Variant::ReceiveRenewed | Variant::ArchiveReceive => 2,
                _ => 3,
            };
            assert_eq!(q, (0..expected_q).collect::<Vec<_>>());
        }
    }
    #[test]
    fn receive_variants_share_credit_owner_and_preserve_every_obligation() {
        let plain = OperationSchedule::for_variant(Variant::Receive);
        let renewed = OperationSchedule::for_variant(Variant::ReceiveRenewed);
        assert_eq!(plain.q, renewed.q);
        assert_eq!(plain.predecessor, renewed.predecessor);
        assert_eq!(plain.tasks, renewed.tasks);
        assert_eq!(plain.stage_count(), 5);
        assert_eq!(
            plain.tasks[0],
            [
                OperationTask::ReceiveConsumedEffects,
                OperationTask::ReceiveCreditEffects,
                OperationTask::ReceiveTransition
            ]
        );
        assert_eq!(
            plain.tasks[3],
            [
                OperationTask::ReceiveSignatures,
                OperationTask::ReceiveAuthorization
            ]
        );
        assert_eq!(plain.q[3], [1]);
        let mut untransitioned = plain.tasks.clone();
        assert_eq!(
            untransitioned[0].pop(),
            Some(OperationTask::ReceiveTransition)
        );
        assert!(OperationTask::validate(Variant::Receive, &untransitioned).is_err());
        let mut dropped = renewed.tasks.clone();
        assert_eq!(dropped[0].remove(1), OperationTask::ReceiveCreditEffects);
        assert!(OperationTask::validate(Variant::ReceiveRenewed, &dropped).is_err());
        let mut substituted = dropped;
        substituted[0].insert(1, OperationTask::ReceiveConsumedEffects);
        assert!(OperationTask::validate(Variant::ReceiveRenewed, &substituted).is_err());
        let mut duplicate = renewed.tasks.clone();
        duplicate[0].push(OperationTask::ReceiveCreditEffects);
        assert!(OperationTask::validate(Variant::ReceiveRenewed, &duplicate).is_err());
        for variant in [Variant::Receive, Variant::ReceiveRenewed] {
            OperationTask::validate(variant, OperationSchedule::for_variant(variant).tasks())
                .unwrap();
        }
    }
    #[test]
    fn canonical_policy_is_exact_compiled_variant_order_and_partitions() {
        let bytes = compiled_schedule_transcript().unwrap();
        let policy: Policy = norito::decode_canonical_with_limits(
            &bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .unwrap();
        assert_eq!(norito::encode_canonical(&policy).unwrap(), bytes);
        assert_eq!(policy.version, 1);
        assert_eq!(policy.records.len(), Variant::ALL.len());
        assert_eq!(policy.routes.len(), 22);
        for (actual, expected) in policy.routes.iter().zip(compiled_routes()) {
            assert_eq!(
                Variant::ALL[usize::from(actual.variant) - 1],
                expected.variant
            );
            assert_eq!(actual.own, expected.own);
            assert_eq!(actual.incoming, expected.incoming);
        }
        for (index, (record, variant)) in policy.records.iter().zip(Variant::ALL).enumerate() {
            assert_eq!(usize::from(record.variant), index + 1);
            let source = OperationSchedule::for_variant(variant);
            assert_eq!(
                record.predecessor,
                source.predecessor.map(|i| u32::try_from(i).unwrap())
            );
            assert_eq!(
                record.q,
                source
                    .q
                    .iter()
                    .map(|p| p
                        .iter()
                        .map(|i| u32::try_from(*i).unwrap())
                        .collect::<Vec<_>>())
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                record.tasks,
                source
                    .tasks
                    .iter()
                    .map(|p| p.iter().map(|t| t.code()).collect::<Vec<_>>())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn routes_cover_every_own_and_incoming_selector_exactly_once() {
        let routes = compiled_routes();
        assert_eq!(routes.len(), 22);
        for variant in Variant::ALL {
            let selected: Vec<_> = routes.iter().filter(|r| r.variant == variant).collect();
            assert!(!selected.is_empty());
            let mut pairs = std::collections::BTreeSet::new();
            for route in &selected {
                assert!(pairs.insert((route.own, route.incoming)));
            }
            let count = match variant {
                Variant::Send | Variant::Receive | Variant::ReceiveRenewed => 4,
                _ => 1,
            };
            assert_eq!(selected.len(), count);
            if matches!(variant, Variant::Receive | Variant::ReceiveRenewed) {
                assert_eq!(pairs, (2..=5).map(|incoming| (6, Some(incoming))).collect());
            } else if variant == Variant::ArchiveReceive {
                assert_eq!(pairs, [(7, Some(6))].into_iter().collect());
            } else {
                assert!(selected.iter().all(|r| r.incoming.is_none()));
            }
        }
    }
}
