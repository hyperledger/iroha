//! Fixed operation-task partitions and the canonical sixteen sigma selectors.

use ff::Field;
use iroha_pasta::Fp;
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{GlueChip, UintChip, Word};
use iroha_plonk_recursion::obligation::ledger::Variant;

/// Global sigma selector order from the wire's sorted `(operation_tag, mask)` set.
/// Refresh kinds share the one constrained tag7 union key.
pub const SIGMA_SELECTORS: [(u8, u8); 16] = [
    (1, 0),
    (2, 0),
    (3, 0),
    (3, 1),
    (3, 2),
    (3, 3),
    (3, 4),
    (3, 5),
    (3, 6),
    (3, 7),
    (4, 0),
    (4, 1),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
];

/// Find the unique global selector; undefined operation/mask pairs are rejected.
pub fn sigma_selector(operation_tag: u8, mask: u8) -> Option<u8> {
    SIGMA_SELECTORS
        .iter()
        .position(|pair| *pair == (operation_tag, mask))
        .and_then(|i| u8::try_from(i).ok())
}

/// Constrain the global index from the exact owning selector mask cells.
/// Send passes its opened enabled-controls mask; Receive passes the boolean
/// derived from the Request's recorded blacklist version. Other tags require0.
///
/// # Errors
/// Undefined fixed operation tag or layout failure. Invalid masks are unsatisfiable.
pub fn constrain_sigma_selector(
    uint: &mut UintChip<'_, Fp>,
    region: &mut Region<'_, Fp>,
    operation_tag: u8,
    mask: &Word<Fp>,
) -> Result<Word<Fp>, Error> {
    match operation_tag {
        3 => {
            uint.range_check::<3>(region, mask)?;
            uint.glue().add_constant(region, mask, Fp::from(2))
        }
        4 => {
            uint.range_check::<1>(region, mask)?;
            uint.glue().add_constant(region, mask, Fp::from(10))
        }
        _ => {
            let index = sigma_selector(operation_tag, 0).ok_or(Error::Synthesis)?;
            GlueChip::assert_constant(region, mask, Fp::ZERO)?;
            uint.glue().constant(region, Fp::from(u64::from(index)))
        }
    }
}

/// Named constraint groups assigned to fixed A stages, never private booleans.
/// Source-key review must establish that each named group actually executes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum OperationTask {
    /// Bootstrap's exact zero state, identity and opening rules.
    BootstrapState = 1,
    /// Bootstrap issuer/credential/provider receipt authentication.
    BootstrapAuthorization = 2,
    /// Load arithmetic and exact depth32 insert-only recovery entry.
    LoadRecovery = 3,
    /// Exact own Advance receipt under the predecessor payment key.
    LoadReceipt = 4,
    /// Send current credential, exact Request and held fee terms.
    SendObjects = 5,
    /// Send pending descriptor insertion into the adjusted lineage map.
    SendPending = 6,
    /// Send conditional fee insertion and untouched maps/burned total.
    SendFeeAndCarry = 7,
    /// Mandatory current credential and Enrollment certificate re-verification on Load.
    LoadCurrentAuthorization = 8,
    /// Send own receipt, current credential and Enrollment certificate.
    SendAuthorization = 9,
    /// Exact public lineage/transport/sigma tape bound to the own receipt.
    SendProof = 10,
    /// Incoming Omega, sigma and transported-claim decoder verdicts on Receive.
    ReceiveProofs = 11,
    /// Exact incoming Payment, Request, payer and receipt body bindings.
    ReceiveObjects = 12,
    /// Incoming Request and Send receipt signatures, including quoted credential.
    ReceiveSignatures = 13,
    /// Authenticated consumed-credit search and its nonmembership verdict.
    ReceiveNonmembership = 14,
    /// Request-recorded blacklist history and exact sigma-key selection.
    ReceiveBlacklist = 15,
    /// Hard own receipt, current credential and Enrollment certificate.
    ReceiveAuthorization = 16,
    /// Exact own sigma bytes bound to the Receive receipt proof digest.
    ReceiveOwnProof = 17,
    /// OQ-3 consumed map, immutable credit record and adjusted burn accounting.
    ReceiveEffects = 18,
    /// Unload's exact redeem-map insertion and value conservation.
    UnloadRecovery = 19,
    /// Retiring's lifecycle transition and adjusted-field synchronization.
    RetiringState = 20,
    /// Unload/Retiring own receipt, current credential and Enrollment certificate.
    UnloadAuthorization = 21,
    /// Unload/Retiring exact predecessor Omega and own sigma receipt binding.
    UnloadProof = 22,
    /// Exact original Omega-plus-sigma consuming digest and both raw commitments.
    ReceiveProofDigest = 23,
    /// Policy update's exact state effects and credential renewal continuity.
    RefreshEffects = 24,
    /// Hard update issuer, purpose certificate and own receipt authorization.
    RefreshUpdateAuthorization = 25,
    /// Mandatory predecessor current credential and direct Enrollment certificate.
    RefreshCurrentAuthorization = 26,
    /// New blacklist version/root insertion into permanent history.
    RefreshBlacklist = 27,
    /// Exact fixed64 ordering, interval and charge-preserving matching rules.
    RefreshQuotaMerge = 28,
    /// Exact held Payment sources and pending descriptor, independent of evidence validity.
    ArchiveRetainedPayment = 29,
    /// Receive-package or `CreditStatus` body and original Credited transcript.
    ArchiveEvidence = 30,
    /// Total incoming proof decoders, succinct verification and key continuity.
    ArchiveProofs = 31,
    /// Incoming evidence receipt signature under the Request's quoted receiver key.
    ArchiveSignatures = 32,
    /// Hard own receipt, current credential and direct Enrollment certificate.
    ArchiveAuthorization = 33,
    /// Exact own sigma tape and its sigma-only receipt digest.
    ArchiveOwnProof = 34,
    /// Terminal evidence iff/no-op rule and exact incoming mode closure.
    ArchiveEffects = 35,
    /// Exact OQ-3 consumed-credit map update under the complete Receive verdict.
    ReceiveConsumedEffects = 36,
    /// Permanent first Payment/burn credit record under the same Receive verdict.
    ReceiveCreditEffects = 37,
    /// Authenticate all64 predecessor usage leaves against the prior state root.
    RefreshQuotaPreviousRoot = 38,
    /// Authenticate all64 signed replacement window leaves.
    RefreshQuotaWindowRoot = 39,
    /// Authenticate all64 successor usage leaves aligned with the new windows.
    RefreshQuotaUsageRoot = 40,
    /// Exact retained Omega/sigma tapes and their unconditional joint bound.
    ArchiveRetainedProofs = 42,
    /// Unconditional removal of the exact retained descriptor from the core map.
    ArchiveCorePending = 43,
    /// Hard adjusted pending path with the complete committed evidence verdict.
    ArchiveLineagePending = 44,
}
impl OperationTask {
    /// Stable context-schema code, not an operation's wire tag.
    pub const fn code(self) -> u8 {
        self as u8
    }
    /// Exact required operation task set; this metadata does not establish
    /// that the operation's complete circuit composition is implemented.
    pub const fn required(variant: Variant) -> &'static [Self] {
        match variant {
            Variant::Bootstrap => &[Self::BootstrapState, Self::BootstrapAuthorization],
            Variant::Load => &[
                Self::LoadRecovery,
                Self::LoadReceipt,
                Self::LoadCurrentAuthorization,
            ],
            Variant::Send => &[
                Self::SendObjects,
                Self::SendPending,
                Self::SendFeeAndCarry,
                Self::SendAuthorization,
                Self::SendProof,
            ],
            Variant::Receive | Variant::ReceiveRenewed => &[
                Self::ReceiveProofs,
                Self::ReceiveObjects,
                Self::ReceiveSignatures,
                Self::ReceiveNonmembership,
                Self::ReceiveBlacklist,
                Self::ReceiveAuthorization,
                Self::ReceiveOwnProof,
                Self::ReceiveEffects,
                Self::ReceiveProofDigest,
                Self::ReceiveConsumedEffects,
                Self::ReceiveCreditEffects,
            ],
            Variant::Unload => &[
                Self::UnloadRecovery,
                Self::UnloadAuthorization,
                Self::UnloadProof,
            ],
            Variant::Retiring => &[
                Self::RetiringState,
                Self::UnloadAuthorization,
                Self::UnloadProof,
            ],
            Variant::RefreshCredential
            | Variant::RefreshSchemePolicy
            | Variant::RefreshTimeAnchor => &[
                Self::RefreshEffects,
                Self::RefreshUpdateAuthorization,
                Self::RefreshCurrentAuthorization,
            ],
            Variant::RefreshBlacklist => &[
                Self::RefreshEffects,
                Self::RefreshUpdateAuthorization,
                Self::RefreshCurrentAuthorization,
                Self::RefreshBlacklist,
            ],
            Variant::RefreshQuotaShare => &[
                Self::RefreshEffects,
                Self::RefreshUpdateAuthorization,
                Self::RefreshCurrentAuthorization,
                Self::RefreshQuotaMerge,
                Self::RefreshQuotaPreviousRoot,
                Self::RefreshQuotaWindowRoot,
                Self::RefreshQuotaUsageRoot,
            ],
            Variant::ArchiveReceive | Variant::ArchiveStatus => &[
                Self::ArchiveRetainedPayment,
                Self::ArchiveEvidence,
                Self::ArchiveProofs,
                Self::ArchiveSignatures,
                Self::ArchiveAuthorization,
                Self::ArchiveOwnProof,
                Self::ArchiveEffects,
                Self::ArchiveRetainedProofs,
                Self::ArchiveCorePending,
                Self::ArchiveLineagePending,
            ],
        }
    }
    pub(super) fn validate(variant: Variant, groups: &[Vec<Self>]) -> Result<(), Error> {
        let required = Self::required(variant);
        if groups
            .iter()
            .any(|group| group.windows(2).any(|w| w[0] >= w[1]))
        {
            return Err(Error::Synthesis);
        }
        let mut actual = groups.iter().flatten().copied().collect::<Vec<_>>();
        actual.sort_unstable();
        if actual != required {
            return Err(Error::Synthesis);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_selectors_exhaust_all_sixteen_without_aliases() {
        for (i, &(tag, mask)) in SIGMA_SELECTORS.iter().enumerate() {
            assert_eq!(sigma_selector(tag, mask), Some(u8::try_from(i).unwrap()));
        }
        for tag in 0..=9 {
            for mask in 0..=8 {
                assert_eq!(
                    sigma_selector(tag, mask).is_some(),
                    SIGMA_SELECTORS.contains(&(tag, mask))
                );
            }
        }
        assert_eq!(sigma_selector(2, 0), Some(1));
        assert_eq!(sigma_selector(7, 0), Some(14));
    }
    #[test]
    fn operation_partitions_require_every_task_once_and_reject_relabelling() {
        use OperationTask::{
            SendAuthorization, SendFeeAndCarry, SendObjects, SendPending, SendProof,
        };
        let honest = vec![
            vec![SendObjects],
            vec![SendPending],
            vec![SendFeeAndCarry],
            vec![SendAuthorization],
            vec![SendProof],
        ];
        assert!(OperationTask::validate(Variant::Send, &honest).is_ok());
        for i in 0..5 {
            let mut missing = honest.clone();
            missing[i].clear();
            assert!(OperationTask::validate(Variant::Send, &missing).is_err());
            let mut repeated = honest.clone();
            repeated[i].push(honest[i][0]);
            assert!(OperationTask::validate(Variant::Send, &repeated).is_err());
        }
        assert!(OperationTask::validate(Variant::Load, &honest).is_err());
        assert!(
            OperationTask::validate(
                Variant::Send,
                &[vec![SendPending, SendObjects, SendFeeAndCarry]]
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod circuit_tests {
    use super::*;
    use iroha_plonk::{
        check::{CheckMode, check_circuit},
        cs::{Column, ConstraintSystem, Instance},
        frontend::{Circuit, Layouter, SimpleFloorPlanner, Value, synthesize},
    };
    use iroha_plonk_gadgets::{
        GlueConfig,
        range::{LimbBits, RunningSumChip, RunningSumConfig},
        tamper::undetected_tampers,
    };
    #[derive(Clone)]
    struct Selectors {
        masks: [Fp; 16],
        known: bool,
    }
    #[derive(Clone, Debug)]
    struct Config {
        glue: GlueConfig,
        range: RunningSumConfig,
        public: Column<Instance>,
    }
    impl Circuit<Fp> for Selectors {
        type Config = Config;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();
        fn without_witnesses(&self) -> Self {
            Self {
                known: false,
                ..self.clone()
            }
        }
        fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
            let columns = core::array::from_fn(|_| meta.advice_column());
            let constants = meta.fixed_column();
            let glue = GlueConfig::configure(meta, columns, constants);
            let column = meta.advice_column();
            let range = RunningSumConfig::configure(meta, column, LimbBits::new(4).unwrap());
            let public = meta.instance_column(16);
            meta.enable_equality(public);
            Config {
                glue,
                range,
                public,
            }
        }
        fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
            let mut glue = GlueChip::new(config.glue);
            let mut range = RunningSumChip::new(config.range);
            range.load_table(&mut layouter)?;
            let out = layouter.assign_region(
                || "canonical selector table",
                |mut region| {
                    let mut out = Vec::new();
                    let mut uint = UintChip::new(&mut glue, &mut range);
                    for ((tag, _), mask) in SIGMA_SELECTORS.iter().zip(self.masks) {
                        let value = if self.known {
                            Value::known(mask)
                        } else {
                            Value::unknown()
                        };
                        let mask = uint.glue().witness(&mut region, value)?;
                        out.push(constrain_sigma_selector(
                            &mut uint,
                            &mut region,
                            *tag,
                            &mask,
                        )?);
                    }
                    Ok(out)
                },
            )?;
            for (i, word) in out.iter().enumerate() {
                layouter.constrain_instance(word.cell(), config.public, i)?;
            }
            Ok(())
        }
    }
    #[test]
    fn canonical_selector_cells_bind_all_masks_and_reject_out_of_range_aliases() {
        let circuit = Selectors {
            masks: SIGMA_SELECTORS.map(|(_, mask)| Fp::from(u64::from(mask))),
            known: true,
        };
        let public = (0..16).map(Fp::from).collect::<Vec<_>>();
        assert!(
            check_circuit(
                &circuit,
                8,
                std::slice::from_ref(&public),
                CheckMode::Strict
            )
            .unwrap()
            .is_satisfied()
        );
        for (i, value) in [
            (0, Fp::ONE),
            (2, Fp::from(8)),
            (10, Fp::from(2)),
            (14, Fp::ONE),
            (9, -Fp::ONE),
        ] {
            let mut wrong = circuit.clone();
            wrong.masks[i] = value;
            assert!(
                !check_circuit(&wrong, 8, std::slice::from_ref(&public), CheckMode::Strict)
                    .unwrap()
                    .is_satisfied()
            );
        }
        let mut wrong = public.clone();
        wrong[2] = Fp::from(3);
        assert!(
            !check_circuit(&circuit, 8, &[wrong], CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        let known = synthesize(&circuit, 8, None).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 8, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        assert!(
            undetected_tampers(&circuit, 8, &[public])
                .unwrap()
                .is_empty()
        );
    }
}

/// Compiled full operation partitions shared by native sources and artifact identity.
pub mod compiled;
