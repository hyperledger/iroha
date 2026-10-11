//! Exhaustive branch authorization and adversarial mode-cell checks.

use iroha_pasta::{Fp, Fq, PastaField};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value},
};
use iroha_plonk_gadgets::{GlueChip, GlueConfig, tamper::undetected_tampers};
use iroha_plonk_recursion::obligation::ledger::{
    Destination, Ledger, LedgerError, Obligation, Source, Variant,
};
use iroha_plonk_recursion::obligation::{ModeCells, constrain_incoming_modes};

#[derive(Clone)]
struct Branch<F> {
    soft: [bool; 2],
    modes: [[F; 3]; 4],
    known: bool,
}

impl<F: PastaField> Circuit<F> for Branch<F> {
    type Config = (GlueConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        (glue, public)
    }

    fn synthesize(
        &self,
        (config, public): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::new(config);
        let valid = layouter.assign_region(
            || "incoming obligation modes",
            |mut region| {
                let soft = self
                    .soft
                    .iter()
                    .map(|bit| {
                        glue.boolean(
                            &mut region,
                            if self.known {
                                Value::known(*bit)
                            } else {
                                Value::unknown()
                            },
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let modes = self
                    .modes
                    .iter()
                    .map(|values| {
                        let values = values.map(|value| {
                            if self.known {
                                Value::known(value)
                            } else {
                                Value::unknown()
                            }
                        });
                        let words = glue.witnesses(&mut region, &values)?;
                        let words = words.try_into().map_err(|_| Error::Synthesis)?;
                        ModeCells::constrain(&mut glue, &mut region, &words)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                // Exercise the public selection bits, whose one-hot constraints
                // must remain bound even when a consuming fold selects a dummy.
                assert_eq!(modes.len(), 4);
                for mode in &modes {
                    let _ = (mode.accept(), mode.trivial(), mode.corrected());
                }
                constrain_incoming_modes(&mut glue, &mut region, &soft, &modes)
            },
        )?;
        layouter.constrain_instance(valid.cell(), public, 0)
    }
}

fn one_hot<F: PastaField>(code: usize) -> [F; 3] {
    core::array::from_fn(|index| if index == code { F::ONE } else { F::ZERO })
}

fn accepts<F: PastaField>(branch: &Branch<F>, valid: bool) -> bool {
    let output = if valid { F::ONE } else { F::ZERO };
    check_circuit(branch, 7, &[vec![output]], CheckMode::Strict)
        .expect("layout")
        .is_satisfied()
}

fn branch_matrix<F: PastaField>() {
    for soft_mask in 0..4 {
        let soft = [soft_mask & 1 != 0, soft_mask & 2 != 0];
        for encoding in 0..81 {
            let mut value = encoding;
            let codes: [usize; 4] = core::array::from_fn(|_| {
                let code = value % 3;
                value /= 3;
                code
            });
            let branch: Branch<F> = Branch {
                soft,
                modes: codes.map(one_hot),
                known: true,
            };
            for claimed_valid in [false, true] {
                // Independent literal §2.7 rules, including the burn witness
                // required when all succinct and consumer checks accept.
                let corrections = codes.iter().filter(|&&code| code == 2).count();
                let expected = if claimed_valid {
                    soft == [true, true] && codes == [0; 4]
                } else {
                    codes.iter().all(|&code| code != 0)
                        && corrections <= 1
                        && (soft != [true, true] || corrections == 1)
                };
                assert_eq!(
                    accepts(&branch, claimed_valid),
                    expected,
                    "soft={soft:?} modes={codes:?} valid={claimed_valid}"
                );
            }
        }
    }
}

#[test]
fn incoming_branch_rules_are_exhaustive_in_both_fields() {
    branch_matrix::<Fp>();
    branch_matrix::<Fq>();
}

fn adversarial<F: PastaField>() {
    let accepted: Branch<F> = Branch {
        soft: [true; 2],
        modes: [one_hot(0); 4],
        known: true,
    };
    let burned = Branch {
        soft: [false, true],
        modes: [one_hot(1); 4],
        known: true,
    };
    let corrected = Branch {
        soft: [true; 2],
        modes: [one_hot(1), one_hot(2), one_hot(1), one_hot(1)],
        known: true,
    };
    for (branch, valid) in [(&accepted, true), (&burned, false), (&corrected, false)] {
        assert!(
            undetected_tampers(branch, 7, &[vec![if valid { F::ONE } else { F::ZERO }]])
                .expect("tamper check")
                .is_empty()
        );
    }
    for index in 0..4 {
        for bad in [
            [F::ZERO; 3],
            [F::ONE; 3],
            [F::from(2), -F::ONE, F::ZERO],
            [F::ZERO, F::from(2), -F::ONE],
        ] {
            let mut forged = accepted.clone();
            forged.modes[index] = bad;
            assert!(!accepts(&forged, true));
            assert!(!accepts(&forged, false));
        }
    }
}

#[test]
fn mode_bits_and_every_assigned_cell_are_bound() {
    adversarial::<Fp>();
    adversarial::<Fq>();
}

#[test]
fn every_unsplit_obligation_is_consumed_exactly_once() {
    use Obligation::{
        AggregatorOpening, IncomingOpening, IncomingPallas, IncomingSigma, IncomingVesta, OwnSigma,
        PredecessorOpening, PredecessorPallas, PredecessorVesta, QOpening, SigmaPart,
    };
    // Independent source sets from Lambda §2.3. This catches a complete,
    // consistently relabeled schedule, not only a single-cell mutation.
    for variant in Variant::ALL {
        let (incoming, predecessor, incoming_sigma) = match variant {
            Variant::Bootstrap => (vec![], false, None),
            Variant::Receive | Variant::ReceiveRenewed => (
                vec![
                    IncomingSigma,
                    IncomingOpening,
                    IncomingPallas,
                    IncomingVesta,
                ],
                true,
                Some(14),
            ),
            Variant::ArchiveReceive => (vec![IncomingSigma], true, Some(12)),
            Variant::ArchiveStatus => (
                vec![IncomingOpening, IncomingPallas, IncomingVesta],
                true,
                None,
            ),
            _ => (vec![], true, None),
        };
        for q_count in [1_u16, 2, 3] {
            for own_k in [12, 14] {
                let ledger =
                    Ledger::new(variant, q_count.try_into().unwrap(), own_k, incoming_sigma)
                        .unwrap();
                let mut expected = vec![OwnSigma, SigmaPart, AggregatorOpening];
                expected.extend((0..q_count).map(QOpening));
                if predecessor {
                    expected.extend([PredecessorOpening, PredecessorPallas, PredecessorVesta]);
                }
                expected.extend(&incoming);
                expected.sort();
                let mut actual: Vec<_> = ledger
                    .slots()
                    .iter()
                    .filter_map(|slot| match slot.source {
                        Source::Claim(id) => Some(id),
                        Source::VestaTrivial => None,
                    })
                    .collect();
                actual.sort();
                assert_eq!(actual, expected, "{variant:?}");
                assert!(actual.windows(2).all(|pair| pair[0] != pair[1]));
                if variant == Variant::Bootstrap {
                    let destination = if q_count == 1 {
                        Destination::PallasForward
                    } else {
                        Destination::PallasFold
                    };
                    let pallas: Vec<_> = ledger.inputs(destination).collect();
                    assert_eq!(pallas.len(), usize::from(q_count));
                    for (index, slot) in pallas.iter().enumerate() {
                        assert_eq!(
                            slot.source,
                            Source::Claim(QOpening(u16::try_from(index).unwrap()))
                        );
                        assert_eq!(slot.source_k, 16);
                        assert!(!slot.gated);
                    }
                }
                let mut gated: Vec<_> = ledger
                    .slots()
                    .iter()
                    .filter(|slot| slot.gated)
                    .map(|slot| match slot.source {
                        Source::Claim(id) => id,
                        Source::VestaTrivial => panic!("padding cannot be gated"),
                    })
                    .collect();
                gated.sort();
                let mut incoming = incoming.clone();
                incoming.sort();
                assert_eq!(gated, incoming);
                let sigma_inputs: Vec<_> = ledger.inputs(Destination::SigmaFold).collect();
                if incoming_sigma.is_some() {
                    assert_eq!(sigma_inputs.len(), 3);
                    assert_eq!(sigma_inputs[2].source, Source::VestaTrivial);
                    assert_eq!(sigma_inputs[2].source_k, 16);
                } else {
                    assert!(sigma_inputs.is_empty());
                    assert_eq!(ledger.inputs(Destination::SigmaForward).count(), 1);
                }
                let vesta: Vec<_> = ledger.inputs(Destination::VestaFold).collect();
                assert_eq!(vesta.len(), 4, "one Omega descriptor for every variant");
                assert_eq!(vesta[1].source, Source::Claim(AggregatorOpening));
                assert_eq!(
                    vesta[2].source,
                    if predecessor {
                        Source::Claim(PredecessorVesta)
                    } else {
                        Source::VestaTrivial
                    }
                );
                assert_eq!(
                    vesta[3].source,
                    if incoming.contains(&IncomingVesta) {
                        Source::Claim(IncomingVesta)
                    } else {
                        Source::VestaTrivial
                    }
                );
                for slot in &vesta[1..] {
                    assert_eq!(slot.source_k, 16);
                }
                let part = vesta[0];
                assert_eq!(part.source, Source::Claim(SigmaPart));
                assert_eq!(
                    part.source_k,
                    if incoming_sigma.is_some() { 16 } else { own_k }
                );
                assert_eq!(ledger.check_bindings(ledger.slots()), Ok(()));
                for index in 0..ledger.slots().len() {
                    let mut missing = ledger.slots().to_vec();
                    missing.remove(index);
                    assert_eq!(ledger.check_bindings(&missing), Err(LedgerError::Bindings));
                    let mut duplicate = ledger.slots().to_vec();
                    duplicate.push(duplicate[index]);
                    assert_eq!(
                        ledger.check_bindings(&duplicate),
                        Err(LedgerError::Bindings)
                    );
                    let mut gated = ledger.slots().to_vec();
                    gated[index].gated = !gated[index].gated;
                    assert_eq!(ledger.check_bindings(&gated), Err(LedgerError::Bindings));
                    let mut reshaped = ledger.slots().to_vec();
                    reshaped[index].source_k ^= 1;
                    assert_eq!(ledger.check_bindings(&reshaped), Err(LedgerError::Bindings));
                }
            }
        }
    }
}

#[test]
fn obligation_plan_rejects_variant_descriptor_mismatches() {
    let one = 1_u16.try_into().unwrap();
    for k in [0, 1, 13, 15, 16, u8::MAX] {
        assert_eq!(
            Ledger::new(Variant::Send, one, k, None),
            Err(LedgerError::SigmaShape)
        );
        assert_eq!(
            Ledger::new(Variant::Receive, one, 12, Some(k)),
            Err(LedgerError::SigmaShape)
        );
    }
    assert_eq!(
        Ledger::new(Variant::Receive, one, 12, None),
        Err(LedgerError::IncomingShape)
    );
    assert_eq!(
        Ledger::new(Variant::ArchiveStatus, one, 12, Some(12)),
        Err(LedgerError::IncomingShape)
    );
}
