//! Native confidential relations with exact compiled keys and consuming proving.

use super::{
    ConfidentialTransferWitnessV2, ConfidentialUnshieldWitnessV2, ConfidentialUnshieldWitnessV3,
};
use ff::{Field, PrimeField};
use iroha_pasta::Fp;
mod backend;
#[cfg(test)]
mod captured;
mod relation;
pub(crate) use relation::Kind;
use relation::{Input, NativeCircuit, Opening, Output};

fn scalar(bytes: [u8; 32]) -> Result<Fp, String> {
    Option::from(Fp::from_repr(bytes)).ok_or_else(|| "noncanonical confidential field".into())
}
fn rho(bytes: [u8; 32], present: bool) -> Fp {
    if !present {
        Fp::ZERO
    } else {
        Fp::from_repr(super::hash_to_scalar(b"iroha.confidential.v3.note_rho", &[&bytes]).to_repr())
            .unwrap()
    }
}
fn transfer<const DEPTH: usize>(
    w: &ConfidentialTransferWitnessV2,
) -> Result<NativeCircuit<0, DEPTH>, String> {
    super::witness_validation::validate_transfer_witness::<DEPTH>(w)?;
    Ok(NativeCircuit {
        opening: Some(Opening {
            inputs: [
                Input {
                    present: true,
                    amount: w.input_0_amount,
                    rho: rho(w.input_0_rho, true),
                    diversifier: scalar(w.input_0_diversifier)?,
                    path: w.input_0_path.clone(),
                },
                Input {
                    present: w.include_input_1,
                    amount: w.input_1_amount,
                    rho: rho(w.input_1_rho, w.include_input_1),
                    diversifier: scalar(w.input_1_diversifier)?,
                    path: w.input_1_path.clone(),
                },
            ],
            outputs: [
                Output {
                    present: true,
                    amount: w.output_0_amount,
                    rho: rho(w.output_0_rho, true),
                    owner: scalar(w.output_0_owner_tag)?,
                },
                Output {
                    present: w.include_output_1,
                    amount: w.output_1_amount,
                    rho: rho(w.output_1_rho, w.include_output_1),
                    owner: scalar(w.output_1_owner_tag)?,
                },
            ],
            spend: scalar(w.spend_scalar)?,
            asset: scalar(w.asset_tag)?,
            network: scalar(w.network_tag)?,
        }),
    })
}
fn full<const DEPTH: usize>(
    w: &ConfidentialUnshieldWitnessV2,
) -> Result<NativeCircuit<1, DEPTH>, String> {
    super::witness_validation::validate_unshield_v2_witness::<DEPTH>(w)?;
    Ok(NativeCircuit {
        opening: Some(Opening {
            inputs: [
                Input {
                    present: true,
                    amount: w.input_0_amount,
                    rho: rho(w.input_0_rho, true),
                    diversifier: scalar(w.input_0_diversifier)?,
                    path: w.input_0_path.clone(),
                },
                Input {
                    present: w.include_input_1,
                    amount: w.input_1_amount,
                    rho: rho(w.input_1_rho, w.include_input_1),
                    diversifier: scalar(w.input_1_diversifier)?,
                    path: w.input_1_path.clone(),
                },
            ],
            outputs: core::array::from_fn(|_| Output {
                present: false,
                amount: 0,
                rho: Fp::ZERO,
                owner: Fp::ZERO,
            }),
            spend: scalar(w.spend_scalar)?,
            asset: scalar(w.asset_tag)?,
            network: scalar(w.network_tag)?,
        }),
    })
}
fn change<const DEPTH: usize>(
    w: &ConfidentialUnshieldWitnessV3,
) -> Result<NativeCircuit<2, DEPTH>, String> {
    super::witness_validation::validate_unshield_v3_witness::<DEPTH>(w)?;
    Ok(NativeCircuit {
        opening: Some(Opening {
            inputs: [
                Input {
                    present: true,
                    amount: w.input_0_amount,
                    rho: rho(w.input_0_rho, true),
                    diversifier: scalar(w.input_0_diversifier)?,
                    path: w.input_0_path.clone(),
                },
                Input {
                    present: w.include_input_1,
                    amount: w.input_1_amount,
                    rho: rho(w.input_1_rho, w.include_input_1),
                    diversifier: scalar(w.input_1_diversifier)?,
                    path: w.input_1_path.clone(),
                },
            ],
            outputs: [
                Output {
                    present: w.include_output_0,
                    amount: w.output_0_amount,
                    rho: rho(w.output_0_rho, w.include_output_0),
                    owner: Fp::ZERO,
                },
                Output {
                    present: false,
                    amount: 0,
                    rho: Fp::ZERO,
                    owner: Fp::ZERO,
                },
            ],
            spend: scalar(w.spend_scalar)?,
            asset: scalar(w.asset_tag)?,
            network: scalar(w.network_tag)?,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_plonk::{
        check::{CheckMode, check_circuit},
        frontend::{Circuit, synthesize},
    };
    fn public(columns: Vec<Vec<super::super::Scalar>>) -> Vec<Vec<Fp>> {
        vec![
            columns
                .into_iter()
                .map(|c| scalar(c[0].to_repr()).unwrap())
                .collect(),
        ]
    }
    fn accepts<const MODE: u8, const DEPTH: usize>(
        circuit: &NativeCircuit<MODE, DEPTH>,
        values: &[Vec<Fp>],
    ) -> bool {
        check_circuit(circuit, 13, values, CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
    fn all_public<const MODE: u8>(circuit: &NativeCircuit<MODE, 2>, values: &[Vec<Fp>]) {
        let report = check_circuit(circuit, 13, values, CheckMode::Strict).unwrap();
        assert!(report.is_satisfied(), "{report}");
        for row in 0..values[0].len() {
            let mut modified = values.to_vec();
            modified[0][row] += Fp::ONE;
            assert!(!accepts(circuit, &modified), "mode{MODE} row{row}");
        }
        let known = synthesize(circuit, 13, Some(values)).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 13, None).unwrap();
        assert_eq!(known.cs, unknown.cs);
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    }
    #[test]
    fn native_confidential_all_presence_shapes_match_captured_public_contracts() {
        for second in [false, true] {
            for change_output in [false, true] {
                let witness = captured::sample_witness_shape(second, change_output);
                all_public(
                    &transfer::<2>(&witness).unwrap(),
                    &public(captured::expected_instances(&witness)),
                );
            }
            let witness = captured::sample_witness_shape(second, false);
            let full_witness = captured::full_unshield_from_transfer(&witness);
            all_public(
                &full::<2>(&full_witness).unwrap(),
                &public(captured::expected_full_unshield_instances(&full_witness)),
            );
            for present in [false, true] {
                let mut change_witness = captured::change_unshield_from_full(&full_witness);
                change_witness.include_output_0 = present;
                if !present {
                    change_witness.output_0_amount = 0;
                    change_witness.output_0_rho = [0; 32];
                }
                all_public(
                    &change::<2>(&change_witness).unwrap(),
                    &public(captured::expected_change_unshield_instances(
                        &change_witness,
                    )),
                );
            }
        }
    }
    #[test]
    fn native_confidential_constraints_reject_private_opening_and_membership_mutations() {
        let witness = captured::sample_witness_shape(true, true);
        let circuit = transfer::<2>(&witness).unwrap();
        let values = public(captured::expected_instances(&witness));
        for index in 0..19 {
            let mut changed = circuit.clone();
            let w = changed.opening.as_mut().unwrap();
            match index {
                0 => w.spend += Fp::ONE,
                1 => w.asset += Fp::ONE,
                2 => w.network += Fp::ONE,
                3 => w.inputs[0].amount += 1,
                4 => w.inputs[1].amount += 1,
                5 => w.outputs[0].amount += 1,
                6 => w.outputs[1].amount += 1,
                7 => w.inputs[0].rho += Fp::ONE,
                8 => w.inputs[1].rho += Fp::ONE,
                9 => w.outputs[0].rho += Fp::ONE,
                10 => w.outputs[1].owner += Fp::ONE,
                11 => w.inputs[0].diversifier += Fp::ONE,
                12 => w.inputs[1].present = false,
                13 => w.outputs[1].present = false,
                14 => w.inputs[0].path.directions[0] ^= 1,
                15 => w.inputs[1].path.witness_nodes[0][0] ^= 1,
                16 => w.inputs[0].path.root[0] ^= 1,
                17 => w.inputs[1].path.root[0] ^= 1,
                _ => w.inputs[1].path.root = [0xff; 32],
            }
            assert!(!accepts(&changed, &values), "mutation{index}");
        }
        for second in [false, true] {
            let transfer_witness = captured::sample_witness_shape(second, false);
            let full_witness = captured::full_unshield_from_transfer(&transfer_witness);
            let change_witness = captured::change_unshield_from_full(&full_witness);
            let values = public(captured::expected_change_unshield_instances(
                &change_witness,
            ));
            let mut changed = change::<2>(&change_witness).unwrap();
            changed.opening.as_mut().unwrap().outputs[0].amount = 13;
            assert!(!accepts(&changed, &values), "redemption underflow");
            changed.opening.as_mut().unwrap().outputs[0].amount = 0;
            assert!(!accepts(&changed, &values), "present zero change");
        }
    }
    #[test]
    fn native_confidential_rejects_noncanonical_witnesses_before_proving() {
        let original = captured::sample_witness_shape(true, true);
        for index in 0..12 {
            let mut witness = original.clone();
            match index {
                0 => witness.spend_scalar = [0xff; 32],
                1 => witness.input_0_path.siblings.push([0; 32]),
                2 => {
                    witness.input_0_path.witness_nodes.pop();
                }
                3 => witness.input_0_path.directions[0] = 2,
                4 => witness.input_0_rho = [0; 32],
                5 => witness.output_0_rho = [0; 32],
                6 => witness.input_1_diversifier = [0; 32],
                7 => witness.output_1_owner_tag = [0; 32],
                8 => witness.asset_tag = [0; 32],
                9 => witness.network_tag = [0; 32],
                10 => witness.input_1_path.root = [0xff; 32],
                _ => witness.input_0_amount = 0,
            }
            assert!(
                transfer::<2>(&witness).is_err(),
                "malformed opening {index}"
            );
        }
        let original = captured::sample_witness_shape(false, false);
        for index in 0..6 {
            let mut witness = original.clone();
            match index {
                0 => witness.input_1_amount = 1,
                1 => witness.input_1_rho = [9; 32],
                2 => witness.input_1_diversifier = Fp::ONE.to_repr(),
                3 => witness.output_1_amount = 1,
                4 => witness.output_1_rho = [9; 32],
                _ => witness.output_1_owner_tag = Fp::ONE.to_repr(),
            }
            assert!(transfer::<2>(&witness).is_err(), "unused opening {index}");
            if index < 3 {
                let full_witness = captured::full_unshield_from_transfer(&witness);
                assert!(full::<2>(&full_witness).is_err());
                assert!(change::<2>(&captured::change_unshield_from_full(&full_witness)).is_err());
            }
        }
        let full_witness = captured::full_unshield_from_transfer(&original);
        let mut change_witness = captured::change_unshield_from_full(&full_witness);
        change_witness.include_output_0 = false;
        change_witness.output_0_amount = 0;
        change_witness.output_0_rho = [0; 32];
        assert!(change::<2>(&change_witness).is_ok());
        change_witness.output_0_amount = 1;
        assert!(change::<2>(&change_witness).is_err());
        change_witness.output_0_amount = 0;
        change_witness.output_0_rho = [1; 32];
        assert!(change::<2>(&change_witness).is_err());
    }
    #[test]
    fn native_confidential_rejects_unbalanced_recomputed_statement() {
        let mut witness = captured::sample_witness_shape(true, true);
        witness.output_0_amount += 1;
        // Recompute the output commitments too: rejection must come from
        // conservation, not from a stale public commitment.
        assert!(!accepts(
            &transfer::<2>(&witness).unwrap(),
            &public(captured::expected_instances(&witness))
        ));
        let mut witness = captured::sample_witness_shape(true, false);
        witness.input_0_path.directions[0] ^= 1;
        assert!(!accepts(
            &transfer::<2>(&witness).unwrap(),
            &public(captured::expected_instances(&witness))
        ));
    }
    #[test]
    fn native_confidential_internal_witness_debug_redacts_secrets() {
        let transfer = captured::sample_witness_shape(true, false);
        let full = captured::full_unshield_from_transfer(&transfer);
        let change = captured::change_unshield_from_full(&full);
        let values: [(&dyn core::fmt::Debug, &str); 3] = [
            (&transfer, "ConfidentialTransferWitnessV2"),
            (&full, "ConfidentialUnshieldWitnessV2"),
            (&change, "ConfidentialUnshieldWitnessV3"),
        ];
        for (value, name) in values {
            for rendered in [format!("{value:?}"), format!("{value:#?}")] {
                let fields = rendered.strip_prefix(name).unwrap();
                assert!(fields.contains(".."));
                assert!(
                    fields
                        .bytes()
                        .all(|byte| matches!(byte, b' ' | b'\n' | b'{' | b'}' | b'.'))
                );
            }
        }
    }
    #[test]
    fn native_confidential_binds_every_path_level_and_private_owner() {
        let witness = captured::sample_witness_shape(true, true);
        let circuit = transfer::<2>(&witness).unwrap();
        let values = public(captured::expected_instances(&witness));
        for input in 0..2 {
            for level in 0..2 {
                for component in 0..3 {
                    let mut changed = circuit.clone();
                    let path = &mut changed.opening.as_mut().unwrap().inputs[input].path;
                    match component {
                        0 => path.siblings[level][0] ^= 1,
                        1 => path.directions[level] ^= 1,
                        _ => path.witness_nodes[level][0] ^= 1,
                    }
                    assert!(
                        !accepts(&changed, &values),
                        "path {input}/{level}/{component}"
                    );
                }
            }
            let mut changed = circuit.clone();
            changed.opening.as_mut().unwrap().inputs[input].diversifier += Fp::ONE;
            assert!(!accepts(&changed, &values));
        }
        for output in 0..2 {
            let mut changed = circuit.clone();
            changed.opening.as_mut().unwrap().outputs[output].owner += Fp::ONE;
            assert!(!accepts(&changed, &values));
            let mut changed = circuit.clone();
            changed.opening.as_mut().unwrap().outputs[output].rho += Fp::ONE;
            assert!(!accepts(&changed, &values));
        }
    }
    #[test]
    fn native_confidential_single_input_full_tree_and_foreign_second_root() {
        for second in [false, true] {
            let mut witness = captured::sample_witness_shape(second, false);
            let input = usize::from(second);
            let commitment = captured::expected_instances(&witness)[input][0].to_repr();
            let replacement = super::super::tests::full_tree_input_path_v3::<2>(commitment);
            if second {
                witness.input_1_path = replacement;
            } else {
                witness.input_0_path = replacement;
            }
            assert_ne!(witness.input_0_path.root, witness.input_1_path.root);
            assert_eq!(
                accepts(
                    &transfer::<2>(&witness).unwrap(),
                    &public(captured::expected_instances(&witness))
                ),
                !second
            );
            let full_witness = captured::full_unshield_from_transfer(&witness);
            assert_eq!(
                accepts(
                    &full::<2>(&full_witness).unwrap(),
                    &public(captured::expected_full_unshield_instances(&full_witness))
                ),
                !second
            );
            for present in [false, true] {
                let mut change_witness = captured::change_unshield_from_full(&full_witness);
                change_witness.include_output_0 = present;
                if !present {
                    change_witness.output_0_amount = 0;
                    change_witness.output_0_rho = [0; 32];
                }
                assert_eq!(
                    accepts(
                        &change::<2>(&change_witness).unwrap(),
                        &public(captured::expected_change_unshield_instances(
                            &change_witness
                        ))
                    ),
                    !second
                );
            }
        }
    }
    #[test]
    fn native_confidential_duplicate_notes_and_redemption_overflow_fail() {
        let mut witness = captured::sample_witness_shape(true, true);
        witness.input_1_amount = witness.input_0_amount;
        witness.input_1_rho = witness.input_0_rho;
        witness.input_1_diversifier = witness.input_0_diversifier;
        witness.input_1_path = witness.input_0_path.clone();
        witness.output_0_amount = 6;
        witness.output_1_amount = 4;
        assert!(!accepts(
            &transfer::<2>(&witness).unwrap(),
            &public(captured::expected_instances(&witness))
        ));
        let full_witness = captured::full_unshield_from_transfer(&witness);
        assert!(!accepts(
            &full::<2>(&full_witness).unwrap(),
            &public(captured::expected_full_unshield_instances(&full_witness))
        ));
        let mut witness = captured::sample_witness_shape(true, true);
        witness.output_0_amount = 6;
        witness.output_1_amount = 6;
        witness.output_1_rho = witness.output_0_rho;
        witness.output_1_owner_tag = witness.output_0_owner_tag;
        assert!(!accepts(
            &transfer::<2>(&witness).unwrap(),
            &public(captured::expected_instances(&witness))
        ));
        let full_witness = captured::full_unshield_from_transfer(&witness);
        let values = public(captured::expected_full_unshield_instances(&full_witness));
        let mut circuit = full::<2>(&full_witness).unwrap();
        circuit.opening.as_mut().unwrap().inputs[0].amount = u128::MAX;
        assert!(!accepts(&circuit, &values));
    }
    fn production_witness() -> ConfidentialTransferWitnessV2 {
        let mut witness = captured::sample_witness_shape(true, true);
        let empty = super::super::confidential_empty_subtree_roots_v3();
        for path in [&mut witness.input_0_path, &mut witness.input_1_path] {
            let mut node = super::super::scalar_from_repr(path.root).unwrap();
            for sibling in empty.iter().take(16).skip(2) {
                path.siblings.push(sibling.to_repr());
                path.directions.push(0);
                node = super::super::merkle_parent_v3(node, *sibling);
                path.witness_nodes.push(node.to_repr());
            }
            path.root = node.to_repr();
        }
        witness
    }
    fn real_proof<const MODE: u8>(circuit: NativeCircuit<MODE, 16>, values: Vec<Vec<Fp>>) {
        use relation::Kind;
        let kind = match MODE {
            0 => Kind::Transfer,
            1 => Kind::Full,
            2 => Kind::Change,
            _ => unreachable!(),
        };
        let verifier = kind.verifier().unwrap();
        assert!(std::ptr::eq(verifier, kind.verifier().unwrap()));
        let carrier: crate::native_pipa_r::CompiledVerifyingKeyV1 =
            norito::decode_canonical(verifier.key_bytes()).unwrap();
        assert_eq!(
            norito::encode_canonical(&carrier).unwrap(),
            verifier.key_bytes()
        );
        eprintln!(
            "native confidential mode{MODE} key digest={}",
            hex::encode(crate::hash_vk_bytes(
                crate::native_pipa_r::BACKEND,
                verifier.key_bytes()
            ))
        );
        let prover = kind.prover().unwrap();
        assert!(std::ptr::eq(prover, kind.prover().unwrap()));
        let iroha_data_model::zk::NativePipaRProofV1 {
            public_inputs: public,
            proof,
        } = prover
            .prove(circuit.opening.unwrap(), values[0].clone())
            .unwrap();
        verifier.verify(&public, &proof).unwrap();
        for row in 0..public.len() {
            let mut changed = public.clone();
            changed[row] = (Fp::from_repr(changed[row]).unwrap() + Fp::ONE).to_repr();
            assert!(
                verifier.verify(&changed, &proof).is_err(),
                "mode{MODE} public row{row}"
            );
        }
        for other in [Kind::Transfer, Kind::Full, Kind::Change] {
            if other != kind {
                assert_ne!(verifier.key_bytes(), other.verifier().unwrap().key_bytes());
                assert!(other.verifier().unwrap().verify(&public, &proof).is_err());
            }
        }
        let mut malformed = proof.clone();
        malformed[proof.len() / 2] ^= 1;
        assert!(verifier.verify(&public, &malformed).is_err());
        assert!(verifier.verify(&public, &proof[..proof.len() - 1]).is_err());
        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(verifier.verify(&public, &trailing).is_err());
        let mut noncanonical = public.clone();
        noncanonical[0] = [0xff; 32];
        assert!(verifier.verify(&noncanonical, &proof).is_err());
        eprintln!(
            "native confidential mode{MODE}: k13, proof={} bytes, key carrier={} bytes",
            proof.len(),
            verifier.key_bytes().len()
        );
    }
    #[test]
    fn native_confidential_production_depth_owned_proofs_verify_all_three_relations() {
        let witness = production_witness();
        real_proof(
            transfer::<16>(&witness).unwrap(),
            public(captured::expected_instances(&witness)),
        );
        let full_witness = captured::full_unshield_from_transfer(&witness);
        real_proof(
            full::<16>(&full_witness).unwrap(),
            public(captured::expected_full_unshield_instances(&full_witness)),
        );
        let change_witness = captured::change_unshield_from_full(&full_witness);
        real_proof(
            change::<16>(&change_witness).unwrap(),
            public(captured::expected_change_unshield_instances(
                &change_witness,
            )),
        );
    }
}

impl Kind {
    pub(crate) const fn circuit_id(self) -> &'static str {
        match self {
            Self::Transfer => super::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
            Self::Full => super::CONFIDENTIAL_UNSHIELD_V2_CIRCUIT_ID,
            Self::Change => super::CONFIDENTIAL_UNSHIELD_V3_CIRCUIT_ID,
        }
    }
    pub(crate) const fn schema(self) -> &'static [u8] {
        match self {
            Self::Transfer => super::CONFIDENTIAL_TRANSFER_V2_PUBLIC_INPUTS_SCHEMA_V1,
            Self::Full => super::CONFIDENTIAL_UNSHIELD_V2_PUBLIC_INPUTS_SCHEMA_V1,
            Self::Change => super::CONFIDENTIAL_UNSHIELD_V3_PUBLIC_INPUTS_SCHEMA_V1,
        }
    }
}
pub(crate) fn key_bytes(kind: Kind) -> Result<&'static [u8], String> {
    Ok(kind.verifier()?.key_bytes())
}
pub(crate) fn proof_length(kind: Kind) -> Result<usize, String> {
    Ok(kind.verifier()?.proof_length())
}
pub(crate) fn verify(kind: Kind, public: &[[u8; 32]], proof: &[u8]) -> Result<(), String> {
    kind.verifier()?.verify(public, proof)
}
pub(super) fn verifying_key(
    kind: Kind,
) -> Result<iroha_data_model::proof::VerifyingKeyBox, String> {
    Ok(iroha_data_model::proof::VerifyingKeyBox::new(
        crate::native_pipa_r::BACKEND.to_owned(),
        key_bytes(kind)?.to_vec(),
    ))
}
pub(super) fn validate_key(
    kind: Kind,
    key: &iroha_data_model::proof::VerifyingKeyBox,
) -> Result<(), String> {
    if key.backend != crate::native_pipa_r::BACKEND
        || (key.bytes.is_empty() || key.bytes.len() > crate::native_pipa_r::MAX_KEY_BYTES)
    {
        return Err("invalid native confidential key backend or length".into());
    }
    if key.bytes != key_bytes(kind)? {
        return Err("foreign native confidential compiled key".into());
    }
    Ok(())
}
fn prove<const MODE: u8>(
    kind: Kind,
    circuit: NativeCircuit<MODE, 16>,
    columns: Vec<Vec<Fp>>,
) -> Result<iroha_data_model::zk::NativePipaRProofV1, String> {
    // Host builders supply the application order as singleton values. The
    // native relation has exactly one public column in that same order.
    if columns.len() != kind.rows() || columns.iter().any(|column| column.len() != 1) {
        return Err("invalid confidential public statement shape".into());
    }
    let public = columns.into_iter().flatten().collect();
    let opening = circuit
        .opening
        .ok_or_else(|| "missing confidential witness".to_owned())?;
    kind.prover()?.prove(opening, public)
}
pub(super) fn prove_transfer(
    witness: ConfidentialTransferWitnessV2,
    public: Vec<Vec<Fp>>,
) -> Result<iroha_data_model::zk::NativePipaRProofV1, String> {
    let circuit = transfer::<16>(&witness)?;
    drop(witness);
    prove(Kind::Transfer, circuit, public)
}
pub(super) fn prove_full(
    witness: ConfidentialUnshieldWitnessV2,
    public: Vec<Vec<Fp>>,
) -> Result<iroha_data_model::zk::NativePipaRProofV1, String> {
    let circuit = full::<16>(&witness)?;
    drop(witness);
    prove(Kind::Full, circuit, public)
}
pub(super) fn prove_change(
    witness: ConfidentialUnshieldWitnessV3,
    public: Vec<Vec<Fp>>,
) -> Result<iroha_data_model::zk::NativePipaRProofV1, String> {
    let circuit = change::<16>(&witness)?;
    drop(witness);
    prove(Kind::Change, circuit, public)
}

#[cfg(test)]
pub(super) fn check_transfer<const DEPTH: usize>(
    witness: &ConfidentialTransferWitnessV2,
    columns: Vec<Vec<Fp>>,
) -> bool {
    let circuit = transfer::<DEPTH>(witness).unwrap();
    iroha_plonk::check::check_circuit(
        &circuit,
        13,
        &[columns.into_iter().flatten().collect()],
        iroha_plonk::check::CheckMode::Strict,
    )
    .unwrap()
    .is_satisfied()
}
