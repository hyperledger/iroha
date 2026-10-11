//! Retained confidential witness vectors and independently computed public statements.
//! These host computations are shared fixtures, not a second proof relation.

use super::super::{
    CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3, CONFIDENTIAL_POSEIDON_MERKLE_NODE_DOMAIN_V3,
    CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3, CONFIDENTIAL_POSEIDON_NULLIFIER_DOMAIN_V3,
    CONFIDENTIAL_POSEIDON_OWNER_DOMAIN_V3, ConfidentialMerklePathV2, ConfidentialTransferWitnessV2,
    ConfidentialUnshieldWitnessV2, ConfidentialUnshieldWitnessV3, Scalar,
    confidential_poseidon_hash_v3, scalar_from_repr, scalar_from_u128, scalar_to_repr_bytes,
};
use ff::Field;

fn native_hash(domain: u64, inputs: &[Scalar]) -> Scalar {
    confidential_poseidon_hash_v3(domain, inputs)
}

pub(in crate::confidential_v2) fn sample_witness_shape(
    include_input_1: bool,
    include_output_1: bool,
) -> ConfidentialTransferWitnessV2 {
    let spend = Scalar::from(41);
    let diversifiers = [
        Scalar::from(43),
        if include_input_1 {
            Scalar::from(47)
        } else {
            Scalar::ZERO
        },
    ];
    let input_rho_bytes = [
        [0x11; 32],
        if include_input_1 { [0x22; 32] } else { [0; 32] },
    ];
    let input_rho = [
        super::super::hash_to_scalar(b"iroha.confidential.v3.note_rho", &[&input_rho_bytes[0]]),
        if include_input_1 {
            super::super::hash_to_scalar(b"iroha.confidential.v3.note_rho", &[&input_rho_bytes[1]])
        } else {
            Scalar::ZERO
        },
    ];
    let asset = Scalar::from(53);
    let input_owner = diversifiers.map(|diversifier| {
        native_hash(CONFIDENTIAL_POSEIDON_OWNER_DOMAIN_V3, &[spend, diversifier])
    });
    let input_commitments = [
        native_hash(
            CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3,
            &[
                Scalar::from(if include_input_1 { 5u64 } else { 12u64 }),
                input_rho[0],
                input_owner[0],
                asset,
            ],
        ),
        if include_input_1 {
            native_hash(
                CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3,
                &[Scalar::from(7), input_rho[1], input_owner[1], asset],
            )
        } else {
            Scalar::ZERO
        },
    ];
    let empty_leaf = native_hash(CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3, &[Scalar::ZERO]);
    let leaves = [
        native_hash(
            CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3,
            &[input_commitments[0]],
        ),
        if include_input_1 {
            native_hash(
                CONFIDENTIAL_POSEIDON_MERKLE_LEAF_DOMAIN_V3,
                &[input_commitments[1]],
            )
        } else {
            empty_leaf
        },
    ];
    let input_pair = native_hash(
        CONFIDENTIAL_POSEIDON_MERKLE_NODE_DOMAIN_V3,
        &[leaves[0], leaves[1]],
    );
    let empty_pair = native_hash(
        CONFIDENTIAL_POSEIDON_MERKLE_NODE_DOMAIN_V3,
        &[empty_leaf, empty_leaf],
    );
    let root = native_hash(
        CONFIDENTIAL_POSEIDON_MERKLE_NODE_DOMAIN_V3,
        &[input_pair, empty_pair],
    );
    let path_0 = ConfidentialMerklePathV2 {
        siblings: [leaves[1], empty_pair].map(scalar_to_repr_bytes).to_vec(),
        directions: vec![0, 0],
        witness_nodes: [input_pair, root].map(scalar_to_repr_bytes).to_vec(),
        root: scalar_to_repr_bytes(root),
    };
    let path_1 = ConfidentialMerklePathV2 {
        siblings: [leaves[0], empty_pair].map(scalar_to_repr_bytes).to_vec(),
        directions: vec![1, 0],
        witness_nodes: [input_pair, root].map(scalar_to_repr_bytes).to_vec(),
        root: scalar_to_repr_bytes(root),
    };
    ConfidentialTransferWitnessV2 {
        include_input_1,
        include_output_1,
        input_0_amount: if include_input_1 { 5 } else { 12 },
        input_1_amount: if include_input_1 { 7 } else { 0 },
        output_0_amount: if include_output_1 { 8 } else { 12 },
        output_1_amount: if include_output_1 { 4 } else { 0 },
        input_0_rho: input_rho_bytes[0],
        input_1_rho: input_rho_bytes[1],
        output_0_rho: [0x33; 32],
        output_1_rho: if include_output_1 {
            [0x44; 32]
        } else {
            [0; 32]
        },
        spend_scalar: scalar_to_repr_bytes(spend),
        input_0_diversifier: scalar_to_repr_bytes(diversifiers[0]),
        input_1_diversifier: scalar_to_repr_bytes(diversifiers[1]),
        output_0_owner_tag: scalar_to_repr_bytes(Scalar::from(59)),
        output_1_owner_tag: scalar_to_repr_bytes(if include_output_1 {
            Scalar::from(67)
        } else {
            Scalar::ZERO
        }),
        asset_tag: scalar_to_repr_bytes(asset),
        network_tag: scalar_to_repr_bytes(Scalar::from(61)),
        input_0_path: path_0,
        input_1_path: if include_input_1 {
            path_1
        } else {
            super::super::confidential_absent_input_path_v3::<2>()
        },
    }
}

pub(in crate::confidential_v2) fn expected_instances(
    witness: &ConfidentialTransferWitnessV2,
) -> Vec<Vec<Scalar>> {
    let spend = scalar_from_repr(witness.spend_scalar).expect("canonical spend scalar");
    let asset = scalar_from_repr(witness.asset_tag).expect("canonical asset tag");
    let network = scalar_from_repr(witness.network_tag).expect("canonical network tag");
    let amounts = [
        witness.input_0_amount,
        witness.input_1_amount,
        witness.output_0_amount,
        witness.output_1_amount,
    ]
    .map(scalar_from_u128);
    let rho_bytes = [
        witness.input_0_rho,
        witness.input_1_rho,
        witness.output_0_rho,
        witness.output_1_rho,
    ];
    let rho = rho_bytes
        .map(|rho| super::super::hash_to_scalar(b"iroha.confidential.v3.note_rho", &[&rho]));
    let input_owners = [witness.input_0_diversifier, witness.input_1_diversifier].map(|bytes| {
        native_hash(
            CONFIDENTIAL_POSEIDON_OWNER_DOMAIN_V3,
            &[
                spend,
                scalar_from_repr(bytes).expect("canonical diversifier"),
            ],
        )
    });
    let output_owners = [
        scalar_from_repr(witness.output_0_owner_tag).expect("canonical owner tag"),
        scalar_from_repr(witness.output_1_owner_tag).expect("canonical owner tag"),
    ];
    let commitments = [
        native_hash(
            CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3,
            &[amounts[0], rho[0], input_owners[0], asset],
        ),
        native_hash(
            CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3,
            &[amounts[1], rho[1], input_owners[1], asset],
        ),
        native_hash(
            CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3,
            &[amounts[2], rho[2], output_owners[0], asset],
        ),
        native_hash(
            CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3,
            &[amounts[3], rho[3], output_owners[1], asset],
        ),
    ];
    let nullifiers = [rho[0], rho[1]].map(|rho| {
        native_hash(
            CONFIDENTIAL_POSEIDON_NULLIFIER_DOMAIN_V3,
            &[spend, rho, asset, network],
        )
    });
    vec![
        vec![commitments[0]],
        vec![if witness.include_input_1 {
            commitments[1]
        } else {
            Scalar::ZERO
        }],
        vec![nullifiers[0]],
        vec![if witness.include_input_1 {
            nullifiers[1]
        } else {
            Scalar::ZERO
        }],
        vec![commitments[2]],
        vec![if witness.include_output_1 {
            commitments[3]
        } else {
            Scalar::ZERO
        }],
        vec![scalar_from_repr(witness.input_0_path.root).expect("canonical root")],
        vec![asset],
        vec![network],
    ]
}

pub(in crate::confidential_v2) fn full_unshield_from_transfer(
    transfer: &ConfidentialTransferWitnessV2,
) -> ConfidentialUnshieldWitnessV2 {
    ConfidentialUnshieldWitnessV2 {
        include_input_1: transfer.include_input_1,
        input_0_amount: transfer.input_0_amount,
        input_1_amount: transfer.input_1_amount,
        input_0_rho: transfer.input_0_rho,
        input_1_rho: transfer.input_1_rho,
        spend_scalar: transfer.spend_scalar,
        input_0_diversifier: transfer.input_0_diversifier,
        input_1_diversifier: transfer.input_1_diversifier,
        asset_tag: transfer.asset_tag,
        network_tag: transfer.network_tag,
        input_0_path: transfer.input_0_path.clone(),
        input_1_path: transfer.input_1_path.clone(),
    }
}

pub(in crate::confidential_v2) fn change_unshield_from_full(
    full: &ConfidentialUnshieldWitnessV2,
) -> ConfidentialUnshieldWitnessV3 {
    ConfidentialUnshieldWitnessV3 {
        include_input_1: full.include_input_1,
        include_output_0: true,
        input_0_amount: full.input_0_amount,
        input_1_amount: full.input_1_amount,
        output_0_amount: 4,
        input_0_rho: full.input_0_rho,
        input_1_rho: full.input_1_rho,
        output_0_rho: [0x75; 32],
        spend_scalar: full.spend_scalar,
        input_0_diversifier: full.input_0_diversifier,
        input_1_diversifier: full.input_1_diversifier,
        asset_tag: full.asset_tag,
        network_tag: full.network_tag,
        input_0_path: full.input_0_path.clone(),
        input_1_path: full.input_1_path.clone(),
    }
}

pub(in crate::confidential_v2) fn expected_full_unshield_instances(
    witness: &ConfidentialUnshieldWitnessV2,
) -> Vec<Vec<Scalar>> {
    let transfer = ConfidentialTransferWitnessV2 {
        include_input_1: witness.include_input_1,
        include_output_1: false,
        input_0_amount: witness.input_0_amount,
        input_1_amount: witness.input_1_amount,
        output_0_amount: witness.input_0_amount + witness.input_1_amount,
        output_1_amount: 0,
        input_0_rho: witness.input_0_rho,
        input_1_rho: witness.input_1_rho,
        output_0_rho: [1; 32],
        output_1_rho: [0; 32],
        spend_scalar: witness.spend_scalar,
        input_0_diversifier: witness.input_0_diversifier,
        input_1_diversifier: witness.input_1_diversifier,
        output_0_owner_tag: scalar_to_repr_bytes(Scalar::ONE),
        output_1_owner_tag: [0; 32],
        asset_tag: witness.asset_tag,
        network_tag: witness.network_tag,
        input_0_path: witness.input_0_path.clone(),
        input_1_path: witness.input_1_path.clone(),
    };
    let transfer_public = expected_instances(&transfer);
    vec![
        transfer_public[0].clone(),
        transfer_public[1].clone(),
        transfer_public[2].clone(),
        transfer_public[3].clone(),
        transfer_public[6].clone(),
        vec![scalar_from_u128(
            witness.input_0_amount + witness.input_1_amount,
        )],
        transfer_public[7].clone(),
        transfer_public[8].clone(),
    ]
}

pub(in crate::confidential_v2) fn expected_change_unshield_instances(
    witness: &ConfidentialUnshieldWitnessV3,
) -> Vec<Vec<Scalar>> {
    let full = ConfidentialUnshieldWitnessV2 {
        include_input_1: witness.include_input_1,
        input_0_amount: witness.input_0_amount,
        input_1_amount: witness.input_1_amount,
        input_0_rho: witness.input_0_rho,
        input_1_rho: witness.input_1_rho,
        spend_scalar: witness.spend_scalar,
        input_0_diversifier: witness.input_0_diversifier,
        input_1_diversifier: witness.input_1_diversifier,
        asset_tag: witness.asset_tag,
        network_tag: witness.network_tag,
        input_0_path: witness.input_0_path.clone(),
        input_1_path: witness.input_1_path.clone(),
    };
    let full_public = expected_full_unshield_instances(&full);
    let spend = scalar_from_repr(witness.spend_scalar).expect("canonical spend");
    let asset = scalar_from_repr(witness.asset_tag).expect("canonical asset");
    let change = if witness.include_output_0 {
        let output_rho = super::super::hash_to_scalar(
            b"iroha.confidential.v3.note_rho",
            &[&witness.output_0_rho],
        );
        let output_owner =
            native_hash(CONFIDENTIAL_POSEIDON_OWNER_DOMAIN_V3, &[spend, Scalar::ONE]);
        native_hash(
            CONFIDENTIAL_POSEIDON_NOTE_DOMAIN_V3,
            &[
                scalar_from_u128(witness.output_0_amount),
                output_rho,
                output_owner,
                asset,
            ],
        )
    } else {
        Scalar::ZERO
    };
    vec![
        full_public[0].clone(),
        full_public[1].clone(),
        full_public[2].clone(),
        full_public[3].clone(),
        vec![change],
        full_public[4].clone(),
        vec![scalar_from_u128(
            witness.input_0_amount + witness.input_1_amount
                - if witness.include_output_0 {
                    witness.output_0_amount
                } else {
                    0
                },
        )],
        full_public[6].clone(),
        full_public[7].clone(),
    ]
}
