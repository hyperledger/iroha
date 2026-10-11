//! Canonical confidential witness admission shared by the relation and prover.

use super::{
    ConfidentialMerklePathV2, ConfidentialTransferWitnessV2, ConfidentialUnshieldWitnessV2,
    ConfidentialUnshieldWitnessV3, Scalar, scalar_from_repr,
};
use ff::Field;

pub(super) fn canonical_scalar(bytes: [u8; 32], label: &str) -> Result<Scalar, String> {
    scalar_from_repr(bytes).ok_or_else(|| format!("{label} must be a canonical Pasta scalar"))
}
pub(super) fn canonical_nonzero_scalar(bytes: [u8; 32], label: &str) -> Result<Scalar, String> {
    canonical_scalar(bytes, label).and_then(|value| {
        if value == Scalar::ZERO {
            Err(format!("{label} must be non-zero"))
        } else {
            Ok(value)
        }
    })
}
fn validate_path<const DEPTH: usize>(
    path: &ConfidentialMerklePathV2,
    label: &str,
) -> Result<(), String> {
    if path.siblings.len() != DEPTH
        || path.directions.len() != DEPTH
        || path.witness_nodes.len() != DEPTH
    {
        return Err(format!(
            "{label} must contain exactly {DEPTH} siblings, directions, and witness nodes"
        ));
    }
    for (level, sibling) in path.siblings.iter().copied().enumerate() {
        canonical_scalar(sibling, &format!("{label} sibling[{level}]"))?;
    }
    for (level, direction) in path.directions.iter().copied().enumerate() {
        if direction > 1 {
            return Err(format!("{label} direction[{level}] must be zero or one"));
        }
    }
    for (level, node) in path.witness_nodes.iter().copied().enumerate() {
        canonical_scalar(node, &format!("{label} witness_node[{level}]"))?;
    }
    canonical_scalar(path.root, &format!("{label} root"))?;
    Ok(())
}
pub(super) fn validate_transfer_witness<const DEPTH: usize>(
    witness: &ConfidentialTransferWitnessV2,
) -> Result<(), String> {
    if witness.input_0_amount == 0 || witness.output_0_amount == 0 {
        return Err("mandatory transfer amounts must be non-zero".to_owned());
    }
    if witness.input_0_rho == [0; 32] || witness.output_0_rho == [0; 32] {
        return Err("mandatory transfer rho values must be non-zero".to_owned());
    }
    canonical_nonzero_scalar(witness.spend_scalar, "transfer spend scalar")?;
    canonical_nonzero_scalar(witness.input_0_diversifier, "transfer input 0 diversifier")?;
    canonical_nonzero_scalar(witness.output_0_owner_tag, "transfer output 0 owner tag")?;
    canonical_nonzero_scalar(witness.asset_tag, "transfer asset tag")?;
    canonical_nonzero_scalar(witness.network_tag, "transfer network tag")?;
    validate_path::<DEPTH>(&witness.input_0_path, "transfer input 0 path")?;
    validate_path::<DEPTH>(&witness.input_1_path, "transfer input 1 path")?;
    if witness.include_input_1 {
        if witness.input_1_amount == 0 || witness.input_1_rho == [0; 32] {
            return Err("present transfer input 1 must have non-zero amount and rho".to_owned());
        }
        canonical_nonzero_scalar(witness.input_1_diversifier, "transfer input 1 diversifier")?;
    } else if witness.input_1_amount != 0
        || witness.input_1_rho != [0; 32]
        || witness.input_1_diversifier != [0; 32]
    {
        return Err(
            "absent transfer input 1 opening must use the canonical all-zero form".to_owned(),
        );
    }
    if witness.include_output_1 {
        if witness.output_1_amount == 0 || witness.output_1_rho == [0; 32] {
            return Err("present transfer output 1 must have non-zero amount and rho".to_owned());
        }
        canonical_nonzero_scalar(witness.output_1_owner_tag, "transfer output 1 owner tag")?;
    } else if witness.output_1_amount != 0
        || witness.output_1_rho != [0; 32]
        || witness.output_1_owner_tag != [0; 32]
    {
        return Err(
            "absent transfer output 1 opening must use the canonical all-zero form".to_owned(),
        );
    }
    Ok(())
}
fn validate_unshield_inputs<const DEPTH: usize>(
    include_input_1: bool,
    input_amounts: [u128; 2],
    input_rhos: [[u8; 32]; 2],
    spend_scalar: [u8; 32],
    diversifiers: [[u8; 32]; 2],
    asset_tag: [u8; 32],
    network_tag: [u8; 32],
    paths: [&ConfidentialMerklePathV2; 2],
) -> Result<(), String> {
    if input_amounts[0] == 0 || input_rhos[0] == [0; 32] {
        return Err("mandatory unshield input must have non-zero amount and rho".to_owned());
    }
    canonical_nonzero_scalar(spend_scalar, "unshield spend scalar")?;
    canonical_nonzero_scalar(diversifiers[0], "unshield input 0 diversifier")?;
    canonical_nonzero_scalar(asset_tag, "unshield asset tag")?;
    canonical_nonzero_scalar(network_tag, "unshield network tag")?;
    validate_path::<DEPTH>(paths[0], "unshield input 0 path")?;
    validate_path::<DEPTH>(paths[1], "unshield input 1 path")?;
    if include_input_1 {
        if input_amounts[1] == 0 || input_rhos[1] == [0; 32] {
            return Err("present unshield input 1 must have non-zero amount and rho".to_owned());
        }
        canonical_nonzero_scalar(diversifiers[1], "unshield input 1 diversifier")?;
    } else if input_amounts[1] != 0 || input_rhos[1] != [0; 32] || diversifiers[1] != [0; 32] {
        return Err(
            "absent unshield input 1 opening must use the canonical all-zero form".to_owned(),
        );
    }
    Ok(())
}
pub(super) fn validate_unshield_v2_witness<const DEPTH: usize>(
    witness: &ConfidentialUnshieldWitnessV2,
) -> Result<(), String> {
    validate_unshield_inputs::<DEPTH>(
        witness.include_input_1,
        [witness.input_0_amount, witness.input_1_amount],
        [witness.input_0_rho, witness.input_1_rho],
        witness.spend_scalar,
        [witness.input_0_diversifier, witness.input_1_diversifier],
        witness.asset_tag,
        witness.network_tag,
        [&witness.input_0_path, &witness.input_1_path],
    )
}
pub(super) fn validate_unshield_v3_witness<const DEPTH: usize>(
    witness: &ConfidentialUnshieldWitnessV3,
) -> Result<(), String> {
    validate_unshield_inputs::<DEPTH>(
        witness.include_input_1,
        [witness.input_0_amount, witness.input_1_amount],
        [witness.input_0_rho, witness.input_1_rho],
        witness.spend_scalar,
        [witness.input_0_diversifier, witness.input_1_diversifier],
        witness.asset_tag,
        witness.network_tag,
        [&witness.input_0_path, &witness.input_1_path],
    )?;
    if witness.include_output_0 {
        if witness.output_0_amount == 0 || witness.output_0_rho == [0; 32] {
            return Err("present unshield output must have non-zero amount and rho".to_owned());
        }
    } else if witness.output_0_amount != 0 || witness.output_0_rho != [0; 32] {
        return Err("absent unshield output must use the canonical all-zero opening".to_owned());
    }
    Ok(())
}
