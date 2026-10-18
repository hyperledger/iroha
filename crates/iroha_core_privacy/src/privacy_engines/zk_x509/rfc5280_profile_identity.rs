//! Bind closed-profile choices to authenticated extension ordinals and documents.
//!
//! Byte-table membership alone does not select the OID appropriate to an
//! original extension ordinal, or the `KeyUsage` appropriate to a leaf or CA.
//! These equations use the original grammar/node identity, with exact zero-safe
//! classifications and no new public witness metadata.
use super::*;

const FIXED_FLAGS: usize = BASE_SMALL_BITS + 12;
const KU_LEAF: usize = FIXED_FLAGS + 6;
const NODE_FLAGS: usize = name_policy::NODE_PREFIX_END;
pub(super) const NODE_PREFIX_END: usize = NODE_FLAGS + 10;
pub(super) const RESIDUES: usize = 43;
const _: () = assert!(KU_LEAF + 2 <= BASE_ACTIVE);
const _: () = assert!(NODE_PREFIX_END <= CALENDAR_END);

fn classification<A: PolynomialAirFieldV1>(
    output: &mut [A; RESIDUES],
    index: &mut usize,
    family: A,
    active: A,
    target: A,
    flag: A,
    inverse: A,
    delta: A,
    subfamily: bool,
) {
    for residue in [
        flag.mul(flag.sub(A::ONE)),
        flag.mul(delta),
        delta.mul(inverse).sub(target).add(flag),
        flag.mul(inverse),
    ] {
        output[*index] = family.mul(residue);
        *index += 1;
    }
    if subfamily {
        output[*index] = family.mul(active.sub(target)).mul(inverse);
        *index += 1;
    }
}

pub(super) fn residues<A: PolynomialAirFieldV1>(
    row: &ZkX509Rfc5280StarkBaseRowV1<A>,
    fixed: &ZkX509Rfc5280StarkFixedRowV1<A>,
) -> [A; RESIDUES] {
    let mut output = [A::ZERO; RESIDUES];
    let mut index = 0;
    let active = row[BASE_ACTIVE];
    let bytes = fixed[ZkX509Rfc5280StarkFamilyV1::FixedByte as usize];
    for (slot, purpose) in [6, 7, 10].into_iter().enumerate() {
        classification(
            &mut output,
            &mut index,
            bytes,
            active,
            active,
            row[FIXED_FLAGS + 2 * slot],
            row[FIXED_FLAGS + 2 * slot + 1],
            row[BASE_ROLE].sub(A::from_base(F(purpose))),
            false,
        );
    }
    let ku = row[FIXED_FLAGS + 4];
    classification(
        &mut output,
        &mut index,
        bytes,
        active,
        ku,
        row[KU_LEAF],
        row[KU_LEAF + 1],
        row[BASE_DOCUMENT]
            .sub(A::from_base(F(5)))
            .sub(row[BASE_CERT2_ACTIVE]),
        true,
    );
    output[index] = bytes
        .mul(row[FIXED_FLAGS].add(row[FIXED_FLAGS + 2]))
        .mul(row[BASE_ENDPOINT_ROLE].sub(row[BASE_H]));
    index += 1;
    output[index] = bytes
        .mul(ku)
        .mul(row[BASE_ENDPOINT_ROLE].sub(A::ONE.sub(row[KU_LEAF])));
    index += 1;

    let node = fixed[ZkX509Rfc5280StarkFamilyV1::SourceNode as usize];
    for (slot, role) in [
        ZkX509Rfc5280GrammarRoleV1::CertificateExtensions,
        ZkX509Rfc5280GrammarRoleV1::CertificateExtension,
    ]
    .into_iter()
    .enumerate()
    {
        classification(
            &mut output,
            &mut index,
            node,
            active,
            active,
            row[NODE_FLAGS + 2 * slot],
            row[NODE_FLAGS + 2 * slot + 1],
            row[BASE_ROLE].sub(A::from_base(F(role as u64))),
            false,
        );
    }
    classification(
        &mut output,
        &mut index,
        node,
        active,
        active,
        row[NODE_FLAGS + 4],
        row[NODE_FLAGS + 5],
        row[BASE_DOCUMENT],
        false,
    );
    let extension = row[NODE_FLAGS + 2];
    for ordinal in 0..2 {
        classification(
            &mut output,
            &mut index,
            node,
            active,
            extension,
            row[NODE_FLAGS + 6 + 2 * ordinal],
            row[NODE_FLAGS + 7 + 2 * ordinal],
            row[BASE_INSTANCE].sub(A::from_base(F(ordinal as u64))),
            true,
        );
    }
    output[index] = node
        .mul(row[NODE_FLAGS])
        .mul(row[BASE_D].sub(A::from_base(F(4))).sub(row[NODE_FLAGS + 4]));
    index += 1;
    output[index] = node.mul(extension).mul(
        row[BASE_D]
            .sub(A::from_base(F(3)))
            .add(row[NODE_FLAGS + 6])
            .add(row[NODE_FLAGS + 8]),
    );
    index += 1;
    assert_eq!(index, RESIDUES);
    output
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
fn populate_classification(
    row: &mut ZkX509Rfc5280StarkBaseRowV1,
    column: usize,
    gate: F,
    delta: F,
) {
    row[column] = gate.mul(F(u64::from(delta == F::ZERO)));
    row[column + 1] = gate.mul(delta.inverse_or_zero_canonical_v1());
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn populate_fixed_byte(row: &mut ZkX509Rfc5280StarkBaseRowV1, certificate_two: F) {
    let active = row[BASE_ACTIVE];
    for (slot, purpose) in [6, 7, 10].into_iter().enumerate() {
        let delta = row[BASE_ROLE].sub(F(purpose));
        populate_classification(row, FIXED_FLAGS + 2 * slot, active, delta);
    }
    let gate = row[FIXED_FLAGS + 4];
    let delta = row[BASE_DOCUMENT].sub(F(5)).sub(certificate_two);
    populate_classification(row, KU_LEAF, gate, delta);
}

#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(super) fn populate_source_node(row: &mut ZkX509Rfc5280StarkBaseRowV1) {
    let active = row[BASE_ACTIVE];
    for (slot, role) in [
        ZkX509Rfc5280GrammarRoleV1::CertificateExtensions,
        ZkX509Rfc5280GrammarRoleV1::CertificateExtension,
    ]
    .into_iter()
    .enumerate()
    {
        let delta = row[BASE_ROLE].sub(F(role as u64));
        populate_classification(row, NODE_FLAGS + 2 * slot, active, delta);
    }
    let document = row[BASE_DOCUMENT];
    populate_classification(row, NODE_FLAGS + 4, active, document);
    let gate = row[NODE_FLAGS + 2];
    for ordinal in 0..2 {
        let delta = row[BASE_INSTANCE].sub(F(ordinal as u64));
        populate_classification(row, NODE_FLAGS + 6 + 2 * ordinal, gate, delta);
    }
}

#[cfg(test)]
#[path = "rfc5280_profile_identity_tests.rs"]
mod tests;
