//! Exact native-workspace bit/carry construction, independently of acceptance.

use super::*;

fn program() -> Program {
    use ivm::encoding::wide as enc;
    Program::new(super::super::tests::contract(
        &[
            enc::encode_jump(wide::control::JAL, 1, 4),
            enc::encode_offset24(wide::control::JALS, 3),
            enc::encode_store(wide::memory::STORE64, 2, 3, -8),
            enc::encode_ri(wide::control::JALR, 0, 1, 0),
        ],
        1_000,
        ivm::ivm_mode::ZK,
    ))
    .unwrap()
}

#[test]
fn native_subset_rejects_coherent_shared_calls_and_nonroot_returns() {
    use super::super::tests::Fixture;
    let program = program();
    for (slot, root) in [(0, false), (1, false), (3, false)] {
        let fixture = Fixture::new(&program, slot, root, 0);
        assert!(fixture.accepts(&program), "valid shared role {slot}");
        let mut residues = Vec::new();
        append_subset_residues(&mut residues, &program, &fixture.row, &fixture.packets);
        assert!(residues.iter().any(|value| *value != F::ZERO));
    }
    for selection in [Some((2, false)), Some((3, true)), None] {
        let fixture = selection.map_or_else(Fixture::padding, |(slot, root)| {
            Fixture::new(&program, slot, root, 0)
        });
        assert!(fixture.accepts(&program));
        let mut residues = Vec::new();
        append_subset_residues(&mut residues, &program, &fixture.row, &fixture.packets);
        assert!(residues.iter().all(|value| *value == F::ZERO));
    }
}

#[test]
fn native_subset_equations_have_degree_two_in_original_fetch_and_parent() {
    use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
    let program = program();
    let degree = measured_maximum_affine_degree_v1(
        [0x78; 32],
        [WIDTH + PORTS * packet::WIDTH, 0, 0, 0, 0],
        8,
        2,
        |row, _, _, _, _| {
            let packets = OriginalPackets::candidate(core::array::from_fn(|slot| {
                row[WIDTH + slot * packet::WIDTH..WIDTH + (slot + 1) * packet::WIDTH]
                    .try_into()
                    .unwrap()
            }));
            let mut residues = Vec::new();
            append_subset_residues(
                &mut residues,
                &program,
                row[..WIDTH].try_into().unwrap(),
                &packets,
            );
            Ok::<_, core::convert::Infallible>(residues)
        },
    );
    assert_eq!(degree, 2);
}

#[test]
fn bit_and_limb_transfers_cover_full_unsigned_width() {
    for value in [0, 1, 0xffff, 0x1_0000, 1 << 63, u64::MAX] {
        let mut encoded = [F::ZERO; 64];
        bits(&mut encoded, value);
        assert_eq!(
            encoded
                .iter()
                .enumerate()
                .fold(0_u64, |word, (bit, field)| word | field.0 << bit),
            value
        );
        for right in [0, 1, 127, u64::MAX] {
            let mut carry = [F::ZERO; 4];
            carries(&mut carry, value, right, false);
            assert_eq!(carry[3], F(u64::from(value.overflowing_add(right).1)));
            carries(&mut carry, value, right, true);
            assert_eq!(carry[3], F(u64::from(value.overflowing_sub(right).1)));
            for limb in 0..4 {
                let shift = (limb + 1) * 16;
                let mask = if shift == 64 {
                    u64::MAX
                } else {
                    (1_u64 << shift) - 1
                };
                assert_eq!(carry[limb], F(u64::from((value & mask) < (right & mask))));
            }
        }
    }
}
