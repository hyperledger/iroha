//! Genuine catalog-width regression across the glue gate's three-term boundary.
use super::*;

fn wide_catalog<C: PastaCurve>() {
    let source = example_for::<C>(&TaggedSquare(32));
    let mut keys = (1..32)
        .map(|tag| {
            keygen_pk_v2(
                &source.plan.params,
                &TaggedSquare(tag),
                &KeygenConfigV2::pipa_r(vec![InstanceType::Bits(4)]),
            )
            .unwrap()
            .vk()
            .clone()
        })
        .collect::<Vec<_>>();
    keys.push(source.key.clone());
    for count in [4, 32] {
        let mut circuit = source.clone();
        circuit.catalog_keys = keys[..count - 1].to_vec();
        circuit.catalog_keys.push(source.key.clone());
        circuit.catalog_index = Some(count - 1);
        circuit.hard = true;
        let public = vec![circuit.expected()];
        assert!(
            check_circuit(&circuit, 16, &public, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        let cells = circuit.catalog_cells.borrow().clone();
        let coordinates = |key: &VerifyingKey<C>| {
            key.fixed_commitments()
                .iter()
                .chain(key.permutation_commitments())
                .flat_map(|point| {
                    let (x, y) = point.coordinates().unwrap();
                    [x, y]
                })
                .collect::<Vec<_>>()
        };
        let actual = coordinates(&source.key);
        let foreign = coordinates(&keys[0]);
        let mutation = cells
            .iter()
            .zip(actual.iter().zip(&foreign))
            .find_map(|(cell, (actual, foreign))| {
                (actual != foreign).then_some(iroha_plonk_gadgets::tamper::Tamper {
                    column: cell.column.index(),
                    row: cell.row_offset,
                    delta: *foreign - actual,
                })
            })
            .expect("different genuine key has a different constrained coordinate");
        assert!(
            !iroha_plonk_gadgets::tamper::check_tampered(&circuit, 16, &public, Some(mutation))
                .unwrap()
                .is_satisfied()
        );
        for index in [0, count] {
            let mut changed = circuit.clone();
            changed.catalog_index = Some(index);
            assert!(
                !check_circuit(&changed, 16, &public, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied()
            );
        }
        let known = iroha_plonk::frontend::synthesize(&circuit, 16, Some(&public)).unwrap();
        let unknown =
            iroha_plonk::frontend::synthesize(&circuit.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.selectors(), unknown.tables.selectors());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
    }
}

#[test]
fn four_and_thirty_two_catalog_keys_bind_every_tail_term_both_curves() {
    wide_catalog::<Ep>();
    wide_catalog::<Eq>();
}
