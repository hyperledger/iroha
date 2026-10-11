//! Actual signed genesis authority and complete unchanged frozen-window controls.

use super::super::ownership_tests::authenticated_source;
use super::*;

#[test]
fn signed_genesis_authority_keeps_original_wider_cutoff_and_authenticates_no_h1_result() {
    let (source, authority, clock, _roster, _budget) = authenticated_source(4, 1000);
    let epoch = crate::sumeragi::epoch::authenticated_genesis(source.genesis.block())
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    assert_eq!(authority.cutoff(), epoch.authorization.last_height - 1);
    assert!(authority.cutoff() > authority.session().acceptances_end_height);
    let signer = &source.validator_keys[0];
    let checked = authority
        .checkpoint_context(
            &clock,
            1,
            1,
            signer,
            "software-provider",
            7,
            [11; 32],
            [0; 32],
            [0; 32],
            [12; 32],
        )
        .unwrap();
    assert_eq!(
        checked.binding().source,
        DkgCheckpointSourceV1::SignedGenesisAuthorization {
            genesis_hash: *epoch.network_id.as_bytes()
        }
    );
    assert_eq!(checked.binding().authority_generation, 0);
    assert_eq!(checked.binding().cutoff_height, authority.cutoff());
    for phase in [2, 3] {
        assert!(
            authority
                .checkpoint_context(
                    &clock,
                    phase,
                    1,
                    signer,
                    "software-provider",
                    7,
                    [11; 32],
                    [13; 32],
                    [14; 32],
                    [12; 32]
                )
                .is_err(),
            "a signed H1 body cannot substitute for a genuine finalized phase source"
        );
    }
    let (_foreign, _, foreign_clock, _, _) = authenticated_source(4, 2000);
    assert!(
        authority
            .checkpoint_context(
                &foreign_clock,
                1,
                1,
                signer,
                "software-provider",
                7,
                [11; 32],
                [0; 32],
                [0; 32],
                [12; 32]
            )
            .is_err()
    );
}
