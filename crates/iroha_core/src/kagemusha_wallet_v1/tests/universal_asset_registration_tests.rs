//! Universal assets use the same exact reserve and routing path without a token allowlist.

use super::*;

#[test]
fn universal_registration_accepts_arbitrary_asset_ids_and_scales_without_parliament() {
    use iroha_data_model::isi::kagemusha_wallet::{
        KagemushaWalletLedgerActionV1 as Action, KagemushaWalletLedgerV1,
    };
    use iroha_model_base::topology::DataSpaceId;

    for (index, scale) in [0, 2, iroha_primitives::numeric::MAX_DECIMAL_SCALE]
        .into_iter()
        .enumerate()
    {
        let mut memory = Memory::new();
        let mut asset_uuid = [u8::try_from(index + 1).unwrap(); 16];
        asset_uuid[6] = (asset_uuid[6] & 0x0f) | 0x40;
        asset_uuid[8] = (asset_uuid[8] & 0x3f) | 0x80;
        memory.registration.asset.asset =
            iroha_data_model::asset::AssetDefinitionId::from_uuid_bytes(asset_uuid).unwrap();
        memory.registration.asset.asset_incarnation =
            *iroha_crypto::Hash::new([u8::try_from(index + 1).unwrap(); 32]).as_ref();
        memory.registration.asset.scale = scale;
        let mut state = world_state(&memory, true);
        let balances = (
            balance(&state, &memory, &memory.authority),
            balance(&state, &memory, &memory.registration.reserve),
        );
        register(&mut state, &memory, 1).unwrap();
        let scheme = memory.registration.scheme.scheme_id();
        let asset = memory.registration.asset.asset_digest();
        let view = state.view();
        let stored: Registration = storage::decode(
            view.world
                .kagemusha_wallet_ledger()
                .get(&storage::key(storage::REGISTRATION, scheme, asset))
                .unwrap(),
            4096,
        )
        .unwrap();
        assert_eq!(stored.asset, memory.registration.asset);
        assert_eq!(stored.balance_scope, AssetBalanceScope::Global);
        // A later operation routes from the exact immutable registration, with no token name,
        // Parliament membership, bank classification or privileged fixture account selection.
        let instruction = KagemushaWalletLedgerV1 {
            scheme,
            action: Action::InstallVerifierPack {
                asset,
                manifest_digest: [7; 32],
                pack: vec![],
            },
        };
        assert_eq!(
            routing::dataspace(&view.world, &instruction).unwrap(),
            DataSpaceId::UNIVERSAL
        );
        assert_eq!(
            balances,
            (
                balance(&state, &memory, &memory.authority),
                balance(&state, &memory, &memory.registration.reserve)
            )
        );
    }
}
