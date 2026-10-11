//! Canonical funded asset custody for State restoration tests.

use super::*;

/// Initialize snapshot fixture custody through the canonical registration and mint paths.
#[cfg(test)]
pub(super) fn registered_custody_world_for_test(
    world: World,
    asset: &AssetId,
    balance: Quantity,
) -> World {
    use crate::smartcontracts::Execute as _;
    use iroha_data_model::isi::{Mint, Register};

    let npos = iroha_data_model::parameter::system::SumeragiNposParameters::default();
    assert_eq!(
        asset.definition(),
        &npos.xor_asset_definition_id,
        "positive custody fixtures use canonical network XOR"
    );
    {
        let mut parameters = world.parameters.block();
        parameters
            .get_mut()
            .set_parameter(Parameter::Custom(npos.into_custom_parameter()));
        parameters.commit();
    }
    let state = State::new(
        world,
        Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    );
    {
        let header = BlockHeader::new(std::num::NonZeroU64::new(1).unwrap(), None, None, 0, 0);
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        Register::asset_definition(AssetDefinition::new(
            asset.definition().clone(),
            "Custody reserve",
            iroha_primitives::numeric::NumericSpec::fractional(9),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .execute(asset.account(), &mut transaction)
        .expect("register fixture custody definition and its canonical AXT incarnation");
        Mint::asset_quantity(balance, asset.clone())
            .execute(asset.account(), &mut transaction)
            .expect("fund fixture custody through canonical asset mutation");
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit fixture custody registration");
    }
    // Subsequent fixtures seed liabilities in this baseline. Both snapshot cuts must
    // therefore contain the registered asset, its incarnation, and its backing balance.
    state.world.block().commit();
    state.world
}
