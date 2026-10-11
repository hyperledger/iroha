//! Route escrows and their custody guards (`specs/sccp.md` §4.15). Owner: ws32; ws20
//! implemented the escrow identity and recognition.
//!
//! One core-created escrow account per route, derived from the live `NetworkId` without the
//! revision and created at genesis. Core rejects every non-SCCP debit, credit, registration or
//! unregistration of it (the guards live in `asset.rs` and `domain.rs` and call
//! [`is_escrow`]), and `balance(escrow(route)) = Σ_r liability(r) + stranded(route)`.
//!
//! Only three movements touch an escrow: [`lock`] (credit by `RecordSccpMessage`), [`release`]
//! (debit by an inbound release, an outbound refund or a Parliament-enacted
//! `ReleaseStranded`) and [`strand`], which keeps the amount in the escrow and books it as
//! `stranded(route)`. Liability bookkeeping belongs to the callers. [`precheck_release`] runs
//! every guard of a release without mutating state, so settlement can hold a message whose
//! credit the movement would refuse.

use super::{Error, store};
use crate::{
    smartcontracts::{Execute, isi::asset::isi as asset_isi},
    state::{StateReadOnly, StateTransaction, WorldReadOnly},
};
use iroha_data_model::{
    NetworkId,
    account::{Account, AccountId},
    asset::AssetId,
    bridge::SccpNetworkV1,
    isi::Register,
    sccp::{
        escrow::{sccp_taira_xor_asset_definition_id, sccp_xor_route_escrow_account_id_v1},
        registry::{SCCP_ROUTE_NETWORKS_V1, SccpRouteV1},
    },
};
use iroha_primitives::numeric::{Numeric, Quantity};

/// Decimal scale of Taira XOR; every SCCP amount is in these Taira units (§0, §3.2).
pub const SCCP_XOR_SCALE: u32 = 9;

/// Return the escrow account of `network`'s route under `network_id`, or `None` for the Taira
/// profile, which has no route.
#[must_use]
pub fn escrow_account(network_id: &NetworkId, network: SccpNetworkV1) -> Option<AccountId> {
    sccp_xor_route_escrow_account_id_v1(network_id, network)
}

/// Convert `amount` Taira units into the canonical XOR quantity.
///
/// # Errors
///
/// Fails when the amount does not form a canonical quantity.
pub fn xor_quantity(amount: u128) -> Result<Quantity, Error> {
    Numeric::try_new(amount, SCCP_XOR_SCALE)
        .map_err(|error| error.to_string())
        .and_then(|numeric| Quantity::try_from_numeric(numeric).map_err(|error| error.to_string()))
        .map_err(|error| {
            Error::InvariantViolation(
                format!("SCCP: amount {amount} is not a quantity: {error}").into(),
            )
        })
}

/// Create the three route escrow accounts and empty routes (genesis, §4.1).
///
/// Each escrow is registered as its own authority with the effects and events of an ordinary
/// `Register<Account>`, before its route exists, so the escrow guards cannot refuse it; once
/// the route is stored, no ordinary registration or unregistration of it succeeds.
///
/// # Errors
///
/// Fails when a route or escrow account already exists.
pub fn create_route_escrows(state_transaction: &mut StateTransaction<'_, '_>) -> Result<(), Error> {
    let network_id = *state_transaction.network_id();
    for network in SCCP_ROUTE_NETWORKS_V1 {
        if store::routes::contains(&*state_transaction.world, &network) {
            return Err(Error::InvariantViolation(
                format!("SCCP: route {} already exists", network.profile_key()).into(),
            ));
        }
        let escrow = escrow_account(&network_id, network).ok_or_else(|| {
            Error::InvariantViolation(
                format!("SCCP: {} has no route", network.profile_key()).into(),
            )
        })?;
        Register::account(Account::new(escrow.clone())).execute(&escrow, state_transaction)?;
        let route = SccpRouteV1::empty(network, escrow).ok_or_else(|| {
            Error::InvariantViolation(
                format!("SCCP: {} has no route", network.profile_key()).into(),
            )
        })?;
        store::routes::insert(state_transaction, network, route)?;
    }
    Ok(())
}

/// Return the XOR balance id of `network`'s registered route escrow.
fn escrow_asset(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
) -> Result<AssetId, Error> {
    let route = store::routes::get(world, &network).ok_or_else(|| {
        Error::InvariantViolation(
            format!("SCCP: route {} is not registered", network.profile_key()).into(),
        )
    })?;
    Ok(AssetId::of(
        sccp_taira_xor_asset_definition_id(),
        route.escrow.clone(),
    ))
}

/// Lock `amount` Taira units of XOR from `from` into `network`'s route escrow for the outbound
/// message `message_id`.
///
/// `from` must be the transaction authority: only its own balance can be locked.
///
/// # Errors
///
/// Fails when the route is not registered or the transfer is refused (balance, policy).
pub fn lock(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    from: &AccountId,
    amount: u128,
    message_id: [u8; 32],
) -> Result<(), Error> {
    let escrow = escrow_asset(&*state_transaction.world, network)?;
    let source = AssetId::of(escrow.definition().clone(), from.clone());
    asset_isi::execute_sccp_escrow_lock(
        state_transaction,
        from,
        source,
        escrow,
        xor_quantity(amount)?,
        message_id,
    )
}

/// Release `amount` Taira units of XOR from `network`'s route escrow to the existing account
/// `to`, bound to the record `record_id`.
///
/// # Errors
///
/// Fails when the route is not registered, `to` does not exist or transfer control refuses
/// the credit.
pub fn release(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    to: &AccountId,
    amount: u128,
    record_id: [u8; 32],
) -> Result<(), Error> {
    let escrow = escrow_asset(&*state_transaction.world, network)?;
    let destination = AssetId::of(escrow.definition().clone(), to.clone());
    asset_isi::execute_sccp_escrow_release(
        state_transaction,
        escrow,
        destination,
        xor_quantity(amount)?,
        record_id,
    )
}

/// Check, without mutating state, that [`release`] of `amount` Taira units from `network`'s
/// route escrow to the existing account `to` passes every guard of the release movement
/// (§4.12.3 step 6, §4.16).
///
/// # Errors
///
/// Returns the refusal the release would report: the route is not registered, `to` does not
/// exist, or the movement's transfer control, holding limit, custody, usage or privacy policy
/// refuses the credit.
pub fn precheck_release(
    state_transaction: &StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    to: &AccountId,
    amount: u128,
) -> Result<(), Error> {
    let escrow = escrow_asset(&*state_transaction.world, network)?;
    let destination = AssetId::of(escrow.definition().clone(), to.clone());
    asset_isi::precheck_sccp_escrow_release(
        state_transaction,
        &escrow,
        &destination,
        &xor_quantity(amount)?,
    )
}

/// Book `amount` Taira units that stay in `network`'s escrow as `stranded(route)` (§4.16).
///
/// # Errors
///
/// Fails when the route is not registered or `stranded` would overflow.
pub fn strand(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    amount: u128,
) -> Result<(), Error> {
    let mut route = store::routes::get(&*state_transaction.world, &network)
        .cloned()
        .ok_or_else(|| {
            Error::InvariantViolation(
                format!("SCCP: route {} is not registered", network.profile_key()).into(),
            )
        })?;
    route.stranded = route
        .stranded
        .checked_add(amount)
        .ok_or_else(|| Error::InvariantViolation("SCCP: stranded amount overflows".into()))?;
    store::routes::insert(state_transaction, network, route)?;
    Ok(())
}

/// Return whether `account` is the escrow of a registered route.
#[must_use]
pub fn is_escrow(world: &(impl WorldReadOnly + ?Sized), account: &AccountId) -> bool {
    store::routes::iter(world).any(|(_, route)| route.escrow == *account)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        smartcontracts::isi::sccp::test_support::{authority, blank_state, header},
        state::{State, World},
    };
    use iroha_data_model::{
        Registrable,
        asset::{AssetBalancePolicy, AssetDefinition},
        isi::{Burn, Mint, Transfer, Unregister},
    };
    use mv::storage::StorageReadOnly;

    /// State with the Taira XOR definition and `holder` funded with `balance` Taira units.
    fn funded_state(holder: &AccountId, balance: u128) -> State {
        let xor = sccp_taira_xor_asset_definition_id();
        let definition = AssetDefinition::numeric(
            xor.clone(),
            "XOR".to_owned(),
            AssetBalancePolicy::Global,
            None,
        )
        .build(holder);
        let world = World::with_assets(
            [],
            [Account::new(holder.clone()).build(holder)],
            [definition],
            [iroha_data_model::asset::Asset::new(
                AssetId::of(xor, holder.clone()),
                xor_quantity(balance).expect("quantity"),
            )],
            [],
        );
        State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        )
    }

    fn balance(stx: &StateTransaction<'_, '_>, account: &AccountId) -> Quantity {
        stx.world
            .assets
            .get(&AssetId::of(
                sccp_taira_xor_asset_definition_id(),
                account.clone(),
            ))
            .map(|value| value.as_ref().clone())
            .unwrap_or_else(Quantity::zero)
    }

    #[test]
    fn escrows_are_per_route_and_bound_to_the_network_id() {
        let state = blank_state();
        let network_id = state.network_id;
        let eth = escrow_account(&network_id, SccpNetworkV1::EthereumMainnet).expect("route");
        let ton = escrow_account(&network_id, SccpNetworkV1::TonMainnet).expect("route");
        assert_ne!(eth, ton);
        assert_eq!(escrow_account(&network_id, SccpNetworkV1::SoraTaira), None);
    }

    #[test]
    fn taira_units_are_scale_nine_quantities() {
        assert_eq!(
            xor_quantity(1_000_000_000).expect("one XOR"),
            Quantity::try_from_numeric(Numeric::new(1_u32, 0)).expect("one")
        );
        assert_eq!(xor_quantity(1).expect("nano").scale(), 9);
        assert!(xor_quantity(0).expect("zero").is_zero());
    }

    #[test]
    fn genesis_creates_three_registered_escrows_once() {
        let state = blank_state();
        let mut block = state.block(header(1));
        let mut stx = block.transaction();
        create_route_escrows(&mut stx).expect("escrows");
        assert_eq!(
            store::routes::iter(&*stx.world)
                .map(|(network, _)| *network)
                .collect::<Vec<_>>(),
            [
                SccpNetworkV1::EthereumMainnet,
                SccpNetworkV1::BscMainnet,
                SccpNetworkV1::TonMainnet
            ],
            "one escrow per route network"
        );
        let network_id = *stx.network_id();
        for network in SCCP_ROUTE_NETWORKS_V1 {
            let escrow = escrow_account(&network_id, network).expect("route");
            assert!(
                stx.world.account(&escrow).is_ok(),
                "{network:?} escrow registered"
            );
            assert!(is_escrow(&*stx.world, &escrow));
            let route = store::routes::get(&*stx.world, &network).expect("route");
            assert_eq!(route.escrow, escrow);
            assert!(route.revisions.is_empty());
            assert_eq!(route.stranded, 0);
        }
        assert!(!is_escrow(&*stx.world, &authority(1)));
        let error = create_route_escrows(&mut stx).expect_err("second creation");
        assert!(error.to_string().contains("already exists"), "{error}");
    }

    #[test]
    fn escrow_accounts_cannot_be_registered_or_unregistered_ordinarily() {
        let state = blank_state();
        let mut block = state.block(header(1));
        let mut stx = block.transaction();
        create_route_escrows(&mut stx).expect("escrows");
        let escrow = escrow_account(stx.network_id(), SccpNetworkV1::BscMainnet).expect("route");
        let error = Unregister::account(escrow.clone())
            .execute(&authority(1), &mut stx)
            .expect_err("unregister escrow");
        assert!(error.to_string().contains("SCCP route escrow"), "{error}");
        assert!(stx.world.account(&escrow).is_ok());
    }

    #[test]
    fn lock_and_release_move_xor_through_the_escrow_only() {
        let holder = authority(1);
        let state = funded_state(&holder, 5_000_000_000);
        let mut block = state.block(header(1));
        // This direct component fixture retains a bounded invocation; it does
        // not authenticate a network transaction or grant publication authority.
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::new(
            b"sccp-escrow-lock-release-component",
        ));
        create_route_escrows(&mut stx).expect("escrows");
        let network = SccpNetworkV1::EthereumMainnet;
        let escrow = escrow_account(stx.network_id(), network).expect("route");

        lock(&mut stx, network, &holder, 2_000_000_000, [1; 32]).expect("lock");
        assert_eq!(balance(&stx, &escrow), xor_quantity(2_000_000_000).unwrap());
        assert_eq!(balance(&stx, &holder), xor_quantity(3_000_000_000).unwrap());

        let error = lock(&mut stx, network, &holder, 9_000_000_000, [2; 32]).expect_err("overdraw");
        assert!(!error.to_string().is_empty());

        release(&mut stx, network, &holder, 500_000_000, [3; 32]).expect("release");
        assert_eq!(balance(&stx, &escrow), xor_quantity(1_500_000_000).unwrap());
        assert_eq!(balance(&stx, &holder), xor_quantity(3_500_000_000).unwrap());

        let unknown = authority(9);
        precheck_release(&stx, network, &unknown, 1).expect_err("absent recipient");
        release(&mut stx, network, &unknown, 1, [4; 32]).expect_err("absent recipient");
        precheck_release(&stx, network, &holder, 1_500_000_000).expect("the whole escrow");
        precheck_release(&stx, network, &holder, 1_500_000_001).expect_err("beyond the escrow");
        precheck_release(&stx, network, &holder, 0).expect_err("a zero release");
        precheck_release(&stx, network, &escrow, 1).expect_err("an escrow destination");
        precheck_release(&stx, SccpNetworkV1::BscMainnet, &holder, 1)
            .expect_err("another route's escrow is empty");
        release(&mut stx, SccpNetworkV1::BscMainnet, &holder, 1, [5; 32])
            .expect_err("another route's escrow is empty");
    }

    #[test]
    fn ordinary_instructions_cannot_touch_an_escrow() {
        let holder = authority(1);
        let state = funded_state(&holder, 5_000_000_000);
        let mut block = state.block(header(1));
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::new(
            b"sccp-escrow-ordinary-instructions-component",
        ));
        create_route_escrows(&mut stx).expect("escrows");
        let network = SccpNetworkV1::TonMainnet;
        let escrow = escrow_account(stx.network_id(), network).expect("route");
        lock(&mut stx, network, &holder, 1_000_000_000, [1; 32]).expect("lock");
        let xor = sccp_taira_xor_asset_definition_id();
        let escrow_asset = AssetId::of(xor.clone(), escrow.clone());
        let one = xor_quantity(1).expect("quantity");

        let credit = Transfer::asset_quantity(
            AssetId::of(xor.clone(), holder.clone()),
            one.clone(),
            escrow.clone(),
        )
        .execute(&holder, &mut stx)
        .expect_err("ordinary credit of an escrow");
        assert!(credit.to_string().contains("SCCP route escrow"), "{credit}");
        let debit = Transfer::asset_quantity(escrow_asset.clone(), one.clone(), holder.clone())
            .execute(&holder, &mut stx)
            .expect_err("ordinary debit of an escrow");
        assert!(!debit.to_string().is_empty());
        let burn = Burn::asset_quantity(one.clone(), escrow_asset.clone())
            .execute(&holder, &mut stx)
            .expect_err("definition-owner burn of an escrow");
        assert!(burn.to_string().contains("SCCP route escrow"), "{burn}");
        let mint = Mint::asset_quantity(one, escrow_asset)
            .execute(&holder, &mut stx)
            .expect_err("mint into an escrow");
        assert!(mint.to_string().contains("SCCP route escrow"), "{mint}");
        assert_eq!(balance(&stx, &escrow), xor_quantity(1_000_000_000).unwrap());
    }

    #[test]
    fn stranding_books_the_amount_on_the_route() {
        let state = blank_state();
        let mut block = state.block(header(1));
        let mut stx = block.transaction();
        strand(&mut stx, SccpNetworkV1::TonMainnet, 1).expect_err("no route yet");
        create_route_escrows(&mut stx).expect("escrows");
        strand(&mut stx, SccpNetworkV1::TonMainnet, 7).expect("strand");
        strand(&mut stx, SccpNetworkV1::TonMainnet, 3).expect("strand");
        let route = store::routes::get(&*stx.world, &SccpNetworkV1::TonMainnet).expect("route");
        assert_eq!(route.stranded, 10);
        strand(&mut stx, SccpNetworkV1::TonMainnet, u128::MAX).expect_err("overflow");
    }
}
