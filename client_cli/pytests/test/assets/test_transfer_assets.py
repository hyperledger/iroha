import allure  # type: ignore
import pytest

from common.consts import Stderr
from src.client_cli import client_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_transfer_asset():
    allure.dynamic.story("Account transfers assets")


@allure.label("sdk_test_id", "transfer_asset")
@allure.label("permission", "no_permission_required")
def test_transfer_asset(
    GIVEN_registered_account,
    GIVEN_currently_authorized_account,
    GIVEN_currently_account_quantity_with_two_quantity_of_asset,
):
    with allure.step(
        f"WHEN {GIVEN_currently_authorized_account.signatory} transfers 1 Quantity"
        f"of {GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name}"
        f"to {GIVEN_registered_account.signatory}"
    ):
        client_cli.transfer(
            asset=GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition,
            source_account=GIVEN_currently_authorized_account,
            target_account=GIVEN_registered_account,
            quantity="1",
        )

    with allure.step(
        f"THEN {GIVEN_currently_authorized_account.signatory} has 1 Quantity "
        f"of {GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name}"
        f"AND {GIVEN_registered_account} has 1 more Quantity"
    ):
        iroha.should(
            have.asset(
                f"{GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name}#"
                f"{GIVEN_currently_authorized_account.domain}#"
                f"{GIVEN_registered_account}"
            )
        )


@allure.label("sdk_test_id", "transfer_with_insufficient_funds")
@allure.label("permission", "no_permission_required")
def test_transfer_with_insufficient_funds(
    GIVEN_registered_account,
    GIVEN_currently_authorized_account,
    GIVEN_currently_account_quantity_with_two_quantity_of_asset,
):
    with allure.step(
        f"WHEN {GIVEN_currently_authorized_account.signatory} attempts to transfer more than available "
        f"Quantity of {GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name}"
        f"to {GIVEN_registered_account.signatory}"
    ):
        client_cli.transfer(
            asset=GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition,
            source_account=GIVEN_currently_authorized_account,
            target_account=GIVEN_registered_account,
            quantity=str(
                int(GIVEN_currently_account_quantity_with_two_quantity_of_asset.value)
                + 1
            ),
        )
    with allure.step(
        f"THEN {GIVEN_currently_authorized_account.signatory} still has the original Quantity "
        f"of {GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name}"
        f"AND {GIVEN_registered_account.signatory} does not receive any additional Quantity"
    ):
        client_cli.should(have.error(Stderr.INSUFFICIENT_FUNDS.value))


@allure.label("sdk_test_id", "exchange_asset_intermediary")
@allure.label("permission", "intermediary_permission_required")
@pytest.mark.xfail(reason="TO DO")
def test_exchange_asset_through_intermediary(
    GIVEN_registered_account,
    GIVEN_intermediary_with_transfer_permission,
    GIVEN_seller_account_with_btc,
    GIVEN_buyer_account_with_eth,
):
    # with allure.step(f'WHEN {GIVEN_intermediary_with_transfer_permission.name}'
    #                  f'exchanges BTC from {GIVEN_seller_account_with_btc.signatory}'
    #                  f'with ETH from {GIVEN_buyer_account_with_eth.signatory}'):
    #     client_cli.exchange_assets(
    #         intermediary_account=GIVEN_intermediary_with_transfer_permission,
    #         seller_account=GIVEN_seller_account_with_btc,
    #         buyer_account=GIVEN_buyer_account_with_eth,
    #         btc_quantity="1",
    #         eth_quantity="10")
    #
    # with allure.step(f'THEN {GIVEN_seller_account_with_btc.signatory} receives ETH '
    #                  f'AND {GIVEN_buyer_account_with_eth.signatory} receives BTC'):
    #     iroha.should(have.asset(
    #         f'eth#{GIVEN_seller_account_with_btc.domain}', quantity="10"))
    #     iroha.should(have.asset(
    #         f'btc#{GIVEN_buyer_account_with_eth.domain}', quantity="1"))
    assert 0


@allure.label("sdk_test_id", "transfer_user_asset")
@allure.label("permission", "can_transfer_user_asset")
@pytest.mark.xfail(reason="TO DO")
def test_transfer_user_asset(
    GIVEN_registered_account, GIVEN_currently_authorized_account
):
    assert 0
