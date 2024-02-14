import allure
import pytest

from src.client_cli import client_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_unregisters_asset():
    allure.dynamic.story('Account unregisters an asset')
    allure.dynamic.label('permission', 'no_permission_required')


@allure.label('sdk_test_id', 'unregister_asset')
@pytest.mark.parametrize("GIVEN_quantity_asset_for_account", ["alice@wonderland"], indirect=True)
@pytest.mark.xfail(reason="wait for #4039")
def test_unregister_asset(
        GIVEN_quantity_asset_for_account,
):
    with allure.step(
            f'WHEN client_cli unregisters the asset "{GIVEN_quantity_asset_for_account.definition.name}"'):
        client_cli.unregister_asset(
            asset_id= f'{GIVEN_quantity_asset_for_account.definition.name}#{GIVEN_quantity_asset_for_account.account}@{GIVEN_quantity_asset_for_account.definition.domain}')
    with allure.step(
            f'THEN Iroha should not have the asset "{GIVEN_quantity_asset_for_account.definition.name}"'):
        iroha.should(have.asset(
            f'{GIVEN_quantity_asset_for_account.definition.name}##{GIVEN_quantity_asset_for_account.account}@{GIVEN_quantity_asset_for_account.definition.domain}'))
