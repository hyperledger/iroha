import allure
import pytest

from src.client_cli import client_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_transfer_asset():
    allure.dynamic.story('Account transfers assets')

@allure.label('sdk_test_id', 'transfer_asset')
@allure.label('permission', 'no_permission_required')
def test_transfer_asset(
        GIVEN_new_one_existence_account,
        GIVEN_currently_authorized_account,
        GIVEN_currently_account_quantity_with_two_quantity_of_asset):
    with allure.step(f'WHEN {GIVEN_currently_authorized_account.name} transfers 1 Quantity'
                     f'of {GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name}'
                     f'to {GIVEN_new_one_existence_account.name}'):
        client_cli.transfer(
            asset=GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition,
            source_account=GIVEN_currently_authorized_account,
            target_account=GIVEN_new_one_existence_account,
            quantity="1")

    with allure.step(f'THEN {GIVEN_currently_authorized_account.name} has 1 Quantity '
                     f'of {GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name}'
                     f'AND {GIVEN_new_one_existence_account} has 1 more Quantity'):
        iroha.should(have.asset(
            f'{GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name}#{GIVEN_currently_authorized_account.domain}#{GIVEN_new_one_existence_account}'))


@allure.label('sdk_test_id', 'transfer_user_asset')
@allure.label('permission', 'can_transfer_user_asset')
@pytest.mark.xfail(reason="TO DO")
def test_transfer_user_asset(
        GIVEN_new_one_existence_account,
        GIVEN_currently_authorized_account):
    assert 0
