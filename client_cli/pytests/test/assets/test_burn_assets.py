import allure
import pytest

from src.client_cli import client_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_client_burn_asset():
    allure.dynamic.story('Account burn an asset')


@allure.label('sdk_test_id', 'burn_asset_for_account_in_same_domain')
@allure.label('permission', 'no_permission_required')
def test_burn_asset_for_account_in_same_domain(
        GIVEN_currently_authorized_account,
        GIVEN_currently_account_quantity_with_two_quantity_of_asset):
    with allure.step(f'WHEN {GIVEN_currently_authorized_account.name} burns 1 Quantity'
                     f'of {GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name}'):
        client_cli.burn(
            asset=GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition,
            account=GIVEN_currently_authorized_account,
            quantity="1")
    with allure.step(f'THEN {GIVEN_currently_authorized_account.name} has 1 Quantity of {GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name}'):
        iroha.should(have.asset_quantity(
            f'{GIVEN_currently_account_quantity_with_two_quantity_of_asset.definition.name}##{GIVEN_currently_authorized_account}',
            '1'))


@allure.label('sdk_test_id', 'burn_other_user_asset')
@allure.label('permission', 'can_burn_assets_with_definition')
@pytest.mark.xfail(reason="TO DO")
def test_burn_other_user_asset(
        GIVEN_existing_asset_definition_with_quantity_value_type,
        GIVEN_new_one_existing_account,
        GIVEN_quantity_value):
    assert 0

@allure.label('sdk_test_id', 'burn_asset_if_condition')
@pytest.mark.xfail(reason="TO DO")
def test_burn_asset_if_condition(
        GIVEN_currently_authorized_account):
    assert 0

@allure.label('sdk_test_id', 'not_burn_asset_if_condition_not_met')
@pytest.mark.xfail(reason="TO DO")
def test_not_burn_asset_if_condition_not_met(
        GIVEN_currently_authorized_account):
    assert 0


@allure.label("sdk_test_id", "burn_fixed_asset")
@pytest.mark.xfail(reason="TO DO")
def test_burn_fixed_asset(
        GIVEN_new_one_existing_account):
    assert 0
