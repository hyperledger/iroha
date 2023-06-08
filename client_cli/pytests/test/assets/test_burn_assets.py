import allure
import pytest


@pytest.fixture(scope="function", autouse=True)
def story_client_burn_asset():
    allure.dynamic.story('Account burn an asset')


@allure.label('sdk_test_id', 'burn_asset_for_account_in_same_domain')
@pytest.mark.xfail(reason="TO DO")
def test_burn_asset_for_account_in_same_domain(
        GIVEN_existence_asset_definition_with_quantity_value_type,
        GIVEN_new_one_existence_account,
        GIVEN_quantity_value):
    assert 0


@allure.label('sdk_test_id', 'burn_other_user_asset')
@allure.label('permission', 'can_burn_assets_with_definition')
@pytest.mark.xfail(reason="TO DO")
def test_burn_other_user_asset(
        GIVEN_existence_asset_definition_with_quantity_value_type,
        GIVEN_new_one_existence_account,
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
        GIVEN_new_one_existence_account):
    assert 0
