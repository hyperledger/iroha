import allure
import pytest

@pytest.fixture(scope="function", autouse=True)
def story_client_change_account_metadata():
    allure.dynamic.story("Account set key value pair")

@allure.label('sdk_test_id', 'set_key_value_in_foreign_asset_after_granting_role')
@pytest.mark.xfail(reason="TO DO")
def test_set_key_value_in_foreign_asset_after_granting_role(
        GIVEN_currently_authorized_account,
        GIVEN_new_one_existence_account,
        GIVEN_existence_asset_definition_with_store_value_type):
    assert 0

@allure.label('sdk_test_id', 'set_key_value_pair_for_another_account_asset_definition')
@pytest.mark.xfail(reason="TO DO")
def test_set_key_value_pair_for_another_account_asset_definition(
        GIVEN_currently_authorized_account,
        GIVEN_new_one_existence_account,
        GIVEN_existence_asset_definition_with_store_value_type):
    assert 0
