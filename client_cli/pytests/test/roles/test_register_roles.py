import allure
import pytest

@pytest.fixture(scope="function", autouse=True)
def story_account_registers_roles():
    allure.dynamic.story('Account registers a role')


@allure.label('sdk_test_id', 'register_role')
@pytest.mark.xfail(reason="TO DO")
def test_register_role(
        GIVEN_fake_name):
    assert 0



@allure.label('sdk_test_id', 'attach_permissions_to_role')
@pytest.mark.xfail(reason="TO DO")
def test_attach_permissions_to_role(
        GIVEN_existing_asset_definition_with_store_value_type):
    assert 0


@allure.label('sdk_test_id', 'grant_role_to_account')
@pytest.mark.xfail(reason="TO DO")
def test_grant_role_to_account(
        GIVEN_currently_authorized_account,
        GIVEN_new_one_existing_account,
        GIVEN_existing_asset_definition_with_store_value_type):
    assert 0
