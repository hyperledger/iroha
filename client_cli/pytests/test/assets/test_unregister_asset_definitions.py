import allure
import pytest

@pytest.fixture(scope="function", autouse=True)
def story_account_unregister_asset_definitions():
    allure.dynamic.story('Account unregisters an asset definition')
    allure.dynamic.label('permission', 'no_permission_required')


@allure.label('sdk_test_id', 'unregister_asset_definition')
@pytest.mark.xfail(reason="TO DO")
def test_unregister_asset_definition(
        GIVEN_existing_asset_definition_with_quantity_value_type):
    assert 0
