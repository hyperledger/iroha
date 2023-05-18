import allure
import pytest

@pytest.fixture(scope="function", autouse=True)
def story_account_unregister_account():
    allure.dynamic.story('Account unregisters an account')
    allure.dynamic.label('permission', 'no_permission_required')

@allure.label('sdk_test_id', 'unregister_account')
@pytest.mark.xfail(reason="TO DO")
def test_unregister_account(
        GIVEN_new_one_existence_account):
    assert 0
