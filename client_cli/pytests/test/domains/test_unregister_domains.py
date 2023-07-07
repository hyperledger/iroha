import allure
import pytest


@pytest.fixture(scope="function", autouse=True)
def story_account_unregister_domain():
    allure.dynamic.story('Account unregisters a domain')
    allure.dynamic.label('permission', 'no_permission_required')

@allure.label('sdk_test_id', 'unregister_domain')
@pytest.mark.xfail(reason="TO DO")
def test_unregister_domain(
        GIVEN_new_one_existing_domain):
    assert 0
