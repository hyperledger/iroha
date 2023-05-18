import allure
import pytest

@pytest.fixture(scope="function", autouse=True)
def story_account_changes_account_metadata():
    allure.dynamic.story("Account changes account metadata")

@allure.label('sdk_test_id', 'change_account_metadata_by_granted_account')
@allure.label('permission', 'can_set_key_value_in_user_account')
@pytest.mark.xfail(reason="TO DO")
def test_change_account_metadata_by_granted_account():
    assert 0
