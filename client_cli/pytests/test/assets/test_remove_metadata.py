import allure
import pytest


@pytest.fixture(scope="function", autouse=True)
def story_account_remove_asset_metadata():
    allure.dynamic.story("Account removes asset metadata")


@allure.label("sdk_test_id", "remove_asset_metadata")
@pytest.mark.xfail(reason="TO DO")
def test_remove_asset_metadata():
    assert 0
