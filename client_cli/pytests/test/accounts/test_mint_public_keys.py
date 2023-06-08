import allure
import pytest

@pytest.fixture(scope="function", autouse=True)
def story_account_mint_public_key():
    allure.dynamic.story('Account mints a public key')


@allure.label('sdk_test_id', 'mint_one_more_public_key')
@pytest.mark.xfail(reason="TO DO")
def test_mint_one_more_public_key(
        GIVEN_public_key):
    assert 0

@allure.label('sdk_test_id', 'mint_public_key_after_burning_one_public_key')
@pytest.mark.xfail(reason="TO DO")
def test_mint_public_key_after_burning_one_public_key():
    assert 0
