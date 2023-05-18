import allure
import pytest

@pytest.fixture(scope="function", autouse=True)
def story_client_sends_multiple_instructions_within_transaction():
    allure.dynamic.story('Client sends a multiple instructions within transaction')

@allure.label('sdk_test_id', 'multiple_instructions_within_transaction')
@pytest.mark.xfail(reason="TO DO")
def test_multiple_instructions_within_transaction(
        GIVEN_currently_authorized_account):
    assert 0
