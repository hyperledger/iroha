import allure
import pytest


@pytest.fixture(scope="function", autouse=True)
def story_client_sends_pair_instructions_within_transaction():
    allure.dynamic.story('Client sends a pair instructions within transaction')


@allure.label('sdk_test_id', 'pair_instruction')
@pytest.mark.xfail(reason="TO DO")
def test_pair_instruction(
        GIVEN_currently_authorized_account):
    assert 0
