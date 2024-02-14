import allure
import pytest


@pytest.fixture(scope="function", autouse=True)
def story_send_pair_instructions_within_transaction():
    allure.dynamic.story('Client sends a wrong instruction in transaction')


@allure.label('sdk_test_id', 'instruction_failed')
@pytest.mark.xfail(reason="TO DO")
def test_instruction_failed(
        GIVEN_currently_authorized_account):
    assert 0
