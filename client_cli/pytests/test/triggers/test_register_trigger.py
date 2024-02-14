import allure
import pytest

from src.client_cli import client_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_registers_trigger():
    allure.dynamic.story('Account register a register_trigger')
    allure.dynamic.label('permission', 'no_permission_required')


@allure.label('sdk_test_id', 'register_trigger')
@pytest.mark.xfail(reason="wait for #4151")
def test_register_trigger(
        GIVEN_currently_authorized_account):
    with allure.step(
            f'WHEN client_cli registers a register_trigger for "{GIVEN_currently_authorized_account}"'):
        client_cli.register_trigger(GIVEN_currently_authorized_account)
    with allure.step(
            f'THEN Iroha should have the asset with nft_number_1_for_genesis##genesis@genesis'):
        iroha.should(have.asset('nft_number_1_for_genesis##genesis@genesis'))
