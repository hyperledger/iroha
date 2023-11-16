import allure
import pytest

from src.client_cli import client_cli, iroha, have

@pytest.fixture(scope="function", autouse=True)
def story_account_transfers_domain():
    allure.dynamic.story('Account transfers a domain')
    allure.dynamic.label('permission', 'no_permission_required')

@allure.label('sdk_test_id', 'transfer_domain_successfully')
def test_transfer_domain(
        GIVEN_currently_authorized_account,
        GIVEN_new_one_existing_account,
        GIVEN_new_one_existing_domain,
):
    with allure.step(
            f'WHEN {GIVEN_currently_authorized_account} transfers domains '
            f'to {GIVEN_new_one_existing_account}'):
        client_cli.execute(f'domain transfer '
                           f'--from={GIVEN_currently_authorized_account} '
                           f'--to={GIVEN_new_one_existing_account} '
                           f'--id={GIVEN_new_one_existing_domain.name}')
    with allure.step(
            f'THEN {GIVEN_new_one_existing_account} should own {GIVEN_new_one_existing_domain}'):
        iroha.should(have.domain(GIVEN_new_one_existing_domain.name, owned_by=GIVEN_new_one_existing_account))
