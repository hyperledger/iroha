import allure

from src.client_cli import client_cli, iroha
import json

@allure.label('sdk_test_id', 'transfer_domain_successfully')
def test_transfer_domain_successfully(
  GIVEN_currently_authorized_account,
  GIVEN_new_one_existing_account,
  GIVEN_new_one_existing_domain,
):
    with allure.step(
            f'WHEN client_cli transfers this domain from {GIVEN_currently_authorized_account} to {GIVEN_new_one_existing_account}'):
        client_cli.execute(f'domain transfer --from={GIVEN_currently_authorized_account} --to={GIVEN_new_one_existing_account} --id={GIVEN_new_one_existing_domain.name}')
    with allure.step(
            f'THEN {GIVEN_new_one_existing_account} should own this domain {GIVEN_new_one_existing_domain}'):
        def condition():
            owned_by = GIVEN_new_one_existing_account
            domain_name = GIVEN_new_one_existing_domain.name
            with allure.step(
                    f'WHEN client_cli query domains filtered by name "{domain_name}"'):
                domains = iroha.list_filter(f'{{"Identifiable": {{"Is": "{domain_name}"}}}}').domains()
            with allure.step(
                    f'THEN Iroha should return only return domains with "{domain_name}" name'):
                allure.attach(
                    json.dumps(domains),
                    name='domains',
                    attachment_type=allure.attachment_type.JSON)
                return len(domains) != 0 and all(domains[key]["id"] == domain_name and domains[key]["owned_by"] == owned_by for key in domains)
        client_cli.wait_for(condition)
