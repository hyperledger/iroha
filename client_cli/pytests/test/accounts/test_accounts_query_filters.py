import json
import allure

from src.client_cli import iroha, client_cli

# using existing account to have at least one account in response
def test_filter_by_domain(GIVEN_new_one_existing_account):
    def condition():
        domain = GIVEN_new_one_existing_account.domain
        with allure.step(
                f'WHEN client_cli query accounts '
                f'in the "{domain}" domain'):
            accounts = iroha.list_filter(f'{{"Identifiable": {{"EndsWith": "@{domain}"}}}}').accounts()
        with allure.step(
                f'THEN Iroha should return only accounts with this domain'):
            allure.attach(
                json.dumps(accounts),
                name='accounts',
                attachment_type=allure.attachment_type.JSON)
            return accounts and all(account.endswith(domain) for account in accounts)
    client_cli.wait_for(condition)

def test_filter_by_account_name(GIVEN_new_one_existing_account):
    def condition():
        name = GIVEN_new_one_existing_account.name
        with allure.step(
                f'WHEN client_cli query accounts with name "{name}"'):
            accounts = iroha.list_filter(f'{{"Identifiable": {{"StartsWith": "{name}@"}}}}').accounts()
        with allure.step(
                f'THEN Iroha should return only accounts with this name'):
            allure.attach(
                json.dumps(accounts),
                name='accounts',
                attachment_type=allure.attachment_type.JSON)
            return accounts and all(account.startswith(name) for account in accounts)
    client_cli.wait_for(condition)

def test_filter_by_account_id(GIVEN_new_one_existing_account):
    def condition():
        account_id = GIVEN_new_one_existing_account.name + "@" + GIVEN_new_one_existing_account.domain
        with allure.step(
                f'WHEN client_cli query accounts with account id "{account_id}"'):
            accounts = iroha.list_filter(f'{{"Identifiable": {{"Is": "{account_id}"}}}}').accounts()
        with allure.step(
                f'THEN Iroha should return only accounts with this id'):
            allure.attach(
                json.dumps(accounts),
                name='accounts',
                attachment_type=allure.attachment_type.JSON)
            return accounts and all(account == account_id for account in accounts)
    client_cli.wait_for(condition)
