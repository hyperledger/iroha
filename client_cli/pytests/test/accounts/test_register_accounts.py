import allure
import pytest

from common.consts import Stderr
from src.client_cli import client_cli, have, iroha

@pytest.fixture(scope="function", autouse=True)
def story_account_register_account():
    allure.dynamic.story('Account registers an account')
    allure.dynamic.label('permission', 'no_permission_required')

@allure.label('sdk_test_id', 'register_account')
def test_register_account(
        GIVEN_fake_name,
        GIVEN_new_one_existing_domain,
        GIVEN_public_key):
    with allure.step(
            f'WHEN client_cli registers the account "{GIVEN_fake_name}" '
            f'in the "{GIVEN_new_one_existing_domain.name}" domain'):
        client_cli.register().account(
            account=GIVEN_fake_name,
            domain=GIVEN_new_one_existing_domain.name,
            key=GIVEN_public_key)
        registered = GIVEN_fake_name + '@' + GIVEN_new_one_existing_domain.name
    with allure.step(
            f'THEN Iroha should have the "{registered}" account'):
        iroha.should(have.account(registered))


@allure.label('sdk_test_id', 'register_account_with_two_public_keys')
@pytest.mark.xfail(reason="TO DO")
def test_register_account_with_two_public_keys(
        GIVEN_fake_name,
        GIVEN_new_one_existing_domain,
        GIVEN_public_key):
    assert 0


@allure.label('sdk_test_id', 'register_account_with_empty_name')
def test_register_account_with_empty_name(
        GIVEN_new_one_existing_domain,
        GIVEN_public_key):
    with allure.step(
            f'WHEN client_cli tries to register an account with an empty name '
            f'in the "{GIVEN_new_one_existing_domain.name}" domain'):
        client_cli.register().account(account='', domain=GIVEN_new_one_existing_domain.name, key=GIVEN_public_key)
    with allure.step(
            f'THEN сlient_cli should have the account error: "{Stderr.CANNOT_BE_EMPTY}"'):
        client_cli.should(have.error(Stderr.CANNOT_BE_EMPTY.value))



@allure.label('sdk_test_id', 'register_account_with_existing_name')
def test_register_account_with_existing_name(
        GIVEN_new_one_existing_domain,
        GIVEN_public_key,
        GIVEN_new_one_existing_account):
    with allure.step(
            f'WHEN client_cli tries to register an account '
            f'with the same name "{GIVEN_new_one_existing_domain.name}"  '
            f'in the "{GIVEN_new_one_existing_domain.name}" domain'):
        client_cli.register().account(account=GIVEN_new_one_existing_account.name, domain=GIVEN_new_one_existing_account.domain,
                                      key=GIVEN_new_one_existing_account.public_key)
    with allure.step(
            f'THEN client_cli should have the account error:  "{GIVEN_new_one_existing_domain.name}"'):
        client_cli.should(have.error(Stderr.REPETITION.value))



@allure.label('sdk_test_id', 'register_account_with_invalid_domain')
def test_register_account_with_invalid_domain(
        GIVEN_fake_name,
        GIVEN_not_existing_name,
        GIVEN_public_key, ):
    with allure.step(
            'WHEN client_cli tries to register an account with an invalid domain'):
        client_cli.register().account(account=GIVEN_fake_name, domain=GIVEN_not_existing_name, key=GIVEN_public_key)
    with allure.step(
            'THEN client_cli should have the error'):
        client_cli.should(have.error(Stderr.FAILED_TO_FIND_DOMAIN.value))



@allure.label('sdk_test_id', 'register_account_with_invalid_character_in_key')
def test_register_account_with_invalid_character_in_key(
        GIVEN_fake_name,
        GIVEN_new_one_existing_domain,
        GIVEN_key_with_invalid_character_in_key):
    with allure.step(
            'WHEN client_cli tries to register an account with invalid character in the key'):
        client_cli.register().account(account=GIVEN_fake_name, domain=GIVEN_new_one_existing_domain.name,
                                      key=GIVEN_key_with_invalid_character_in_key)
    with allure.step(
            'THEN client_cli should have the error'):
        client_cli.should(have.error(Stderr.INVALID_CHARACTER.value))


@allure.label('sdk_test_id', 'register_account_with_max_name')
def test_register_account_with_max_name(
        GIVEN_127_lenght_name,
        GIVEN_new_one_existing_domain,
        GIVEN_public_key):
    with allure.step(
            'WHEN client_cli register an account with the 127 lenght name'):
        client_cli.register().account(account=GIVEN_127_lenght_name, domain=GIVEN_new_one_existing_domain.name,
                                      key=GIVEN_public_key)
        registered = GIVEN_127_lenght_name + '@' + GIVEN_new_one_existing_domain.name
    with allure.step(
            f'THEN Iroha should have the "{registered}" account'):
        iroha.should(have.account(registered))



@allure.label('sdk_test_id', 'register_account_with_special_characters')
@pytest.mark.xfail(reason="TO DO")
def test_register_account_with_special_characters(
        GIVEN_new_one_existing_domain,
        GIVEN_public_key):
    assert 0


@allure.label('sdk_test_id', 'register_account_with_long_account_name')
def test_register_account_with_long_account_name(
        GIVEN_new_one_existing_domain,
        GIVEN_129_lenght_name,
        GIVEN_public_key):
    with allure.step(
            'WHEN client_cli tries to register an account with a name with 129 characters'):
        client_cli.register().account(account=GIVEN_129_lenght_name, domain=GIVEN_new_one_existing_domain.name,
                                      key=GIVEN_public_key)
    with allure.step(
            f'THEN client_cli should have the name error: "{Stderr.TOO_LONG}"'):
        client_cli.should(have.error(Stderr.TOO_LONG.value))

@allure.label('sdk_test_id', 'register_account_with_metadata')
@pytest.mark.xfail(reason="TO DO")
def test_register_account_with_metadata(
        GIVEN_fake_name,
        GIVEN_new_one_existing_domain,
        GIVEN_public_key):
    assert 0
