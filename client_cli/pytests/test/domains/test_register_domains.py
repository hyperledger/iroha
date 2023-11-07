import allure
import pytest

from common.consts import Stderr
from src.client_cli import client_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_registers_domain():
    allure.dynamic.story('Account registers a domain')
    allure.dynamic.label('permission', 'no_permission_required')

@allure.label('sdk_test_id', 'register_domain')
def test_register_domain(
        GIVEN_fake_name):
    with allure.step(
            f'WHEN client_cli registers the domain name "{GIVEN_fake_name}"'):
        client_cli.execute(f'domain register --id={GIVEN_fake_name}')
    with allure.step(
            f'THEN Iroha should have the domain name "{GIVEN_fake_name}"'):
        iroha.should(have.domain(GIVEN_fake_name))

@allure.label('sdk_test_id', 'register_empty_domain')
def test_register_empty_domain(
        # GIVEN_empty_string
):
    with allure.step(
            'WHEN client_cli registers an empty domain'):
        client_cli.register().domain('')
    with allure.step(
            f'THEN client_cli should have the domain error: "{Stderr.CANNOT_BE_EMPTY}"'):
        client_cli.should(have.error(Stderr.CANNOT_BE_EMPTY.value))

@allure.label('sdk_test_id', 'register_existing_domain')
def test_register_existing_domain(
        GIVEN_new_one_existing_domain):
    with allure.step(
            f'WHEN client_cli registers an existing domain "{GIVEN_new_one_existing_domain.name}"'):
        client_cli.register().domain(GIVEN_new_one_existing_domain.name)
    with allure.step(
            f'THEN client_cli should have the domain error:  "{GIVEN_new_one_existing_domain.name}"'):
        client_cli.should(have.error(Stderr.REPETITION.value))

@allure.label('sdk_test_id', 'register_existing_domain_with_uppercase_letter')
def test_register_existing_domain_uppercase_with_uppercase_letter(
        GIVEN_existing_domain_with_uppercase_letter):
    with allure.step(
            f'WHEN client_cli registers an existing domain, '
            f'but with uppercase letter "{GIVEN_existing_domain_with_uppercase_letter.name}"'):
        client_cli.register().domain(GIVEN_existing_domain_with_uppercase_letter.name)
    with allure.step(
            f'THEN Iroha should have the domain name "{GIVEN_existing_domain_with_uppercase_letter.name}"'):
        iroha.should(have.domain(GIVEN_existing_domain_with_uppercase_letter.name))

@allure.label('sdk_test_id', 'register_one_letter_domain')
def test_register_one_letter_domain(
        GIVEN_random_character):
    with allure.step(
            f'WHEN client_cli registers the one letter domain "{GIVEN_random_character}"'):
        client_cli.register().domain(GIVEN_random_character)
    with allure.step(
            f'THEN Iroha should have the domain "{GIVEN_random_character}"'):
        iroha.should(have.domain(GIVEN_random_character))

@allure.label('sdk_test_id', 'register_max_lenght_domain')
def test_register_max_lenght_domain(
        GIVEN_128_lenght_name):
    with allure.step(
            f'WHEN client_cli registers the longest domain "{GIVEN_128_lenght_name}"'):
        client_cli.register().domain(GIVEN_128_lenght_name)
    with allure.step(
            f'THEN Iroha should have the longest domain "{GIVEN_128_lenght_name}"'):
        iroha.should(have.domain(GIVEN_128_lenght_name))

@allure.label('sdk_test_id', 'register_domain_with_too_long_name')
def test_register_domain_with_too_long_name(
        GIVEN_129_lenght_name):
    with allure.step(
            f'WHEN client_cli registers the domain "{GIVEN_129_lenght_name}" with too long name'):
        client_cli.register().domain(GIVEN_129_lenght_name)
    with allure.step(
            f'THEN client_cli should have the too long domain error: "{Stderr.TOO_LONG}"'):
        client_cli.should(have.error(Stderr.TOO_LONG.value))

@allure.label('sdk_test_id', 'register_domain_with_reserved_character')
def test_register_domain_with_reserved_character(
        GIVEN_string_with_reserved_character):
    with allure.step(
            f'WHEN client_cli registers a domain "{GIVEN_string_with_reserved_character}" with reserved characters'):
        client_cli.register().domain(GIVEN_string_with_reserved_character)
    with allure.step(
            f'THEN client_cli should has the domain error: "{Stderr.RESERVED_CHARACTER.value}"'):
        client_cli.should(have.error(Stderr.RESERVED_CHARACTER.value))

@allure.label('sdk_test_id', 'register_domain_with_whitespaces')
def test_register_domain_with_whitespaces(
        GIVEN_string_with_whitespaces):
    with allure.step(
            f'WHEN client_cli registers a domain "{GIVEN_string_with_whitespaces}" with whitespaces'):
        client_cli.register().domain(GIVEN_string_with_whitespaces)
    with allure.step(
            f'THEN client_cli should has the domain error: "{Stderr.WHITESPACES.value}"'):
        client_cli.should(have.error(Stderr.WHITESPACES.value))
