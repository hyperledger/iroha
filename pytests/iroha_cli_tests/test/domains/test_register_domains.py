import allure  # type: ignore
import pytest

from ...common.consts import Stderr
from ...src.iroha_cli import iroha_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_registers_domain():
    allure.dynamic.story("Account registers a domain")
    allure.dynamic.label("permission", "no_permission_required")


@allure.label("sdk_test_id", "register_domain")
def test_register_domain(GIVEN_fake_name):
    with allure.step(f'WHEN iroha_cli registers the domain name "{GIVEN_fake_name}"'):
        iroha_cli.execute(f"domain register --id={GIVEN_fake_name}")
    with allure.step(f'THEN Iroha should have the domain name "{GIVEN_fake_name}"'):
        iroha.should(have.domain(GIVEN_fake_name))


@allure.label("sdk_test_id", "register_empty_domain")
def test_register_empty_domain(
    # GIVEN_empty_string
):
    with allure.step("WHEN iroha_cli registers an empty domain"):
        iroha_cli.register().domain("")
    with allure.step(f'THEN iroha_cli should have the domain error: "{Stderr.EMPTY}"'):
        iroha_cli.should(have.error(Stderr.EMPTY.value))


@allure.label("sdk_test_id", "register_existing_domain")
def test_register_existing_domain(GIVEN_registered_domain):
    with allure.step(
        f'WHEN iroha_cli registers an existing domain "{GIVEN_registered_domain.name}"'
    ):
        iroha_cli.register().domain(GIVEN_registered_domain.name)
    with allure.step(
        f'THEN iroha_cli should have the domain error: "{GIVEN_registered_domain.name}"'
    ):
        iroha_cli.should(have.error(Stderr.REPETITION.value))


@allure.label("sdk_test_id", "register_existing_domain_with_uppercase_letter")
def test_register_existing_domain_uppercase_with_uppercase_letter(
    GIVEN_registered_domain_with_uppercase_letter,
):
    with allure.step(
        f"WHEN iroha_cli registers an existing domain, "
        f'but with uppercase letter "{GIVEN_registered_domain_with_uppercase_letter.name}"'
    ):
        iroha_cli.register().domain(GIVEN_registered_domain_with_uppercase_letter.name)
    with allure.step(
        f'THEN Iroha should have the domain name "{GIVEN_registered_domain_with_uppercase_letter.name}"'
    ):
        iroha.should(have.domain(GIVEN_registered_domain_with_uppercase_letter.name))


@allure.label("sdk_test_id", "register_one_letter_domain")
def test_register_one_letter_domain(GIVEN_random_character):
    with allure.step(
        f'WHEN iroha_cli registers the one letter domain "{GIVEN_random_character}"'
    ):
        iroha_cli.register().domain(GIVEN_random_character)
    with allure.step(f'THEN Iroha should have the domain "{GIVEN_random_character}"'):
        iroha.should(have.domain(GIVEN_random_character))


@allure.label("sdk_test_id", "register_domain_with_reserved_character")
def test_register_domain_with_reserved_character(GIVEN_string_with_reserved_character):
    with allure.step(
        f'WHEN iroha_cli registers a domain "'
        f'{GIVEN_string_with_reserved_character}" with reserved characters'
    ):
        iroha_cli.register().domain(GIVEN_string_with_reserved_character)
    with allure.step(
        f'THEN iroha_cli should has the domain error: "{Stderr.RESERVED_CHARACTER.value}"'
    ):
        iroha_cli.should(have.error(Stderr.RESERVED_CHARACTER.value))


@allure.label("sdk_test_id", "register_domain_with_whitespaces")
def test_register_domain_with_whitespaces(GIVEN_string_with_whitespaces):
    with allure.step(
        f'WHEN iroha_cli registers a domain "{GIVEN_string_with_whitespaces}" with whitespaces'
    ):
        iroha_cli.register().domain(GIVEN_string_with_whitespaces)
    with allure.step(
        f'THEN iroha_cli should has the domain error: "{Stderr.WHITESPACES.value}"'
    ):
        iroha_cli.should(have.error(Stderr.WHITESPACES.value))
