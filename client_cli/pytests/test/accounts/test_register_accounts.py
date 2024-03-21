import allure  # type: ignore
import pytest

from common.consts import Stderr
from src.client_cli import client_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_register_account():
    allure.dynamic.story("Account registers an account")
    allure.dynamic.label("permission", "no_permission_required")


@allure.label("sdk_test_id", "register_account")
def test_register_account(GIVEN_public_key, GIVEN_registered_domain):
    with allure.step(
        f'WHEN client_cli registers the account "{GIVEN_public_key}" '
        f'in the "{GIVEN_registered_domain.name}" domain'
    ):
        client_cli.register().account(
            signatory=GIVEN_public_key,
            domain=GIVEN_registered_domain.name,
        )
        registered = GIVEN_public_key + "@" + GIVEN_registered_domain.name
    with allure.step(f'THEN Iroha should have the "{registered}" account'):
        iroha.should(have.account(registered))


@allure.label("sdk_test_id", "register_account_with_existing_signatory")
def test_register_account_with_existing_signatory(
    GIVEN_registered_domain, GIVEN_registered_account
):
    with allure.step(
        f"WHEN client_cli tries to register an account "
        f'with the same signatory "{GIVEN_registered_account.signatory}" '
        f'in the "{GIVEN_registered_domain.name}" domain'
    ):
        client_cli.register().account(
            signatory=GIVEN_registered_account.signatory,
            domain=GIVEN_registered_account.domain,
        )
    with allure.step("THEN client_cli should have the account error"):
        client_cli.should(have.error(Stderr.REPETITION.value))


@allure.label("sdk_test_id", "register_account_with_invalid_domain")
def test_register_account_with_invalid_domain(
    GIVEN_not_existing_name,
    GIVEN_public_key,
):
    with allure.step(
        "WHEN client_cli tries to register an account with an invalid domain"
    ):
        client_cli.register().account(
            signatory=GIVEN_public_key,
            domain=GIVEN_not_existing_name,
        )
    with allure.step("THEN client_cli should have the error"):
        client_cli.should(have.error(Stderr.FAILED_TO_FIND_DOMAIN.value))


@allure.label("sdk_test_id", "register_account_with_invalid_character_in_key")
def test_register_account_with_invalid_character_in_key(
    GIVEN_registered_domain, GIVEN_key_with_invalid_character_in_key
):
    with allure.step(
        "WHEN client_cli tries to register an account with invalid character in the key"
    ):
        client_cli.register().account(
            signatory=GIVEN_key_with_invalid_character_in_key,
            domain=GIVEN_registered_domain.name,
        )
    with allure.step("THEN client_cli should have the error"):
        client_cli.should(have.error(Stderr.INVALID_CHARACTER.value))


@allure.label("sdk_test_id", "register_account_with_metadata")
@pytest.mark.xfail(reason="TO DO")
def test_register_account_with_metadata(
    GIVEN_fake_name, GIVEN_registered_domain, GIVEN_public_key
):
    assert 0
