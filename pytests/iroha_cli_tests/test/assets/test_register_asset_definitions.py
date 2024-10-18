import allure  # type: ignore
import pytest

from ...common.consts import Stderr
from ...src.iroha_cli import iroha_cli, have, iroha


@pytest.fixture(scope="function", autouse=True)
def story_account_registers_asset_definitions():
    allure.dynamic.story("Account registers an asset definition")
    allure.dynamic.label("permission", "no_permission_required")


@allure.label("sdk_test_id", "register_asset_definition_with_numeric_type")
def test_register_asset_definition_with_numeric_type(
    GIVEN_fake_asset_name, GIVEN_registered_domain, GIVEN_numeric_type
):
    with allure.step(
        f'WHEN iroha_cli registers the asset_definition "{GIVEN_fake_asset_name}" '
        f'with "{GIVEN_numeric_type}" value type'
        f'in the "{GIVEN_registered_domain.name}" domain'
    ):
        iroha_cli.register().asset_definition(
            asset=GIVEN_fake_asset_name,
            domain=GIVEN_registered_domain.name,
            type_=GIVEN_numeric_type,
        )
    with allure.step(f'THEN Iroha should have the asset "{GIVEN_fake_asset_name}"'):
        iroha.should(
            have.asset_definition(
                GIVEN_fake_asset_name + "#" + GIVEN_registered_domain.name
            )
        )


@allure.label("sdk_test_id", "register_asset_definition_with_store_type")
def test_register_asset_definition_with_store_type(
    GIVEN_fake_asset_name, GIVEN_registered_domain, GIVEN_store_type
):
    with allure.step(
        f'WHEN iroha_cli registers the asset_definition "{GIVEN_fake_asset_name}" '
        f'with "{GIVEN_store_type}" value type'
        f'in the "{GIVEN_registered_domain.name}" domain'
    ):
        iroha_cli.register().asset_definition(
            asset=GIVEN_fake_asset_name,
            domain=GIVEN_registered_domain.name,
            type_=GIVEN_store_type,
        )
    with allure.step(f'THEN Iroha should have the asset "{GIVEN_fake_asset_name}"'):
        iroha.should(
            have.asset_definition(
                GIVEN_fake_asset_name + "#" + GIVEN_registered_domain.name
            )
        )


@allure.label("sdk_test_id", "register_asset_with_existing_name")
def test_register_asset_with_existing_name(
    GIVEN_registered_asset_definition_with_numeric_type,
):
    with allure.step(
        f"WHEN account tries to register an asset definition "
        f'with the same name "{GIVEN_registered_asset_definition_with_numeric_type.name}"'
        f'in the "{GIVEN_registered_asset_definition_with_numeric_type.domain}" domain'
    ):
        iroha_cli.register().asset_definition(
            asset=GIVEN_registered_asset_definition_with_numeric_type.name,
            domain=GIVEN_registered_asset_definition_with_numeric_type.domain,
            type_=GIVEN_registered_asset_definition_with_numeric_type.type_,
        )
    with allure.step(
        f'THEN iroha_cli should have the asset definition error: "'
        f'{GIVEN_registered_asset_definition_with_numeric_type.__repr__()}"'
    ):
        iroha_cli.should(have.error(Stderr.REPETITION.value))


@allure.label("sdk_test_id", "register_asset_with_empty_name")
def test_register_asset_with_empty_name(GIVEN_registered_domain):
    with allure.step(
        "WHEN iroha_cli tries to register an asset definition with an empty name"
        f'in the "{GIVEN_registered_domain.name}" domain'
    ):
        iroha_cli.register().asset_definition(
            asset="", domain=GIVEN_registered_domain.name, type_="Numeric"
        )
    with allure.step(f'THEN сlient_cli should have the asset error: "{Stderr.EMPTY}"'):
        iroha_cli.should(have.error(Stderr.EMPTY.value))


@allure.label("sdk_test_id", "register_asset_with_not_existing_domain")
def test_register_asset_with_not_existing_domain(
    GIVEN_not_existing_name, GIVEN_numeric_type, GIVEN_fake_asset_name
):
    with allure.step(
        "WHEN iroha_cli tries to register an asset definition with not existing domain"
    ):
        iroha_cli.register().asset_definition(
            asset=GIVEN_fake_asset_name,
            domain=GIVEN_not_existing_name,
            type_=GIVEN_numeric_type,
        )
    with allure.step("THEN iroha_cli should have the error"):
        iroha_cli.should(have.error(Stderr.FAILED_TO_FIND_DOMAIN.value))


# FIXME: this should not work anymore
@allure.label("sdk_test_id", "register_asset_with_too_long_type")
def test_register_asset_with_too_long_type(
    GIVEN_fake_asset_name, GIVEN_registered_domain
):
    with allure.step(
        "WHEN iroha_cli tries to register an asset definition with too long value type"
    ):
        iroha_cli.register().asset_definition(
            asset=GIVEN_fake_asset_name,
            domain=GIVEN_registered_domain.name,
            type_="coin",
        )
    with allure.step("THEN iroha_cli should have the error"):
        iroha_cli.should(have.error(Stderr.INVALID_TYPE.value))
