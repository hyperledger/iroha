# pylint: disable=redefined-outer-name
# pylint: disable=invalid-name
"""
This module contains pytest fixtures for testing.
"""
import allure  # type: ignore
import pytest

from typing import Any, Generator, List

from ..common.consts import ValueTypes
from ..common.helpers import (
    fake_asset_name,
    fake_name,
    generate_public_key,
    generate_random_string_with_reserved_char,
    generate_random_string_with_whitespace,
    generate_random_string_without_reserved_chars,
    key_with_invalid_character_in_key,
    name_with_uppercase_letter,
    not_existing_name,
    random,
    string,
)
from ..common.settings import PEER_CONFIGS_PATH
from ..models import Account, Asset, AssetDefinition, Domain
from ..src.iroha_cli import iroha_cli, config


# General fixtures
@pytest.fixture(scope="session", autouse=True)
def before_all() -> Generator[None, None, None]:
    """Initial setup for all test sessions.
    This fixture generates configurations based on peers and is automatically
    used for every test session."""
    config.generate_by_peers(PEER_CONFIGS_PATH)
    yield


@pytest.fixture(scope="function", autouse=True)
def before_each() -> Generator[None, None, None]:
    """Fixture to set up and reset the iroha_cli state."""
    allure.dynamic.label("sdk", "Client CLI")
    allure.dynamic.label("owner", "astrokov")
    yield
    iroha_cli.reset()


# Fixtures for creating objects (domains, accounts, asset definitions, assets)
@pytest.fixture()
def GIVEN_registered_domain() -> Domain:
    """Fixture to create and register a domain."""
    domain = Domain(fake_name())
    with allure.step(f"GIVEN a registered domain {domain.name}"):
        iroha_cli.register().domain(domain.name)
    return domain


@pytest.fixture()
def GIVEN_registered_domain_with_uppercase_letter(
    GIVEN_registered_domain: Domain,
) -> Domain:
    """Fixture to create and register a domain, but with an uppercase letter."""
    domain = GIVEN_registered_domain
    domain.name = name_with_uppercase_letter(domain.name)
    with allure.step(f"GIVEN a registered domain {domain.name}"):
        iroha_cli.register().domain(domain.name)
    return domain


@pytest.fixture()
def GIVEN_registered_account(
    GIVEN_registered_domain: Domain, GIVEN_public_key: str
) -> Account:
    """Fixture to create and register an account."""
    account = Account(signatory=GIVEN_public_key, domain=GIVEN_registered_domain.name)
    with allure.step(
        f'GIVEN the account "{account.signatory}" in the "{account.domain}" domain'
    ):
        iroha_cli.register().account(signatory=account.signatory, domain=account.domain)
    return account


@pytest.fixture()
def GIVEN_registered_account_granted_with_CanSetParameters(
    GIVEN_registered_account: Account, GIVEN_currently_authorized_account: Account
) -> Account:
    """Fixture to grant the account with CanSetParameters permission."""
    with allure.step(
        f'GIVEN "{GIVEN_registered_account}" granted with permission CanSetParameters'
    ):
        iroha_cli.grant_permission(
            destination=GIVEN_registered_account, permission="CanSetParameters"
        )
    return GIVEN_registered_account


@pytest.fixture()
def GIVEN_currently_authorized_account() -> Account:
    """Fixture to get the currently authorized account."""
    account = Account(
        signatory=config.account_signatory,
        domain=config.account_domain,
    )
    with allure.step(
        f'GIVEN the currently authorized account "{account.signatory}" '
        f'in the "{account.domain}" domain'
    ):
        pass
    return account


@pytest.fixture()
def GIVEN_currently_account_quantity_with_two_quantity_of_asset(
    GIVEN_currently_authorized_account: Account,
    GIVEN_numeric_type: str,
    GIVEN_fake_asset_name: str,
) -> Asset:
    """Fixture to get the currently authorized account's asset with a quantity of 2."""
    asset_def = AssetDefinition(
        name=GIVEN_fake_asset_name,
        domain=GIVEN_currently_authorized_account.domain,
        type_=GIVEN_numeric_type,
    )
    asset = Asset(
        definition=asset_def,
        value="2",
        account=GIVEN_currently_authorized_account,
    )
    name = fake_name()
    with allure.step(
        f'GIVEN the asset definition "{name}" '
        f'in the "{GIVEN_currently_authorized_account.domain}" domain'
    ):
        iroha_cli.register().asset_definition(
            asset=asset.definition.name,
            domain=asset.definition.domain,
            type_=asset.definition.type_,
        )
        iroha_cli.mint().asset(
            account=GIVEN_currently_authorized_account,
            asset_definition=asset.definition,
            value_of_type=asset.value,
        )
    return asset


@pytest.fixture()
def GIVEN_numeric_asset_for_account(
    request: Any,
    GIVEN_numeric_type: str,
    GIVEN_fake_asset_name: str,
    GIVEN_numeric_value: str,
) -> Asset:
    """Fixture to get an asset for a given account and domain with a specified quantity."""
    account_str, domain = request.param.split("@")
    account = Account(signatory=account_str, domain=domain)

    asset_def = AssetDefinition(
        name=GIVEN_fake_asset_name, domain=domain, type_=GIVEN_numeric_type
    )
    asset = Asset(
        definition=asset_def, value=GIVEN_numeric_value, account=account.signatory
    )

    with allure.step(
        f'GIVEN the asset definition "{asset_def.name}" in the "{domain}" domain'
    ):
        iroha_cli.register().asset_definition(
            asset=asset.definition.name,
            domain=asset.definition.domain,
            type_=asset.definition.type_,
        )
        iroha_cli.mint().asset(
            account=account,
            asset_definition=asset.definition,
            value_of_type=asset.value,
        )

    return asset


@pytest.fixture()
def GIVEN_registered_asset_definition_with_numeric_type(
    GIVEN_registered_domain: Domain,
    GIVEN_numeric_type: str,
    GIVEN_fake_asset_name: str,
) -> AssetDefinition:
    """Fixture to create and register an asset definition with a numeric value type."""
    asset_def = AssetDefinition(
        name=GIVEN_fake_asset_name,
        domain=GIVEN_registered_domain.name,
        type_=GIVEN_numeric_type,
    )
    with allure.step(
        f'GIVEN the asset definition "{asset_def.name}" '
        f'in the "{asset_def.domain}" domain'
    ):
        iroha_cli.register().asset_definition(
            asset=asset_def.name,
            domain=asset_def.domain,
            type_=asset_def.type_,
        )
    return asset_def


@pytest.fixture()
def GIVEN_minted_asset_quantity(
    GIVEN_registered_asset_definition_with_numeric_type: AssetDefinition,
    GIVEN_registered_account: Account,
    GIVEN_numeric_value: str,
) -> Asset:
    """Fixture to create and return an asset with a specified quantity."""
    asset = Asset(
        account=GIVEN_registered_account,
        definition=GIVEN_registered_asset_definition_with_numeric_type,
        value=GIVEN_numeric_value,
    )
    iroha_cli.mint().asset(
        account=asset.account,
        asset_definition=asset.definition,
        value_of_type=asset.value,
    )
    return asset


@pytest.fixture()
def GIVEN_registered_asset_definition_with_store_type(
    GIVEN_registered_domain: Domain, GIVEN_store_type: str, GIVEN_fake_asset_name: str
) -> AssetDefinition:
    """Fixture to create and register an asset definition with a store value type."""
    asset_def = AssetDefinition(
        name=GIVEN_fake_asset_name,
        domain=GIVEN_registered_domain.name,
        type_=GIVEN_store_type,
    )
    with allure.step(
        f'GIVEN the asset definition "{asset_def.name}" '
        f'in the "{asset_def.domain}" domain'
    ):
        iroha_cli.register().asset_definition(
            asset=asset_def.name,
            domain=asset_def.domain,
            type_=asset_def.type_,
        )
    return asset_def


# Fixtures for generating various types of data (strings, keys, names, etc.)
@pytest.fixture()
def GIVEN_fake_name() -> str:
    """Fixture to provide a fake name."""
    name = fake_name()
    with allure.step(f'GIVEN a "{name}" name'):
        pass
    return name


@pytest.fixture()
def GIVEN_fake_asset_name() -> str:
    """Fixture to provide a fake asset name."""
    asset_name = fake_asset_name()
    with allure.step(f'GIVEN a "{asset_name}" asset'):
        pass
    return asset_name


@pytest.fixture()
def GIVEN_not_existing_name() -> str:
    """Fixture to provide a non-existing name."""
    name = not_existing_name()
    with allure.step(f"GIVEN a non-existing {name}"):
        pass
    return name


@pytest.fixture()
def GIVEN_public_key() -> str:
    """Fixture to provide a public key."""
    public_key = generate_public_key()
    with allure.step(f"GIVEN a public key {public_key}"):
        pass
    return public_key


@pytest.fixture()
def GIVEN_random_character() -> str:
    """Fixture to provide a random character from ASCII letters."""
    letter = random.choice(string.ascii_letters)
    with allure.step(f'GIVEN a "{letter}" character'):
        pass
    return letter


@pytest.fixture()
def GIVEN_random_invalid_base64_character() -> str:
    """Fixture to provide a random invalid base64 character."""
    invalid_chars = [
        ch
        for ch in string.printable
        if not (ch.isalpha() or ch.isdigit() or ch in ["=", "+", "/"])
    ]
    letter = random.choice(invalid_chars)
    with allure.step(f'GIVEN an invalid base64 character "{letter}"'):
        pass
    return letter


# Fixtures for providing specific values or conditions (e.g., name length, strings with spaces)
@pytest.fixture()
def GIVEN_key_with_invalid_character_in_key(
    GIVEN_public_key: str, GIVEN_random_invalid_base64_character: str
) -> str:
    """Fixture to provide a public key with an invalid character."""
    invalid_key = key_with_invalid_character_in_key(
        GIVEN_public_key, GIVEN_random_invalid_base64_character
    )
    with allure.step(f'GIVEN an invalid key "{invalid_key}"'):
        pass
    return invalid_key


@pytest.fixture()
def GIVEN_numeric_type() -> str:
    """Fixture to provide a numeric value type."""
    type_ = ValueTypes.NUMERIC.value
    with allure.step(f'GIVEN a "{type_}" value type'):
        pass
    return type_


@pytest.fixture()
def GIVEN_store_type() -> str:
    """Fixture to provide a store value type."""
    type_ = ValueTypes.STORE.value
    with allure.step(f'GIVEN a "{type_}" value type'):
        pass
    return type_


@pytest.fixture()
def GIVEN_numeric_value() -> str:
    """Fixture to provide a random numeric value."""
    rand_int = str((random.getrandbits(96)) - 1)
    return rand_int


@pytest.fixture()
def GIVEN_128_length_name() -> str:
    """Fixture to provide a string with 128 characters."""
    ident = generate_random_string_without_reserved_chars(128)
    with allure.step(f'GIVEN a name with 128 characters "{ident}"'):
        pass
    return ident


@pytest.fixture()
def GIVEN_129_length_name() -> str:
    """Fixture to provide a string with 129 characters."""
    ident = generate_random_string_without_reserved_chars(129)
    with allure.step(f'GIVEN a name with 129 characters "{ident}"'):
        pass
    return ident


@pytest.fixture()
def GIVEN_string_with_reserved_character() -> str:
    """Fixture to provide a string with reserved characters."""
    new_string = generate_random_string_with_reserved_char()
    with allure.step(f'GIVEN a string with reserved characters "{new_string}"'):
        pass
    return new_string


@pytest.fixture()
def GIVEN_string_with_whitespaces() -> str:
    """Fixture to provide a string with whitespaces."""
    new_string = generate_random_string_with_whitespace()
    with allure.step(f'GIVEN a string with whitespaces "{new_string}"'):
        pass
    return new_string
