# pylint: disable=redefined-outer-name
# pylint: disable=invalid-name
"""
This module contains pytest fixtures for testing.
"""
import allure  # type: ignore
import pytest

from common.consts import ValueTypes
from common.helpers import (
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
from common.settings import PEERS_CONFIGS_PATH
from models import Account, Asset, AssetDefinition, Domain
from src.client_cli import client_cli, config


# General fixtures
@pytest.fixture(scope="session", autouse=True)
def before_all():
    """Initial setup for all test sessions.
    This fixture generates configurations based on peers and is automatically
    used for every test session."""
    config.generate_by_peers(PEERS_CONFIGS_PATH)
    yield


@pytest.fixture(scope="function", autouse=True)
def before_each():
    """Fixture to set up and reset the client_cli state."""
    allure.dynamic.label("sdk", "Client CLI")
    allure.dynamic.label("owner", "astrokov")
    yield
    client_cli.reset()


# Fixtures for creating objects (domains, accounts, asset definitions, assets)
@pytest.fixture()
def GIVEN_registered_domain():
    """Fixture to create and register a domain."""
    domain = Domain(fake_name())
    with allure.step(f"GIVEN a registered domain {domain.name}"):
        client_cli.register().domain(domain.name)
    return domain


@pytest.fixture()
def GIVEN_registered_domain_with_uppercase_letter(GIVEN_registered_domain):
    """Fixture to create and register a domain, but with uppercase letter."""
    domain = GIVEN_registered_domain
    domain.name = name_with_uppercase_letter(domain.name)
    with allure.step(f"GIVEN a registered domain {domain.name}"):
        client_cli.register().domain(domain.name)
    return domain


@pytest.fixture()
def GIVEN_registered_account(GIVEN_registered_domain, GIVEN_public_key):
    """Fixture to create an account."""
    account = Account(signatory=GIVEN_public_key, domain=GIVEN_registered_domain.name)
    with allure.step(
        f'GIVEN the account "{GIVEN_public_key}" in the "{GIVEN_registered_domain.name}" domain'
    ):
        client_cli.register().account(
            signatory=account.signatory, domain=account.domain
        )
    return account


@pytest.fixture()
def GIVEN_currently_authorized_account():
    """Fixture to get the currently authorized account."""
    account: Account = Account(
        signatory=config.account_signatory,
        domain=config.account_domain,
    )
    with allure.step(
        f'GIVEN the currently authorized account "{account.signatory}" '
        f'in the "{account.domain}" domain'
    ):
        return account


@pytest.fixture()
def GIVEN_currently_account_quantity_with_two_quantity_of_asset(
    GIVEN_currently_authorized_account, GIVEN_numeric_value_type, GIVEN_fake_asset_name
):
    """Fixture to get the currently authorized account asset"""
    asset_def = AssetDefinition(
        name=GIVEN_fake_asset_name,
        domain=GIVEN_currently_authorized_account.domain,
        value_type=GIVEN_numeric_value_type,
    )
    asset = Asset(
        definition=asset_def, value="2", account=GIVEN_currently_authorized_account
    )
    name = fake_name()
    with allure.step(
        f'GIVEN the asset_definition "{name}" '
        f'in the "{GIVEN_currently_authorized_account.domain}" domain'
    ):
        client_cli.register().asset().definition(
            asset=asset.definition.name,
            domain=asset.definition.domain,
            value_type=asset.definition.value_type,
        )
        client_cli.mint().asset(
            account=GIVEN_currently_authorized_account,
            asset_definition=asset.definition,
            value_of_value_type=asset.value,
        )
    return asset


@pytest.fixture()
def GIVEN_numeric_asset_for_account(
    request, GIVEN_numeric_value_type, GIVEN_fake_asset_name, GIVEN_numeric_value
):
    """Fixture to get an asset for a given account and domain with specified quantity."""
    account, domain = request.param.split("@")
    account = Account(signatory=account, domain=domain)

    asset_def = AssetDefinition(
        name=GIVEN_fake_asset_name, domain=domain, value_type=GIVEN_numeric_value_type
    )
    asset = Asset(
        definition=asset_def, value=GIVEN_numeric_value, account=account.signatory
    )

    with allure.step(
        f'GIVEN the asset_definition "{asset_def.name}" ' f'in the "{domain}" domain'
    ):
        client_cli.register().asset().definition(
            asset=asset.definition.name,
            domain=asset.definition.domain,
            value_type=asset.definition.value_type,
        )
        client_cli.mint().asset(
            account=account,
            asset_definition=asset.definition,
            value_of_value_type=asset.value,
        )

    return asset


@pytest.fixture()
def GIVEN_registered_asset_definition_with_numeric_value_type(
    GIVEN_registered_domain, GIVEN_numeric_value_type, GIVEN_fake_asset_name
):
    """Fixture to create and register an asset definition with numeric value type."""
    asset_def = AssetDefinition(
        name=GIVEN_fake_asset_name,
        domain=GIVEN_registered_domain.name,
        value_type=GIVEN_numeric_value_type,
    )
    with allure.step(
        f'GIVEN the asset_definition "{GIVEN_fake_asset_name}" '
        f'in the "{GIVEN_registered_domain.name}" domain'
    ):
        client_cli.register().asset().definition(
            asset=asset_def.name,
            domain=asset_def.domain,
            value_type=asset_def.value_type,
        )
    return asset_def


@pytest.fixture()
def GIVEN_minted_asset_quantity(
    GIVEN_registered_asset_definition_with_numeric_value_type,
    GIVEN_registered_account,
    GIVEN_numeric_value,
):
    """Fixture to create and return an asset with a specified quantity.
    It takes a registered asset definition, a registered account, and a numeric value.
    """
    asset = Asset(
        account=GIVEN_registered_account,
        definition=GIVEN_registered_asset_definition_with_numeric_value_type,
        value=GIVEN_numeric_value,
    )
    client_cli.mint().asset(
        account=asset.account,
        asset_definition=asset.definition,
        value_of_value_type=asset.value,
    )
    return asset


@pytest.fixture()
def GIVEN_registered_asset_definition_with_store_value_type(
    GIVEN_registered_domain, GIVEN_store_value_type, GIVEN_fake_asset_name
):
    """Fixture to create and register an asset definition with store value type."""
    asset_def = AssetDefinition(
        name=GIVEN_fake_asset_name,
        domain=GIVEN_registered_domain.name,
        value_type=GIVEN_store_value_type,
    )
    with allure.step(
        f'GIVEN the asset_definition "{GIVEN_fake_asset_name}" '
        f'in the "{GIVEN_registered_domain.name}" domain'
    ):
        client_cli.register().asset().definition(
            asset=asset_def.name,
            domain=asset_def.domain,
            value_type=asset_def.value_type,
        )
    return asset_def


# Fixtures for generating various types of data (strings, keys, names, etc.)
@pytest.fixture()
def GIVEN_fake_name():
    """Fixture to provide a fake name."""
    name = fake_name()
    with allure.step(f'GIVEN a "{name}" name'):
        return name


@pytest.fixture()
def GIVEN_fake_asset_name():
    """Fixture to provide a fake asset name."""
    asset_name = fake_asset_name()
    with allure.step(f'GIVEN a "{asset_name}" asset'):
        return asset_name


@pytest.fixture()
def GIVEN_not_existing_name():
    """Fixture to provide a non-existing name."""
    name = not_existing_name()
    with allure.step(f"GIVEN an non-existing {name}"):
        return name


@pytest.fixture()
def GIVEN_public_key():
    """Fixture to provide a public key."""
    public_key = generate_public_key()
    with allure.step(f"GIVEN a public key {public_key}"):
        return public_key


@pytest.fixture()
def GIVEN_random_character():
    """Fixture to provide a random character from the ASCII letters."""
    letter = random.choice(string.ascii_letters)
    with allure.step(f'GIVEN a "{letter}" name'):
        return letter


@pytest.fixture()
def GIVEN_random_invalid_base64_character():
    """Fixture to provide a random invalid base64 character
    (not a-z,A-Z,0-9,+,/,=).
    """
    invalid_chars = [
        ch
        for ch in string.printable
        if not (ch.isalpha() or ch.isdigit() or ch in ["=", "+", "/"])
    ]
    letter = random.choice(invalid_chars)
    with allure.step(f'GIVEN a "{letter}" name'):
        return letter


# Fixtures for providing specific values or conditions (e.g., name length, string with spaces)
@pytest.fixture()
def GIVEN_key_with_invalid_character_in_key(
    GIVEN_public_key, GIVEN_random_invalid_base64_character
):
    """Fixture to provide a public key with an invalid character."""
    invalid_key = key_with_invalid_character_in_key(
        GIVEN_public_key, GIVEN_random_invalid_base64_character
    )
    with allure.step(f'GIVEN an invalid key "{invalid_key}"'):
        return invalid_key


@pytest.fixture()
def GIVEN_numeric_value_type():
    """Fixture to provide a numeric value type."""
    value_type = ValueTypes.NUMERIC.value
    with allure.step(f'GIVEN a "{value_type}" value type'):
        return value_type


@pytest.fixture()
def GIVEN_store_value_type():
    """Fixture to provide a store value type."""
    value_type = ValueTypes.STORE.value
    with allure.step(f'GIVEN a "{value_type}" value type'):
        return value_type


@pytest.fixture()
def GIVEN_numeric_value():
    """Fixture to provide a random numeric value based on the given value type."""
    rand_int = str((random.getrandbits(96)) - 1)
    return rand_int


@pytest.fixture()
def GIVEN_128_length_name():
    ident = generate_random_string_without_reserved_chars(128)
    with allure.step(f'GIVEN a name with 128 length "{ident}"'):
        return ident


@pytest.fixture()
def GIVEN_129_length_name():
    ident = generate_random_string_without_reserved_chars(129)
    with allure.step(f'GIVEN a name with 129 length "{ident}"'):
        return ident


@pytest.fixture()
def GIVEN_string_with_reserved_character():
    """Fixture to provide a random string with reserved characters."""
    new_string = generate_random_string_with_reserved_char()
    with allure.step(f'GIVEN a "{new_string}" string'):
        return new_string


@pytest.fixture()
def GIVEN_string_with_whitespaces():
    """Fixture to provide a random string with whitespaces."""
    new_string = generate_random_string_with_whitespace()
    with allure.step(f'GIVEN a "{new_string}" string'):
        return new_string
