# pylint: disable=redefined-outer-name
"""
This module contains pytest fixtures for testing.
"""
import allure
import pytest

from common.consts import ValueTypes
from common.helpers import *
from models import Account, AssetDefinition, Domain
from src.client_cli import client_cli, config

# General fixtures
@pytest.fixture(scope='function', autouse=True)
def before_each():
    """Fixture to set up and reset the client_cli state."""
    allure.dynamic.label('sdk', 'Client CLI')
    allure.dynamic.label("owner", "astrokov")
    yield
    client_cli.reset()

# Fixtures for creating objects (domains, accounts, asset definitions, assets)
@pytest.fixture()
def GIVEN_new_one_existence_domain():
    """Fixture to create and register an existing domain."""
    domain = Domain(fake_name())
    with allure.step(f'GIVEN an existence domain {domain.name}'):
        client_cli.register().domain(domain.name)
    return domain

@pytest.fixture()
def GIVEN_existence_domain_with_uppercase_letter(
        GIVEN_new_one_existence_domain):
    """Fixture to create and register an existing domain, but with uppercase letter."""
    domain = GIVEN_new_one_existence_domain
    domain.name = name_with_uppercase_letter(domain.name)
    with allure.step(f'GIVEN an existence domain {domain.name}'):
        client_cli.register().domain(domain.name)
    return domain

@pytest.fixture()
def GIVEN_new_one_existence_account(GIVEN_new_one_existence_domain, GIVEN_public_key):
    """Fixture to create and register an existing account."""
    account = Account(
        name=fake_name(),
        domain=GIVEN_new_one_existence_domain.name,
        public_key=GIVEN_public_key)
    name = fake_name()
    with allure.step(f'GIVEN the account "{name}" in the "{GIVEN_new_one_existence_domain.name}" domain'):
        client_cli.register().account(
            account=account.name,
            domain=account.domain,
            key=account.public_key)
    return account

@pytest.fixture()
def GIVEN_currently_authorized_account():
    """Fixture to get the currently authorized account."""
    account: Account = Account(
        name=config.account_name,
        domain=config.account_domain,
        public_key=config.public_key)
    with allure.step(f'GIVEN the currently authorized account "{account.name}" in the "{account.domain}" domain'):
        return account

@pytest.fixture()
def GIVEN_currently_account_quantity_with_two_quantity_of_asset(
        GIVEN_currently_authorized_account,
        GIVEN_quantity_value_type,
        GIVEN_fake_asset_name):
    """Fixture to get the currently authorized account asset"""
    asset_def = AssetDefinition(name=GIVEN_fake_asset_name,
                                domain=GIVEN_currently_authorized_account.domain,
                                value_type=GIVEN_quantity_value_type)
    name = fake_name()
    with allure.step(f'GIVEN the asset_definition "{name}" '
                     f'in the "{GIVEN_currently_authorized_account.domain}" domain'):
        client_cli.register().asset().definition(
            asset=asset_def.name,
            domain=asset_def.domain,
            value_type=asset_def.value_type)
        client_cli.mint().asset(
                account=GIVEN_currently_authorized_account,
                asset_definition=asset_def,
                value_of_value_type="2"
        )
    return asset_def



@pytest.fixture()
def GIVEN_existence_asset_definition_with_quantity_value_type(
        GIVEN_new_one_existence_domain,
        GIVEN_quantity_value_type,
        GIVEN_fake_asset_name):
    """Fixture to create and register an existing asset definition with random value type."""
    asset_def = AssetDefinition(name=GIVEN_fake_asset_name,
                                domain=GIVEN_new_one_existence_domain.name,
                                value_type=GIVEN_quantity_value_type)
    name = fake_name()
    with allure.step(f'GIVEN the asset_definition "{name}" '
                     f'in the "{GIVEN_new_one_existence_domain.name}" domain'):
        client_cli.register().asset().definition(asset=asset_def.name,
                                                 domain=asset_def.domain,
                                                 value_type=asset_def.value_type)
    return asset_def

@pytest.fixture()
def GIVEN_existence_asset_definition_with_store_value_type(
        GIVEN_new_one_existence_domain,
        GIVEN_store_value_type,
        GIVEN_fake_asset_name):
    """Fixture to create and register an existing asset definition with store value type."""
    asset_def = AssetDefinition(name=GIVEN_fake_asset_name,
                                domain=GIVEN_new_one_existence_domain.name,
                                value_type=GIVEN_store_value_type)
    name = fake_name()
    with allure.step(f'GIVEN the asset_definition "{name}" '
                     f'in the "{GIVEN_new_one_existence_domain.name}" domain'):
        client_cli.register().asset().definition(asset=asset_def.name,
                                                 domain=asset_def.domain,
                                                 value_type=asset_def.value_type)
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
    """Fixture to provide a non-existent name."""
    name = not_existing_name()
    with allure.step(f'GIVEN an existence domain {name}'):
        return name

@pytest.fixture()
def GIVEN_public_key():
    """Fixture to provide a public key."""
    public_key = generate_public_key()
    with allure.step(f'GIVEN a public key {public_key}'):
        return public_key

@pytest.fixture()
def GIVEN_random_character():
    """Fixture to provide a random character from the ASCII letters."""
    letter = random.choice(string.ascii_letters)
    with allure.step(f'GIVEN a "{letter}" name'):
        return letter

@pytest.fixture()
def GIVEN_random_invalid_base64_character():
    """Fixture to provide a random invalid base64 character (not a-z,A-Z,0-9,+,/,=)."""
    letter = random.choice([ch for ch in string.printable if not (ch.isalpha() or ch.isdigit() or ch == "=" or ch == "+" or ch == "/")])
    with allure.step(f'GIVEN a "{letter}" name'):
        return letter

# Fixtures for providing specific values or conditions (e.g., name length, string with spaces)
@pytest.fixture()
def GIVEN_key_with_invalid_character_in_key(
        GIVEN_public_key,
        GIVEN_random_invalid_base64_character):
    """Fixture to provide a public key with an invalid character."""
    invalid_key = key_with_invalid_character_in_key(GIVEN_public_key, GIVEN_random_invalid_base64_character)
    with allure.step(f'GIVEN an invalid key "{invalid_key}"'):
        return invalid_key

@pytest.fixture()
def GIVEN_quantity_value_type():
    """Fixture to provide a quantity value type."""
    value_type = ValueTypes.QUANTITY.value
    with allure.step(f'GIVEN a "{value_type}" value type'):
        return value_type

@pytest.fixture()
def GIVEN_store_value_type():
    """Fixture to provide a store value type."""
    value_type = ValueTypes.STORE.value
    with allure.step(f'GIVEN a "{value_type}" value type'):
        return value_type

@pytest.fixture()
def GIVEN_quantity_value():
    """Fixture to provide a random quantity value based on the given value type."""
    rand_int = str(random.getrandbits(32))
    return rand_int

@pytest.fixture()
def GIVEN_128_lenght_name():
    ident = generate_random_string_without_reserved_chars(128)
    with allure.step(f'GIVEN a name with 128 lenght "{ident}"'):
        return ident

@pytest.fixture()
def GIVEN_129_lenght_name():
    ident = generate_random_string_without_reserved_chars(129)
    with allure.step(f'GIVEN a name with 129 lenght "{ident}"'):
        return ident

@pytest.fixture()
def GIVEN_127_lenght_name():
    ident = generate_random_string_without_reserved_chars(127)
    with allure.step(f'GIVEN a name with 127 lenght "{ident}"'):
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

