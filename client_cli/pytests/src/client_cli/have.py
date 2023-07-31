"""
This module contains functions for checking expected results in tests.
"""

import json
import allure

from src.client_cli import client_cli, iroha, match

def expected_in_actual(expected, actual) -> bool:
    allure.attach(
        json.dumps(actual),
        name='actual',
        attachment_type=allure.attachment_type.JSON)
    allure.attach(
        json.dumps(expected),
        name='expected',
        attachment_type=allure.attachment_type.JSON)

    return expected in actual

def domain(expected):
    """
    Check if the expected domain is present in the list of domains.

    :param expected: The expected domain object.
    :return: True if the domain is present, False otherwise.
    """
    def domain_in_domains() -> bool:
        domains = iroha.list_filter(f'{{"Identifiable": {{"Is": "{expected}"}}}}').domains() 
        return expected_in_actual(expected, domains)
    return client_cli.wait_for(domain_in_domains)


def account(expected):
    """
    Check if the expected account is present in the list of accounts.

    :param expected: The expected account object.
    :return: True if the account is present, False otherwise.
    """
    def account_in_accounts() -> bool:
        accounts = iroha.list_filter(f'{{"Identifiable": {{"Is": "{expected}"}}}}').accounts() 
        return expected_in_actual(expected, accounts)
    return client_cli.wait_for(account_in_accounts)


def asset_definition(expected):
    """
    Check if the expected asset definition is present in the list of asset definitions.

    :param expected: The expected asset definition object.
    :return: True if the asset definition is present, False otherwise.
    """
    expected_domain = expected.split('#')[1]
    def asset_definition_in_asset_definitions() -> bool:
        asset_definitions = iroha.list_filter(f'{{"Identifiable": {{"Is": "{expected_domain}"}}}}').asset_definitions()
        return expected_in_actual(expected, asset_definitions)
    return client_cli.wait_for(asset_definition_in_asset_definitions)

def asset(expected):
    """
    Check if the expected asset is present in the list of assets.

    :param expected: The expected asset object.
    :return: True if the asset is present, False otherwise.
    """
    def asset_in_assets() -> bool:
        assets = iroha.list_filter(f'{{"Identifiable": {{"Is": "{expected}"}}}}').assets() 
        return expected_in_actual(expected, assets)
    return client_cli.wait_for(asset_in_assets)

def asset_quantity(asset_id, expected_quantity):
    """
    Check if the expected asset quantity is present in the list of assets.

    :param asset_id: The asset ID.
    :param expected_quantity: The expected quantity of the asset.
    :return: True if the asset quantity matches the expected quantity, False otherwise.
    """
    return match.iroha_have_asset(
        expected_quantity,
        actual=iroha.list_all().assets().get_quantity(asset_id))


def error(expected):
    """
    Check if the expected error is present in the client_cli stderr.

    :param expected: The expected error message.
    :return: True if the error is present, False otherwise.
    """
    return match.client_cli_have_error(
        expected=expected,
        actual=client_cli.stderr)
