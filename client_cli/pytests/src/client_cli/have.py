"""
This module contains functions for checking expected results in tests.
"""

from src.client_cli import client_cli, iroha, match


def domain(expected):
    """
    Check if the expected domain is present in the list of domains.

    :param expected: The expected domain object.
    :return: True if the domain is present, False otherwise.
    """
    return match.iroha_have_domain(
        expected=expected,
        actual=lambda: iroha.list_all().domains().get_domains())


def account(expected):
    """
    Check if the expected account is present in the list of accounts.

    :param expected: The expected account object.
    :return: True if the account is present, False otherwise.
    """
    return match.iroha_have_account(
        expected=expected,
        actual=lambda: iroha.list_all().accounts().get_accounts())


def asset_definition(expected):
    """
    Check if the expected asset definition is present in the list of asset definitions.

    :param expected: The expected asset definition object.
    :return: True if the asset definition is present, False otherwise.
    """
    return match.iroha_have_asset_definition(
        expected=expected,
        actual=lambda: iroha.list_all().asset_definitions().get_asset_definitions())


def asset(expected):
    """
    Check if the expected asset is present in the list of assets.

    :param expected: The expected asset object.
    :return: True if the asset is present, False otherwise.
    """
    return match.iroha_have_asset(
        expected=expected,
        actual=lambda: iroha.list_all().assets().get_assets())


def error(expected):
    """
    Check if the expected error is present in the client_cli stderr.

    :param expected: The expected error message.
    :return: True if the error is present, False otherwise.
    """
    return match.client_cli_have_error(
        expected=expected,
        actual=client_cli.stderr)
