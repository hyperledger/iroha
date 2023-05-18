"""
This module provides helper functions for matching expected and actual values in Iroha objects.
"""

import allure

from src.client_cli import client_cli


def wait_for(expected, actual):
    """
    Waits for the expected value to be present in the actual value.

    :param expected: The expected value.
    :param actual: The actual value.
    """
    client_cli.wait_for(expected, actual, lambda: actual)


def iroha_have_domain(expected: str, actual: str):
    """
    Checks if Iroha has the expected domain.

    :param expected: The expected domain.
    :param actual: The actual domain list.
    """
    wait_for(expected, actual)


def iroha_have_account(expected: str, actual: str):
    """
    Checks if Iroha has the expected account.

    :param expected: The expected account.
    :param actual: The actual account list.
    """
    wait_for(expected, actual)


def iroha_have_asset_definition(expected: str, actual: str):
    """
    Checks if Iroha has the expected asset definition.

    :param expected: The expected asset definition.
    :param actual: The actual asset definition list.
    """
    wait_for(expected, actual)


def iroha_have_asset(expected: str, actual: str):
    """
    Checks if Iroha has the expected asset.

    :param expected: The expected asset.
    :param actual: The actual asset list.
    """
    wait_for(expected, actual)


def client_cli_have_error(expected: str, actual: str):
    """
    Checks if the command-line client has the expected error.

    :param expected: The expected error.
    :param actual: The actual error.
    """
    try:
        assert expected in actual
    except AssertionError as error:
        allure.attach(actual, name='actual', attachment_type=allure.attachment_type.TEXT)
        allure.attach(expected, name='expected', attachment_type=allure.attachment_type.TEXT)
        raise error
