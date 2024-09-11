"""
This module provides helper functions for matching expected and actual values in Iroha objects.
"""

import allure  # type: ignore


def iroha_cli_have_error(expected: str, actual: str):
    """
    Checks if the command-line client has the expected error.

    :param expected: The expected error.
    :param actual: The actual error.
    """
    try:
        assert expected in actual
    except AssertionError as error:
        allure.attach(
            actual, name="actual", attachment_type=allure.attachment_type.TEXT
        )
        allure.attach(
            expected, name="expected", attachment_type=allure.attachment_type.TEXT
        )
        raise error
