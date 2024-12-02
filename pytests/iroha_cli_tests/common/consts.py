"""
This module contains constant values and enums used throughout the application.
"""

import string
from enum import Enum

from faker import Faker

fake = Faker()


class Stderr(Enum):
    """
    Enum for standard error messages.
    """

    EMPTY = "Empty"
    REPETITION = "Repetition"
    TOO_LONG = "Name length violation"
    FAILED_TO_FIND_DOMAIN = "Failed to find domain"
    FAILED_TO_FIND_ACCOUNT = "Failed to find account"
    INVALID_CHARACTER = "Failed to parse"
    INVALID_TYPE = "should be either `Store` or `Numeric`"
    RESERVED_CHARACTER = (
        "The `@` character is reserved for `account@domain` constructs, "
        "and `#` — for `asset#domain`."
    )
    WHITESPACES = "White space not allowed"
    INSUFFICIENT_FUNDS = "Not enough quantity to transfer/burn"
    NOT_PERMITTED = "Operation is not permitted: This operation is only allowed inside the genesis block"
    UNKNOWN_PERMISSION = "Unknown permission"


class ReservedChars(Enum):
    """
    Enum for reserved characters in names.
    """

    SPECIAL = "@#"
    WHITESPACES = string.whitespace
    ALL = SPECIAL + WHITESPACES


class ValueTypes(Enum):
    """
    Enum for value types used in the application.
    """

    STORE = "Store"  # storing key-values in object's metadata
    NUMERIC = "Numeric"  # 96bit decimal value with optional decimal point
