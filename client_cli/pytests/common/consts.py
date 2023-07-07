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
    CANNOT_BE_EMPTY = 'cannot be empty\n\nFor more information try --help\n'
    REPETITION = 'Repetition'
    TOO_LONG = 'Name length violation'
    FAILED_TO_FIND_DOMAIN = 'Entity missing'
    INVALID_CHARACTER = 'Invalid character'
    INVALID_VALUE_TYPE = 'Matching variant not found'
    RESERVED_CHARACTER = 'The `@` character is reserved for `account@domain` constructs, `#` — for `asset#domain` and `$` — for `trigger$domain`'
    WHITESPACES = "White space not allowed"


class ReservedChars(Enum):
    """
    Enum for reserved characters in names.
    """
    SPECIAL = "@#$"
    WHITESPACES = string.whitespace
    ALL = SPECIAL + WHITESPACES


class ValueTypes(Enum):
    """
    Enum for value types used in the application.
    """
    QUANTITY = 'Quantity'  # unsigned 32-bit integer
    STORE = 'Store' #storing key-values in object's metadata
    # BIG_QUANTITY = 'BigQuantity' unsigned 128-bit integer
    # FIXED = 'Fixed' 64-bit fixed-precision number with
    # nine significant digits after the decimal point
