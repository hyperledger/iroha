"""
This module provides an Account class for working with Iroha network accounts.
"""

from dataclasses import dataclass


@dataclass
class Account:
    """
    Account class represents an Iroha account.

    :param signatory: The signatory of the account.
    :type signatory: str
    :param domain: The domain of the account.
    :type domain: str
    """

    signatory: str
    domain: str

    def __repr__(self):
        return f"{self.signatory}@{self.domain}"
