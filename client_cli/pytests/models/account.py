"""
This module provides an Account class for working with Iroha network accounts.
"""
from dataclasses import dataclass

@dataclass
class Account:
    """
    Account class represents an Iroha account.

    :param name: The name of the account.
    :type name: str
    :param domain: The domain of the account.
    :type domain: str
    :param public_key: The public key of the account.
    :type public_key: str
    """
    name: str
    domain: str
    public_key: str

    def __repr__(self):
        return f"{self.name}@{self.domain}"
