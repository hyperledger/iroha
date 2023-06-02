"""
This module contains the Domain class.
"""
from dataclasses import dataclass

@dataclass
class Domain:
    """
    Domain class represents a domain in the Iroha network.

    :param name: The name of the domain.
    :type name: str
    """
    name: str


    def get_name(self):
        """
        Get the name of the domain.

        :return: The name of the domain.
        :rtype: str
        """
        return self.name
