"""
This module contains the Domain class.
"""

class Domain:
    """
    Domain class represents a domain in the Iroha network.

    :param name: The name of the domain.
    :type name: str
    """
    def __init__(self, name: str):
        self.name = name

    def __repr__(self):
        return self.name

    def get_name(self):
        """
        Get the name of the domain.

        :return: The name of the domain.
        :rtype: str
        """
        return self.name
