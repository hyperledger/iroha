"""
This module contains the AssetDefinition and Asset classes.
"""

from dataclasses import dataclass

@dataclass
class AssetDefinition:
    """
    AssetDefinition class represents an asset definition in the Iroha network.

    :param name: The name of the asset definition.
    :type name: str
    :param domain: The domain of the asset definition.
    :type domain: str
    :param value_type: The value type of the asset definition.
    :type value_type: str
    """
    name: str
    domain: str
    value_type: str

    def __repr__(self):
        return f"{self.name}#{self.domain}"

    def get_id(self):
        """
        Get the asset definition ID.

        :return: The asset definition ID.
        :rtype: str
        """
        return f"{self.name}#{self.domain}"

@dataclass
class Asset:
    """
    Asset class represents an asset in the Iroha network.

    :param definition: The asset definition of the asset.
    :type definition: AssetDefinition
    :param value: The value of the asset.
    :type value: str
    """
    definition: AssetDefinition
    value: str

    def __repr__(self):
        return f"{self.definition.get_id()}:{self.value}"

    def get_value(self):
        """
        Get the value of the asset.

        :return: The value of the asset.
        :rtype: float
        """
        return self.value
