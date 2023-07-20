"""
This module contains the Iroha class, which is a subclass of ClientCli.
"""

import json
from typing import Any, Dict, List, Union
from src.client_cli.client_cli import ClientCli, Config


class Iroha(ClientCli):
    """
    Iroha is a subclass of ClientCli that provides additional methods
    for interacting with the Iroha network.
    """

    def __init__(self, config: Config):
        """
        :param config: A configuration object containing the details for the client.
        :type config: Config
        :param path: The path where the client executable is located.
        :type path: str
        """
        super().__init__(config)
        self._storage: Union[Dict, List] = {}
        self._domains: Union[Dict, List] = {}
        self._accounts: Union[Dict, List] = {}
        self._assets: Union[Dict, List] = {}
        self._asset_definitions: Dict[str, Any] = {}

    def _execute_command(self, command_name: str):
        """
        Execute a command by inserting the command_name into the command list and then executing it.

        :param command_name: The name of the command to execute.
        :type command_name: str
        """
        self.command.insert(2, command_name)
        self.execute()

    def should(self, _expected):
        """
        Placeholder method for implementing assertions.

        :param expected: The expected value.
        :type expected: str
        :return: The current Iroha object.
        :rtype: Iroha
        """
        return self

    def domains(self):
        """
        Retrieve domains from the Iroha network and store them in the _domains attribute.

        :return: The current Iroha object.
        :rtype: Iroha
        """
        self._execute_command('domain')
        self._storage = json.loads(self.stdout)
        self._domains = [self._storage["id"] for self._storage in self._storage]
        return self

    def accounts(self):
        """
        Retrieve accounts from the Iroha network and store them in the _accounts attribute.

        :return: The current Iroha object.
        :rtype: Iroha
        """
        self._execute_command('account')
        self._accounts = json.loads(self.stdout)
        self._accounts = [self._accounts["id"] for self._accounts in self._accounts]
        return self

    def assets(self):
        """
        Retrieve assets from the Iroha network and store them in the _assets attribute.

        :return: The current Iroha object.
        :rtype: Iroha
        """
        self._execute_command('asset')
        self._assets = json.loads(self.stdout)
        self._assets = [self._assets["id"] for self._assets in self._assets]
        return self

    def get_quantity(self, asset_id):
        """
        Get the quantity of the asset with the specified ID.

        :param asset_id: The asset ID.
        :return: The quantity of the asset or None if the asset was not found.
        """
        for asset in json.loads(self.stdout):
            if asset["id"] == asset_id:
                return str(asset["value"]["Quantity"])
        return None

    def asset_definitions(self):
        """
        Retrieve asset definitions from the Iroha network
        and store them in the _asset_definitions attribute.

        :return: The current Iroha object.
        :rtype: Iroha
        """
        self._execute_command('domain')
        self._storage = json.loads(self.stdout)
        for obj in self._storage:
            asset_defs = obj.get('asset_definitions', {})
            for asset_def in asset_defs.values():
                asset_id = asset_def.get('id')
                value_type = asset_def.get('value_type')
                if asset_id and value_type:
                    self._asset_definitions[asset_id] = value_type
        return self

    def get_domains(self):
        """
        Get the list of domains.

        :return: A list of domain IDs.
        :rtype: list
        """
        return self._domains

    def get_accounts(self):
        """
        Get the list of accounts.

        :return: A list of account IDs.
        :rtype: list
        """
        return self._accounts

    def get_asset_definitions(self):
        """
        Get the dictionary of asset definitions.

        :return: A dictionary containing asset definition IDs as keys
        and their value types as values.
        :rtype: dict
        """
        return self._asset_definitions

    def get_assets(self):
        """
        Get the list of assets.

        :return: A list of asset IDs.
        :rtype: list
        """
        return self._assets

    def get_storage(self):
        """
        Get the storage data.

        :return: The storage data in its current form.
        :rtype: str
        """
        return self._storage
