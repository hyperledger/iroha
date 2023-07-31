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
        self.command.insert(3, command_name)
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

    def domains(self) -> List[str]:
        """
        Retrieve domains from the Iroha network and return then as list of ids.

        :return: List of domains ids.
        :rtype: List[str]
        """
        self._execute_command('domain')
        domains = json.loads(self.stdout)
        domains = [domain["id"] for domain in domains]
        return domains

    def accounts(self) -> List[str]:
        """
        Retrieve accounts from the Iroha network and return them as list of ids.

        :return: List of accounts ids.
        :rtype: List[str]
        """
        self._execute_command('account')
        accounts = json.loads(self.stdout)
        accounts = [account["id"] for account in accounts]
        return accounts

    def assets(self) -> List[str]:
        """
        Retrieve assets from the Iroha network and return them as list of ids.

        :return:  List of assets ids.
        :rtype: List[str]
        """
        self._execute_command('asset')
        assets = json.loads(self.stdout)
        assets = [asset["id"] for asset in assets]
        return assets

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

    def asset_definitions(self) -> Dict[str, str]:
        """
        Retrieve asset definitions from the Iroha network
        and return them as map where ids are keys and value types are values

        :return: Dict of asset definitions ids with there value type.
        :rtype: Dict[str, str]
        """
        self._execute_command('domain')
        domains = json.loads(self.stdout)
        asset_definitions = {}
        for domain in domains:
            asset_defs = domain.get('asset_definitions')
            for asset_def in asset_defs.values():
                value_type = asset_def.get('value_type')
                if value_type:
                    asset_definitions[asset_def['id']] = value_type
        return asset_definitions
