"""
This module contains the Iroha class, which is a subclass of ClientCli.
"""

import json
from typing import Dict, List
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

    def domains(self) -> Dict[str, Dict]:
        """
        Retrieve domains from the Iroha network and return then as list of ids.

        :return: List of domains ids.
        :rtype: List[str]
        """
        self._execute_command('domain')
        domains = json.loads(self.stdout)
        domains_dict = { domain["id"]: domain for domain in domains }
        return domains_dict

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

    def assets(self) -> Dict[str, str]:
        """
        Retrieve assets from the Iroha network and return them as a dictionary
        where the keys are asset ids and the values are the corresponding asset objects.

        :return:  Dictionary of assets.
        :rtype: Dict[str, Any]
        """
        self._execute_command('asset')
        assets = json.loads(self.stdout)
        asset_dict = {asset["id"]: asset for asset in assets}
        return asset_dict

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
