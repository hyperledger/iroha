"""
This module contains the Iroha class, which is a subclass of ClientCli.
"""

import json
from typing import Dict, List

from src.client_cli.client_cli import ClientCli


class Iroha(ClientCli):
    """
    Iroha is a subclass of ClientCli that provides additional methods
    for interacting with the Iroha network.
    """

    def _execute_command(self, command_name: str):
        """
        Execute a command by inserting the command_name into the command list and then executing it.

        :param command_name: The name of the command to execute.
        :type command_name: str
        """
        self.command.insert(2, command_name)
        self.execute()

    def should(self, *args, **kwargs):
        """
        Placeholder method for implementing assertions.

        :param kwargs:
        :return: The current Iroha object.
        :rtype: Iroha
        """
        return self

    def should_not(self, func):
        """
        Decorator that inverts the result of the check function.

        :param func: The function to be inverted.
        :return: Inverted result of the function.
        """

        def wrapper(*args, **kwargs):
            return not func(*args, **kwargs)

        return wrapper

    def domains(self) -> Dict[str, Dict]:
        """
        Retrieve domains from the Iroha network and return then as list of ids.

        :return: List of domains ids.
        :rtype: List[str]
        """
        self._execute_command("domain")
        if self.stdout is not None:
            try:
                domains = json.loads(self.stdout)
            except json.decoder.JSONDecodeError:
                print("JSON decode error occurred with this input:", self.stdout)
                print("STDERR:", self.stderr)
                raise
            domains_dict = {domain["id"]: domain for domain in domains}
            return domains_dict
        else:
            return {}

    def accounts(self) -> List[str]:
        """
        Retrieve accounts from the Iroha network and return them as list of ids.

        :return: List of accounts ids.
        :rtype: List[str]
        """
        self._execute_command("account")
        if self.stdout is not None:
            accounts = json.loads(self.stdout)
            accounts = [account["id"] for account in accounts]
            return accounts
        else:
            return []

    def assets(self) -> Dict[str, str]:
        """
        Retrieve assets from the Iroha network and return them as a dictionary
        where the keys are asset ids and the values are the corresponding asset objects.

        :return: Dictionary of assets.
        :rtype: Dict[str, Any]
        """
        self._execute_command("asset")
        if self.stdout is not None:
            assets = json.loads(self.stdout)
            asset_dict = {asset["id"]: asset for asset in assets}
            return asset_dict
        else:
            return {}

    def asset_definitions(self) -> Dict[str, str]:
        """
        Retrieve asset definitions from the Iroha network
        and return them as map where ids are keys and value types are values

        :return: Dict of asset definitions ids with there value type.
        :rtype: Dict[str, str]
        """
        self._execute_command("domain")
        if self.stdout is not None:
            domains = json.loads(self.stdout)
            asset_definitions = {}
            for domain in domains:
                asset_defs = domain.get("asset_definitions")
                for asset_def in asset_defs.values():
                    value_type = asset_def.get("value_type")
                    if value_type:
                        asset_definitions[asset_def["id"]] = value_type
            return asset_definitions
        else:
            return {}
