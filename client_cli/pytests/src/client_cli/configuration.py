"""
This module provides a Config class to manage Iroha network configuration.
"""

import json
import os
import random
from urllib.parse import urlparse


class Config:
    """
    Configuration class to handle Iroha network configuration. The class is responsible for reading
    the configuration file, updating the TORII_API_URL with a random port number from the specified
    range, and providing access to the updated TORII_API_URL.

    :param path_config_client_cli: The path to the configuration file.
    :type path_config_client_cli: str
    :param port_min: The minimum port number for the TORII_API_URL.
    :type port_min: int
    :param port_max: The maximum port number for the TORII_API_URL.
    :type port_max: int
    """
    def __init__(self, path_config_client_cli, port_min, port_max):
        if not os.path.exists(path_config_client_cli):
            self.create_default_config(path_config_client_cli)
        with open(path_config_client_cli, 'r', encoding='utf-8') as config_file:
            self._config = json.load(config_file)
        self.file = path_config_client_cli
        self.port_min = port_min
        self.port_max = port_max

    @staticmethod
    def create_default_config(path_config_client_cli):
        default_config = {
            "PUBLIC_KEY": "ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0",
            "PRIVATE_KEY": {
                "digest_function": "ed25519",
                "payload": "9ac47abf59b356e0bd7dcbbbb4dec080e302156a48ca907e47cb6aea1d32719e7233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"
            },
            "ACCOUNT_ID": "alice@wonderland",
            "BASIC_AUTH": {
                "web_login": "mad_hatter",
                "password": "ilovetea"
            },
            "TORII_API_URL": "http://127.0.0.1:8080",
            "TORII_TELEMETRY_URL": "http://127.0.0.1:8180",
            "TRANSACTION_TIME_TO_LIVE_MS": 100000,
            "TRANSACTION_STATUS_TIMEOUT_MS": 15000,
            "TRANSACTION_LIMITS": {
                "max_instruction_number": 4096,
                "max_wasm_size_bytes": 4194304
            },
            "ADD_TRANSACTION_NONCE": False
        }
        try:
            with open(path_config_client_cli, 'w') as f:
                json.dump(default_config, f)
        except Exception as e:
            raise Exception(f"Failed to create config file at {path_config_client_cli}: {str(e)}")

    def update_torii_api_port(self):
        """
        Update the TORII_API_URL configuration value
        with a random port number from the specified range.

        :return: None
        """
        parsed_url = urlparse(self._config['TORII_API_URL'])
        new_netloc = parsed_url.hostname + ':' + str(random.randint(self.port_min, self.port_max))
        self._config['TORII_API_URL'] = parsed_url._replace(netloc=new_netloc).geturl()
        with open(self.file, 'w', encoding='utf-8') as config_file:
            json.dump(self._config, config_file)

    @property
    def torii_api_port(self):
        """
        Get the TORII_API_URL configuration value after updating the port number.

        :return: The updated TORII_API_URL.
        :rtype: str
        """
        self.update_torii_api_port()
        return self._config['TORII_API_URL']

    @property
    def account_id(self):
        """
        Get the ACCOUNT_ID configuration value.

        :return: The ACCOUNT_ID.
        :rtype: str
        """
        return self._config['ACCOUNT_ID']

    @property
    def account_name(self):
        """
        Get the account name from the ACCOUNT_ID configuration value.

        :return: The account name.
        :rtype: str
        """
        return self.account_id.split('@')[0]

    @property
    def account_domain(self):
        """
        Get the account domain from the ACCOUNT_ID configuration value.

        :return: The account domain.
        :rtype: str
        """
        return self.account_id.split('@')[1]

    @property
    def public_key(self):
        """
        Get the PUBLIC_KEY configuration value.

        :return: The public key.
        :rtype: str
        """
        return self._config['PUBLIC_KEY'].split('ed0120')[1]
