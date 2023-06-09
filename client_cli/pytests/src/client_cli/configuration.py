"""
This module provides a Config class to manage Iroha network configuration.
"""

import json
import os
import random
from urllib.parse import urlparse


class Config:
    """
    Configuration class to handle Iroha network configuration. The class provides methods for loading
    the configuration from a file, updating the TORII_API_URL with a random port number from the specified
    range, and accessing the configuration values.

    :param port_min: The minimum port number for the TORII_API_URL.
    :type port_min: int
    :param port_max: The maximum port number for the TORII_API_URL.
    :type port_max: int
    """
    def __init__(self, port_min, port_max):
        self._config = None
        self.file = None
        self.port_min = port_min
        self.port_max = port_max

    def load(self, path_config_client_cli):
        """
        Load the configuration from the given config file.

        :param path_config_client_cli: The path to the configuration file.
        :type path_config_client_cli: str
        :raises IOError: If the file does not exist.
        """
        if not os.path.exists(path_config_client_cli):
            raise IOError(f"No config file found at {path_config_client_cli}")
        with open(path_config_client_cli, 'r', encoding='utf-8') as config_file:
            self._config = json.load(config_file)
        self.file = path_config_client_cli

    def update_torii_api_port(self):
        """
        Update the TORII_API_URL configuration value
        with a random port number from the specified range.

        :return: None
        """
        if self._config is None:
            raise ValueError("No configuration loaded. Use load_config(path_config_client_cli) to load the configuration.")
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
