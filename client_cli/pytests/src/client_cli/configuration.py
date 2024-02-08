"""
This module provides a Config class to manage Iroha network configuration.
"""

import tomlkit
import os
import random
from urllib.parse import urlparse


class Config:
    """
    Configuration class to handle Iroha network configuration. The class provides methods for loading
    the configuration from a file, accessing the configuration values, and randomising Torii URL
    to access different peers.

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
        self._envs = dict()

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
            self._config = tomlkit.load(config_file)
        self.file = path_config_client_cli

    def randomise_torii_url(self):
        """
        Update Torii URL.
        Note that in order for update to take effect,
        `self.env` should be used when executing the client cli.

        :return: None
        """
        parsed_url = urlparse(self._config["torii_url"])
        random_port = random.randint(self.port_min, self.port_max)
        self._envs["TORII_URL"] = parsed_url._replace(netloc=f"{parsed_url.hostname}:{random_port}").geturl()

    @property
    def torii_url(self):
        """
        Get the Torii URL set in ENV vars.

        :return: Torii URL
        :rtype: str
        """
        return self._envs["TORII_URL"]

    @property
    def env(self):
        """
        Get the environment variables set to execute the client cli with.

        :return: Dictionary with env vars (mixed with existing OS vars)
        :rtype: dict
        """
        return {**os.environ, **self._envs}

    @property
    def account_id(self):
        """
        Get the ACCOUNT_ID configuration value.

        :return: The ACCOUNT_ID.
        :rtype: str
        """
        return self._config['account']["id"]

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
        return self._config["account"]['public_key'].split('ed0120')[1]
