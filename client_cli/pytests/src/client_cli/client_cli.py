"""
This module contains the ClientCli class, which is responsible for building and executing
commands for interacting with Iroha blockchain using the Iroha command-line client.
"""
import subprocess
from time import sleep, time
from typing import Callable

import allure

from src.client_cli.configuration import Config


class ClientCli:
    """
    A class to represent the Iroha client command line interface.
    """

    def __init__(self, config: Config, path: str):
        """
        :param config: The configuration object.
        :type config: Config
        :param path: Path to the Iroha client command line interface executable.
        :type path: str
        """
        self.config = config
        self.default_command = [path, f'--config={self.config.file}']
        self.command = self.default_command.copy()
        self.stdout = None
        self.stderr = None
        self._timeout = 5

    def __enter__(self):
        """
        Called when entering a context managed by the ClientCli object.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Called when exiting a context managed by the ClientCli object.

        :param exc_type: The type of exception raised within the context (if any).
        :param exc_val: The instance of the exception raised within the context (if any).
        :param exc_tb: A traceback object encapsulating the call stack at the point
                        where the exception was raised (if any).
        """
        self.reset()

    def wait_for(self, expected: str, actual: str, timeout=None):
        """
        Wait for a certain condition to be met, specified by the expected and actual values.

        :param expected: The expected value.
        :type expected: str
        :param actual: The actual value.
        :type actual: str
        :param timeout: Maximum time to wait for the condition to be met, defaults to None.
        :type timeout: int, optional
        """
        timeout = timeout or self._timeout
        start_time = time()
        while expected not in actual:
            if time() - start_time > timeout:
                allure.attach(actual, name='actual', attachment_type=allure.attachment_type.TEXT)
                allure.attach(expected, name='expected', attachment_type=allure.attachment_type.TEXT)
                raise TimeoutError(f"Expected '{expected}' "
                                   f"to be in '{actual}' "
                                   f"after waiting for '{timeout}' seconds.")
            sleep(1)
        assert expected in actual

    def reset(self):
        """
        Resets the stdout and stderr attributes of the ClientCli object.
        """
        self.stdout = None
        self.stderr = None
        self.command = self.default_command.copy()

    def register(self):
        """
        Appends the 'register' command to the command list.

        :return: The current ClientCli object.
        :rtype: ClientCli
        """
        self.command.append('register')
        return self

    def mint(self):
        """
        Appends the 'mint' command to the command list.

        :return: The current ClientCli object.
        :rtype: ClientCli
        """
        self.command.append('mint')
        return self

    def list_all(self):
        """
        Appends the 'list all' command to the command list.

        :return: The current ClientCli object.
        :rtype: ClientCli
        """
        self.command.append('list')
        self.command.append('all')
        return self

    def domain(self, domain: str):
        """
        Executes the 'domain' command for the given domain.

        :param domain: The domain to be queried.
        :type domain: str
        :return: The current ClientCli object.
        :rtype: ClientCli
        """
        self.command.insert(2, 'domain')
        self.command.append('--id=' + domain)
        self.execute()
        return self

    def account(self, account: str, domain: str, key: str):
        """
        Executes the 'account' command for the given account, domain, and key.

        :param account: The account to be queried.
        :type account: str
        :param domain: The domain of the account.
        :type domain: str
        :param key: The key for the account.
        :type key: str
        :return: The current ClientCli object.
        :rtype: ClientCli
        """
        self.command.insert(2, 'account')
        self.command.append('--id=' + account + '@' + domain)
        self.command.append('--key=ed0120' + key)
        self.execute()
        return self

    def asset(self, asset_definition=None, account=None, value_of_value_type=None):
        """
        Executes the 'asset' command with the given asset definition, account, and value.

        :param asset_definition: The asset definition to be queried, defaults to None.
        :type asset_definition: AssetDefinition, optional
        :param account: The account to be queried, defaults to None.
        :type account: Account, optional
        :param value_of_value_type: The value of the value type, defaults to None.
        :type value_of_value_type: str, optional
        :return: The current ClientCli object.
        :rtype: ClientCli
        """
        self.command.insert(2, 'asset')
        if asset_definition and account and value_of_value_type:
            self.command.append('--account=' + account.name + '@' + asset_definition.domain)
            self.command.append('--asset=' + repr(asset_definition))
            self.command.append(
                '--' + asset_definition.value_type.lower() + '=' + value_of_value_type)
            self.execute()
        return self

    def transfer(self, asset, by, to, quantity: str):
        self.command.append('asset')
        self.command.append('transfer')
        self.command.append('--from=' + repr(by))
        self.command.append('--to=' + repr(to))
        self.command.append('--asset-id=' + repr(asset))
        self.command.append('--quantity=' + quantity)
        self.execute()
        return self

    def definition(self, asset: str, domain: str, value_type: str):
        """
        Executes the 'definition' command for the given asset, domain, and value type.

        :param asset: The asset to be defined.
        :type asset: str
        :param domain: The domain of the asset.
        :type domain: str
        :param value_type: The value type of the asset.
        :type value_type: str
        :return: The current ClientCli object.
        :rtype: ClientCli
        """
        self.command.append('--id=' + asset + '#' + domain)
        self.command.append('--value-type=' + value_type)
        self.execute()
        return self

    def should(self, _expected):
        """
        Placeholder method for implementing assertions.

        :param expected: The expected value.
        :type expected: str
        :return: The current ClientCli object.
        :rtype: ClientCli
        """
        return self

    def execute(self):
        """
        Executes the command and captures stdout and stderr.

        :return: The current ClientCli object.
        :rtype: ClientCli
        """
        command = '\n'.join(self.command)
        with allure.step(f'{command} on the {str(self.config.torii_api_port)} peer'):
            try:
                with subprocess.Popen(
                        self.command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                ) as process:
                    self.stdout, self.stderr = process.communicate()
            except Exception as exception:
                raise RuntimeError(
                    f"Error executing command: {command}. "
                    f"Error: {exception}"
                ) from exception
            finally:
                self.command = self.default_command.copy()
            return self


    @property
    def config(self) -> Config:
        """
        Getter for the 'config' attribute.

        :return: The configuration object.
        :rtype: Config
        """
        return self._config

    @config.setter
    def config(self, value):
        """
        Setter for the 'config' attribute.

        :param value: The new configuration object.
        :type value: Config
        """
        self._config = value
