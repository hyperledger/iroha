"""
This module initializes the Iroha client and configuration using environment variables.
"""

from common.settings import PATH_CONFIG_CLIENT_CLI, PORT_MAX, PORT_MIN
from src.client_cli.client_cli import ClientCli
from src.client_cli.configuration import Config
from src.client_cli.iroha import Iroha

config = Config(PORT_MIN, PORT_MAX)
config.load(PATH_CONFIG_CLIENT_CLI)
client_cli = ClientCli(config)
iroha = Iroha(config)
