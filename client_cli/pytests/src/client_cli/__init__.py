"""
This module initializes the Iroha client and configuration using environment variables.
"""

from common.settings import path_config_client_cli, port_min, port_max
from src.client_cli.client_cli import ClientCli
from src.client_cli.configuration import Config
from src.client_cli.iroha import Iroha

config = Config(path_config_client_cli, port_min, port_max)
client_cli = ClientCli(config)
iroha = Iroha(config)
