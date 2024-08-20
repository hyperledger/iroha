"""
This module initializes the Iroha client and configuration using environment variables.
"""

from ...common.settings import PATH_CONFIG_IROHA_CLI, PORT_MAX, PORT_MIN
from .iroha_cli import IrohaCli
from .configuration import Config
from .iroha import Iroha

config = Config(PORT_MIN, PORT_MAX)
config.load(PATH_CONFIG_IROHA_CLI)
iroha_cli = IrohaCli(config)
iroha = Iroha(config)
