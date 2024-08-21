"""
This module initializes the Iroha client and configuration using environment variables.
"""

from ...common.settings import IROHA_CLI_CONFIG, PORT_MAX, PORT_MIN
from .iroha_cli import IrohaCli
from .configuration import Config
from .iroha import Iroha

config = Config(PORT_MIN, PORT_MAX)
config.load(IROHA_CLI_CONFIG)
iroha_cli = IrohaCli(config)
iroha = Iroha(config)
