"""
This module loads environment variables and sets up important paths
for tests.
"""

import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname \
    (os.path.dirname
     (os.path.dirname
      (os.path.abspath(__file__))))


PATH_CONFIG_CLIENT_CLI = os.environ["CLIENT_CLI_CONFIG"]
CLIENT_CLI_PATH = os.environ["CLIENT_CLI_BINARY"]

PORT_MIN = int(os.getenv('TORII_API_PORT_MIN', '8080'))
PORT_MAX = int(os.getenv('TORII_API_PORT_MAX', '8083'))
