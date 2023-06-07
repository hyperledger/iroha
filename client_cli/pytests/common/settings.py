import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname \
    (os.path.dirname
     (os.path.dirname
      (os.path.abspath(__file__))))

ROOT_DIR = os.environ.get("CLIENT_CLI_DIR", BASE_DIR)

PATH_CONFIG_CLIENT_CLI = os.path.join(ROOT_DIR, "config.json")
CLIENT_CLI_PATH = os.path.join(ROOT_DIR, "iroha_client_cli")

PORT_MIN = int(os.getenv('TORII_API_PORT_MIN', '8080'))
PORT_MAX = int(os.getenv('TORII_API_PORT_MAX', '8083'))
