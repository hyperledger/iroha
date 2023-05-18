import os
from dotenv import load_dotenv

load_dotenv()

base_dir = os.path.dirname \
    (os.path.dirname
     (os.path.dirname
      (os.path.abspath(__file__))))

root_dir = os.environ.get("CLIENT_CLI_DIR", base_dir)

path_config_client_cli = os.path.join(root_dir, "config.json")
client_cli_path = os.path.join(root_dir, "iroha_client_cli")

port_min = int(os.getenv('TORII_API_PORT_MIN', '8080'))
port_max = int(os.getenv('TORII_API_PORT_MAX', '8083'))
