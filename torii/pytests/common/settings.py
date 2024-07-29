import os
from dotenv import load_dotenv
import toml

load_dotenv()

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
CONFIG_DIR = os.path.join(BASE_DIR, "defaults/client.toml")

with open(CONFIG_DIR, "r") as file:
    config = toml.load(file)
BASE_URL = config.get("torii_url", "http://127.0.0.1:8080").rstrip("/")
print(BASE_URL)
