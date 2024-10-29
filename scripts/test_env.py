#!/usr/bin/env python3
"""
Setup or tear down a bare metal
environment running a debug build of Iroha.
"""

import argparse
import datetime
import ipaddress
import json
import logging
import os
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import tomli_w

SWARM_CONFIGS_DIRECTORY = pathlib.Path("defaults")
SHARED_CONFIG_FILE_NAME = "config.base.toml"

class Network:
    """
    A network of bootstrapped peers to run on bare metal.
    """
    def __init__(self, args: argparse.Namespace):
        logging.info("Setting up test environment...")

        self.out_dir = pathlib.Path(args.out_dir)
        peers_dir = self.out_dir / "peers"
        os.makedirs(peers_dir, exist_ok=True)

        self.peers = [_Peer(args, i) for i in range(args.n_peers)]

        logging.info("Generating shared configuration...")
        trusted_peers = [{"address": f"{peer.host_ip}:{peer.p2p_port}", "public_key": peer.public_key} for peer in self.peers]
        genesis_path = pathlib.Path(args.out_dir) / "genesis.json"
        genesis_key_pair = kagami_generate_key_pair(args.out_dir, seed="Irohagenesis")
        genesis_public_key = genesis_key_pair["public_key"]
        genesis_private_key = genesis_key_pair["private_key"]
        shared_config = {
            "chain": "00000000-0000-0000-0000-000000000000",
            "genesis": {
                "public_key": genesis_public_key
            },
            "sumeragi": {
                "trusted_peers": trusted_peers
            },
            "logger": {
                "level": "INFO",
                "format": "pretty",
            }
        }
        with open(peers_dir / SHARED_CONFIG_FILE_NAME, "wb") as f:
            tomli_w.dump(shared_config, f)

        copy_or_prompt_build_bin("irohad", args.root_dir, peers_dir)
        generate_genesis_json_and_change_topology(args, genesis_path, genesis_public_key, trusted_peers)
        sign_genesis_with_kagami(args, genesis_path, genesis_public_key, genesis_private_key)


    def wait_for_genesis(self, n_tries: int):
        for i in range(n_tries):
            logging.info(f"Waiting for genesis block to be created... Attempt {i+1}/{n_tries}")
            try:
                with urllib.request.urlopen(f"http://{self.peers[0].host_ip}:{self.peers[0].api_port}/status/blocks") as response:
                    block_count = int(response.read())
                    if block_count >= 1:
                        logging.info(f"Genesis block created. Block count: {block_count}")
                        return
                    else:
                        logging.info("Sleeping 1 second...")
                        time.sleep(1)
            except urllib.error.URLError as e:
                logging.info(f"Error connecting to genesis peer: {e}. Sleeping 1 second...")
                time.sleep(1)
        logging.critical(f"Genesis block wasn't created within {n_tries} seconds. Aborting...")
        cleanup(self.out_dir, True)
        logging.critical(f"Test environment directory `{self.out_dir}` was left intact. "
                         f"Inspect it or use `cleanup` subcommand to remove it.")
        sys.exit(2)

    def run(self):
        for i, peer in enumerate(self.peers):
            peer.run()
        self.wait_for_genesis(20)

class _Peer:
    """
    A single bootstrapped peer. Could be a genesis node or a regular peer.
    Should not be run directly, but rather as a part of a Network.
    """
    def __init__(self, args: argparse.Namespace, nth: int):
        self.nth = nth
        self.name = f"iroha{nth}"
        self.p2p_port = 1337 + nth
        self.api_port = 8080 + nth
        self.tokio_console_port = 5555 + nth
        self.out_dir = pathlib.Path(args.out_dir)
        self.root_dir = pathlib.Path(args.root_dir)
        self.peer_dir = self.out_dir / "peers" / self.name
        self.config_path = self.peer_dir / "config.toml"
        self.host_ip = args.host_ip

        logging.info(f"Peer {self.name} generating key pair...")

        seed = self.name if args.peer_name_as_seed else None
        self.key_pair = kagami_generate_key_pair(args.out_dir, seed)
        os.makedirs(self.peer_dir, exist_ok=True)

        config = {
            "extends": f"../{SHARED_CONFIG_FILE_NAME}",
            "public_key": self.public_key,
            "private_key": self.private_key,
            "network": {
                "address":  f"{self.host_ip}:{self.p2p_port}"
            },
            "torii": {
                "address": f"{self.host_ip}:{self.api_port}"
            },
            "kura": {
                "store_dir": "storage"
            },
            "snapshot": {
                "store_dir": "storage/snapshot"
            },
            # it is not available in debug Iroha build
            # "logger": {
            #     "tokio_console_addr": f"{self.host_ip}:{self.tokio_console_port}",
            # }
        }
        config["genesis"] = {
            "file": "../../genesis.signed.scale"
        }
        with open(self.config_path, "wb") as f:
            tomli_w.dump(config, f)
        logging.info(f"Peer {self.name} initialized")

    @property
    def public_key(self):
        return self.key_pair["public_key"]

    @property
    def private_key(self):
        return self.key_pair["private_key"]

    def run(self):
        logging.info(f"Running peer {self.name}...")

        # FD never gets closed
        log_file = open(self.peer_dir / "log.txt", "w")
        # These processes are created detached from the parent process already
        subprocess.Popen([self.name, "--config", self.config_path],
                    executable=self.out_dir / "peers/irohad", stdout=log_file, stderr=log_file)

def pos_int(arg):
    if int(arg) > 0:
        return int(arg)
    else:
        raise argparse.ArgumentTypeError(f"Argument {arg} must be a positive integer")

def copy_or_prompt_build_bin(bin_name: str, root_dir: pathlib.Path, target_dir: pathlib.Path):
    bin_path = root_dir / "target/debug" / bin_name
    try:
        shutil.copy2(bin_path, target_dir)
    except FileNotFoundError:
        logging.error(f"The binary `{bin_name}` wasn't found in `{root_dir}` directory")
        while True:
            prompt = input(f"Build it by running `cargo build --bin {bin_name}`? (Y/n)\n")
            if prompt.lower() in ["y", "yes", ""]:
                subprocess.run(
                    ["cargo", "build", "--bin", bin_name],
                    cwd=root_dir
                )
                shutil.copy2(bin_path, target_dir)
                break
            elif prompt.lower() in ["n", "no"]:
                logging.critical("Can't launch the network without the binary. Aborting...")
                sys.exit(4)
            else:
                logging.error("Please answer with either `y[es]` or `n[o]`")

def kagami_generate_key_pair(out_dir: pathlib.Path, seed: str = None):
    command = [out_dir / "kagami", "crypto", "-j"]
    if seed is not None:
        command.extend(["-s", seed])
    kagami = subprocess.run(command, capture_output=True)
    if kagami.returncode:
        logging.error("Kagami failed to generate a key pair.")
        sys.exit(3)
    # dict with `{ public_key: string, private_key: string }`
    return json.loads(kagami.stdout)

def generate_genesis_json_and_change_topology(args: argparse.Namespace, genesis_path, genesis_public_key, topology):
    genesis_dir_abs = genesis_path.parent.resolve()
    executor_abs = (args.root_dir / SWARM_CONFIGS_DIRECTORY / "executor.wasm").resolve()
    wasm_dir_abs = (args.root_dir / SWARM_CONFIGS_DIRECTORY / "libs").resolve()
    executor_rel = executor_abs.relative_to(genesis_dir_abs, walk_up=True)
    wasm_dir_rel = wasm_dir_abs.relative_to(genesis_dir_abs, walk_up=True)

    command = [
        args.out_dir / "kagami",
        "genesis",
        "generate",
        "--executor", executor_rel,
        "--wasm-dir", wasm_dir_rel,
        "--genesis-public-key", genesis_public_key
    ]
    kagami = subprocess.run(command, capture_output=True)
    if kagami.returncode:
        logging.error("Kagami failed to generate genesis.json")
        sys.exit(1)

    genesis = json.loads(kagami.stdout)

    genesis["topology"] = topology

    with open(genesis_path, 'w') as f:
        json.dump(genesis, f, indent=4)

def sign_genesis_with_kagami(args: argparse.Namespace, genesis_path, genesis_public_key, genesis_private_key):
    command = [
        args.out_dir / "kagami",
        "genesis",
        "sign",
        genesis_path,
        "--public-key", genesis_public_key,
        "--private-key", genesis_private_key,
        "--out-file", args.out_dir / "genesis.signed.scale"
    ]
    kagami = subprocess.run(command)
    if kagami.returncode:
        logging.error("Kagami failed to sign genesis.json")
        sys.exit(5)

def main(args: argparse.Namespace):
    # Bold ASCII escape sequence
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
        style="{",
        format="{asctime} {levelname} \033[1m{funcName}:{lineno}\033[0m: {message}",)
    # ISO 8601 timestamps without timezone
    logging.Formatter.formatTime = (lambda self, record, datefmt=None:
        datetime.datetime.fromtimestamp(record.created)
        .isoformat(sep="T",timespec="microseconds"))
    # Colored log levels
    logging.addLevelName(logging.INFO, f"\033[32m{logging.getLevelName(logging.INFO)}\033[0m")
    logging.addLevelName(logging.ERROR, f"\033[35m{logging.getLevelName(logging.ERROR)}\033[0m")
    logging.addLevelName(logging.CRITICAL, f"\033[31m{logging.getLevelName(logging.CRITICAL)}\033[0m")
    if args.command == "setup":
        setup(args)
    elif args.command == "cleanup":
        cleanup(args.out_dir, False)

def setup(args: argparse.Namespace):
    logging.info(f"Starting Iroha network with {args.n_peers} peers...")
    os.makedirs(args.out_dir, exist_ok=True)
    copy_or_prompt_build_bin("iroha", args.root_dir, args.out_dir)
    with open(os.path.join(args.out_dir, "metadata.json"), "w") as f:
        f.write('{"comment":{"String": "Hello Meta!"}}')
    shutil.copy2(pathlib.Path(args.root_dir) / SWARM_CONFIGS_DIRECTORY / "client.toml", args.out_dir)
    copy_or_prompt_build_bin("kagami", args.root_dir, args.out_dir)

    Network(args).run()

def cleanup(out_dir: pathlib.Path, keep_out_dir: bool):
    logging.info("Killing peer processes...")
    subprocess.run(["pkill", "-9", "iroha"])
    if keep_out_dir:
        logging.info(f"Leaving test directory `{out_dir}` as-is...")
    else:
        logging.info(f"Cleaning up test directory `{out_dir}`...")
        shutil.rmtree(out_dir)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument("command", choices=["setup", "cleanup"],
                        help="Available actions. The `setup` command will create and run \
                        a new test environment with specified number of peers in a \
                        directory of choice. This is meant to be run from `iroha` root dir. \
                        The `cleanup` command will kill all peer processes \
                        that were started by the `setup` command and remove the test directory")
    parser.add_argument("n_peers", nargs="?", default=4, type=pos_int,
                        help="Number of peers to bootstrap. \
                        Defaults to 4. If setup was run with a custom number of peers, \
                        the same number doesn't need to be provided to cleanup as \
                        it kills all processes named `iroha`, so proper caution is advised")

    parser.add_argument("--out-dir", "-o", default="./test", type=pathlib.Path,
                        help="Directory to store config and log files. \
                        Defaults to `./test`. If setup was run with a custom directory, \
                        the same directory must be provided to cleanup, otherwise only \
                        peer processes will be destroyed")
    parser.add_argument("--host-ip", "-i", default="127.0.0.1", type=ipaddress.IPv4Address,
                        help="IP address of the host machine. Used in trusted peer \
                        generation. Defaults to localhost. Note that the port/s shouldn't \
                        be provided as for each peer's endpoints they're assigned automatically")
    parser.add_argument("--root-dir", "-r", default=".", type=pathlib.Path,
                        help="Directory containing Iroha project root. \
                        Defaults to `.`, i.e. the directory script is being run from. \
                        This is used to locate the `irohad` binary and config files")
    parser.add_argument("--peer-name-as-seed", action="store_true",
                        help="Use peer name as seed for key generation. \
                        This option could be useful to preserve the same peer keys between script invocations")

    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose output")

    args = parser.parse_args()
    main(args)
