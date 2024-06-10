# Iroha Swarm

Docker Compose peer configuration generator for Iroha.

## Usage

```
iroha_swarm [OPTIONS] --peers <PEERS> --config-dir <CONFIG_DIR> --image <IMAGE> --out-file <OUT_FILE>
```

### Options

- `-p, --peers <PEERS>`: Number of peer services in the configuration
- `-s, --seed <SEED>`: The Unicode `seed` string for deterministic key-generation
- `--healthcheck`: Includes a healthcheck for every service in the configuration.
  - The healthchecks use predefined settings.
  - For more details on healthcheck configurations in Docker Compose files, visit: [Docker Compose Healthcheck](https://docs.docker.com/compose/compose-file/compose-file-v3/#healthcheck)
- `-c, --config-dir <CONFIG_DIR>`: Path to a directory with Iroha configuration. It will be mapped to a volume for each container.
  - The directory should contain `genesis.json` and the executor.
- `--image <IMAGE>`: Docker image used by the peer services.
  - By default, the image is pulled from Docker Hub if not cached. Pass the `--build` option to build the image from a Dockerfile instead.
  - **Note**: Swarm only guarantees that the Docker Compose configuration it generates is compatible with the same Git revision it is built from itself. Therefore, if the specified image is not compatible with the version of Swarm you are running, the generated configuration might not work.
- `--build <PATH>`: Build the image from the Dockerfile in the specified directory. Do not rebuild if the image has been cached.
  - The provided path is resolved relative to the current working directory.
- `--no-cache`: Always pull or rebuild the image even if it is cached locally
- `-o, --out-file <OUT_FILE>`: Path to the generated configuration.
  - If file exists, the app will prompt its overwriting. If the TTY is not interactive, the app will stop execution with a non-zero exit code. To overwrite the file anyway, pass the `--force` flag.
- `--force`: Overwrite the target file if it already exists
- `--no-banner`: Disable the banner in the file saying that the file is generated.
  - It includes all passed arguments in order to help with reproducibility.


## Examples

Generate `docker-compose.dev.yml` with 5 peers, using `iroha` UTF-8 bytes as a cryptographic seed, using `./peer_config` as a directory with configuration, and using `.` as a directory with the Iroha `Dockerfile` to build a `myrepo/iroha:dev` image: 

```bash
iroha_swarm \
    --peers 5 \
    --seed iroha \
    --config-dir ./peer_config \
    --image myrepo/iroha:dev \
    --build . \
    --out-file docker-compose.dev.yml
```

Same, but using an existing image pulled from Docker Hub instead, and adding a healthcheck to every peer:

```bash
iroha_swarm \
    --peers 5 \
    --seed iroha \
    --healthcheck \
    --config-dir ./peer_config \
    --image hyperledger/iroha:dev \
    --out-file docker-compose.dev.yml
```
