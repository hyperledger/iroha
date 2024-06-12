# Iroha Swarm

Command-line tool for generating Docker Compose configuration for Iroha.

## Usage

```bash
iroha_swarm [OPTIONS] --peers <COUNT> --config-dir <DIR> --image <NAME> --out-file <FILE>
```

### Options

- `-p, --peers <COUNT>`: Specifies the number of peer services in the configuration.

- `-s, --seed <SEED>`: Sets the UTF-8 seed for deterministic key-generation.

- `-H, --healthcheck`: Includes a healthcheck for every service in the configuration. 
  - Healthchecks use predefined settings. 
  - For more details on healthcheck configuration in Docker Compose files, see: [Docker Compose Healthchecks](https://docs.docker.com/compose/compose-file/compose-file-v3/#healthcheck).

- `-c, --config-dir <DIR>`: Sets the directory with Iroha configuration. 
  - It will be mapped to a volume for each container. 
  - The directory should contain `genesis.json` and the executor.

- `-i, --image <NAME>`: Specifies the Docker image used by the peer services. 
  - By default, the image is pulled from Docker Hub if not cached. 
  - Pass the `--build` option to build the image from a Dockerfile instead. 
  - *Swarm only guarantees that the Docker Compose configuration it generates is compatible with the same Git revision it is built from itself. Therefore, if the specified image is not compatible with the version of Swarm you are running, the generated configuration might not work.*

- `-b, --build <DIR>`: Builds the image from the Dockerfile in the specified directory. 
  - Do not rebuild if the image has been cached. 
  - The provided path is resolved relative to the current working directory.

- `-C, --no-cache`: Always pull or rebuild the image even if it is cached locally.

- `-o, --out-file <FILE>`: Sets the path to the target Compose configuration file. 
  - If the file exists, the app will prompt its overwriting. 
  - If the TTY is not interactive, the app will stop execution with a non-zero exit code. 
  - To overwrite the file anyway, pass the `--force` flag.

- `-P, --print`: Print the generated configuration to stdout instead of writing it to the target file.

- `-F, --force`: Overwrites the target file if it already exists.

- `-B, --no-banner`: Do not include the banner with the generation notice in the file.
  - The banner includes the passed arguments in order to help with reproducibility.

## Examples

Generate `docker-compose.dev.yml` with 4 peers, using `xyzzy` as the cryptographic seed, using `./peer_config` as a directory with configuration, and using `.` as a directory with the Iroha `Dockerfile` to build a `myiroha:local` image: 

```bash
iroha_swarm \
    --peers 4 \
    --seed xyzzy \
    --config-dir ./peer_config \
    --image myiroha:local \
    --build . \
    --out-file docker-compose.yml
```

Same, but using an existing image pulled from Docker Hub instead, and adding a healthcheck to every peer:

```bash
iroha_swarm \
    --peers 4 \
    --seed xyzzy \
    --healthcheck \
    --config-dir ./peer_config \
    --image hyperledger/iroha:dev \
    --out-file docker-compose.yml
```
