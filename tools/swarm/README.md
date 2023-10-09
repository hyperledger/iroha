# `iroha_swarm`

CLI to generate Docker Compose configuration.

## Usage

```bash
iroha_swarm <options>
```

**Options:**

- **`--outfile <path>`** (required): specify the output file name, e.g. `./docker-compose.yml`. If the file exists, the prompt appears (might be disabled with `--force` option).
- **`--config-dir <path>`** (required): specify the path to the directory containing `config.json` and `genesis.json`. The path to the config will be written into the file specified by `--outfile` relative to its location.
- **Image source** (required):
  - **`--image <name>`**: specify image name, like `hyperledger/iroha2:dev`
  - **`--build <path>`**: specify path to the Iroha repo
- **`--peers <number>` (`-p`)** (required): amount of peers to generate
- **`--seed <string>` (`-s`)** (optional): specify a string to use as a cryptographic seed for keys generation. Allows to generate compose configurations deterministically. UTF-8 bytes of the string will be used.
- **`--force`** (optional): override file specified with `--outfile` if it exists

## Examples

Generate `docker-compose.yml` with 5 peers, using `iroha` utf-8 bytes as a cryptographic seed, using `./configs/peer` as a directory with configuration, and using `.` as a directory with `Dockerfile` of Iroha: 

```bash
iroha_swarm \
    --build . \
    --peers 5 \
    --seed iroha \
    --config-dir ./configs/peer \
    --outfile docker-compose.yml
```

Same, but using an existing Docker image instead:

```bash
iroha_swarm \
    --image hyperledger/iroha2:dev \
    --peers 5 \
    --seed iroha \
    --config-dir ./configs/peer \
    --outfile docker-compose.yml
```
