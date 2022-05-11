# How to hot reload Iroha in a Docker container

Here is the overall procedure for hot reloading Iroha in a Docker container:

1. Build Iroha on your host OS.

    To avoid issues with dynamic linking, run:

    ```bash
    cargo build --release --target x86_64-unknown-linux-musl --features "vendored"
    ```

    <details> <summary> An explanation for using `cargo build` with these parameters. </summary>

    You may experience an issue with dynamic linking if your host OS has a newer version of `glibc` compared to the one in the Docker container. The options used in the command above resolve the issue:

    - `--target x86_64-unknown-linux-musl` forces static linking against `musl` libc implementation
    - `--features "vendored"` facilitates static linkage of the `openssl` library

    </details>

2. Enter Docker container. For example:

    ```bash
    docker exec -it iroha-iroha0-1 bash
    ```

3. Copy Iroha to the current directory:

    ```bash
    docker cp root/soramitsu/iroha/target/x86_64-unknown-linux-musl/release/iroha .
    ```

4. (Optional) Make any modifications you need:

    - [Recommit genesis block](#wiping-previous-blockchain-state-recommit-genesis)
    - [Use custom configuration files](#use-custom-configuration-files)
    - [Use custom environment variables](#use-custom-environment-variables)

5. Exit docker container and restart it using `docker restart`.

    **Note:** If you use the combination of `container down` and `container up`, any modifications you made on the previous step will be lost. Use `docker restart` to preserve changes.

If you skip the optional step (step 4), the state of the blockchain after hot reload will be the same as it was before the Docker container was restarted.

Note that if you get the `Kura initialisation failed` error message, it might mean one of two things: corruption or binary incompatibility of the stored block. To fix this, remove the `blocks/` directory.

## Wiping previous blockchain state (recommit genesis)

To recommit a custom genesis block, remove the previously stored blocks before restarting the container:

```bash
rm blocks/*
```

The new genesis block will be automatically recommited upon container restart.

## Use custom configuration files 

To use custom configuration files, such as `config.json` or `genesis.json`, copy (or bind mount) them to the `config/` subvolume before restarting the Docker container.

The changes will take effect upon container restart.

## Use custom environment variables

To use custom environment variables (e.g. `IROHA_PUBLIC_KEY`), simply modify them before restarting the Docker container. For example:

```bash
    IROHA_PUBLIC_KEY=<new_key> docker restart
```

The changes will take effect upon container restart.