# Command-Line Help for `kagami`

This document contains the help content for the `kagami` command-line program.

**Command Overview:**

* [`kagami`↴](#kagami)
* [`kagami crypto`↴](#kagami-crypto)
* [`kagami schema`↴](#kagami-schema)
* [`kagami genesis`↴](#kagami-genesis)
* [`kagami genesis default`↴](#kagami-genesis-default)
* [`kagami genesis synthetic`↴](#kagami-genesis-synthetic)
* [`kagami config`↴](#kagami-config)
* [`kagami config client`↴](#kagami-config-client)
* [`kagami config peer`↴](#kagami-config-peer)
* [`kagami docs`↴](#kagami-docs)
* [`kagami tokens`↴](#kagami-tokens)
* [`kagami validator`↴](#kagami-validator)
* [`kagami swarm`↴](#kagami-swarm)
* [`kagami help-rendered`↴](#kagami-help-rendered)

## `kagami`

Kagami is a tool used to generate and validate automatically generated data files that are shipped with Iroha

**Usage:** `kagami <COMMAND>`

###### **Subcommands:**

* `crypto` — Generate cryptographic key pairs using the given algorithm and either private key or seed
* `schema` — Generate the schema used for code generation in Iroha SDKs
* `genesis` — Generate the genesis block that is used in tests
* `config` — Generate the default client/peer configuration
* `docs` — Generate a Markdown reference of configuration parameters
* `tokens` — Generate a list of predefined permission tokens and their parameters
* `validator` — Generate the default validator
* `swarm` — Generate a docker-compose configuration for a variable number of peers
using a Dockerhub image, GitHub repo, or a local Iroha repo.
* `help-rendered` — Render CLI help message as Markdown



## `kagami crypto`

Generate cryptographic key pairs using the given algorithm and either private key or seed

**Examples:**

- Generate a key pair:

  ```bash
  kagami crypto
  ```

  Output:

  ```
  No flags specified, generating key-pair.
  Public key (multihash): "ed0120232ADEC551BFA1856279EBCCC3C3A09783C516478F4CBB2F42F342614BEC7601"
  Private key (ed25519): "A1E2C094496DD53EA103F1423B90CCB7D65FF25AB46F5FA1643C14E6010F7F75232ADEC551BFA1856279EBCCC3C3A09783C516478F4CBB2F42F342614BEC7601"
  ```

- Generate a key pair from a given seed:

   ```bash
   kagami crypto --seed <seed>
   ```

- Generate a key with the `secp256k1` algorithm and a given private
 key (`B32129AF69B829A88AB9BAC60B2A33CC57F8843E93AAE0478E93F2285059C236`):

   ```bash
   kagami crypto --algorithm secp256k1 --private-key "B32129AF69B829A88AB9BAC60B2A33CC57F8843E93AAE0478E93F2285059C236"
   ```

   Output:

   ```
   Public key (multihash): "e70121031C59A9CABAF58F3B8A6157362B9F6FEAC3DD47EE947FBF2F335805E1A7F96BDE"
   Private key (secp256k1): "B32129AF69B829A88AB9BAC60B2A33CC57F8843E93AAE0478E93F2285059C236"
   ```

- Generate a key in JSON format:

   ```bash
   kagami crypto --json
   ```

   Output:

   ```json
   {
       "public_key": "ed01203189E4982F98DC293AB9E32CF2B2D75FBA49ADBC345318A576377B75CC9E15C1",
       "private_key": {
           "digest_function": "ed25519",
           "payload": "D2162546E2025D28B680D062B91043A1E990DE7DA7861EE5E8039A6B39C9551F3189E4982F98DC293AB9E32CF2B2D75FBA49ADBC345318A576377B75CC9E15C1"
       }
   }
   ```

- Generate a key in compact format:

   ```bash
   kagami crypto --compact
   ```

   Output:

   ```
   ed01208C8A612F0D20F339A0EA8DF21FEA777CBBE3604281E5F52311E5C5602CD38D8E
   878F0FC05183857871A17605FE8F63B4AAF72AC9AF4A5D8DD22536F6D016DFF18C8A612F0D20F339A0EA8DF21FEA777CBBE3604281E5F52311E5C5602CD38D8E
   ed25519
   ```

**Usage:** `kagami crypto [OPTIONS]`

###### **Options:**

* `-a`, `--algorithm <ALGORITHM>` — The algorithm to use for the key-pair generation

  Default value: `ed25519`

  Possible values: `ed25519`, `secp256k1`, `bls_normal`, `bls_small`

* `-p`, `--private-key <PRIVATE_KEY>` — The `private_key` to generate the key-pair from
* `-s`, `--seed <SEED>` — The `seed` to generate the key-pair from
* `-j`, `--json` — Output the key-pair in JSON format
* `-c`, `--compact` — Output the key-pair without additional text



## `kagami schema`

Generate the schema used for code generation in Iroha SDKs

**Usage:** `kagami schema`



## `kagami genesis`

Generate the genesis block that is used in tests

**Examples:**

- Generate a genesis block in JSON format:

   ```bash
   kagami genesis --inlined-validator
   ```
- Generate a genesis block in JSON format and write the output to the specified file:

   ```bash
   kagami genesis --inlined-validator >genesis.json
   ```
- Generate a synthetic genesis block in JSON format and write the `n` domains, `m` accounts per domain and `p` assets per domain:

   ```bash
   kagami genesis --inlined-validator synthetic --domains n --accounts-per-domain m --assets-per-domain p
   ```

- Generate a default genesis block in JSON format and provide path to the validator file (it could be absolute or relative to genesis file)

   ```bash
   kagami genesis --compiled-validator-path ./validator.wasm
   ```

**Usage:** `kagami genesis <--inlined-validator|--compiled-validator-path <COMPILED_VALIDATOR_PATH>> [COMMAND]`

###### **Subcommands:**

* `default` — Generate default genesis
* `synthetic` — Generate synthetic genesis with specified number of domains, accounts and assets

###### **Options:**

* `--inlined-validator` — If this option provided validator will be inlined in the genesis
* `--compiled-validator-path <COMPILED_VALIDATOR_PATH>` — If this option provided validator won't be included in the genesis and only path to the validator will be included. Path is either absolute path to validator or relative to genesis location. Validator can be generated using `kagami validator` command



## `kagami genesis default`

Generate default genesis

**Usage:** `kagami genesis default`



## `kagami genesis synthetic`

Generate synthetic genesis with specified number of domains, accounts and assets.

Synthetic mode is useful when we need a semi-realistic genesis for stress-testing Iroha's startup times as well as being able to just start an Iroha network and have instructions that represent a typical blockchain after migration.

**Usage:** `kagami genesis synthetic [OPTIONS]`

###### **Options:**

* `--domains <DOMAINS>` — Number of domains in synthetic genesis

  Default value: `0`
* `--accounts-per-domain <ACCOUNTS_PER_DOMAIN>` — Number of accounts per domains in synthetic genesis. Total number of  accounts would be `domains * assets_per_domain`

  Default value: `0`
* `--assets-per-domain <ASSETS_PER_DOMAIN>` — Number of assets per domains in synthetic genesis. Total number of assets would be `domains * assets_per_domain`

  Default value: `0`



## `kagami config`

Generate the default client/peer configuration

**Usage:** `kagami config <COMMAND>`

###### **Subcommands:**

* `client` — 
* `peer` — 



## `kagami config client`

**Usage:** `kagami config client`



## `kagami config peer`

**Usage:** `kagami config peer`



## `kagami docs`

Generate a Markdown reference of configuration parameters

**Usage:** `kagami docs`



## `kagami tokens`

Generate a list of predefined permission tokens and their parameters

**Usage:** `kagami tokens`



## `kagami validator`

Generate the default validator

**Usage:** `kagami validator`



## `kagami swarm`

Generate a docker-compose configuration for a variable number of peers
using a Dockerhub image, GitHub repo, or a local Iroha repo.

This command builds the docker-compose configuration in a specified directory. If the source
is a GitHub repo, it will be cloned into the directory. Also, the default configuration is
built and put into `<target>/config` directory, unless `--no-default-configuration` flag is
provided. The default configuration is equivalent of running:

```bash
kagami config peer
kagami validator
kagami genesis default --compiled-validator-path ./validator.wasm
```

Default configuration building will fail if Kagami is run outside of Iroha repo ([tracking
issue](https://github.com/hyperledger/iroha/issues/3473)). If you are going to run it outside
of the repo, make sure to pass `--no-default-configuration` flag.

Be careful with specifying a Dockerhub image as a source: Kagami Swarm only guarantees that
the docker-compose configuration it generates is compatible with the same Git revision it
is built from itself. Therefore, if specified image is not compatible with the version of Swarm
you are running, the generated configuration might not work.

**Usage:** `kagami swarm [OPTIONS] --peers <PEERS> --outdir <OUTDIR> <--image <IMAGE>|--build <PATH>|--build-from-github>`

###### **Options:**

* `--image <IMAGE>` — Use specified docker image
* `--build <PATH>` — Use local path location of the Iroha source code to build images from
* `--build-from-github` — Clone `hyperledger/iroha` repo from the revision Kagami is built itself, and use the cloned source code to build images from
* `-p`, `--peers <PEERS>` — How many peers to generate within the docker-compose
* `--outdir <OUTDIR>` — Target directory where to place generated files
* `--outdir-force` — Re-create the target directory if it already exists
* `--no-default-configuration` — Do not create default configuration in the `<outdir>/config` directory
* `-s`, `--seed <SEED>` — Might be useful for deterministic key generation



## `kagami help-rendered`

Render CLI help message as Markdown

**Usage:** `kagami help-rendered`



<hr/>

<small><i>
    This document was generated automatically by
    <a href="https://crates.io/crates/clap-markdown"><code>clap-markdown</code></a>.
</i></small>

