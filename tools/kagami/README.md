# Kagami (Teacher and Exemplar and/or Looking glass)

Kagami is a tool used to generate and validate automatically generated data files that are shipped with Iroha.

## Build

From anywhere in the repository, run:

```bash
cargo build --bin kagami
```

This will place `kagami` inside the `target/debug/` directory (from the root of the repository).

## Usage

Run Kagami:

```
kagami <SUBCOMMAND>
```

### Subcommands

|        Command        |                             Description                              |
| --------------------- | -------------------------------------------------------------------- |
| [`crypto`](#crypto)   | Generate cryptographic key pairs                                     |
| [`docs`](#docs)       | Generate a Markdown reference of configuration parameters            |
| [`genesis`](#genesis) | Generate the default genesis block that is used in tests             |
| [`schema`](#schema)   | Generate the schema used for code generation in Iroha SDKs           |
| [`tokens`](#tokens)   | Generate a list of predefined permission tokens and their parameters |
| [`config`](#config)   | Generate the default configuration for the client or the peer        |
| `help`                | Print the help message for the tool or a subcommand                  |

## `crypto`

The `crypto` command generate cryptographic key pairs using the given algorithm and either private key or seed.

|     Option      |                                          Description                                           | Default value  |  Type  |
| --------------- | ---------------------------------------------------------------------------------------------- | -------------- | ------ |
| `--algorithm`   | The algorithm used to generate the key-pair: `ed25519`, `secp256k1`, `bls_normal`, `bls_small` | `ed25519`      | String |
| `--private_key` | The `private_key` used to generate the key-pair                                                | Not applicable | String |
| `--seed`        | The `seed` used to generate the key-pair                                                       | Not applicable | String |

You can also choose output format:

|   Flag      |                Description                                              |
| ----------- | ----------------------------------------------------------------------- |
| `--json`    | A flag to specify whether or not to output the key-pair in JSON format. |
| `--compact` | A flag to specify whether or not to output the key-pair compact format. |

### `crypto` usage examples

- Generate a key pair:

    ```bash
    ./kagami crypto
    ```

  <details> <summary>Expand to see the output</summary>

    ```bash
    Kagami. To see help run with `--help`.
    No flags specified, generating key-pair.
    Public key (multihash): "ed0120232ADEC551BFA1856279EBCCC3C3A09783C516478F4CBB2F42F342614BEC7601"
    Private key (ed25519): "A1E2C094496DD53EA103F1423B90CCB7D65FF25AB46F5FA1643C14E6010F7F75232ADEC551BFA1856279EBCCC3C3A09783C516478F4CBB2F42F342614BEC7601"
    ```
  </details>

- Generate a key pair from a given seed:

    ```bash
    ./kagami crypto --seed <seed>
    ```

- Generate a key with the `secp256k1` algorithm and a given private key (`B32129AF69B829A88AB9BAC60B2A33CC57F8843E93AAE0478E93F2285059C236`):

    ```bash
    ./kagami crypto --algorithm secp256k1 --private-key "B32129AF69B829A88AB9BAC60B2A33CC57F8843E93AAE0478E93F2285059C236"
    ```

  <details> <summary>Expand to see the output</summary>

    ```bash
    Public key (multihash): "e70121031C59A9CABAF58F3B8A6157362B9F6FEAC3DD47EE947FBF2F335805E1A7F96BDE"
    Private key (secp256k1): "B32129AF69B829A88AB9BAC60B2A33CC57F8843E93AAE0478E93F2285059C236"
    ```
  </details>

- Generate a key in JSON format:

    ```bash
    ./kagami crypto --json
    ```

  <details> <summary>Expand to see the output</summary>

    ```json
    {
        "public_key": "ed01203189E4982F98DC293AB9E32CF2B2D75FBA49ADBC345318A576377B75CC9E15C1",
        "private_key": {
            "digest_function": "ed25519",
            "payload": "D2162546E2025D28B680D062B91043A1E990DE7DA7861EE5E8039A6B39C9551F3189E4982F98DC293AB9E32CF2B2D75FBA49ADBC345318A576377B75CC9E15C1"
        }
    }
    ```
  </details>

- Generate a key in compact format:

    ```bash
    ./kagami crypto --compact
    ```

  <details> <summary>Expand to see the output</summary>

    ```bash
    ed01208C8A612F0D20F339A0EA8DF21FEA777CBBE3604281E5F52311E5C5602CD38D8E
    878F0FC05183857871A17605FE8F63B4AAF72AC9AF4A5D8DD22536F6D016DFF18C8A612F0D20F339A0EA8DF21FEA777CBBE3604281E5F52311E5C5602CD38D8E
    ed25519
    ```
  </details>

## `genesis`

- Generate a genesis block in JSON format:

    ```bash
    kagami genesis
    ```
- Generate a genesis block in JSON format and write the output to the specified file:

    ```bash
    kagami genesis >genesis.json
    ```
 - Generate a synthetic genesis block in JSON format and write the `n` domains, `m` accounts per domain and `p` assets per domain:

    ```bash
    kagami genesis --synthetic --domains n --accounts-per-domain m --assets-per-domain p
    ```

## `schema`

- Generate the schema in JSON format:

    ```bash
    kagami schema
    ```

- Generate the schema in JSON format and write the output to the specified file:

    ```bash
    kagami schema >schema.json
    ```

## `docs`

Generate peer configuration reference in a Markdown format:

```bash
kagami docs
```

The output should be identical to the [reference configuration](../../docs/source/references/config.md).

## `tokens`

- Generate a list of predefined permission tokens and their parameters:

    ```bash
    kagami tokens
    ```

- Generate a list of predefined permission tokens and their parameters and write the output to the specified JSON file:

    ```bash
    kagami tokens >tokens.json
    ```

## `config`

- Generate the default peer configuration:

    ```bash
    kagami config peer > peer-config.json
    ```

- Generate the default client configuration:

    ```bash
    kagami config client > client-config.json
    ```
