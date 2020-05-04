# Iroha 2

A very simple and performant blockchain.

## What's new in V2

>> To reach the performance targets, Iroha v2 does not use a database to store data, but instead implements a custom storage solution, called Kura, that is specially designed for storing and validating blockchain data.

Up to date description can be found in [whitepaper](https://github.com/hyperledger/iroha/blob/iroha2/iroha_2_whitepaper.md#28-data-storage).

## Getting started

### Deploy a peer

#### Generate key pair

Before deployment each Peer should generate pair of crypthographic keys. In our example we will use `Ed25519` and 
`ursa_key_utils` CLI tool.

```bash
./ursa_key_utils
```

As a result you will see something like that:

```bash
Public key: [101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]
Private key: [113, 107, 241, 108, 182, 178, 31, 12, 5, 183, 243, 184, 83, 0, 238, 122, 77, 86, 20, 245, 144, 31, 128, 92, 166, 251, 245, 106, 167, 188, 20, 8, 101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]
```

Paste values into config file:

```json
...
  "IROHA_PUBLIC_KEY": "[101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]",
  "IROHA_PRIVATE_KEY": "[113, 107, 241, 108, 182, 178, 31, 12, 5, 183, 243, 184, 83, 0, 238, 122, 77, 86, 20, 245, 144, 31, 128, 92, 166, 251, 245, 106, 167, 188, 20, 8, 101, 170, 80, 164, 103, 38, 73, 61, 223, 133, 83, 139, 247, 77, 176, 84, 117, 15, 22, 28, 155, 125, 80, 226, 40, 26, 61, 248, 40, 159, 58, 53]"
...
```
