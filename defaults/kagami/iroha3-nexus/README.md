# iroha3-nexus sample bundle

- chain id: 00000000-0000-0000-0000-000000000753
- VRF seed (hex): 3E448A9DBA73125E26B0178E036E291374CE17CD39AC321D7BC605963577332D
- genesis public key: ed012065D3D00819052AB4D41FD6D168D1F59BE9CE384591383F7762F99C5F9C7A9B11
- topology: 3 logical lanes (`core`, `governance`, `zk`) in the single physical `universal` dataspace
- peers:
- peer 1: public_key=ea0130B48BDF428DF3CCCA7347BD63FB81812CA09315AF56E867117236984D8F80477F8D909C9B1771032F04009AC96536FAC0 address=127.0.0.1:1337 pop_hex=ab06b4f0908551a5504ee8a15229c8326e11bc0994fc52e59774d9025cccb4e493e39cce869ed58892d25906990ae0ad06bdfce0cb4c6653a8f6f427a721ca06acf6eaf12340fe4f50577fa27a0b7569c3d593552d81817ecfcc5f98dc2ae7f6
- peer 2: public_key=ea0130A201DF89B0B1750B54937C3D165E13BC37F5F8736C89AB9FD2A1F24C8EC65762E46027E410BA92FC8D5FB4C398E15EC3 address=127.0.0.1:1338 pop_hex=a3531ad7162812bd3b24f743fd72f82bbb1ec5ec749ee5ac4256e1dcff28e44817900d5903aef1f66877ab88490934340a977c632d11150d1e4fc8cbba6a2cddc913a0dd38e5f68660c0c2619ccdc3734c6abd293ead08acfdd286b05879c6e8
- peer 3: public_key=ea01308FE66200B925944721CC5D08FDC2F4A4D0B6532E33D2874F0294D171C8312363F8FFCE609F7991EB291E4CB90E6A7B66 address=127.0.0.1:1339 pop_hex=a4d08e6d50b63d8ef586a754fad460358d64512843b1eac9a949913b23f6c66985dccc67b2fdfc92dc82a0419b9727420a166383f75d560b20bf38ae8f32234f09fc3b5c345064afc44b175e18fe6242da17ac9472760a898f4369a7a0b29616
- peer 4: public_key=ea0130A9DBBA9104C16C34C4293E68B9A999EE402705F9E7DFD889ED8326730EE7505A96641B1F88D4F93B0B3D0322D02A16FB address=127.0.0.1:1340 pop_hex=a0dc9d607b933fb3e7dcca835e21b5c445da4d063ce6ea73fb48b576b6073a1c0771f965bb4eacc8e455a4c97b69b40b1045a2b783f6fb188abb92ce5249d687dc8e51eb43243ec188d3e4ce341d2f05773926fabeba2f1463a7b5037a0e1a2a

Files:
- genesis.template.json — non-signable topology source; deployable public Nexus genesis must be generated with the canonical XOR asset definition
- `sumeragi_context.nexus_amx_context_hash` is the config-only template projection; the production signer replaces it with the exact staged roster commitment only after the operator supplies that XOR identity
- `sumeragi_context.execution_policy_hash` is likewise a template value; the production signer replaces it with the exact staged V1 execution-policy commitment before refreshing the fingerprint and signing
- verify.txt — policy note; profile verification requires a regenerated genesis with the operator-supplied canonical XOR id
- config.toml — non-deployable public-only Nexus configuration template; validator, SoraNet transport, and streaming signing keys must be supplied through the named per-peer files under `/run/secrets/iroha`
- docker-compose.yml — inert marker; no validator service is emitted until the
  operator supplies the canonical Nexus XOR identity and regenerates the
  complete signed four-validator bundle

Runtime keys are deliberately absent. A regenerated deployable bundle fails closed until every file named by its validator configs is provisioned by the operator.

Wallet loads are ordinary transactions authenticated by finalized blocks.

Regenerate:
- cargo xtask kagami-profiles --profile iroha3-nexus --nexus-xor-asset-definition-id <BASE58>
