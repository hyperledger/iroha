# Node Capabilities — Runtime ABI (Torii)

Endpoint
- `GET /v1/node/capabilities`

Response (first release; single ABI policy V1)
```json
{
  "abi_version": 1,
  "data_model_version": 4,
  "crypto": {
    "sm": {
      "enabled": false,
      "default_hash": "sha2_256",
      "allowed_signing": ["ed25519"],
      "sm2_distid_default": "",
      "openssl_preview": false,
      "acceleration": {
        "scalar": true,
        "neon_sm3": false,
        "neon_sm4": false,
        "policy": "scalar-only"
      }
    },
    "curves": {
      "registry_version": 1,
      "allowed_curve_ids": [1]
    }
  }
}
```

Notes
- `abi_version` is the single ABI version accepted by the node at admission and used by Kotodama compilers.
- `data_model_version` is the data model compatibility version. The current
  wire contract is version `4`; SDKs should reject submissions when the node
  advertises a different value.
- `crypto.curves.allowed_curve_ids` enumerates the [`address_curve_registry`](../references/address_curve_registry.md) identifiers derived from the exact committed `crypto_admission_policy_v1` allowed algorithms. Use this advert to decide whether ML‑DSA/GOST/SM controllers are usable on the target cluster.

See also
- `GET /v1/runtime/metrics` for a compact JSON summary of runtime metrics (ABI version and upgrade lifecycle counters).
