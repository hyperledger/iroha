# Runtime ABI — Canonical Hash (Torii)

Endpoint
- `GET /v1/runtime/abi/hash`

Response (first release; single policy V1)
```json
{
  "policy": "V1",
  "abi_hash_hex": "cd18f9400b814b2b00724f6d3a077ef34a838c4b5be3f5f1c0663f45ec8ebc19"
}
```

Notes
- The hash binds the complete V1 ABI surface, including syscall signatures, pointer types, program metadata and canonical value layouts.
- Contracts may embed this value in manifests (abi_hash) to bind to the node's ABI.
