# Runtime ABI — Canonical Hash (Torii)

Endpoint
- `GET /v1/runtime/abi/hash`

Response (first release; single policy V1)
```json
{
  "policy": "V1",
  "abi_hash_hex": "d87449f2ec45628b835c736c9915eaa85bfcb87e544da269fdb7c4889d3db82f"
}
```

Notes
- The hash binds the complete V1 ABI surface, including syscall signatures, pointer types, program metadata and canonical value layouts.
- Contracts may embed this value in manifests (abi_hash) to bind to the node's ABI.
