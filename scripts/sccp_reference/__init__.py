"""Independent Python reference of the SCCP v1 contract-visible relation (`specs/sccp.md` revision 5).

Modules:

* `keccak` – Ethereum Keccak-256;
* `bls12_381`, `hash_to_curve`, `bls_sig` – BLS12-381, RFC 9380 hash-to-G2 and
  the min-pk proof-of-possession signature suite under `DST_SIG`;
* `payload`, `merkle`, `finality` – payloads and message ids, leaves, the
  promote-odd commitment tree and history accumulator, the 221-byte finality
  header `X`, `R`, `QC_FIXED`, the Commit preimage `P`, committee roots,
  anchors and certificates;
* `destination` – an executable model of the §5.1 destination contracts;
* `taira`, `scenario` – a deterministic producer of headers and certificates
  and the scenario recorder;
* `vectors_*` and `generate` – the fixture builders and their CLI.

The code favours readability over speed and is not constant time; it must
never handle real secret keys.
"""
