# Independent finite-sequence wiring review

Reviewed binder SHA-256:
`02eaf6145033344d2c06cdf05faaf97a5e32e64b4c86cb7ecb6b46d068633131`.
The review covers static register ownership, relocation, geometry, selected
malformed descriptors and inverse composition. No additional actionable wiring
defect was found after the two repairs below. This is an internal implementation
review, not independent cryptographic acceptance or production qualification.

Two findings were reported and repaired by the binder owner:

- `describe` accepted negative, noninteger or excessive private-coin metadata
  from an otherwise constructible `Generator`; it now requires an exact natural
  integer no greater than the retained original-input width.
- `Relocation.gate` hashed or sorted malformed wire operands before validating
  their types. It now rejects foreign operands with its normal `ValueError`
  contract, and bounds the variable length width before a shift.

The independent suite has **51 passing controls**: 21 private-coin rejection
cases through accepted/content/common adapters; 21 variable-F start-type cases;
7 elementary wire-type cases; one excessive-width case; and one complete
four-branch sequence control. The last executes two synthetic requests and two
lookups with correlated inputs, arbitrary XOR targets and spectator labels. It
checks last-write lookup results, input retention, zero workspace at each call
boundary, gate totals and the actual reverse-call/request inverse. The four
explicit complex amplitudes are retained under that selected basis permutation;
this does not prove the full joint-state theorem or adaptive experiment.

The original owned suite also passed, **24 tests in 3.77 seconds**, in a separate
uncaptured command. Its result is supplementary; the authenticated review
receipt concerns only the 51 independent controls. No source-provided full-size
generator stream was executed by this review.

`capture.py` records exact collected test IDs and outcomes, 62 selected source
hashes before and after execution, and 36 loaded repository modules, all inside
the selected inventory. The selected files were stable. Runtime was Python
3.11.17 and pytest 9.1.0. The loader, Python, pytest and the selected source
contracts remain trusted; this is not a dependency-closure or atomic-read
attestation. The known live ballot Cargo-manifest drift is outside this Python
test scope and is not accepted as current-candidate qualification.

Reproduction from the same selected source paths:

```sh
/opt/homebrew/opt/python@3.11/bin/python3.11 target/parliament-sequential-composition-review/capture.py
```

Receipt SHA-256:
`31652fce3c1026c3eb6ae7e72aeb620d6575bb11d3a33367bd71a943b8aa594c`.

Only this review directory was written by the reviewer. Frozen source captures,
published packages, Rust code and production gates were not edited. Full
adaptive selection, descriptor and coin preparation, arbitrary source-kernel
semantics, primitive-entry assumptions, uniform family bounds, physical memory
and production qualification remain outside this evidence.
