# W0 independent component review

Read-only review of `write_machine.py` and the exact pinned framing helper is
clear under the declared retained-log and generated-transcript premises.
The fixed schedule performs challenge1, challenge2, then every primary trial,
including disabled trials. It uses source-order fields, separate trial-index
wires, little-endian counters, exact length tags and zero record padding.
Inverse traversal restores the prior chronological array and counter.

The original factory evaluated a shift before validating `length_bits`;
the owner corrected the ordering. The independent module has16 passing cases
covering refusal before source I/O, holes in enable flags with original trial
indices, complete state equality, exact emitted counts, inverse traversal and
an omitted control-uncompute counterexample. Root separately reports17 owner
cases, including all four actual row/role source frames. This review does not
claim those two runs were one frozen capture.

The fixed circuit accepts more enable patterns than source S0 generates.
Source correspondence requires S0's prefix flags and canonical log capacity;
the tests with holes establish robust local routing, not a different sampler.
Full W0 request composition, joint cleanup, primitive assumptions, physical
resources and production qualification remain unproved. No tracked source or
native runtime was changed or executed.
