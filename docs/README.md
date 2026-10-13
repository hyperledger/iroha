# Iroha Documentation

Public and in-depth Iroha 3 documentation is published at
[docs.iroha.tech](https://docs.iroha.tech/). Its canonical source is the
[`hyperledger-iroha/iroha-docs`](https://github.com/hyperledger-iroha/iroha-docs)
repository.

This directory is reserved for concise repository-local guidance, generated
reference artifacts, and validation notes. Implementation specifications live
in [`../specs`](../specs/), formal artifacts in [`../formal`](../formal/), and
executable documentation fixtures in
[`../fixtures/documentation`](../fixtures/documentation/). Add user guides,
operator manuals, tutorials, and other long-form public material to
`iroha-docs`, then link to it from here when a source-repository pointer is
useful.

The `iroha` workspace builds and tests independently; a sibling `iroha-docs`
checkout is not required.

For SORA Nexus articles and conceptual explanations, start with **data spaces**:
the environments for data, authority, policy, and applications. The data space
catalog defines data spaces. The lane catalog defines transaction-processing
lanes, each bound to one data space; a data space can have multiple lanes. Call a
bank's environment a data space, and introduce its lanes when explaining routing
or capacity. Follow the writing rules in [`../AGENTS.md`](../AGENTS.md#documentation).
The execution contracts are [`sumeragi_lanes.md`](../specs/sumeragi_lanes.md)
for public lane batches and [`sumeragi.md` §11](../specs/sumeragi.md#11-dataspace-local-finality-and-amx-via-two-phase-commit-application-layer)
for independently executing data spaces.
