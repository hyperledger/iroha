# Arena checkpoint on optimizations

This directory preserves all 162 source, documentation and test changes from
`codex/arena-native-games` against base `8209033deae7409d800fcc576a63609a0c2c5f9d`.
The exact patch and inventory are copied from game master checkpoint `610bb97`.
Dependencies and build outputs are excluded. All source hashes were rechecked.

This is a recovery checkpoint, not a completed runtime integration. The target
`optimizations` checkout at `9bb9d36ab5` has moved the proof engine into
`iroha_core_privacy`, replaced Sumeragi code and refactored privacy and game
boundaries. The old whole-tree patch must not be applied directly over the new
runtime. The preliminary path-aware classification records unresolved conflicts
and removals; it is an integration aid, not an automated migration.

A future explicit resumption should port Arena changes into current owners,
retain current consensus/privacy behavior, and re-run current-source tests and
proofs. Old component evidence does not qualify this newer branch. No runtime
code or preexisting working edits were replaced by this preservation transfer.

Commit signing remains required by the repository's AGENTS.md. This checkpoint
is prepared for a signed commit; creating a commit without signing requires an
explicit user exception. No signing identity or repository policy is changed.
