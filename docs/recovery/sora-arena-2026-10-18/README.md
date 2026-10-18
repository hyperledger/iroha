# Native working-tree recovery checkpoint

This checkpoint preserves the mixed Iroha working changes against the exact
commit in `base-commit.txt`. It is stored in the game repository so the work can
be committed to game master without silently making an unsigned native commit.
The native checkout, index, configuration and refs were left unchanged.

`native-working-tree.patch` contains all tracked working changes and untracked
source/documentation/test files observed at capture time, except the installed
`javascript/iroha_js/node_modules` dependency. There are no generated build
binaries, art assets or private dependency directories. Source-controlled test
fixtures remain included. `inventory.json` records every path, base blob,
source hash and exclusion. This includes existing non-Arena changes such as
staking and consensus work; it is a recovery bundle, not an approved combined
implementation or release candidate. Do not apply the whole bundle as though
all changes were independently reviewed or qualified.

The separate `staged-hit-review/` bundle contains a narrower eight-file
component patch with surgical module registration and an optional new README.
Its isolated build is unvalidated. Earlier native proof results refer to older
source bytes; final-source proving remains pending following the instruction
to stop. The latest full dirty-tree Core integration passed two tests with one
ignored, which does not qualify either recovery patch or a complete game.

Both patches passed read-only applicability checks against copies of their
base files. No patch was applied to native, and no new build or proof was run.
`content-audit.json` records the credential-pattern and source-content review
without printing credential values. The original native tree remains intact.

The native repository's `AGENTS.md` states: “Never bypass commit signing (do not
use `git commit --no-gpg-sign`). If GPG signing is not available in the automation
environment, leave the change uncommitted and ask the user to create a signed
commit locally.” GPG is unavailable here. No unsigned native commit was made.
Restore into an isolated checkout at the recorded base, review the mixed
changes, and commit using the configured signing identity when available.

The checkpoint is not backward compatibility, a second runtime, or a registered
proof profile. It cannot authorize real-value bonding, trading or settlement.
