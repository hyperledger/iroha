# Parliament B6 component family arithmetic

This package establishes conditional arithmetic envelopes for three frozen
request components: P1 over all bounded typed REG length tuples, and P0/P1/R1
over all 998 VOTE actual lengths 3..1000. It does not establish a full request
or lifetime resource bound. Production and profile qualification remain false.

The [component review](record/README.md) gives the source derivations, exact
domains, counted gates and exclusions. Its historical relative links are
preserved as recorded; use this package index and inventory for captured files.
The [census](record/capture/census.json) retains component maxima and the
[CSV](record/capture/vote-census.csv) retains all 1996 VOTE row/length cases.

REG P1's maximum X count occurs at body length 4095 and all six context lengths 255:
234 X above the maximum-sized shape. The body 4096/context 256 endpoint nevertheless
has 278 more elementary gates and is the exact elementary maximum. The proof
uses the exact prefix popcounts and monotone absorption/block terms, not an
inference from two endpoint measurements. The convention is X+CX+5*CCX; ideal
F calls remain separate.

For VOTE, P0/P1 scalar counts include prefix popcounts, ordering scans and hash
padding at every admitted size. R1's per-item increment is independently derived
from its field product/copy/select/XOR schedule: 1054244 CX, 786432 CCX, 524800
history/work bits and no X or F increment. The fixed R1 intercept comes from the
authenticated source observation and is not independently rederived here.
Each clean component already includes its own compute/copy/inverse; the outer
request generator and inverse invoke these components again.

All 37 tests passed in 113.53 seconds with exact collection/execution membership.
They cover source-builder comparisons, mixed REG lengths and padding boundaries,
all 7849 distinct family SHA3 lengths, all 998 scalar VOTE lengths per row, R1
source counts at 3, 4, 32, 1000, and consistency with the four frozen content cases.
The [receipt](record/capture/receipt.json) records all 153 selected frozen source
hashes and four review-script hashes, stable before/after execution. Individual
tests are in [JUnit](record/capture/junit.xml). The earlier 24-test JUnit is retained
separately as historical evidence.

The 153 selected frozen sources are the published request machine's 152 inputs
plus its later published content observation. All 157 source/script snapshots are
included here, so restoration needs no ignored target files. The live Parliament
Cargo manifest differs from the recorded one; this is evidence for the frozen
model, not current production-candidate qualification. No runtime, compiler,
allocator, hardware, complete adversary or cryptographic-review claim is made.

## Integrity and replay

[SHA256SUMS](SHA256SUMS) authenticates this package's files. The original record
and capture manifests and receipts are preserved byte-for-byte. Source files
have a `.template` suffix to keep them inert in the documentation tree.
[inventory.json](inventory.json) maps each package file to its exact original
record path. The captured source tree uses the same relative paths and bytes
as the execution that produced the receipt.

To restore, load inventory.json and, for each entry in `files`, verify SHA-256 of
`package_path`, then copy those exact bytes to a fresh directory at
`restored_record_path`. Do not strip suffixes heuristically or overwrite an
existing tree. Verify the restored top-level SHA256SUMS and
capture/SHA256SUMS against that restored tree. No other source repository files
are needed for the focused checks.

The replay root is `RESTORED/capture/source`. With Python 3.11 and pytest 9.1.0,
clear PYTEST_ADDOPTS, PYTEST_PLUGINS and PYTHONPATH, set
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 and PYTHONDONTWRITEBYTECODE=1, then run:

```sh
python3.11 -m pytest -c /dev/null -o addopts= --noconftest -p no:cacheprovider RESTORED/capture/source/target/parliament-family-bounds-review/test_arithmetic.py
python3.11 RESTORED/capture/source/target/parliament-family-bounds-review/census.py --root RESTORED/capture/source --out NEW_EMPTY_OUTPUT_DIRECTORY
```

The census command expects the fresh empty output directory to exist. It must
reproduce the CSV and JSON bytes recorded here. The historical capture wrapper
also refers to the published packages in the original repository; it is retained
as provenance. The two commands above replay the self-contained captured check
and census sources, without rerunning that wrapper or implying full runtime
dependency closure. Do not overwrite the frozen receipts on replay.

TODO: Complete and validate combined request composition and remaining lifetime,
entry, native workspace, hardware, owner-acceptance and review obligations.
Component maxima do not close those requirements or permit production activation.
