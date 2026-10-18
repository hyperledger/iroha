# Conditional ContentFamily lifetime accounting

This package extends the frozen lifetime metadata ledger with the four observed
candidate/comparator VOTE cases at list counts 3 and 1000. It combines those
events with the previously supported accepted requests, rejected-size VOTE
events and full-message oracle queries. It counts complete body computation,
original public inputs and coins, caller outputs, one shared persistent log,
counter and reusable clean workspace. It is not an executed adaptive driver.

**55 owned tests and 72 independent controls passed** in an isolated replay of
the exact historical sources, with no failures, errors or skips. The capture
checks 154 frozen catalog paths and seven execution inputs before and after
execution. Independent controls cover append arithmetic, all mixed-event
orderings, storage ownership, retained purification, boundary sizes, source and
interface refusals, and conservative capacity reservations.

The request cap has an explicit additional premise: T bounds **all typed
request events**, including invalid content and size rejection. The source
theorem's bound on valid requests alone does not imply this restriction.
Bounded-content events pay the full cost and reserve M+2 append slots without a
caller validity flag; actual validity and actual occupancy remain unknown.

## Historical source scope and current refusal

The current native candidate is not validated by these results. During review,
the live `crates/iroha_parliament_ballot_proof/Cargo.toml` differed from the frozen
catalog: actual SHA-256 `3224f341475b4e60fb4e8d778c43971a94d77534670cd2c9bebad444e76de904`
versus expected `f1b9e23aceb1039ff92b3d4dc2f9a94d63afa35842b5b3541b7c9e32b00f76d5`.
The live CLI correctly refused with exit 1 and no JSON report. No repinning or
source replacement was used. The isolated replay restored authenticated
historical bytes from the three existing evidence packages.

The ordinary historical CLI returned exit 0; `--require-qualified` returned
exit 2 with byte-identical conditional JSON. Complete-resource, family-maximum,
adaptive-execution, primitive-bridge, physical-workspace, independent-crypto-
review and qualification flags remain false. All external resource terms stay
unknown. Production remains gated.

## Package and replay

[The review](review/README.md) describes the checked boundary and findings.
[The original capture receipt](capture/receipt.json) and
[original capture manifest](capture/SHA256SUMS) are retained unchanged. Source
files are archived with `.template` suffixes to prevent accidental discovery.
[The replay map](replay-inputs.json) identifies every original path and digest.
Its 154 catalog files refer to exact members of the published request-machine,
lifetime-ledger and content-resource packages; only seven new execution inputs
are copied here. [The dependency record](dependencies.json) pins all three
published manifests. The original capture manifest's 176 logical members can
therefore be verified without duplicating its 161-file replay source tree.

Use the outer manifest digest supplied with this package. From the repository
root, restore to a new, absent directory with Python 3.11 or newer:

```sh
python3 -B <package>/restore.py.template --package <package> --repository . --destination <new-replay-root> --manifest-sha256 <outer-manifest-digest>
```

The restorer verifies the outer package, all three dependency manifests, every
selected replay input and the complete original capture manifest before writing.
It refuses an existing destination. In the new replay root, run:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_ADDOPTS='' PYTEST_PLUGINS='' /opt/homebrew/bin/pytest -q -c /dev/null --noconftest -p no:cacheprovider target/parliament-ledger-content-extension-stage/test_content_ledger.py target/parliament-ledger-content-extension-review/test_independent_content_ledger.py
python3 -B target/parliament-ledger-content-extension-stage/content_ledger.py --root . --events target/parliament-ledger-content-extension-stage/example.json --require-qualified
```

The second command intentionally returns exit 2. The retained capture used the
installed Python/pytest/standard library as trusted execution premises; selected
source hashing is not a full runtime closure or atomic filesystem attestation.

TODO: cover remaining typed shapes and family bounds, price entry checks and
preparation, build the adaptive driver, complete primitive-entry obligations,
qualify the current native candidate and obtain required hardware/external
evidence before any production qualification claim.
