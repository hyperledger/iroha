# Independent ballot-proof reference

These Python sources reproduce the experimental construction in
`specs/parliament_ballot_proof_profile.md` section 6 independently of the Rust
implementation. They are test tooling, are not constant time, and must never
receive real credential secrets. No profile is selected or qualified.

Python 3.10 or newer, its standard library, and a Unix-like platform with
`multiprocessing` fork support are required. From the repository
root, generate into a disposable directory:

```sh
python3.11 -I crates/iroha_parliament_ballot_proof/tests/reference/gen_vectors.py \
  --output-dir /tmp/parliament-ballot-vectors --jobs 4
```

The default run proves and verifies registration plus votes at 3, 500 and 1,000
seats for both parameter rows. Each file is deterministic. Existing files in the
output directory are overwritten. `--row fast --seats 3` selects a shorter
reproduction; `--help` lists the options. The pure-Python comparator can take
roughly 30 minutes per case on the development machine.

The output includes complete proofs (`.proof.hex`), public inputs and per-field
digests (`.txt`), witness and constraint intermediates (`.intermediate.txt`),
public sealed lists (`.list.txt`), and large internal VOLE test values (`.V.txt`).
The committed fixtures retain only the files used by the Rust tests. The
credential secrets and tapes in every output are public deterministic test
values derived from `SHAKE256("PARL-ballot-proto/fixture/v1/" || label)`.

`ballot.py` owns the application relation, `faest.py` the generic backend,
`crt_tables_ref.py` the table generator, and `fixtures.py` the deterministic
inputs. The sources were recovered from the independently written Python
prototype, updated for the final salt/counter/affine-leaf decision, and preserved
here so fixture generation does not depend on a private scratch directory. The
ordinary FAEST reference mode and the experimental extended mode are explicit.
Only the former has official FAEST test vectors. Neither agreement between
implementations nor these self-generated vectors proves the ballot's security.

The backend's independent affine-leaf and transcript fixture can also be
regenerated from these sources:

```sh
python3.11 -I crates/iroha_zkp_vole/tests/fixtures/extended_v1/generate.py \
  crates/iroha_parliament_ballot_proof/tests/reference
```

Its header records hashes of the Python backend and CRT source. The ballot
fixture inventory records the generated files and their hashes separately.
This directory's `SHA256SUMS` pins the reference and fast-test Python sources;
verify it from this directory with `shasum -a 256 -c SHA256SUMS`.
