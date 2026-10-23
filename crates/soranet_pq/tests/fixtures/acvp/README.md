# Pinned NIST ACVP subset

These are 50 unchanged test objects in 24 selected groups from the official
[NIST ACVP-Server repository](https://github.com/usnistgov/ACVP-Server), pinned to
[`975de31eb83d87039ec88934fdc47d8c312b892d`](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d).
The expected cryptographic bytes and negative dispositions come from NIST's
`internalProjection.json` files, independently of Iroha's implementation.
Unselected groups and cases are omitted; selected objects and group metadata
are copied without changing fields. Public test secret keys are fixtures only.

The subset SHA-256 is
`d9d0a4d7e15e07df887d8fd068e9cea86d2580ec179b47fa5b04cb4a00815860`.
The Rust tests and the standard-library-only checker pin this digest separately.
The checker also pins each complete upstream source digest before extraction.

| Source under `gen-val/json-files/` | Full source SHA-256 |
| --- | --- |
| [ML-KEM-keyGen-FIPS203](https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json) | `d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b` |
| [ML-KEM-encapDecap-FIPS203-tr1](https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-encapDecap-FIPS203-tr1/internalProjection.json) | `5e88fbd351dc2915b2ab399f5dffd269e1cdbdd0186103ab0e90b374cf592187` |
| [ML-DSA-keyGen-FIPS204](https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json) | `e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf` |
| [ML-DSA-sigGen-FIPS204-tr1](https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigGen-FIPS204-tr1/internalProjection.json) | `b61576c765b1eb0e6a667a67a68380df944592be8740f9c020c9ea5a89136f18` |
| [ML-DSA-sigVer-FIPS204](https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json) | `47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437` |

## Selection and tests

- ML-KEM: one key generation and encapsulation case per suite; one valid and
  one modified-ciphertext decapsulation case per suite using expanded keys;
  one positive and one negative encapsulation/decapsulation key-check case
  per suite. The modified ciphertext must return the exact official implicit
  rejection secret. It must not become an encoding error.
- ML-DSA: one key generation case per suite; external pure-message randomized
  signing cases with empty context, 255-byte context, and a one-byte message
  (the ML-DSA-65 maximum-context case also has a one-byte message); one case
  for each of the five official signature verification reason classes per suite.
- Repository-derived negative tests mutate those official valid inputs to check
  wrong encoded lengths, context/message substitution, excessive context,
  unused hint padding, excessive hint counts and repeated hint indices. These
  mutations are explicitly repository tests, not additional official ACVP cases.
- The exported `verify_mldsa65_detached` entry used by `iroha_crypto` and IVM
  receives the official empty-context ML-DSA-65 vector and rejects substituted
  messages and nonempty-context signatures. This exercises the shared entry;
  it does not by itself qualify every downstream protocol or target platform.

Exact selected `tgId: [tcId, ...]` values:

```json
{
  "ML-KEM-keyGen-FIPS203": {
    "1": [
      1
    ],
    "2": [
      26
    ],
    "3": [
      51
    ]
  },
  "ML-KEM-encapDecap-FIPS203-tr1": {
    "1": [
      1
    ],
    "2": [
      26
    ],
    "3": [
      51
    ],
    "5": [
      86,
      88
    ],
    "7": [
      106,
      109
    ],
    "9": [
      126,
      127
    ],
    "10": [
      136,
      137
    ],
    "11": [
      146,
      147
    ],
    "12": [
      156,
      157
    ],
    "13": [
      166,
      171
    ],
    "14": [
      176,
      177
    ],
    "15": [
      186,
      187
    ]
  },
  "ML-DSA-keyGen-FIPS204": {
    "1": [
      1
    ],
    "2": [
      26
    ],
    "3": [
      51
    ]
  },
  "ML-DSA-sigGen-FIPS204-tr1": {
    "27": [
      399,
      403,
      405
    ],
    "31": [
      452,
      462
    ],
    "35": [
      512,
      513,
      521
    ]
  },
  "ML-DSA-sigVer-FIPS204": {
    "1": [
      1,
      2,
      3,
      5,
      7
    ],
    "3": [
      31,
      32,
      33,
      34,
      35
    ],
    "5": [
      61,
      63,
      64,
      65,
      72
    ]
  }
}
```

## Reproduction

Run from the repository root. The default check is offline:

```sh
python3 -B scripts/check_soranet_pq_acvp.py
```

To authenticate the full NIST files and check that extraction reproduces the
tracked subset, use a durable cache under ignored `dist/`:

```sh
python3 -B scripts/check_soranet_pq_acvp.py \
  --source-dir dist/soranet-pq-acvp-upstream --download
```

`--download` only retrieves missing files at the pinned revision and verifies
SHA-256 before writing them. Existing corrupt cache files fail authentication;
they are not silently replaced. `--write` explicitly writes the reproduced
subset; it still requires the pinned subset digest to match. No algorithm under
test is called while selecting vectors or checking provenance.

Run the crate's tests with `cargo test -p soranet_pq`; the ACVP unit modules are
included alongside all existing PQClean count-zero and repository KAT tests.

## Scope

The [NIST ML-KEM](https://pages.nist.gov/ACVP/draft-celi-acvp-ml-kem.html) and
[ML-DSA](https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html) protocol documents
explain the group fields. `FIPS203-tr1` and `FIPS204-tr1` are test revisions of
the same FIPS standards, not new cryptographic algorithms.

This is a bounded regression subset, not an ACVP session, NIST certification,
or complete F.5 qualification. The ML-DSA APIs tested here implement external
pure-message signing/verification. Prehash and externally supplied `mu` groups
are deliberately outside this API's coverage. The signing fixtures use explicit
nonzero randomness, matching SoraNet's randomized signing policy; deterministic
zero-randomness and internal-interface corner cases are not claimed. All
existing KAT assertions remain required. Cross-target execution and remaining
F.5 transcript/consumer coverage remain separate work.
