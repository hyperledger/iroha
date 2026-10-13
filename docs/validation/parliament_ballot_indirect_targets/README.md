# Source-conditional provider targets in the frozen ARM64 workers

The [catalog](catalog.json) resolves the seven backend indirect call sites in
each retained resource-worker image to three possible AES provider targets per
site. The slot values are extracted from the actual executable bytes. Target-set
completeness additionally assumes the pinned Rust source's private ownership and
ordinary memory safety. This is a separate diagnostic; the
[original compiled-stack audit](../parliament_ballot_compiled_stack/README.md)
and its inputs remain unchanged. No executable was rebuilt or run.

## What the evidence establishes

The helper reads checked thin ARM64 Mach-O headers and section mappings. For each
of the three constructor branches it follows the emitted `adrp`/`add` constant
address to a 32-byte table in `__DATA_CONST,__const`, checks ordinary dyld rebases
at its two pointer slots, and checks the path to the constructor's fat-pointer
store. The catalog retains raw table bytes, file offsets, header/load-command
bytes, exact symbols, and instruction extracts. The section's `SG_READ_ONLY`
flag means read-only after fixups under the pinned Apple SDK header definition.
It is not a runtime observation of memory permissions.

All addresses below are preferred **unslid** Mach-O VM addresses. Dyld applies
the image slide to the pointer rebases; these are not measured process addresses.

| Mode | AES bits | Table | Drop target | Encrypt target | Size word | Alignment word |
|---|---:|---|---|---|---:|---:|
| Portable | 128 | `0x1000d09d8` | `0x1000173e4` | `0x100014908` | 704 | 8 |
| Portable | 192 | `0x1000d09f8` | `0x1000173e8` | `0x100014a24` | 832 | 8 |
| Portable | 256 | `0x1000d0a18` | `0x100017400` | `0x100014b40` | 960 | 8 |
| Accel | 128 | `0x1000d1838` | `0x10001d8a0` | `0x1000157e4` | 704 | 16 |
| Accel | 192 | `0x1000d1858` | `0x10001d900` | `0x100015b04` | 832 | 16 |
| Accel | 256 | `0x1000d1878` | `0x10001d970` | `0x100015e98` | 960 | 16 |

Each image has one `Prg::fill` call loading the encrypt pointer from byte offset
24 and six destructor calls loading offset 0. The helper checks the observed
load/spill/reload shapes, null guards, argument setup immediately before `blr`,
and destructor metadata loads. Unsupported or changed patterns fail. All three
AES key sizes are retained at every site; verifier inputs are not used to narrow
the sets to AES-256.

The completeness premise comes from
[`prg.rs`](../../../crates/iroha_zkp_vole/src/prg.rs): private `Encryptor`
implementations (lines 62–103), private `Prg.cipher: Box<dyn Encryptor>`
(124–127), the two constructors (153–202), and the sole encrypt dispatch (239).
The pinned BAVC and VOLE conversion sources supply the corresponding ownership
paths. The tool does not perform whole-program points-to analysis, prove that
every register/spill remains uncorrupted, or assume a stable Rust vtable slot ABI.
The actual slot layout is evidence about these two compiled images. The
[Rust Reference](https://doc.rust-lang.org/reference/types/trait-object.html)
describes virtual method dispatch through trait-object metadata without fixing
these offsets. The raw rebase dump is obtained with
[`llvm-objdump`](https://llvm.org/docs/CommandGuide/llvm-objdump.html).

## Separate conditional graph result

The helper loads the exact archived analyzer bytes, copies its function graph,
replaces only the seven named indirect-call frontiers with 21 source-conditional
edges, and reruns the same region calculation.

| Worker-root result | Portable | Accel |
|---|---:|---:|
| Reachable functions after these edges | 329 | 324 |
| Resolved region maximum, including modeled red zones | 15,984 bytes | 13,232 bytes |
| Remaining indirect-call frontiers | 32 | 32 |
| Remaining native-edge frontiers | 169 | 163 |
| Remaining indirect branches | 4 | 4 |
| Exceptional terminals | 42 | 42 |
| Function-boundary fallthroughs | 83 | 83 |
| Positive-weight recursive components | 1 (69 functions) | 1 (69 functions) |

The region maxima are unchanged from the original audit. They do not bound a
complete verification call: the unresolved frontiers and recursive component
remain, along with the analyzer's stated ABI and hidden-runtime assumptions.
`complete_stack_bound_bytes` remains null. Neither the supplied 8 MiB stack's
sufficiency, a complete 64 MiB workspace certificate, nor production profile
qualification is established.

## Reproduction and checks

From the repository root, with Python 3.11, Xcode's `llvm-objdump`, the retained
`/tmp/parliament-resource-contract/resource-{portable,accel}` images, and the
unchanged original evidence available:

```sh
python3.11 scripts/parliament_ballot_indirect_targets.py --output /tmp/parliament-indirect-new
python3.11 -m pytest -q scripts/tests/parliament_ballot_indirect_targets_test.py
```

The output directory must not already exist. A failed attempt cannot overwrite
an earlier successful catalog. The helper checks source/binary/report hashes
before extraction and all captured inputs again afterward. The
[validation receipt](validation-receipt.json) records **36 passing tests** and
unchanged helper/test source identities. Synthetic Mach-O bytes and adversarial
instruction mutations exercise raw-table extraction, bounds, rebase/scalar
separation, wrong or clobbered targets, owner-window boundaries, preserved old
graphs, and refusal to overwrite existing output. These tests validate the
diagnostic's checked cases; they are not an ISA proof.

The catalog pins the original build receipt/source manifest, both executable
hashes, frozen reports/disassembly/analyzer, the three source premises, Python,
objdump, and the SDK header. Source templates and raw rebase output are retained
here, and [SHA256SUMS](SHA256SUMS) covers this artifact set. Old resource reports
have not been repinned. The primary remaining work is proving or bounding the
unresolved runtime/indirect/recursive paths and their native resource use.
