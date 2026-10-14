# Frozen P0/P1/R1 family arithmetic

This review derives and checks component-specific resource envelopes for the
frozen standalone typed request models. It covers P1 over every allowed REG
length tuple, and P0/P1/R1 over every VOTE actual length 3..1000. It does not
establish a maximum for a full request, a lifetime experiment, or a production
verifier. All qualification flags remain false.

The domain is the bounded opaque Rust interface described in the separately
recorded [domain audit](../parliament-family-domain-stage/README.md). REG permits
B in 0..4096 and six independent context lengths c_i in 0..256. VOTE's passing
actual sizes are 3..1000; invalid byte content at those sizes is included by the
fixed totalized P0/P1 schedules. Raw decoding, overlength REG constructor
refusals, rejected VOTE sizes, application witnesses and authority checks are
outside this component review. No new source admission limit is introduced.

## Derivation and independently checked boundaries

[arithmetic.py](arithmetic.py) reconstructs the public framing call tree and its
fresh Boolean history without invoking the actual public circuit builder. For
each clean hash it counts both permutation traversals, all absorption and
padding work, response copies, and retained intermediate states. Profile CRT
table bytes are read in the frozen source's exact order; both namespaces are
charged. H_mu and H4 each retain the full 2112-bit supplied F response workspace.
They are not concrete SHAKE implementations or independently sampled functions.

The outer P0/P1 clean embedding doubles the forward arithmetic and adds one
CNOT per output bit. This is already included in every number below. The
request generator and its inverse invoke those clean maps again; that further
request-level repetition is **not** included here. R1 likewise already includes
its own clean compute/copy/inverse, but not the outer request repetition.

The clean Keccak permutation has (X,CX,CCX) = (76972,539372,76800) and 192086
clean work bits. For a hash message of m bytes and rate r, h=floor(m/r)+1
blocks, and p padding bits, its kernel contributes

```text
X    = 2*h*76972 + 2*p
CX   = 2*h*539372 + 32*m + 512 + 2*p
CCX  = 2*h*76800
work = 1600 + 8*m + p + 1600*h + 192086.
```

SHA3-512 uses r=72,p=3. Profile SHAKE256 uses r=136,p=6. An extra block at
an exact rate boundary is retained. The tests compare the scalar formula to
the frozen hash kernel for all 7849 distinct message lengths used by the REG and
VOTE families, plus SHAKE padding boundaries and both CRT table sizes. These
are metadata and arithmetic checks; no full gate stream or native hash run is
claimed.

### REG P1

Let s=sum(c_i), and

```text
h = floor((40+B)/72)+1 + floor((343+B+s)/72)+1
p = 3*popcount(B) + 2*sum(popcount(c_i)).
```

After subtracting a row-specific constant independent of B and c_i, the clean
P1 gate counts are exactly

```text
X   = 4*76972*h + 2*p
CX  = 4*539372*h + 64*(2*B+s)
CCX = 4*76800*h.
```

The three B prefix occurrences are BODY, REG-AUTH and F_REG; each context
prefix occurs in REG-AUTH and F_REG. Prefix widths are fixed, so only their
popcounts change X counts; their history widths do not change. Original raw
body/context wires are borrowed and retained, not treated as freshly computed
or free input preparation.

Increasing B by one increases elementary cost X+CX+5*CCX by at least
128-6*11=62. Increasing any c_i by one increases it by at least 64-4*7=36.
The block contribution is nonnegative in both cases. Thus the size endpoint
B=4096,c_i=256 maximizes elementary cost and CX. It also attains the maximum
CCX, though a maximum can be attained at other tuples.

X is not coordinatewise monotone: 4095 has twelve one bits and 255 has eight,
while 4096 and 256 each have one. The tuple B=4095,c_i=255 simultaneously
attains all seven popcount maxima and both SHA3 block maxima. It therefore
attains the exact X maximum, 234 X above the size endpoint. Its CX is 512 lower,
so its elementary cost is 278 lower. No exponential tuple enumeration or
max-plus DP is necessary for these particular equations.

History, output width and F count are independent of all seven lengths.
Profile SHAKE requires 1860124 work bits for candidate or 1848924 for comparator;
even the largest REG hash needs less. That fixed profile workspace therefore
dominates P1 scratch throughout REG. The original public input maximum is
46592 bits; P1's interface additionally retains the supplied 128-bit iv_pre and
256-bit salt, for 46976 input bits. Their preparation is a separate obligation.

| Row | Maximum X | Endpoint CX | Endpoint CCX | Maximum elementary | P1 clean work |
| --- | ---: | ---: | ---: | ---: | ---: |
| candidate | 237420996 | 1665194476 | 236236800 | 3083799238 | 2544332 |
| comparator | 236192006 | 1656526124 | 235008000 | 3067757896 | 2528332 |

Both rows use 8 F calls and return 6376 bits. X in the table and the elementary
maximum are attained by different tuples. The scope is exactly P1 across
4097*257^6 = 1180496500391613953 typed length tuples per row.

### VOTE P0/P1/R1

P0 reconstructs three vote comparisons, the full adjacent LexLess scan,
first-error index selection, actual/declared size equality, concrete list hash,
digest equality and all output masks. Each LexLess has 1024 fixed bit steps;
its internal clean traversal is counted before the enclosing P0 traversal.
The list hash has 114+128*n message bytes. This charges the fixed overcomputation
even when the typed input has an early content error. No behavioral correctness
or error-priority proof is added by these resource checks.

P1's authorization hash has 536+128*n bytes, while F_VOTE framing has 506+128*n
bytes. Its clean output is 7976+1024*n bits. The 998 scalar cases are enumerated
separately for both rows, including all index and length prefix popcounts.
Every displayed gate coordinate, clean work width, input width and output width
is nondecreasing; n=1000 attains their component maxima. Constant coordinates
such as F count have many maximizers.

An additional R1 list item introduces one field product and one field XOR in
the selector sum, then 1024 field selections and 1024 field XORs for the public
commitment bits. All degrees and the number of emitted constraints stay fixed
for these accepted sizes. Its field operands are copied into disjoint work
registers and cleaned, so copies cannot be dropped.

Independent long division of every product monomial modulo
x^256+x^10+x^5+x^2+1 gives 1298 CNOTs for the clean field product, with
2*256^2 Toffolis. Including operand copies and both R1 traversals gives

```text
delta CX      = 2*(1298 + 1024 + 1025*512) = 1054244
delta CCX     = 2*(2*256^2 + 1024*256)     = 786432
delta history = (1+1025+1024)*256          = 524800 bits.
```

X and F increments are zero. R1 returns 322 bits and retains a constant
1023-bit shared kernel workspace, so total clean work increases by 524800
bits. R1 input increases by 1024 bits. The independent source-builder checks
cover n=3,4,32,1000, and the published observations independently retain n=3
and 1000 for both rows. The complete 998-case affine census uses the captured
n=3 absolute R1 baseline; it does not independently rederive the fixed R1
intercept or build 998 complete relation schedules.

| Component at n=1000 | Elementary gates | F calls | Clean work bits |
| --- | ---: | ---: | ---: |
| P0, both rows | 7225099904 | 0 | 4138235 |
| P1, candidate | 9674666504 | 8 | 4764001 |
| P1, comparator | 9658625162 | 8 | 4759201 |
| R1, both rows | 776551805828 | 0 | 924930303 |

The machine-readable [census](capture/census.json) includes R1 totals, individual
gate counts, input and return widths. The [CSV](capture/vote-census.csv) retains
all 1996 row/length records, not only the endpoints.

## Reproduction and scope of evidence

[capture.py](capture.py) restores the exact 152 selected inputs from the
published request-machine snapshot, plus the published full-cap content
observation, into [capture/source](capture/source). It authenticates the source
buffers before copying, then checks the selected copies and four review scripts
before and after execution. The shared sources and published snapshots are not
edited or repinned. The receipt records current-checkout differences separately;
the frozen Cargo manifest and the live Cargo manifest differ, so this is not
current production-candidate qualification.

Run once into a fresh capture directory:

```sh
PYTHONDONTWRITEBYTECODE=1 /opt/homebrew/bin/python3.11 target/parliament-family-bounds-review/capture.py
```

The runner disables plugin autoload and repository conftest loading, clears
pytest environment overrides, compares collection and execution membership,
refuses failed/skipped tests, and refuses to overwrite an existing capture.
All 37 collected tests passed in 113.53 seconds, with exactly matching execution
membership and no skipped cases. The [receipt](capture/receipt.json) records all
153 selected source hashes before and after the run, plus the four review
script hashes; [JUnit](capture/junit.xml) records individual test cases. The
top-level `junit.xml` is the retained earlier 24-test run,
not the final validation. This runner does not attest the entire Python,
pytest, compiler, dependency or OS runtime closure.

Still unestablished here: a combined request envelope including S0, opening,
R0, validated W/E and the common return; family selection and descriptor
authentication; rejected-size and raw-constructor entry maps; witness and
application checks; all input/coin preparation and purification; the adaptive
driver, full F implementation, external adversary work, native allocation,
baseline devices, cryptographic review and production acceptance. No component
maximum removes these obligations. Production remains gated.
