# Kotodama exact numerics and declaration grammar (ABI V1)

This document is normative for the first Kotodama/IVM release. The keywords
`MUST`, `MUST NOT`, `SHOULD`, and `MAY` have their usual standards meaning.
There is no compatibility contract for the pre-release declaration grammar,
numeric types, pointer layouts, or numeric syscalls described as retired
below.

## Source-language surface

Kotodama uses type-first declarations consistently:

```kotodama
seiyaku Counter {
    permission CanIncrement;
    const int initial = 1;
    const int step = 2;

    state int value;

    hajimari() {
        value = initial;
    }

    kotoage fn increment() authorize(CanIncrement) {
        value = value + step;
    }

    view fn current() authorize(anyone) -> int {
        return value;
    }
}
```

The same order applies to local variables and parameters:

```text
let int count = 0;
fn add(int lhs, int rhs) -> int { return lhs + rhs; }
```

The old `name: Type` declaration form is invalid. The source type names `i64`,
`u128`, `Int`, `Integer`, `Decimal`, `Fixed`, `FixedPoint`, `Amount`, `Quantity`,
`num`, `number`, `float`, and `money`, and suffixed numeric literals such as
`1i64`, `1u128`, `1amt`, and `1qty`, are invalid. Diagnostics MUST identify the
retired surface and show the type-first replacement.

Exact `Amount` is forbidden in every source identifier position. The other
retired spellings are reserved only when declaring or referring to a type and
remain ordinary value-namespace identifiers; lowercase `amount` therefore
remains valid, so `fn total(quantity amount) -> quantity` is valid and
unambiguous. (A parameter still cannot share its function's name: functions and
locals live in one value namespace.)

V1 exposes three numeric types:

- `int`: a bounded signed integer with adaptive encoded width;
- `decimal`: a bounded exact base-10 value, not IEEE-754 floating point;
- `quantity`: a nominal, canonical, non-negative asset quantity.

The language does not define a primitive `money` type. Iroha assets may model
commodities, votes, rights, or money, so calling every balance “money” would be
incorrect. Applications MAY define nominal monetary types and policies over
`quantity`.

An unsuffixed whole-number literal has type `int` when no expected type exists.
It may be checked contextually as `decimal` or `quantity`; a contextual
`quantity` literal MUST be non-negative. A literal containing a decimal point
or decimal exponent has type `decimal` unless a `quantity` is expected.
Literal conversion is exact and occurs at compile time.
The expected numeric domain propagates into exact literal arithmetic and into
tuple, struct, list, return, argument, and constant-initializer positions.
This rule changes only exact literal expressions: it never implicitly converts
an existing runtime `int`, `decimal`, or `quantity` value to another nominal
domain.
Literal mantissa and scale are normalized before the canonical scale bound is
checked. Thus a spelling with more than 28 fractional places is accepted only
when removing trailing decimal zeroes reduces its canonical scale to at most
28.

Integer literals MAY use decimal, `0x` hexadecimal, or `0b` binary spelling.
Decimal literals MAY use exact exponent notation. Digit separators are allowed
only between digits. `1.`, `.5`, repeated separators, and missing exponent
digits are invalid. Parsing MUST treat a leading sign and the following literal
as one range-checking operation so `-2^511` is accepted.

## Value domains

### `int`

An `int` is an integer `m` in the closed range:

```text
-2^511 <= m <= 2^511 - 1
```

This is a signed 512-bit two's-complement domain. “512-bit” never means a sign
plus a 512-bit magnitude.

### `decimal`

A `decimal` represents the mathematical value `m * 10^-s`, where:

```text
-2^511 <= m <= 2^511 - 1
0 <= s <= 28
```

Every value has exactly one canonical representation:

1. `(0, s)` normalizes to `(0, 0)`.
2. While `s > 0` and `m` is divisible by ten, replace `(m, s)` with
   `(m / 10, s - 1)`.

Canonicalization discards source-level significant-zero intent. Consequently
`1`, `1.0`, and `1.00` are the same numeric value and encode identically. A
separate application type is required when declared precision is part of the
business meaning.

### `quantity`

A `quantity` has the same canonical representation and scale bound as
`decimal`, with the additional invariant `m >= 0`. It is a distinct nominal
type. There is no implicit conversion from an arbitrary `decimal` or `int` to
`quantity`.

`quantity` itself is asset-independent. The generic
`quantity::try_from_decimal` conversion has no asset identifier and therefore
checks only canonical decimal representation, the 512-bit domain, and
non-negativity. At an asset boundary, the runtime MUST separately validate the
result against that asset definition's `NumericSpec` before changing a balance
or durable economic record. Failure of that second check is an asset numeric
type mismatch, not a quantity-conversion failure. No implementation may infer
asset precision from ambient state inside the generic conversion syscall.

## Arithmetic semantics

Checked arithmetic computes the exact mathematical result using conceptually
unbounded intermediates, canonicalizes the result, and only then checks the
final V1 domain. An implementation's host bigint width, allocation strategy,
or temporary representation MUST NOT affect success, failure, or output.

After canonicalization, result-domain failures are checked in this stable
order: canonical scale, signed mantissa width, then the nominal non-negative
`quantity` invariant. Thus simultaneous scale and mantissa failure reports
`ScaleOverflow`, and a negative result whose magnitude is also out of range
reports `MantissaOverflow`. `quantity - quantity` maps a representable negative
mathematical result to `QuantityUnderflow`.

The following tables are the complete ordinary numeric operator surface. An
em dash means that the combination is a compile-time error; operators are not
commutatively inferred, so an allowed `quantity * decimal` row does not create
a `decimal * quantity` row.

| Operand | Unary `-` result | Semantics |
| --- | --- | --- |
| `int` | `int` | exact checked negation; negating `-2^511` overflows |
| `decimal` | `decimal` | exact negation, canonicalize, then check the final domain |
| `quantity` | — | a non-negative nominal value has no ordinary negation |

| Left | Right | `+` | `-` | `*` | `/` | `%` |
| --- | --- | --- | --- | --- | --- | --- |
| `int` | `int` | `int` | `int` | `int` | `int` | `int` |
| `int` | `decimal` | — | — | — | — | — |
| `int` | `quantity` | — | — | — | — | — |
| `decimal` | `int` | — | — | — | — | — |
| `decimal` | `decimal` | `decimal` | `decimal` | `decimal` | `decimal` | — |
| `decimal` | `quantity` | — | — | — | — | — |
| `quantity` | `int` | — | — | — | — | — |
| `quantity` | `decimal` | — | — | `quantity` | `quantity` | — |
| `quantity` | `quantity` | `quantity` | `quantity` | — | `decimal` | — |

All allowed arithmetic is exact and checked. `int / int` truncates toward
zero and `int % int` is its paired remainder. Runtime `int` and `decimal`
operands require an explicit `decimal::from_int(value)` conversion before they
can share a decimal operator. Decimal division accepts only a canonical exact
result representable with scale in `0..=28`. Quantity
addition remains non-negative by construction; quantity subtraction reports
`QuantityUnderflow` for a representable negative result. Multiplication or
division of a quantity by a decimal preserves the nominal quantity domain and
therefore rejects a negative result. Dividing quantity by quantity produces
an exact dimensionless decimal ratio. No ordinary numeric `%` exists outside
`int % int`.

Each of `==`, `!=`, `<`, `<=`, `>`, and `>=` has this complete matrix:

| Left | `int` right | `decimal` right | `quantity` right |
| --- | --- | --- | --- |
| `int` | `bool` | — | — |
| `decimal` | — | `bool` | — |
| `quantity` | — | — | `bool` |

Comparison is over mathematical values after canonicalization and requires the
same declared numeric type after contextual literal inference. Runtime
`int`/`decimal` comparison requires an explicit `decimal::from_int(value)`
conversion. `quantity` compares only with `quantity`; crossing its nominal
boundary requires a named conversion. These unary, arithmetic, and comparison
tables comprise 102 ordered rows (34 allowed and 68 rejected) in
numeric-semantics descriptor version 3.

Compound assignment applies the same operator matrix and then requires the
result to remain assignable to the target's declared type. A runtime
`decimal += int` is invalid; write
`value += decimal::from_int(delta)` explicitly. A contextually inferred whole
literal such as `value += 2` remains valid because its decimal type is fixed and
folded at compile time. `int += decimal` is also invalid. `quantity` retains its
intentional heterogeneous nominal operator rows.

For `quantity / <whole-number literal>`, the expected result resolves the two
valid rows without adding a runtime conversion. An expected `quantity` (or no
expected type) checks the divisor as `decimal`; an expected `decimal` checks it
as `quantity`, producing a dimensionless ratio. For example,
`fn half(quantity q) -> quantity { q / 2 }` and
`fn ratio(quantity q) -> decimal { q / 2 }` are both exact and have the stated
result types. A non-literal divisor is never retagged this way.

For integer division, with nonzero `b`:

```text
q = trunc(a / b)
a = q * b + r
abs(r) < abs(b)
r has the sign of a unless r = 0
```

`min_int / -1` and `min_int % -1` fail with mantissa overflow because the
paired quotient is not representable. Division by zero has its own fault.

Decimal multiplication forms the exact product at the sum of input scales,
normalizes it, and rejects only when the canonical final scale remains above
28 or its final mantissa is out of range. It never rounds implicitly.

Exact division first reduces and classifies the denominator. A representable
quotient performs exactly one division at its proven minimum scale. A failure
performs no speculative output-scale attempts and distinguishes:

- `RepeatingDecimal`: the reduced denominator contains a prime factor other
  than two or five;
- `ExactDivisionScaleOverflow`: the expansion terminates but needs a canonical
  scale above 28.

For nonzero `b`, exact decimal division is normatively equivalent to this
pseudocode. Every integer in the pseudocode is conceptual and unbounded until
the final-domain check:

```text
exact_divide((ma, sa), (mb, sb)):
    if mb == 0: fail DivisionByZero

    division_operands(output_scale):
        shift = sb + output_scale - sa
        if shift >= 0: return (ma * 10^shift, mb)
        else:          return (ma, mb * 10^(-shift))

    n0, d0 = division_operands(0)
    g = gcd(abs(n0), abs(d0))
    d = abs(d0) / g

    twos = 0
    while d % 2 == 0: d = d / 2; twos += 1
    fives = 0
    while d % 5 == 0: d = d / 5; fives += 1
    if d != 1: fail RepeatingDecimal

    scale = max(twos, fives)
    if scale > 28: fail ExactDivisionScaleOverflow
    n, d = division_operands(scale)
    mantissa, remainder = truncating_div_rem(n, d)
    require remainder == 0             # proven by classification
    result = canonicalize(mantissa, scale)
    check final scale, signed mantissa, then nominal quantity domain
    return result
```

Classification uses exact Euclidean quotient/remainder steps and repeated
exact division by two and five, then performs exactly one quotient/remainder
attempt at the proven scale. A zero dividend follows the same classification
and exact-attempt sequence, but its canonical result emits no divide-by-ten
normalization probe. A host bigint library's GCD or radix-specific shortcut is
not a different observable algorithm.

Rounded division requires an output scale and one of these stable modes:

```text
decimal.div_round(decimal divisor, int scale, rounding-mode mode) -> decimal
quantity.div_round(decimal divisor, int scale, rounding-mode mode) -> quantity
quantity.ratio_round(quantity divisor, int scale, rounding-mode mode) -> decimal
```

Fused operations additionally expose:

```text
decimal.mul_div_round(multiplier: decimal, divisor: decimal, scale: int, mode: rounding-mode) -> decimal
quantity.mul_div_round(multiplier: decimal, divisor: decimal, scale: int, mode: rounding-mode) -> quantity
```

Like every receiver method, the four arguments may be passed positionally in
the order shown or with these labels. These operations retain the mathematical product
before division and round exactly once at the requested scale. The product does
not pass through the ordinary bounded multiplication result type; an overflowing
intermediate is allowed when the final rounded result is representable. Constant
folding and execution use the same fused primitive and all existing deterministic
rounding modes. No compiler or diagnostic selects a financial rounding policy.

`DECIMAL_MUL_DIV_ROUND` (`0x010130`) and `QUANTITY_MUL_DIV_ROUND`
(`0x010150`) take value, decimal multiplier, decimal divisor, Int scale, and raw
rounding mode in `r10..r14`; `r15` must be zero. `r10` returns the typed result.
The existing observed fused primitive charges canonical envelopes, exact limb
multiplication/division and final rounding under staged metering. These calls
must not lower to separate bounded multiplication and division syscalls.

Like every receiver method, these accept their arguments positionally in the
order shown or with the declared labels. `rounding-mode`
denotes one of the seven `Rounding::*` paths below, not a user-declarable type
or an integer tag. `scale` is
checked against `0..=28`; a constant outside that range is rejected with
`E_INVALID_SCALE`, and a dynamic value is checked by the numeric syscall before
arithmetic. `div_round` is not defined on `int`, and `ratio_round` is defined
only on `quantity`. The result domain is fixed by the signature and never
inferred from assignment context.

| Tag | Mode | Meaning |
| ---: | --- | --- |
| 0 | `Rounding::toward_zero` | toward zero |
| 1 | `Rounding::away_from_zero` | away from zero |
| 2 | `Rounding::floor` | toward negative infinity |
| 3 | `Rounding::ceil` | toward positive infinity |
| 4 | `Rounding::nearest_even` | nearest, ties to an even mantissa |
| 5 | `Rounding::nearest_away` | nearest, ties away from zero |
| 6 | `Rounding::nearest_toward_zero` | nearest, ties toward zero |

The tag is the stable numeric ABI tag emitted by the compiler; source does not
expose raw numeric rounding tags. Any spelling outside this table is rejected
with `E_NUMERIC_ROUNDING_MODE`.

Rounded decimal division is normatively equivalent to:

```text
rounded_divide((ma, sa), (mb, sb), output_scale, mode):
    require 0 <= output_scale <= 28
    if mb == 0: fail DivisionByZero
    shift = sb + output_scale - sa
    if shift >= 0: n = ma * 10^shift; d = mb
    else:          n = ma;              d = mb * 10^(-shift)
    q, r = truncating_div_rem(n, d)
    if r != 0:
        adjust q by at most one unit according to mode, sign(n / d),
        comparison(2 * abs(r), abs(d)), and q parity for nearest_even
    result = canonicalize(q, output_scale)
    check final scale, signed mantissa, then nominal quantity domain
    return result
```

`toward_zero` never adjusts; `away_from_zero` always adjusts a nonzero
remainder away from zero; `floor` adjusts only a negative result; `ceil`
adjusts only a positive result. The three nearest modes adjust when
`2*abs(r) > abs(d)` and apply their documented tie rule when equal. All modes
use the same charged conservative work bound.

The source conversion surface is explicit and complete:

| Operation | Result | Normative behavior |
| --- | --- | --- |
| `decimal::from_int(value)` | `decimal` | exact `(value, 0)`; cannot lose range or precision |
| `decimal::to_int_exact(value)` | `int` | succeeds only when the mathematical value is integral; otherwise `InexactConversion` |
| `decimal::to_int_trunc(value)` | `int` | discards the fractional part toward zero |
| `decimal::to_int_round(value, mode)` | `int` | rounds to scale zero using exactly one of the seven modes above |
| `quantity::try_from_int(value)` | `Result<quantity, NumericError>` | exact scale-zero conversion; a negative input returns `NumericError::NegativeQuantity` |
| `quantity::try_from_decimal(value)` | `Result<quantity, NumericError>` | preserves the exact canonical value; a negative input returns `NumericError::NegativeQuantity` |
| `decimal::from_quantity(value)` | `decimal` | exact nominal-domain exit with identical mantissa and scale |

The `NumericError` error payload of a recoverable quantity conversion identifies
the exact numeric fault. Its ABI status register carries the corresponding stable
`NumericFaultV1` tag. Exact and truncating decimal-to-int forms and all infallible
conversions trap on an impossible final-domain violation rather than saturating.
Width-specific constructors,
implicit assignment/argument/return/arithmetic/comparison conversions, and
generic `numeric::*` arithmetic helpers are not part of V1.

These conversions establish only the generic numeric domain shown in the
table. Asset-specific scale validation is a distinct, mandatory ledger-boundary
operation because the conversion ABI carries no asset context.

Checked negation, addition, subtraction, multiplication, division, and
remainder fail rather than wrap. The explicit integer wrapping operations use
modulo `2^512` and reinterpret the result in the signed domain. V1 does not
inherit an `i64` or `u128` modulus from retired source types.

```text
math::wrapping_neg(int value) -> int
math::wrapping_add(int left, int right) -> int
math::wrapping_sub(int left, int right) -> int
math::wrapping_mul(int left, int right) -> int
```

Like every `math::` helper, the binary forms accept their operands positionally
or labelled `left:` and `right:`. These four
spellings are the complete V1 wrapping surface; flat `wrapping_*` aliases and
generic `numeric::*` helpers are not source APIs.

V1 defines no source bitwise or shift operators. A future operation must first
specify its complete 512-bit two's-complement semantics, valid shift counts,
gas, and ABI surface; host-language bigint behavior is never inherited
implicitly.

The checked helpers `math::isqrt(value)` and `math::abs(value)` accept one
`int`. Binary helpers take two `int` operands, positionally or labelled `left:`
and `right:` (`dividend:` and `divisor:` for `div_ceil`).
All operands and final results obey the complete signed 512-bit domain.

| Helper | Result and faults |
| --- | --- |
| `isqrt` | Floor square root; negative input faults with `NegativeSquareRoot` (13). |
| `abs` | Absolute value; the minimum signed integer overflows. |
| `min`, `max` | Signed comparison over the full domain. |
| `div_ceil` | Mathematical ceiling; zero divisor and an unrepresentable result fault. |
| `gcd` | Nonnegative gcd of absolute operands; `gcd(0, 0) = 0`; an unrepresentable result faults. |
| `mean` | Truncate the full intermediate sum divided by two toward zero. |

Constant folding and runtime call the same observed primitive algorithms in
`iroha_primitives::numeric_int`. Runtime uses typed numeric syscalls
`0x010114..=0x01011A`, charging each logical limb phase before doing its work.
No helper narrows an operand to the host machine width. Invalid constant
expressions produce the corresponding compile-time numeric diagnostic.

## Canonical wire values

Numeric pointer payloads are complete, schema-bound, uncompressed Norito
frames. V1 permits no layout flags and no alignment padding.

The schema names and 16-byte schema hashes are:

| Type | Schema name | Hash (hex) |
| --- | --- | --- |
| `int` | `iroha.numeric.IntValueV1` | `07c039457363b9e1d36bbd31d93dec4a` |
| `decimal` | `iroha.numeric.DecimalValueV1` | `ba2ffed52e4d8ee16f17efefe1828524` |
| `quantity` | `iroha.numeric.QuantityValueV1` | `e4769984c81ce0e8b678f2eb06274ee3` |

ABI V1 descriptor format 8 embeds numeric-semantics descriptor version 3 and
the bounded typed-private-input descriptor used by full-width numeric
commitments. It binds all three value domains, exact-intermediate and
result-validation rules,
the complete operator/conversion/wrapping rules, canonicalization, integer and
decimal division behavior, and the ordered arithmetic and validation failure
stages. It also binds the canonical JSON boundary as decoded JSON strings with
these exact content grammars:

```text
int       0|-?[1-9][0-9]*
decimal   -?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?
quantity  (0|[1-9][0-9]*)(\.[0-9]*[1-9])?
```

The grammar is followed by the type's scale, mantissa, and sign checks. JSON
number tokens, leading plus signs or zeroes, negative zero, exponent spelling,
and removable fractional zeroes are not alternate representations.

The descriptor separately binds wire-format version 1, all three schema names
and hashes, the complete frame and pointer-envelope layout strings, rounding,
failure, arithmetic-fault, and pointer-fault names/tags. Changing any bound
semantic or layout changes the V1 ABI hash; an implementation MUST NOT mutate
behavior while retaining the old hash.

The numeric body begins with a four-byte little-endian unsigned mantissa byte
length, followed by the minimal little-endian two's-complement bytes. Decimal
and quantity bodies append one scale byte. Integer bodies do not carry a scale.

Zero has length zero and no mantissa bytes. An empty mantissa is therefore the
only zero encoding. Redundant `0x00` or `0xff` sign extension is invalid. A
positive value needing a sign-preserving leading byte is valid only when the
complete minimal encoding remains at most 64 bytes.

With the fixed 40-byte canonical Norito V1 header, maximum frame sizes are 108 bytes for
`int` and 109 bytes for `decimal` and `quantity`. The pointer envelope adds a
seven-byte header containing a big-endian `u16` pointer type, one-byte version
`1`, and big-endian `u32` frame length, followed by a 32-byte
`iroha_crypto::Hash::new` digest of the complete frame. The resulting maxima
are 147, 148, and 148 bytes respectively.

### Typed durable-state identity

The same ABI V1 descriptor binds aggregate durable values rather than merely
the `STATE_VALUE_ENCODE` and `STATE_VALUE_DECODE` syscall signatures. The
`StateValueSchemaV1` and `StateValueRecordV1` frames use stable nominal Norito
schema names, and the descriptor contains their schema hashes, the exact
`KOTODAMA_STATE_VALUE_SCHEMA_V1\0` schema-binding domain, every
`StateValueKindV1`, `StateValueNodeV1`, and `StateValueAtomV1` name and explicit
`u32` wire tag, each variant layout, leaf-to-pointer-type mapping, resource
handle marker, preorder/active-payload traversal rules, Option/Result tag
meaning, decoded word-table layout, and every node/word/byte/list cap.

The enum variants carry explicit `#[codec(index = ...)]` discriminants, so a
source reorder cannot silently alter persisted state. Any change to one of
these durable wire identities changes the ABI V1 hash. This is still ABI
version 1: first-release artifacts carrying an earlier hash are rejected at
admission rather than interpreted under new semantics.

The descriptor also binds the literal `CNTR` section marker and framing,
nominal `EmbeddedContractInterfaceV1` and `EmbeddedStateTypeV1` schema names
and hashes, the complete ordered table of all 20 one-byte state-type tags with
canonical sample frames and layouts, the 256-node nesting limit, and the exact
admission rules. A `StateMap` is a top-level durable collection only and cannot
appear inside another state type. Its key must be one of the supported
canonical scalar domains; tuples require at least two elements, structs must
have a canonical nonempty name and canonical unique nonempty fields, and list
capacity is `1..=64`. Admission rejects a CNTR tree that the runtime cannot
reconstruct and validate.

When CNTR metadata is present, `STATE_GET`, `STATE_SET`, `STATE_DEL`,
`STATE_HAS`, and `STATE_LEN` accept only a declared scalar path or a canonical
child of a declared `StateMap`; a bare map base is a collection prefix, not a
value. `STATE_SCAN` and `STATE_COUNT` accept that bare map base; only `STATE_SCAN` produces bounded live keyset pages. Before a
write mutates state, and before a present read publishes bytes to the guest,
the host reconstructs the exact schema from CNTR and requires a canonical
`StateValueRecordV1` whose schema hash, active atom stream, pointer types,
pointer hashes, and leaf payloads all match it. Contract execution without its
CNTR section fails closed. Generic non-contract VM programs have no
authenticated durable-state namespace, so every durable-state syscall is
rejected during static admission and again before host dispatch. They retain
the ABI V1 pure compute, numeric, codec, crypto, output, query, and ordinary
permission-checked ISI surface; the exact contract-bound denylist and reserved
transaction-metadata keys are part of `abi_hash`.

The digest is the uniform pointer-ABI frame-integrity binding: it proves that
the bounded frame snapshot subsequently decoded is exactly the frame carried
by the envelope. It is not an authorization mechanism. Before work begins, the
VM debits the declared, capped frame bytes for snapshot transport and
`32 + frame_bytes` for supplied-digest handling plus the complete hash
traversal, then decodes only that authenticated snapshot.

Pointer type IDs are:

```text
0x000C  unassigned (rejected as unknown)
0x0010  QuantityValueV1
0x0011  IntValueV1
0x0012  DecimalValueV1
0x0013  AxtAnchoredSpendV1 (non-numeric, rejected as wrong type)
0x0014  unassigned (rejected as unknown)
```

Numeric comparison and equality operate on the mathematical value after
canonicalization. A numeric `StateMap` key's identity and hash input are its
canonical encoded bytes, so alternate spellings of one value cannot create
distinct keys. Deterministic `StateMap` iteration uses canonical encoded-key
byte order; that order is not promised to match signed numeric magnitude.
The VM binds map-key construction and iteration to the loaded CNTR declaration:
the base must name exactly one declared `StateMap`, and numeric keys must be
canonical pointer envelopes of that map's nominal `int`, `decimal`, or
`quantity` key type. Missing schemas, malformed or noncanonical frames, and
cross-type envelopes fail closed. Number `0x54` is unassigned in ABI V1 and is
rejected as unknown; V1 defines no compatibility reservation or tombstone for
the pre-release scalar path helper.
SDKs MUST use arbitrary-precision integer or exact-decimal representations and
MUST NOT map these values to JavaScript
`number`, Java/Kotlin `double`, Swift `Double`, or another lossy host type.
Norito JSON and SDK-facing JSON render all three numeric domains as canonical
base-10 strings: `int` has no decimal point, while `decimal` and `quantity`
use the shortest non-exponent spelling implied by their canonical mantissa and
scale. JSON numeric tokens and alternate string spellings are rejected at a
typed numeric boundary.

## Syscalls and failures

ABI V1 contains the unconditional numeric syscall blocks:

```text
0x010100..0x01011A  int
0x010120..0x010130  decimal
0x010140..0x010150  quantity
```

Typed exact-number JSON getters occupy exactly `0x010160..0x010162`: `int`,
`decimal`, and `quantity`. They accept only a canonical base-10 JSON string and
return `Option::none` only when the key is absent. A present JSON number token,
exponent spelling, leading plus or zero, negative quantity, removable
fractional zero, or out-of-domain string traps with `DecodeError`, so malformed
input never reads as a missing field; it is never rounded or converted through
a host floating-point type. Numbers
`0x010163..0x010165` are unassigned and return `UnknownSyscall` before syscall
gas charging, allocation, or state mutation. Generic `JSON_SET_I64` remains a
number-token constructor outside the exact-number surface.

The detailed signatures live in `crates/ivm/spec/syscalls.toml`. The retired
pre-release generic-`Numeric` and `Amount` syscall blocks are not in the V1
allowlist. Every host MUST implement the allowed blocks identically or reject
an unknown number with `VMError::UnknownSyscall`.

Stable numeric fault tags are:

```text
1 MantissaOverflow
2 ScaleOverflow
3 DivisionByZero
4 RepeatingDecimal
5 ExactDivisionScaleOverflow
6 InvalidScale
7 InexactConversion
8 NegativeQuantity
9 QuantityUnderflow
10 InvalidRoundingMode
11 InvalidFailureMode
12 ReservedRegisterNonZero
13 NegativeSquareRoot
```

Stable numeric pointer-validation fault tags are:

```text
1 InvalidAddress
2 UnknownType
3 TypeNotAllowed
4 WrongType
5 InvalidEnvelopeVersion
6 OversizedLength
7 TruncatedEnvelope
8 PayloadHashMismatch
9 MalformedFrame
10 SchemaMismatch
11 NonCanonical
```

Both fault tables, including names and tags, are inputs to the ABI V1 hash.

Fallible arithmetic and checked conversions accept failure mode `0` (trap) or
`1` (return the fault in the status register). `INT_TO_I64`, `INT_TO_U64`,
`DECIMAL_TO_INT_EXACT`, `QUANTITY_FROM_INT`, and `QUANTITY_FROM_DECIMAL` read
the authenticated source pointer from `r10`, require zero `r11..r13`, and read
the failure mode from `r14`. Trap mode preserves the exact `NumericFaultV1`;
it does not lower a failed conversion to a generic abort. Status mode returns
zero in `r10` and the fault tag in `r11`. Success returns the converted value
in `r10` and zero in `r11`. The compiler selects status mode only for source
operations that return `Result`, such as `quantity::try_from_int`; source
operations with a checked value result use trap mode. Invalid pointer
envelopes, versions, lengths, hashes, schemas, flags,
canonical encodings, scale pointers, rounding tags, failure modes, and required
zero registers have deterministic distinct validation behavior.

## Deterministic gas

Numeric syscalls use staged metering. They never reserve a worst-case quote and
never refund. Each phase is debited immediately before its bounded work begins;
an unaffordable phase performs no work and leaves earlier phase charges
consumed.

The complete formula and stable OOG phase-tag map have gas-formula version 6.
That version is an input to gas-schedule descriptor format 4 under domain
`iroha.ivm.gas-schedule.v4`. The descriptor also encodes every staged phase
name and numeric tag directly, in tag order; the phase table is not represented
only by an indirect formula-version constant. Changing any logical-work
formula, charge-point ordering, phase name, or phase tag MUST increment the
appropriate descriptor/formula version and regenerate the gas-schedule hash
golden.

The version-3 phase tags are `0 Entry`, `1 PointerHeader`,
`2 PointerEnvelope`, `3 PayloadHash`, `4 NoritoDecode`,
`5 CanonicalValidation`, `6 Arithmetic`, `7 Normalization`, and
`8 OutputSerialization`. Every tag names work that a production numeric path
can actually reach; V1 has no reserved or quote-only staged phases.

Every ABI V1 numeric syscall number requires the wide `SYSTEM`/`SCALLX`
instruction. Executing that instruction costs 5 gas before syscall admission
or staged dispatch. That opcode cost is part of total VM gas, but is
deliberately outside the numeric staged-call formula below. Therefore:

```text
total_vm_gas_for_one_numeric_call = 5 + completed_numeric_stage_gas
```

The stage charge unit is exact and uses checked `u64` arithmetic:

| Phase | Charge immediately before work | Repetition |
| --- | ---: | --- |
| `Entry` | `384` | once per admitted numeric call |
| `PointerHeader` | `7` | once per pointer operand |
| `PointerEnvelope` | `frame_bytes` | once per pointer operand |
| `PayloadHash` | `32 + frame_bytes` | once per pointer operand |
| `NoritoDecode` | `4 * decode_work(frame_bytes)` | once per pointer operand |
| `CanonicalValidation` | `4 * canonical_work(frame_bytes)`, plus `4 * QR(mantissa_limbs, 1)` when a canonicality probe is required | in operand-register order |
| `Arithmetic` | `4 * event_work` | once before every arithmetic event actually begun |
| `Normalization` | `4 * QR(mantissa_limbs, 1)` | once before each divide-by-ten normalization probe actually begun |
| `OutputSerialization` | `4 * finalization_work(output_limbs)`, then `output_envelope_bytes + 2 * output_frame_bytes` | only when a numeric pointer result is produced |

Here `QR` is `quotient_remainder_work` defined below. Boolean or scalar
results do not acquire a nonexistent pointer-output charge. A trap or
recoverable arithmetic fault has no output charge. The operational state
machine is:

```text
execute_numeric_scallx(call):
    debit 5                         # ordinary VM instruction gas
    staged_debit(Entry, 384)
    initialize the staged context and validate syscall privacy
    for pointer operand in register order:
        staged_debit(PointerHeader, 7)
        read header; validate provenance, type, version, and capped length
        staged_debit(PointerEnvelope, frame_bytes)
        staged_debit(PayloadHash, 32 + frame_bytes)
        snapshot bounded tail; authenticate the exact snapshot
        staged_debit(NoritoDecode, 4 * decode_work(frame_bytes))
        structurally validate the frame
        staged_debit(CanonicalValidation, 4 * canonical_work(frame_bytes))
        decode the body; debit any canonicality probe before performing it
    validate scalar controls in the specified precedence order
    for event in the selected exact operation:
        staged_debit(event.phase, 4 * event_work(event))
        perform event
    if a pointer result exists:
        debit its output-length probe
        derive exact bounded frame/envelope lengths
        debit framing, checksum, authentication, and publication bytes
        allocate, write, and publish result registers
```

`staged_debit` first compares the whole phase charge with remaining gas. If it
is unaffordable, it deducts nothing for that phase, reports that phase's stable
tag, and preserves all earlier charges. There is no quote, reservation, or
refund path.

The successful aggregate identity is:

```text
gas = 384
    + canonical input envelope bytes
    + input frame bytes traversed by the authentication hash
    + canonical output envelope bytes
    + 2 * output frame bytes
    + 4 * logical_limb_work
```

The two output-frame traversals cover canonical Norito framing/checksum work
and the outer authentication hash. `logical_limb_work` includes the bounded
output-length probe before exact compact serialization begins.

There is no implicit minimum applied to `logical_limb_work`; operations whose
normative work is zero still pay the entry and envelope charges.

For a numeric output mantissa `m`, the signed-length probe uses
`output_limbs = L(bit_length(abs(m)) + 1)`. Zero therefore uses one limb.
The extra conceptual sign bit covers every positive sign-extension boundary;
it deliberately charges a conservative extra limb for negative exact powers
of two at a 64-bit boundary, including nine limbs for `-2^511`. The later byte
charge still uses the exact minimal two's-complement frame length. The probe's
four gas units per limb cover the conservative bit-width scan, the V1 signed
domain check, exact minimal-length derivation, and deterministic control. The
serializer consumes the already-canonical `Numeric`/`Quantity` proof and MUST
NOT repeat decimal divisibility validation; mantissa byte emission, framing,
checksumming, hashing, and publication are covered by the subsequent byte
charge.

The constants are consensus weights, not host-cycle counts. They are not
considered release-calibrated until the required benchmark evidence is
archived. The
entry weight `384` covers syscall dispatch, staged-context initialization,
bounded validation of at most four control/reserved registers, and completion
bookkeeping. Pointer traversal is excluded because every traversed envelope
byte is charged separately. The limb-work weight `4` budgets one logical
base-`2^64` work cell for operand access, the arithmetic/carry or trial step,
result access, and deterministic loop/control overhead. Multiplication counts
every input-cell product; division and normalization formulas count their
normalization, quotient-trial, remainder, and probe cells explicitly. Thus a
backend cannot make an uncharged algorithmic pass by selecting a different
bigint representation.

Release calibration uses `cargo bench -p ivm --bench gas_calibration`. The
`ivm-numeric-limb-cal` benchmark pins the formula's work denominator in every
benchmark ID for one through eight input limbs, products through sixteen
limbs, division/remainder, scale-28 rounded division, and minimum/maximum
input snapshot/authentication/canonical-decode and output
framing/authentication/publication pipelines. A failing
numeric syscall with an invalid zero pointer separately measures the entry,
dispatch/control, and seven-byte pointer-header boundary without performing
payload work. Its calibration denominator is the staged `384 + 7` gas; the
generic five-gas `SCALLX` instruction charge is asserted against the VM's total
consumption but excluded from that denominator, so it cannot hide an
underpriced numeric entry phase. For each supported
baseline hardware tier, maintainers compare median time per declared work cell
against the scalar IVM `ADD` baseline. `ADD` and the VM-based numeric entry
pipeline subtract the measured `EMPTY_HARNESS` cost before normalization;
direct bigint, decimal, and frame-codec benchmarks do not contain that VM
harness and therefore are not adjusted by it. The
rounded-up worst ratio, plus a minimum 25% safety margin, MUST remain no greater
than `4`; bounded dispatch/control overhead MUST remain no greater than `384`
baseline gas units. A failure requires increasing the constants, changing the
gas-formula version/hash, and regenerating gas goldens before release—it MUST
NOT be hidden by a hardware-specific implementation. The first-release
reference-calibration target is Apple M1 Ultra (`Mac13,2`, arm64). The
first-release slowest supported tier is AWS Graviton3 `c7g.4xlarge`
(`Neoverse-V1`, 16 logical CPUs, Linux arm64). Both profiles use Rust 1.93.1
(`01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf`, 2026-02-11). Release records
MUST retain the complete Criterion output for both profiles alongside the
build artifacts. This specification does not claim calibration has completed
unless both archived outputs are present for the exact candidate SHA. Machines
below the pinned Graviton3 tier are not a first-release performance-supported
validator target.
The `numeric_v1_calibration.yml` release workflow is a two-profile matrix and a
manual or reusable **pre-tag** gate. It accepts only an untagged protected-branch commit, requires
the requested full SHA to equal both the caller/source SHA and the SHA of this
job-defining workflow (so reusable calls must use this repository at the same
candidate commit), and targets two self-hosted runners. The reference runner
requires `numeric-v1-release-calibration`, `apple-m1-ultra`, and `mac13-2`;
the slowest-tier runner requires `numeric-v1-release-calibration`,
`numeric-v1-slowest-supported-tier`, `aws-graviton3`, and `c7g-4xlarge`.
Those labels route the jobs but do not establish trust: the checker rejects a
missing or mismatched hardware profile, architecture, logical CPU count,
runner identity, Rust release/host triple, source SHA, repository, release
tag, or workflow-run identity. The reference runner MUST expose an English
`SPHardwareDataType` record whose model is `Mac13,2` and chip is
`Apple M1 Ultra`. The slowest-tier runner MUST expose AWS IMDSv2 instance type
`c7g.4xlarge` and `lscpu` model `Neoverse-V1`. Both runners require Python 3,
GitHub CLI, `tar`, `curl`, and a SHA-256 utility. A reusable caller MUST grant `contents: write`,
`attestations: write`, and `id-token: write`; called workflows cannot elevate a
caller's token permissions, so a missing grant fails closed.

Before the gate runs, release engineering MUST provision the dedicated,
unpublished GitHub draft release named by `evidence_release_tag` (by default
`numeric-v1-calibration-evidence-v1`). Its tag is a storage anchor and MUST be
different from the candidate `release_tag`; the candidate tag itself MUST not
exist. An accepted run packages the complete Criterion directory, structured
host/toolchain record, exact command, console and verifier transcripts,
machine-readable report, and per-file SHA-256 manifest. Each matrix profile
attests its own profile-qualified bundle, uploads the bundle and its checksum
as uniquely named assets on the evidence archive without clobbering any prior
record, reads back GitHub's asset digest, and verifies again that the candidate
tag is absent. The two archive assets and repository attestations are the
durable release evidence; the separate 14-day Actions artifacts are diagnostic
only and MUST NOT satisfy this gate. Candidate tag publication must not proceed
unless the archive contains passing reference and slowest-tier bundles for the
exact release SHA and both attestations and read-back digests verify.

`scripts/check_numeric_v1_calibration.py` requires one of the two structured,
profile-qualified host records, binds the report to a digest of every consumed Criterion estimate,
applies the harness adjustment, normalizes every declared work/gas denominator,
applies the 25% margin, and fails when factor `4` is insufficient. Neither
profile can substitute for the other.

The fixed entry charge includes bounded register-contract checks (required-zero
registers, failure mode, and rounding tag). It is not followed by hidden fixed
decode, divisor, or control surcharges. Strict numeric-frame validation adds
these explicit logical work units, where `H = 40` is the fixed header size:

```text
decode_work(frame_bytes) = max(1, ceil(frame_bytes / 8))
canonical_work(frame_bytes) = max(1, ceil(max(frame_bytes - H, 0) / 8))
canonicality_probe_work(m, s) = 0, if s = 0
canonicality_probe_work(m, s) = quotient_remainder_work(limbs(m), 1), if s > 0
frame_validation_work = decode_work + canonical_work + canonicality_probe_work
```

`decode_work` covers the complete structural Norito pass, including its CRC
traversal. `canonical_work` covers body decoding, minimal signed encoding, and
decimal/quantity domain checks. A canonical nonzero scaled decimal or quantity
then performs one divisibility-by-ten probe; it is charged with the same
logical quotient/remainder formula used everywhere else immediately before the
probe. Scale-zero values and canonical zero perform no such probe. Frame bytes
are counted once as input-envelope transport and once for authentication-hash
traversal; the logical work units separately account for structural and
canonical decode passes.

The checked core decimal operations also validate their own operands before
arithmetic so callers outside the pointer decoder cannot bypass the canonical
value invariant. Consequently `decimal` negation/arithmetic/division and
decimal-to-int conversion, plus `quantity` arithmetic/division/ratio, emit and
charge one additional canonicality probe for each nonzero-scale operand.
Comparisons and the explicit `int`/`decimal`/`quantity` representation
conversions do not perform this second probe. This is real repeated validation
work, not a transport-byte charge, and it is included in
`logical_limb_work` through the observed primitive work steps.

Logical limbs are 64 bits, so an input has at most eight limbs. Arithmetic
width uses the bit length of the unsigned magnitude, with zero assigned one
limb. A sign-preserving byte in the canonical
two's-complement wire representation affects envelope-byte gas, not arithmetic
limb work. Gas is monotonic in the explicitly charged encoded-byte widths and
logical work widths, not in numerical magnitude in general: two values in the
same widths can cost the same, and division/alignment structure can make a
smaller numerical value cost more than a larger one. Let `B(d)` be the exact
integer bit length of `10^d` and let:

```text
L(b) = max(1, ceil(b / 64))
P(d) = L(B(d))
C(d) = sum(P(k), k = 0..d-1)
S(0, d) = 1
S(b, 0) = L(b), for b > 0
S(b, d) = L(b + B(d)), for b > 0 and d > 0
A(0, d) = 1
A(b, 0) = L(b), for b > 0
A(b, d) = C(d) + L(b) * P(d), for b > 0 and d > 0
```

`B(d)` is pinned as an integer table for `d` in `0..=56`; gas computation never
uses floating-point logarithms. `C(d)` charges deterministic construction of
`10^d` as the sequence `1 * 10`, `10 * 10`, ..., `10^(d-1) * 10`; the
primitive implementation performs that same bounded sequence instead of an
unmetered backend exponentiation. A zero operand never constructs `10^d` or
performs a multiplication: it emits one one-limb `Materialize` event for every
alignment delta. `A(b, 0)` charges the owned temporary that the implementation
materializes even when no decimal scaling is needed.
Comparison charges both alignment
multiplications using `A` plus the largest conservative aligned width from `S`,
all before it materializes aligned operands. Addition and subtraction debit
each alignment multiplication first; once those exact aligned operands exist,
they debit the largest *actual* aligned limb width immediately before the add
or subtract. This actual width is deterministic and no greater than `S`.
Multiplication charges the product of input limb widths.

The apparently tighter `L(b + B(d) - 1)` is not a valid consensus bound. For
example, a 61-bit value multiplied by ten can require 65 bits. The deliberately
conservative `S` above pins that boundary at two limbs on every implementation.

For long division with dividend width `n` and divisor width `d`:

```text
q = max(1, max(n, 1) - max(d, 1) + 1), with subtraction clamped at zero
division_work(n, d) = max(n, 1) + max(d, 1) + max(d, 1) * q
quotient_remainder_work(n, d) = division_work(n, d)
    + q * max(d, 1)
    + max(n, 1)
```

Rounded division uses one conservative all-mode bound. Let
`r = min(max(n, 1), max(d, 1))`; then:

```text
rounded_division_work(n, d) = quotient_remainder_work(n, d)
    + 2*r                         # remainder absolute-value and doubling scans
    + max(d, 1)                   # denominator absolute-value scan
    + max(max(d, 1), r + 1)       # doubled-remainder comparison
    + 1                           # nearest-even parity probe
    + q + 1                       # possible quotient adjustment
```

The same bound applies to every rounding mode so the selected tag and whether
the result is a tie do not create a gas side channel. Exact classification
first charges `numerator_limbs + 2 * denominator_limbs` for its absolute-value
and state-copy preparation. Every final conceptual result charges one scan of
its limb width before the signed-domain check. Checked integer operations also
include their generic-bigint and V1-domain result scans. Wrapping operations
separately charge arithmetic and the source scan, eight-limb sign fill,
truncation, and two eight-limb reconstruction/domain scans used by modulo
`2^512` reduction.

For avoidance of doubt, the directly precharged integer work formulas are:

| Operation | Logical work |
| --- | ---: |
| checked `int` negation | `v + 2*(v + 1)` |
| checked `int` addition or subtraction | `m + 2*(m + 1)`, where `m = max(l, r, 1)` |
| checked `int` multiplication | `l*r + 2*(l + r)` |
| checked `int` division or remainder | `QR(l, r) + 2*(q + min(l, r))` |
| any `int` comparison | `max(l, r, 1)` |
| wrapping negation before reduction | `2*v + 1` |
| wrapping addition/subtraction before reduction | `2*m + 1` |
| wrapping multiplication before reduction | `l*r + l + r` |
| wrapping reduction of a signed temporary with `x` conservative signed limbs | `x + 3*8 + min(x, 8)` |

Here every operand width is at least one limb and `q` is the quotient-limb
bound above. For a wrapping temporary `t`, `x = L(bit_length(abs(t)) + 1)`;
zero therefore has one limb, while `-2^511` deliberately has nine conservative
signed limbs even though its minimal two's-complement input encoding occupies
eight. A wrapping operation pays both its pre-reduction row and the
wrapping-reduction row. Simple representation conversions and scalar range
checks pay one scan of the source value; an output pointer, when present, is
still charged separately.

Decimal and quantity primitives report this closed work-event vocabulary.
The VM sums the listed work and debits `4 * work` immediately before each
reported event, so an implementation cannot fuse away a consensus charge or
perform an unreported backend pass:

| Work event | Logical work |
| --- | ---: |
| `CanonicalityProbe(m, scale)` | `0` when no probe is emitted; otherwise `QR(m, 1)` |
| `ScaleByPowerOfTen(v, d)` | `0` if `d = 0`; otherwise `C(d) + v*P(d)` |
| `Materialize(v)` | `max(v, 1)` |
| `Negate(v)` | `max(v, 1)` |
| `Add(l, r)` or `Subtract(l, r)` | `max(l, r, 1)` |
| `Multiply(l, r)` | `max(l, 1) * max(r, 1)` |
| `DivisionClassificationPrepare(n, d)` | `max(n, 1) + 2*max(d, 1)` |
| `DivisionClassification(n, d)` | `QR(n, d)` |
| `ExactDivisionAttempt(n, d)` | `QR(n, d)` |
| `RoundedDivision(n, d)` | `rounded_division_work(n, d)` |
| `Normalize(m, scale)` | `QR(m, 1)` for the divide-by-ten probe about to run |
| `Finalize(v)` | `max(v, 1)` |

Scale alignment emits `ScaleByPowerOfTen` for each nonzero operand with a
positive delta and `Materialize` for an unchanged or zero operand, then the
applicable add/subtract/compare event. Exact denominator reduction
emits preparation followed by every Euclidean/classification event actually
begun, and a terminating quotient emits one `ExactDivisionAttempt` at its
proven minimum scale. Rounded division emits exactly one bounded
`RoundedDivision` event after its scale operands are materialized. Result
canonicalization emits one `Normalize` event per attempted division by ten;
zero emits none.

Exact division first charges the Euclidean reduction and denominator
classification steps actually begun. Once classification proves a terminating
result, it charges the single division at the proven minimum output scale
immediately before that division. Decimal normalization charges each
divide-by-ten probe immediately before the probe. The dedicated zero rule
`(0, s) -> (0, 0)` performs no bigint division and therefore emits and charges
zero normalization probes. Conceptual scales through
56, aligned widths through ten limbs, scale-adjusted division widths through
eleven limbs, and multiplication intermediates through sixteen limbs are
included in golden vectors.

Pointer processing is ordered and charged as follows:

1. debit the fixed entry charge;
2. debit the seven-byte header charge, then validate readable provenance and
   read the header;
3. validate the hard length cap with checked arithmetic;
4. debit the declared frame bytes for the envelope-snapshot phase, then debit
   `32 + frame_bytes` for supplied-digest handling and the complete
   `Hash::new(frame)` traversal;
5. snapshot exactly that range and validate its payload hash;
6. debit `4 * decode_work`, then validate the Norito header, schema, flags,
   length, and CRC; only if that succeeds, debit `4 * canonical_work`, then
   decode the numeric body; for a nonzero scaled decimal/quantity, debit
   `4 * canonicality_probe_work` immediately before its canonicality probe;
7. debit each arithmetic/normalization phase before it begins;
8. debit the signed-length probe, determine the exact output envelope length,
   then debit `envelope_bytes + 2 * frame_bytes` for framing/checksum,
   authentication hashing, and publication;
9. allocate and write the output, then publish result registers.

Malformed inputs never cause allocation based on an uncapped length. Guest
memory used for execution is the same snapshot used for validation. Numeric
bytes may also incur transport/state decoding gas outside the syscall; that is
an intentional transport cost and is distinct from syscall marshalling.

## Error precedence and atomicity

Validation follows the phase order above. Within an operand, pointer
provenance/type/version/length precede payload hash, which precedes frame/schema
and canonical-value validation. Pointer operands are authenticated and decoded
in register order. For rounded division and ratio calls, this includes fully
authenticating the `int` scale pointer in `r12` before interpreting either
scalar control: the rounding tag in `r13` is validated next, followed by the
failure tag in `r14`. Only after those malformed-call checks pass is the
decoded scale value resolved against `0..=28`; an out-of-range but canonical
scale is the recoverable `InvalidScale` numeric fault. Thus a bad scale pointer
precedes bad scalar controls, while a bad rounding or failure tag precedes a
semantic out-of-range scale.

Required-zero registers otherwise precede the failure tag according to each
published signature. The rounded decimal-to-int conversion is the explicit
special case: after authenticating `r10`, it checks required-zero `r11` and
`r12` before validating the rounding tag in `r13`; that conversion has no
failure-mode register. Invalid rounding, failure, or required-zero controls are
malformed-call traps with their distinct fault tags and are never converted to
status-mode arithmetic failures. All applicable control and scale checks
precede divisor-zero validation, which precedes arithmetic.

If a phase is unaffordable, out-of-gas for that phase takes precedence over an
error discoverable only by performing the phase. A phase that has not begun is
not charged. No numeric failure writes an output envelope. A recoverable fault
writes only the result/status registers. Trapping and out-of-gas paths leave
numeric output allocation and durable state unchanged.

## Ledger and economic boundaries

Objectively non-negative ledger values use the nominal `quantity` domain, not
generic signed decimals. This includes asset balances and totals, mint/burn/
transfer values, fees and fee caps, stake and bonds, reward and slash amounts,
budget/campaign/notional caps, payouts, escrowed values, subscription usage and
charges, and other durable available/required amount records. The rule applies
to public instructions, events, state, configuration, query/readback models,
and SDK construction surfaces.

The only fixed-width exception is a field whose width is itself part of a
versioned cryptographic statement, witness, proof transcript, or circuit
constraint. Such a field is a protocol scalar, not an alternative public
amount type. Code MUST perform a checked, exact conversion from that scalar to
`quantity`, followed by the applicable asset `NumericSpec` validation, before
it can affect a balance or another durable economic record. A circuit-facing
`u128` therefore never authorizes a general API, configuration field, event,
or stored balance to bypass `quantity`.

`quantity` deliberately does not mean `money`: an asset can represent money,
a commodity, a vote, a right, or another counted resource. Applications that
need a monetary nominal type SHOULD define a policy-bearing newtype over an
asset-associated `quantity`; the base language does not label every asset as
money.

Every signed-decimal crossing uses an explicit checked conversion equivalent
to:

```text
quantity::try_from_decimal(value)
decimal::from_quantity(value)
```

The generic conversion is exact and enforces the canonical scale/range and
non-negative quantity domain. Because it carries no asset identifier, it does
not enforce an asset-definition precision policy. An asset-boundary MUST then
perform the separate `NumericSpec` check described above before publication or
mutation. Negative values, excess generic precision, out-of-range results, and
asset precision mismatches have stable, distinct errors. Generic decimal
values are not implicitly accepted by amount-bearing APIs. Internal price,
rate, ratio, profit/loss, exposure, and signed-delta calculations remain
`decimal`; if their result returns to a non-negative public or durable
boundary, the implementation MUST perform the named checked conversion and any
applicable asset-specific validation before publication or mutation.

Conversion to a host binary floating-point value is never a ledger operation.
Rust exposes it only as the explicitly lossy `Numeric::to_f64_lossy` helper for
telemetry and approximate presentation metrics. Consensus, fee, settlement,
ordering, validation, serialization, hashing, and persisted-state code MUST NOT
use that helper or another binary floating-point projection.

## First-release activation and validation gates

ABI V1 has not previously been released as a compatibility contract. This
definition replaces every pre-release V1 numeric layout and syscall surface.
Old ABI hashes and artifacts are rejected before execution. The numeric pointer
surface assigns only `Quantity = 0x0010`, `Int = 0x0011`, and
`Decimal = 0x0012`; `0x0013` is the assigned `AxtAnchoredSpendV1` type and is
rejected as wrong type by numeric decoders. `0x000C` and `0x0014` are
unassigned and rejected as unknown.

Merge and release require:

- full workspace format, build, test, and strict clippy gates;
- compiler-folding versus runtime differential tests;
- an independent exact-arithmetic reference algorithm;
- cross-SDK canonical frame fixtures;
- encode/decode and malformed-frame fuzzing;
- quote-free staged gas/OOG tests at every phase;
- boundary vectors at every signed-byte and logical-limb transition;
- exact division, all signed rounding ties, wrapping endpoints, and
  multiplication/alignment intermediates above the input limb maximum;
- stale artifact/ABI-hash rejection and canonical numeric map-key tests;
- execution parity across supported architectures using V1's sole supported
  `num-bigint` backend. Introducing another bigint backend makes differential
  parity against both backends a mandatory gate before that backend is
  supported.

The `workspace_release.yml` workflow is the exact-source full-workspace gate.
It runs for main-branch and `v*` tag pushes and also supports manual and
same-commit reusable invocation. Every job verifies that its checkout and the
workflow definition resolve to the triggering SHA, pins Rust 1.93.1, and runs
the locked format, build, test, or strict all-target/all-feature Clippy phase.

The dedicated `numeric_v1_fuzz.yml` gate runs the `numeric_v1` libFuzzer
target for pull requests that touch the numeric corridor, every push to the
main branch, release-tag pushes, reusable workflow callers, and manual runs.
The target combines raw envelope/frame decoding, structure-aware corruption of
valid envelopes, canonical round trips, exact-arithmetic metamorphic checks,
all rounding modes, quantity-domain invariants, and randomized staged
out-of-gas budgets that assert result-publication atomicity.
It installs `cargo-fuzz 0.13.2`, selects `nightly-2025-05-08`, and invokes
`scripts/fuzz_smoke.sh --strict --numeric-v1-only`. Strict mode rejects a
missing or mismatched Cargo, rustup, nightly, or cargo-fuzz prerequisite and
propagates every target failure; it may never report a skipped fuzz run as a
passing CI/release gate. The optimized sanitizer build uses sixteen codegen
units to bound clean-build LLVM latency and memory without weakening sanitizer
coverage. Running the script without `--strict` remains an
explicitly optional developer convenience and prints a skip diagnostic when
the pinned fuzz toolchain is unavailable.
