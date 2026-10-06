# Kotodama V1 language specification

This document is the single normative source-language specification for the
first Kotodama release. Translations, examples, editor grammars, generated
tables, and compiler behavior are subordinate to it; a disagreement in the
Rust compiler is an implementation bug.

The machine-readable documentation policy is
[`kotodama_v1_docs.json`](./kotodama_v1_docs.json). Pull-request CI extracts
every tracked `kotodama` or `ko` source fence, plus every documented
`cat > *.ko` heredoc, below its configured roots and checks the unique source
contents with the canonical Rust `koto` driver.

Kotodama compiles to deterministic Iroha Virtual Machine bytecode (`.to`). It is not a standalone RISC-V language. ABI version 1 is the only release ABI.

## Lexical grammar

Source is UTF-8 and V1 identifiers are ASCII. Keywords are case-sensitive.
Four branded declaration features each have a romanized Japanese spelling and
its exact Japanese-language equivalent: `seiyaku`/`誓約`,
`kotoage`/`言挙げ`, `hajimari`/`始まり`, and `kaizen`/`改善`.
Those eight spellings are first-class keywords, not compatibility aliases.
Other non-ASCII text is permitted only inside strings and comments; English
`contract`, `entry`, `init`, and `upgrade` are not Kotodama V1 keywords.

The following lexical tables are generated from
`crates/kotodama_lang/grammar/v1.lex`; edits belong in that machine-readable
grammar rather than in this rendered copy or an editor grammar.

<!-- BEGIN GENERATED: kotodama-v1-keywords -->
| Spelling | Token |
| --- | --- |
| `as` | `As` |
| `authorize` | `Authorize` |
| `break` | `Break` |
| `const` | `Const` |
| `continue` | `Continue` |
| `else` | `Else` |
| `enum` | `Enum` |
| `error` | `Error` |
| `export` | `Export` |
| `false` | `False` |
| `fn` | `Fn` |
| `for` | `For` |
| `hajimari` | `Hajimari` |
| `始まり` | `Hajimari` |
| `if` | `If` |
| `import` | `Import` |
| `in` | `In` |
| `include` | `Include` |
| `kaizen` | `Kaizen` |
| `改善` | `Kaizen` |
| `kotoage` | `Kotoage` |
| `言挙げ` | `Kotoage` |
| `let` | `Let` |
| `match` | `Match` |
| `module` | `Module` |
| `return` | `Return` |
| `seiyaku` | `Seiyaku` |
| `誓約` | `Seiyaku` |
| `state` | `State` |
| `struct` | `Struct` |
| `trigger` | `Trigger` |
| `true` | `True` |
| `var` | `Var` |
| `view` | `View` |
<!-- END GENERATED: kotodama-v1-keywords -->

<!-- BEGIN GENERATED: kotodama-v1-operators -->
| Spelling |
| --- |
| `+` |
| `-` |
| `*` |
| `/` |
| `%` |
| `==` |
| `!=` |
| `<` |
| `<=` |
| `>` |
| `>=` |
| `&&` |
| `\|\|` |
| `!` |
| `=` |
| `+=` |
| `-=` |
| `*=` |
| `/=` |
| `%=` |
| `->` |
| `=>` |
| `::` |
| `.` |
| `..` |
| `,` |
| `:` |
| `;` |
| `?` |
| `#` |
| `(` |
| `)` |
| `{` |
| `}` |
| `[` |
| `]` |
<!-- END GENERATED: kotodama-v1-operators -->

```ebnf
identifier      = (ASCII-letter | "_") (ASCII-letter | ASCII-digit | "_")* ;
integer-literal = decimal-literal | hexadecimal-literal | binary-literal ;
decimal-literal = ASCII-digit (ASCII-digit | "_")* ;
exact-decimal-literal = decimal-literal
                        (("." decimal-literal) exponent? | exponent) ;
exponent        = ("e" | "E") ("+" | "-")? decimal-literal ;
hexadecimal-literal = "0x" hex-digit (hex-digit | "_")* ;
binary-literal  = "0b" ("0" | "1" | "_")+ ;
string-literal  = '"' string-character* '"' ;
bytes-literal   = "b" string-literal ;
comment         = "//" non-newline-character* ;
```

String escapes are `\\`, `\"`, `\n`, `\r`, `\t`, `\0`, `\xNN`, and
`\u{...}`. Raw and raw-byte strings preserve their contents without escape
processing. Quoted strings retain their decoded UTF-8 text even when it starts
with `0x`: `"0x6162"` is six characters, not `"ab"`. Byte literals also retain
their explicit contents: `b"0x6162"` contains six bytes, while `b"\x61\x62"`
contains two. The shared runtime Blob pointer ABI does not permit the compiler
to reinterpret a string as its internal hexadecimal byte-literal carrier.
Decimal fractions and decimal exponents are exact: they never
create a binary floating-point value. Separators are permitted only between
digits. Spellings such as `1.`, `.5`, `1__0`, and an exponent without digits
are invalid. Leading zeroes are valid in source numeric literals: `0007` is
base ten (never octal), and leading zeroes in decimal, hexadecimal, or binary
coefficients do not change the mathematical value or its domain check.
Likewise, `0001.2300` is normalized by the exact-decimal rules. Source
acceptance does not weaken canonical external encodings: typed numeric JSON
strings and numeric pointer payloads reject leading or otherwise redundant
zeroes. V1 has no numeric suffixes.

The compiler applies the same mandatory frontend budgets in every driver: at
most 1 MiB (1,048,576 UTF-8 bytes) per source file, 250,000 significant tokens
including end-of-file, and 256 levels of syntactic nesting. The nesting budget
is shared by active delimiters, generic type arguments, unary-prefix chains,
and conditional-expression structure; combining individually shallow forms
cannot evade it. Inputs beyond a budget fail with stable `K0001`, `K0002`, or
`K0003` diagnostics before resolution or code generation. Parsing and cleanup
at the inclusive boundary use explicit work stacks and must not consume the
native call stack in proportion to source nesting.

Named value types share the 256-level limit after resolution. Semantic
analysis measures each acyclic dependency DAG leaf-first, then resolves every
accepted named struct exactly once into an immutable shared product graph.
Parameters, returns, state declarations, constants, and expression checks
reuse that canonical graph; referring to a type never clones or recursively
re-expands its fields. A source is rejected with `K2008` if a conceptual
expanded shape exceeds 256 levels or if all conceptual expanded local struct
shapes exceed 250,000 type nodes. Branching DAGs and repeated references
therefore cannot amplify compact source into unbounded compiler work.

## Source units

A deployable file contains exactly one named `seiyaku`/`誓約`. A reusable file contains exactly one named module. A file cannot contain both, and source units cannot be nested.

```ebnf
source          = seiyaku | module ;
fragment        = (seiyaku-item | exported-item)* ;
seiyaku         = seiyaku-keyword identifier "{" seiyaku-item* "}" ;
seiyaku-keyword = "seiyaku" | "誓約" ;
module          = "module" identifier "{" module-item* "}" ;

seiyaku-item    = struct | error-enum | constant | state | function | kotoage
                | view | hajimari | kaizen | trigger | include | import ;
module-item     = exported-item | include | import ;
exported-item   = "export"? (struct | error-enum | constant | function) ;
include         = "include" string-literal ";" ;
import          = "import" string-literal "as" identifier ";" ;
```

A source unit may include bare declaration fragments with `include "./state.ko";`.
Includes expand declarations at the directive position and share the owning
contract or module's functions, types, constants and state. Each fragment has one
owner. Include cycles and duplicate declarations are errors. A fragment has no
`seiyaku` or `module` wrapper and is parsed only through an explicit include or
fragment-formatting operation. Fragment declarations must be valid for the owner;
module fragments cannot introduce contract state or entrypoints.

`import "./math.ko" as arithmetic;` imports a named local module. Only declarations
marked `export` are accessible through `arithmetic::name`; functions remain ordinary
private functions for runtime-entrypoint purposes. Types, error enums and constants
can also be exported. A published package additionally requires each externally
visible declaration in its manifest export allowlist. Local import cycles fail.
Paths resolve relative to the declaring file within the supplied source root;
absolute paths and escaping that root are rejected. The compiler consumes the
explicit source bundle and preserves every file's native source ranges.

For example, these three files form one contract source bundle:

```kotodama bundle
// file: app.ko
seiyaku App {
    include "./helpers.ko";
    import "./math.ko" as arithmetic;
    view fn answer() -> int { twice(arithmetic::SCALE) }
}
// file: helpers.ko
fn twice(int _ value) -> int { value + value }
// file: math.ko
module Math { export const int SCALE = 21; }
```

Seiyaku identity is the declared name; the compiler must preserve it through CST, AST, HIR, diagnostics, interfaces, and documentation. Modules are linked at typed HIR. Textual AST rewriting and wildcard imports are not part of V1.

The following spellings and forms are errors: English declaration words
`contract`, `entry`, `init`, and `upgrade`; implicit `main`; raw `call`
statements; source-level `messages`/`kotoba` localization tables; source macros
such as `account!` or `json!`; and multiple deployable units in one file.
Seiyaku failures use declared numeric error enums; presentation-layer
localization is outside the deployable language. Constructors are ordinary
typed calls (`AccountId::parse("...")`, `Json::parse("{...}")`); bytes use
`b"..."`. There is no compatibility parser or edition switch.

## Declarations

```ebnf
struct          = "struct" identifier "{" (field (("," | ";") field)* ("," | ";")?)? "}" ;
field           = type identifier ;

error-enum      = "error" "enum" identifier "{"
                  error-variant (("," | ";") error-variant)* ("," | ";")?
                  "}" ;
error-variant   = error-message? identifier "=" integer-literal ;
error-message   = "#[" "message" "(" string-literal ")" "]" ;

constant        = "const" type identifier "=" expression ";" ;
state           = "state" type identifier ";" ;

function        = "fn" identifier parameters return-type? block ;
kotoage         = kotoage-keyword "fn" identifier parameters return-type?
                  "authorize" "(" string-literal ")" block ;
kotoage-keyword = "kotoage" | "言挙げ" ;
view            = "view" "fn" identifier parameters return-type?
                  authorization? block ;
hajimari        = hajimari-keyword parameters block ;
hajimari-keyword = "hajimari" | "始まり" ;
kaizen          = kaizen-keyword parameters block ;
kaizen-keyword  = "kaizen" | "改善" ;
authorization   = "authorize" "(" string-literal ")" ;
parameters      = "(" (parameter ("," parameter)*)? ")" ;
parameter       = type "_"? identifier ;
return-type     = "->" type ;

trigger         = "trigger" identifier "->" trigger-call "{"
                  trigger-filter trigger-option* "}" ;
trigger-call    = identifier ("::" identifier)? ;
trigger-filter  = "on" (time-filter | execute-filter | data-filter | pipeline-filter) ";"? ;
trigger-option  = "repeats" ("indefinitely" | integer-literal) ";"
                | "authority" (identifier | string-literal) ";"
                | "metadata" "{" metadata-entry* "}" ";"? ;
metadata-entry  = (identifier | string-literal) ":" expression ";" ;
time-filter     = "time" ("pre_commit" | "schedule" "(" integer-literal
                  ("," integer-literal)? ")") ;
execute-filter  = "execute" "trigger" (identifier | string-literal) ;
data-filter     = "data" ("any" | identifier identifier "{" data-matcher* "}") ;
data-matcher    = identifier (identifier | string-literal) ";" ;
pipeline-filter = "pipeline" ("transaction" | "block") "approved"? ;
```

An optional `#[message("Permission required")]` before an error variant provides
static presentation text. The decoded string must contain 1 through 4096 UTF-8
bytes and at least one non-whitespace character. Duplicate message attributes,
computed expressions and attributes on the enum itself are rejected. Messages
are included in contract metadata and editor hover/completion; they do not alter
the enum's numeric codes or nominal identity.


Every parameter, field, constant, and state declaration has an explicit type.
Ordinary function parameters accept positional values or their declared names.
`int _ value` declares a positional-only parameter; these parameters form a
contiguous prefix of the signature. For example,
`fn clamp(int _ value, int minimum, int maximum)` accepts both `clamp(7, 0, 10)`
and `clamp(7, minimum: 0, maximum: 10)`. Builtins retain their explicit registry
call policies, including required names for ledger operations.
Declaration types always precede names; the retired `name: Type` form is a
syntax error with a type-first diagnostic. Every error variant has an explicit,
non-zero `u32` code, and names and codes are unique within the
enum. Missing types, unknown types, duplicate declarations, reserved names,
ambiguous resolution, recursive value types, duplicate parameters, and
shadowing are compile errors.

A `kotoage fn`/`言挙げ fn` mutates or submits ledger state and always declares
caller authorization. Authorization is checked at runtime and is separate from
compiler-derived effects and operation-specific host authorization. Views are
public unless they add `authorize`. Lifecycle declarations never accept
source-level authorization: ABI V1 binds both `hajimari`/`始まり` and
`kaizen`/`改善` hook dispatch to the runtime-defined
`CanInvokeContractEntrypoint` permission. That hook permission does not grant
address lifecycle control: deployment creates the address atomically, while
later activation and deactivation require its account owner plus an exact
lifecycle revision or the certified Parliament corridor.

Lifecycle hooks are accepted only as top-level calls to a deployed seiyaku
instance. A hash-only governance stub can never become active: the complete
verified `.to` bytes and their exact signed manifest must exist before direct
or governance binding. Activating new code stages one consensus-owned
`hajimari`/`始まり`
transition when that declaration exists; rebinding an already-active address
to a different verified code hash stages one `kaizen`/`改善` transition when
the new artifact declares it. The exact pending transition and active code
binding are rechecked immediately before effects are applied, and a successful
hook consumes the transition atomically. While a transition is pending, all
other calls and views are rejected. Replaying a consumed hook, invoking
`kaizen` without an in-place code replacement, or selecting either lifecycle
hook from raw IVM, a trigger, or a nested seiyaku call is rejected. Seiyaku
units that omit the applicable declaration do not acquire a pending transition.

CLI and Torii callers may submit a JSON object keyed by parameter name. At that
boundary, tooling validates it against the exact compiler-emitted
`EntrypointArgumentSchemaV1` and converts it to a schema-bound
`EntrypointArgumentRecordV1`. The host retains that complete signed Norito
record. For prepared calls, it first validates the compiler-owned flat schema
and derives the schema's conservative maximum aggregate and pointer-allocation
bound. The signed wire lengths and that bound must be affordable before the
untrusted canonical record is decoded exactly once. The complete record stays
host-owned; the VM receives a fixed table of typed ABI words, and JSON is never
the VM argument transport. Before guest entry the host preflights pointer
copies, active aggregates, the argument table, and the exact result reservation
together. Pointer TLVs prefer INPUT and spill into owned HEAP; argument/result
tables and raw `List` and sum storage use owned HEAP. Raw decode-syscall quoting uses
only bounded record/schema envelope lengths and reserves the full HEAP before
authenticating either payload. The argument-record protocol cap is inclusive
at 1 MiB, while the selected artifact/node cycle ceiling still limits what an
invocation can afford. Struct
parameters use exact JSON objects, tuples use
exact arrays, `Option<T>` uses exactly `{"some": value}` or `{"none": true}`,
and `Result<T,E>` uses exactly `{"ok": value}` or `{"err": value}`. Decoding
either sum materializes one compiler-owned typed heap handle containing only
the active variant and payload; no inactive placeholder payload is constructed.
Unknown fields, duplicate schema names, alternate tags, non-canonical typed
identifiers, schema-hash mismatches, and malformed typed atoms are rejected. A
`Json` parameter is still a named field in the record and does not receive the
whole outer boundary object.

VM-to-VM invocation uses that same schema-bound record directly:
`CALL_CONTRACT` accepts `EntrypointArgumentRecordV1` Norito bytes, or a literal
zero only when the selected public or lifecycle declaration has no parameters. It never accepts or
reconstructs JSON. The host quotes authenticated envelope lengths and escrows
gas before copying or decoding the record, rejects private or tainted target,
selector, and argument registers, and decodes the canonical record exactly
once against the callee's signed schema.

Every public return, including Unit, has an exact flat-preorder
`EntrypointValueTypeV1` tape in CNTR and the signed manifest. Both the return type
and its schema are required: an omitted source annotation emits `()` and a Unit
schema, and admission rejects an absent descriptor pair. Aggregate children
immediately follow their parent; a `List` node carries only its capacity and is
followed by exactly one element subtree. The valid V1 boundary is 256 nodes and
256 levels. Admission, decoding, materialization, and rendering use explicit
work stacks, so valid schemas never depend on the native call stack. Public
return handles are validated against that exact tape, including canonical sum
tags, list lengths and element schemas, typed pointer envelopes, UTF-8 and Norito
payloads, and ZK public-memory tags. Nested calls return one schema-hashed
`EntrypointReturnRecordV1`; JSON rendering happens only at Torii and CLI
boundaries. The complete returned `NoritoBytes` TLV is bounded to 1 MiB, so its
encoded record payload is at most 1,048,537 bytes after the exact 39-byte V1
TLV envelope. Cumulative pointer cloning is rejected before a repeated or
aliased large pointer can amplify memory use.

Every V1 function uses caller-owned argument and result tables. On entry `r10`
contains the argument-table address, `r11` its exact word count, `r12` the
result-table address, and `r13` its exact schema-derived capacity. On return
`r10` names that same result table and `r11` gives its exact initialized word
count. Each table is aligned to eight bytes and bounded to 64 KiB (8,192 words);
an empty argument table uses `(address, count) = (0, 0)`. Unit returns one zero
word. An empty nominal struct occupies one zero word while preserving its
nominal identity. Struct and tuple fields flatten in declaration order; Option, Result, and
List retain one active-only handle. Private and public functions use this same
convention, including calls with one argument or one result.

The authenticated CNTR callable descriptors bind every function root, its
aligned stack-frame reservation, and every argument/result slot's representation
and privacy role. Admission checks public signatures against their canonical
schemas. Runtime checks caller ownership, disjoint table ranges, exact counts,
initialized bytes, privacy tags, restored stack pointers, and trusted return
addresses. Internal scratch tables are reserved once in the caller frame and
reused across loop calls; public invocation tables belong to the current host
invocation. Canonical public records retain their independent encoded-record,
schema-size, and type-node bounds. Root result reservation costs eight gas per
word. Frame validation reserves `frame_bytes / 8 + result_words` gas before
allocating initialization coverage, and charges eight gas before validating each
typed argument or result slot. Pointer validation costs `16 + 39 + payload_bytes`
before authentication; secret numeric pointers use the declared type's maximum
frame length so gas does not reveal a private length. Active sum and list headers
cost eight and sixteen gas respectively.

Self-describing IVM trigger actions select their callback explicitly with
`contract_entrypoint` action metadata. When an event fires, the runtime validates
that event's arguments against the selected callback schema and constructs the
same canonical Norito record before starting the VM. Trigger metadata may not
provide a fixed `contract_payload`, and host operations never interpret a null
pointer or numeric zero as a request to re-read JSON trigger arguments.

## Bindings and assignment

`let` creates an immutable local. `var` creates a mutable local. Struct and tuple
fields inherit their root binding's mutability: `record.lifecycle = ACTIVE`,
`record.details.nonce += 1`, and `pair.0 = value` update a mutable value. The
compiler rebuilds the enclosing products, so copies retain their previous
values; changing a record read from a `StateMap` requires an explicit
`map[key] = record` to persist it. Assigning through a `let`, parameter, or
constant is an error, as is assigning a field of a temporary expression.
Redeclaring or shadowing a name in an enclosing scope is an error.

The compiler eliminates projections of known products in SSA before register
allocation, preserving evaluation order while removing intermediate record
reconstructions. Branches and loops carry the product's leaf words so updates
and copies retain value semantics. Calls and state encoding keep the same ABI
and reuse address bases for consecutive stack-table words; these optimizations
require no changes to contract source.

```ebnf
binding         = ("let" | "var") (type identifier | binding-pattern)
                  "=" expression ";" ;
binding-pattern = identifier | positional-destructure | struct-pattern ;
positional-destructure = "(" identifier ("," identifier)* ")" ;
struct-pattern  = type-name "{" (pattern-field ("," pattern-field)*)?
                  (","? "..")? ","? "}" ;
pattern-field   = identifier (":" identifier)? ;
assignment      = place ("=" | "+=" | "-=" | "*=" | "/=" | "%=") expression ";" ;
place           = identifier ("." (identifier | integer-literal))*
                | identifier "[" expression "]" ;
```

Every local binding is initialized at its declaration. Positional destructuring
accepts tuples and contains exactly one identifier for every element; `_`
discards a position. Structs use named fields, for example
`let Receipt { amount, recipient: payee, memo: _ } = receipt;`. Field order is
irrelevant, aliases choose local names, and a trailing `..` explicitly discards
unspecified fields. Without `..`, every field must appear. Unknown or duplicate
fields, duplicate non-`_` bindings, and a different nominal struct type are errors.
Both forms evaluate the initializer once and support one level of binding.
`var` makes every non-`_` binding mutable. Ordinary single-name annotations
remain type-first.

## Types

The V1 type vocabulary is:

<!-- BEGIN GENERATED: kotodama-v1-source-policy -->
| Source policy | Canonical V1 values |
| --- | --- |
| Active type spellings | `int`, `decimal`, `quantity`, `bool`, `string`, `bytes`, `Json`, `AccountId`, `AssetDefinitionId`, `AssetId`, `DomainId`, `Name`, `NftId`, `DataSpaceId`, `Option`, `Result`, `List`, `ListError`, `NumericError`, `StateMap`, `StateCursor`, `StatePage`, `Secret`, `AccountView`, `AssetView`, `AssetDefinitionView`, `DomainView`, `NftView`, `QueryPage` |
| Forbidden in every source identifier position | `Amount` |
| Reserved retired numeric type spellings | `i8`, `i16`, `i32`, `i64`, `i128`, `isize`, `u8`, `u16`, `u32`, `u64`, `u128`, `usize`, `num`, `Int`, `Integer`, `float`, `f32`, `f64`, `Decimal`, `Fixed`, `FixedPoint`, `Amount`, `amount`, `money`, `Quantity`, `number` |
| Ordinary value/function identifier examples | `amount` |
| Retired literal suffixes with safe fix-its | `amt` (remove the suffix), `qty` (remove the suffix) |
| Durable `StateMap` key types (ordered) | `int`, `decimal`, `quantity`, `bool`, `string`, `bytes`, `DataSpaceId`, `AccountId`, `AssetDefinitionId`, `AssetId`, `NftId`, `DomainId`, `Name` |
| Dynamic-access bound kinds (ordered) | `page`, `take` |
| Dynamic-access key bound | `1..=64` |
| Dynamic-access base | One direct declared top-level `StateMap`, encoded as `state:<state_declaration_identifier>` |
| Dynamic-access scheduler semantics | Advisory only; never authorization or scheduler-authoritative evidence |

| Source type | Rust nominal type | Pointer ID | Schema name | Schema hash |
| --- | --- | --- | --- | --- |
| `int` | `Int` | `0x0011` | `iroha.numeric.IntValueV1` | `07c039457363b9e1d36bbd31d93dec4a` |
| `decimal` | `Decimal` | `0x0012` | `iroha.numeric.DecimalValueV1` | `ba2ffed52e4d8ee16f17efefe1828524` |
| `quantity` | `Quantity` | `0x0010` | `iroha.numeric.QuantityValueV1` | `e4769984c81ce0e8b678f2eb06274ee3` |

`0x000c`, `0x0014` is unassigned and rejected as unknown; it is not an ABI tombstone.
<!-- END GENERATED: kotodama-v1-source-policy -->

- `int`
- `decimal`
- `quantity`
- `bool`
- `string`
- `bytes`
- `Json`
- typed Iroha identifiers, including `AccountId`, `AssetDefinitionId`, `AssetId`, `NftId`, `DomainId`, `DataSpaceId`, and `Name`
- declared structs and tuples
- `Option<T>`
- `Result<T, E>`
- `List<T, N>`, where `N` is a compile-time capacity from 1 through 64
- `StateMap<K, V>`
- the compiler-declared `AccountView`, `AssetView`, `AssetDefinitionView`,
  `DomainView`, `NftView`, and `QueryPage<View>` query projections
- `Secret<T>` inside ZK seiyaku, subject to the information-flow rules below

`i64`, `u128`, `Int`, `Integer`, `Decimal`, `Fixed`, `FixedPoint`, `Amount`,
`Quantity`, `float`, `num`, `number`, `money`, `Opaque`, `fixed_u128`, `String`,
`Blob`, `Bytes`, `Balance`, and in-memory `Map` are not types in V1.
Retired type spellings are reserved only in the type namespace and in declared
type names. Except for exact `Amount`, which is forbidden in every identifier
position, the other retired type spellings remain available for ordinary
function, parameter, and local value names; for example,
`fn amount(quantity amount) -> quantity` is valid.
Unit is written `()` in both type and value position. Omitted return annotations
mean `()`, and an omitted return value is the same canonical Unit value. Unit
occupies one zero scalar word and renders as JSON `null`; schemas carry an
explicit Unit node. It composes inside structs, lists, `Option`, `Result`, durable
state, and public argument/return records. Nonzero Unit words reject. `(T)` is
not a one-element tuple type; ordinary tuple types contain at least two elements.
Payloadless declared error enums, `ListError`, and `NumericError` are nominal
value types with equality, exhaustive matching, state, and boundary support.

```ebnf
type            = "(" ")" | "int" | "decimal" | "quantity" | "bool" | "string" | "bytes"
                | "Json" | iroha-id-type | identifier
                | tuple-type | "Option" "<" type ">"
                | "Result" "<" type "," type ">"
                | "List" "<" type "," capacity ">"
                | "QueryPage" "<" query-view-type ">"
                | "StateMap" "<" type "," type ">"
                | "StateCursor" "<" type ">"
                | "StatePage" "<" type "," type "," capacity ">"
                | "Secret" "<" type ">" ;
capacity        = integer-constant-expression ;
integer-constant-expression = constant-term (("+" | "-") constant-term)* ;
constant-term   = constant-factor (("*" | "/" | "%") constant-factor)* ;
constant-factor = integer-literal | identifier | "-" constant-factor
                | "(" integer-constant-expression ")" ;
query-view-type = "AccountView" | "AssetView" | "AssetDefinitionView"
                | "DomainView" | "NftView" ;
tuple-type      = "(" type "," type ("," type)* ")" ;
iroha-id-type   = "AccountId" | "AssetDefinitionId" | "AssetId"
                | "NftId" | "DomainId" | "DataSpaceId" | "Name" ;
```

Boolean values are not integers. `quantity` is a nominal non-negative decimal
and cannot be substituted for `decimal`, even though both use exact base-10
arithmetic. Whole-number literals default to `int` and may be checked exactly
against an expected `decimal` or `quantity`; fractional and exponent literals
default to `decimal` and may be checked exactly against an expected `quantity`.
Negative contextual quantities are rejected at compile time.

Runtime `int` and `decimal` values never mix implicitly in arithmetic,
comparison, or compound assignment. Convert the `int` explicitly with
`decimal::from_int(value)` before operating in the decimal domain. Exact
numeric literals may still infer `decimal` or `quantity` from their expression
context because that compile-time choice inserts no runtime conversion. All
other cross-type conversions are also named and checked. In particular,
`quantity::try_from_decimal`, `decimal::from_quantity`, and exact, truncating,
or explicitly rounded decimal-to-int conversions make domain changes visible.
There is no implicit assignment, argument, return, arithmetic, comparison, or
ledger-boundary conversion between numeric runtime values. Pointer-ABI
constructors return their exact declared type and cannot be substituted for one
another.

## Control flow and expressions

V1 supports `if`/`else`, `return`, and compiler-proven bounded `for` loops. It rejects `while`, recursion, indirect source calls, and loops whose bound cannot be proven.

Collection iteration accepts `List<T, N>` with a static capacity of at most
64. The loop binding accepts a name, tuple pattern, or named struct pattern.
`map.page(after: cursor, limit: N)` returns `StatePage<K, V, N>` containing
`items: List<(K, V), N>` and `next: Option<StateCursor<K>>`. Pass `Option::none`
for the first page. Limits are compile-time integer expressions, including
named constants, in `1..=64`. `map.take(N)` returns the first page's items.
Offset-based `map.range` is not supported.

The same integer constant evaluator handles generic capacities such as
`List<int, PAGE_SIZE * 2>` and `StatePage<int, int, PAGE_SIZE>`, numeric
`range(PAGE_SIZE * 2)`, and `items.take(PAGE_SIZE)`. Integer constants are
available to type annotations independently of the annotation's source order;
constant declarations may reference earlier constants. Constants also accept
nominal error variants and canonical typed literal constructors over constant
strings, such as
`const Name ADMIN_KEY = Name::parse("admin");` and
`const VaultError MISSING = VaultError::Missing;`. These values are expanded
through the same typed literal and error paths as their inline forms. Live
account aliases are not constant account identifiers: store an alias as bytes
and resolve it explicitly when needed. Runtime variables cannot determine a
capacity or loop limit.

Each scan follows canonical state-key order and examines at most 64 candidate
positions, stopping once it finds `N` live entries. Tombstones count toward
the work bound. A continuation may therefore lead to an empty page; continue
until `next` is `Option::none`. A cursor is opaque and binds the contract
instance, declared map, value schema, and key type. Page items are materialized
before the loop body executes. `break` and `continue` are valid only inside an
accepted bounded loop. `#[test]` is the only source attribute.

`&&` and `||` short-circuit. The right operand is evaluated only when required.

```ebnf
block           = "{" statement* tail-expression? "}" ;
tail-expression = expression ;
statement       = binding | assignment | expression ";" | return-statement
                | if-statement | if-let-statement | for-statement
                | "break" ";" | "continue" ";" ;
return-statement = "return" expression? ";" ;
if-statement    = "if" expression block ("else" (block | if-statement))? ;
if-let-statement = "if" "let" sum-pattern "=" expression block
                   ("else" block)? ;
for-statement   = "for" identifier "in" "range" "(" expression ")" block
                | "for" binding-pattern "in" expression block ;

expression      = conditional ;
conditional     = logical-or ("?" expression ":" expression)? ;
logical-or      = logical-and ("||" logical-and)* ;
logical-and     = comparison ("&&" comparison)* ;
comparison      = additive (("==" | "!=" | "<" | "<=" | ">" | ">=") additive)* ;
additive        = multiplicative (("+" | "-") multiplicative)* ;
multiplicative  = unary (("*" | "/" | "%") unary)* ;
unary           = ("!" | "-") unary | postfix ;
postfix         = primary (("." (identifier | integer-literal)) | ("[" expression "]")
                | call-arguments | "?")* ;
primary         = integer-literal | exact-decimal-literal
                | string-literal | bytes-literal
                | "true" | "false" | qualified-name
                | qualified-name call-arguments | "(" expression ")" | "(" ")"
                | tuple-expression | struct-literal | list-literal
                | list-comprehension | if-expression | if-let-expression
                | match-expression | sum-constructor | native-json ;
qualified-name  = identifier ("::" identifier)*
                | "state" "::" identifier
                | identifier "::" "trigger" "::" identifier
                | identifier "::" seiyaku-keyword "::" identifier
                | identifier "::" kotoage-keyword ;
call-arguments  = "(" (positional-arguments ("," named-arguments)?
                      | named-arguments)? ","? ")" ;
positional-arguments = expression ("," expression)* ;
named-arguments = named-argument ("," named-argument)* ;
named-argument  = (identifier | keyword) ":" expression ;
tuple-expression = "(" expression "," expression ("," expression)* ")" ;
type-name       = identifier ("::" identifier)? ;
struct-literal  = type-name "{" (struct-field ("," struct-field)* ","?)? "}" ;
struct-field    = identifier (":" expression)? ;
list-literal    = "[" (expression ("," expression)* ","?)? "]" ;
list-comprehension = "[" expression "for" identifier "in" expression
                     ("if" expression)? "]" ;
if-expression   = "if" expression block "else" (block | if-expression) ;
if-let-expression = "if" "let" sum-pattern "=" expression block
                    "else" block ;
match-expression = "match" expression "{" match-arm ("," match-arm)* ","? "}" ;
match-arm       = sum-pattern "=>" (block | expression) ;
sum-pattern     = "Option::some" "(" (identifier | "_") ")"
                | "Option::none"
                | "Result::ok" "(" (identifier | "_") ")"
                | "Result::err" "(" (identifier | "_") ")" ;
sum-constructor = "Option::some" "(" expression ")" | "Option::none"
                | "Result::ok" "(" expression ")"
                | "Result::err" "(" expression ")" ;
native-json     = "json" (json-object | json-array) ;
json-object     = "{" (json-entry ("," json-entry)* ","?)? "}" ;
json-entry      = (identifier | string-literal) ":" expression ;
json-array      = "[" (expression ("," expression)* ","?)? "]" ;
```

`(expression)` is grouping and does not construct a one-element tuple. Bare
`()` is the Unit value and may be returned explicitly or with `return;`.
Nonempty tuple expressions, like nonempty tuple types, contain at least two elements.

A block's final expression has no semicolon and supplies the block value.
Functions, `if`/`if let`, and `match` all use the same tail rule; explicit
`return` remains available. `if` and `if let` require `else` when used as
values. Sum matches are exhaustive and use only the namespaced patterns above.
Postfix `?` propagates only the same `Option` family or the exact same `Result`
error type returned by the enclosing function; V1 performs no implicit error
conversion. The retired lowercase placeholder constructors are syntax errors
with active-only fix-its.

Ordinary function calls accept a positional prefix followed by optional named
arguments. Named arguments may appear in any order; argument expressions always
evaluate left to right in source order. A positional argument after a named
argument, a name for a positional-only parameter, a duplicate argument, or a
missing required argument is an error.
Keywords are contextual argument labels immediately before `:`, so canonical
builtins can use labels such as `trigger:`. This does not make keywords valid
local binding names. Call labels depend only on the signature and are included in package interface
fingerprints. Builtin call modes are explicit registry metadata. Structs are
constructed with named fields. Locked packages may explicitly export struct
and error types, referenced as `Alias::Type` in declarations and patterns.

The branded `seiyaku`/`誓約` and `kotoage`/`言挙げ` tokens are contextual in
canonical capability paths, and `kotoage`/`言挙げ` is contextual as the named
selector argument for those capabilities. They normalize to the romanized
registry spelling. Outside paths and argument labels, these tokens remain reserved: they cannot
be bindings, declarations, ordinary root namespaces, or compatibility aliases.

Collection traversal materializes a `List` of at most 64 items. Integer `range`
loops accept non-negative constant bounds; execution remains subject to the
contract's gas budget. A page continuation supports traversing larger maps in
separate bounded scans.

## Arithmetic

Arithmetic is checked by default. Overflow, quantity underflow, division by
zero, remainder by zero, and negating the minimum `int` produce deterministic
seiyaku failures and revert effects. Compile-time folding calls the same exact
arithmetic implementation as runtime execution.

Intentional modular arithmetic is written with explicit operations such as `math::wrapping_add`, `math::wrapping_sub`, `math::wrapping_mul`, and `math::wrapping_neg`. Ordinary operators never silently wrap.

```text
math::wrapping_neg(int value) -> int
math::wrapping_add(int left, int right) -> int
math::wrapping_sub(int left, int right) -> int
math::wrapping_mul(int left, int right) -> int
```

The binary forms are named-only. These are the complete V1 modular-arithmetic
APIs; the corresponding flat names and all generic `numeric::*` helpers are
retired source spellings.

`int` is the signed range `-2^511..=2^511-1`; its compact encoding does not
change its semantic bounds. Division truncates toward zero, and remainder has
the dividend's sign. `min_int / -1` and the paired remainder operation fail
with overflow. Explicit wrapping helpers operate modulo `2^512`.

`decimal` and `quantity` use a signed 512-bit mantissa and canonical decimal
scale `0..=28`; `quantity` additionally rejects negative values. Trailing
fractional zeros are removed and zero always has scale zero. Ordinary
arithmetic computes the exact mathematical result with conceptual unbounded
intermediates, normalizes it, and then checks the final bounds. Plain decimal
division succeeds only for a canonical exact result representable through
scale 28; repeating results and terminating results needing more precision are
distinct failures. Rounded operations require an output scale and exactly one
of `Rounding::toward_zero`, `Rounding::away_from_zero`, `Rounding::floor`,
`Rounding::ceil`, `Rounding::nearest_even`, `Rounding::nearest_away`, or
`Rounding::nearest_toward_zero`, as documented in
[`kotodama_numeric_v1.md`](./kotodama_numeric_v1.md). Other rounding spellings
are rejected rather than treated as compatibility aliases.
Rounded operations never round implicitly. Invalid constant arithmetic is
diagnosed during compilation; runtime failures use the same stable numeric
faults.

The exact rounded source surface is:

```text
decimal.div_round(decimal divisor, int scale, rounding-mode mode) -> decimal
quantity.div_round(decimal divisor, int scale, rounding-mode mode) -> quantity
quantity.ratio_round(quantity divisor, int scale, rounding-mode mode) -> decimal
```

All three arguments are named-only. `rounding-mode` denotes one of the seven
`Rounding::*` paths listed above, not an integer tag or a user-declarable type.
The scale is checked in `0..=28`; `div_round` is not an `int` method, and
`ratio_round` is not a `decimal` method.

## Bounded lists

An uncontextualized non-empty `[a, b]` infers `List<T, 2>`. Context may provide
a larger capacity; `[]` requires a `List<T, N>` context. A comprehension's
proven maximum is its source capacity, even when it has an `if` filter, and it
is rejected if that maximum exceeds 64 or the contextual capacity. Lists may
nest and contain ordinary structured values, but never resource handles such
as `StateMap` or `Secret`. Every element schema must flatten to at least one
runtime word. An empty nominal struct uses one initialized zero word, so lists
can contain empty structs and products composed of empty structs.

The bounded API includes `len`, `get(index) -> Option<T>`,
`set(index: int, value: T) -> ()`, `push(value) -> ()`,
`try_set(index: int, value: T) -> Result<(), ListError>`,
`try_push(value) -> Result<(), ListError>`, `pop() -> Option<T>`, `contains`,
`take(constant_limit)`, and bounded `enumerate`. `push` and `try_push` take their
single value positionally. All four writes and `pop` require a mutable `var`
receiver. Checked `set`/`push` abort and revert the invocation with the same
nominal `ListError` their fallible counterpart returns. `IndexOutOfBounds = 1`
and `CapacityExceeded = 2` are the complete compiler-owned ListError schema.
Recoverable failures preserve both list contents and length. Resource exhaustion
and malformed runtime values remain fatal faults.

Indexed assignment is unsupported. Its diagnostic recommends
`list.set(index: index, value: value);`. `contains` uses the same canonical value
equality as `==` and `!=`, including nominal error identity and recursive
structured values. Aggregate equality requires the same declared type, including
struct identity, error identity, and List capacity. Structs and tuples compare fields in
declaration order; sums compare their tag and only the active payload; Lists
compare their length and active elements. Inactive sum storage and unused List
capacity are not compared. Both operand expressions execute exactly once, from
left to right, before comparison. `!=` negates equality. `Secret` and `StateMap`
values are not comparable, including when nested in an aggregate.

Every `Result` value is must-use. Implicit expression discards, unread result
bindings, and overwrites of unconsumed result bindings are compile errors,
including control-flow paths which lose a value. Consume a result by returning,
matching, propagating, or reading it into another checked use. `let _ = value;`
is the explicit deliberate-discard form. Obligations follow product fields,
`Option` and `Result` payloads, and `List` elements: observing another field,
an outer tag, or a collection length does not handle nested results. Canonical
whole-value equality, including `List.contains`, reads the compared values and
consumes their obligations. Named
pattern `_` fields and `..` explicitly discard their selected or omitted fields.
List handles can be shared; when exact alias or dynamic-index facts are unknown,
the checker conservatively retains potentially unread elements. Handle or
explicitly discard outstanding values before overwriting a possibly shared
slot. Traversal handles the items it visits, including every reachable exit
path; elements appended after its initial length was captured remain must-use.
`?` propagates only an identical error type; exhaustive `match` expresses
conversion to another nominal error type.
`take(limit)` accepts a compile-time constant from zero through the source
capacity. `take(0)` returns an empty list with the minimum valid static capacity
`List<T, 1>`; a positive limit `L` returns `List<T, L>`.

## Native JSON values

```kotodama
seiyaku NativeJsonExample {
    view fn build(AccountId account_id, string label) -> Json {
        json {
            owner: account_id,
            amount: 1.25,
            labels: json ["primary", label],
        }
    }
}
```

JSON object keys are identifiers or string literals, duplicates are errors,
and encoded keys are sorted canonically regardless of source order. Each
object or array node contains at most 64 entries or elements. JSON
construction recursively accepts booleans, `int`, `decimal`, `quantity`,
strings, canonical IDs, `Json`, `()`, nominal errors, `Option`, and `List`; bytes become lowercase
`0x` hex. Unit becomes `null` and nominal errors become their variant names.
Options always use the same tagged objects as public arguments and returns:
`Option::some(value)` becomes `{"some": value}` and `Option::none` becomes
`{"none": true}`. Thus `Option::some(())` becomes `{"some": null}`, while
nested Options and list elements retain every active tag. No nullable Option
encoding is accepted. Literal-only and dynamic native JSON expressions use
the same schema-bound construction operation. `Result` and arbitrary structs require explicit handling. Typed
getters return `Option<T>` and use `.get_int(key)`, `.get_decimal(key)`, and
`.get_quantity(key)` for the three numeric domains. Retired numeric getter
spellings are errors.

`Json::parse` accepts exactly one direct string literal and validates that
literal at compile time. Parameters, locals, and constants are not accepted as
parser input and produce `E_JSON_LITERAL_REQUIRED`; construct dynamic typed JSON
with native `json { ... }` and `json [ ... ]` expressions instead.

## Typed core ledger queries

The five compiler-declared projections and the page wrapper have these exact
field names, declaration order, and types:

```text
AccountView {
    AccountId id,
    Json metadata,
}
AssetView {
    AssetId id,
    quantity amount,
}
AssetDefinitionView {
    AssetDefinitionId id,
    string name,
    Option<string> description,
    AccountId owned_by,
    quantity total_quantity,
    Json metadata,
}
DomainView {
    DomainId id,
    AccountId owned_by,
    Json metadata,
}
NftView {
    NftId id,
    AccountId owned_by,
    Json content,
}
QueryPage<T> {
    List<T, 64> items,
    Option<int> next_offset,
}
```

`ledger::query::account`, `asset`, `asset_definition`, `domain`, and `nft`
accept their exact typed ID and return `Option<View>`. Their plural forms
`accounts`, `assets`, `asset_definitions`, `domains`, and `nfts` require named
`int offset` and `int limit` arguments and return `QueryPage<View>` with
`List<View, 64> items` and `Option<int> next_offset`. Offset is in
`0..=i64::MAX`, limit is 1 through 64, and the `offset + limit` page window must
fit `i64`. Ordering is canonical ID order, and `next_offset` is present only
when another page exists. Other specialist query families remain explicit byte
APIs; the typed balance API is unchanged.

## Durable state

Scalar seiyaku state must be initialized by `hajimari`/`始まり` on every
successful `hajimari`/`始まり` path before it can be observed. `StateMap` is
host-backed and does not require allocation in `hajimari`.

`StateMap.get` returns `Option<V>`; absence is not represented by a zero, empty
string, or implicit default. `map.get(key).expect(Error::Missing)` extracts a
present value and rejects absence with the exact nominal error. It evaluates
the receiver and error once in source order, and aborts before reading the
absent payload. `value.unwrap_or(default)` explicitly supplies an eager fallback;
`value.is_some()` and `value.is_none()` inspect presence. Rvalue indexing such
as `map[key]` and compound
indexed assignment such as `map[key] += value` are errors because both would
read a possibly absent value without handling `Option<V>`. Simple
`map[key] = value` remains the canonical per-key write form. The flat spelling
`get(map, key)` is not a StateMap operation; only the receiver form
`map.get(key)` invokes the intrinsic, while an unrelated user-declared function
named `get` resolves normally. `StateMap.remove(key)` returns the removed
`Option<V>` and is not permitted in views. Every scalar or aggregate state root
and every `StateMap` value is encoded once as one canonical, schema-bound record
under one durable key. Its domain-separated schema hash covers the exact type
and named-field layout; mismatched schemas, malformed typed leaves, invalid
active-only sums, and null active pointers are rejected. Nested `StateMap`
values and unsupported leaves are compile errors. V1 map keys may be `int`,
`decimal`, `quantity`, `bool`, `string`, `bytes`, or a typed Iroha identifier;
aggregate, `Json`, optional, result, secret, and nested-map keys are rejected.
Numeric keys are canonicalized before hashing and ordering, so equivalent
decimal spellings cannot create distinct keys. Durable paths are the distinct
nominal `StatePath` storage type, transported to IVM state syscalls as canonical
Norito bytes rather than as `Name` pointers. Physical V1 map paths retain the
form `Name-base/<reversible lowercase hexadecimal canonical-Norito key bytes>`,
so path order is canonical key-byte order without hash-collision ambiguity.
Map keys are capped at 4 KiB, map bases retain the 255-byte `Name` bound,
complete paths are capped at 16 KiB, and iteration pages are canonical
`Vec<StatePath>` values limited to 64 items. The source helper
`base.path(key)` therefore returns `bytes` containing a framed `StatePath`;
passing a `Name` directly to `state::get`, `set`, `delete`, `keys`, `has`,
`len`, or `count` is a type error.

Record updates keep the absence check and durable write explicit:

```kotodama
seiyaku Notebook {
    error enum NoteError { Missing = 1 }
    struct Note { int nonce, bytes commitment }
    state StateMap<Name, Note> Notes;
    const NoteError MISSING = NoteError::Missing;

    kotoage fn revise(Name id, bytes commitment) authorize("Revise") {
        var note = Notes.get(id).expect(MISSING);
        note.nonce += 1;
        note.commitment = commitment;
        Notes[id] = note;
    }
}
```

Compiler-derived access metadata is advisory until independently verified from bytecode. Unknown, dynamic, incomplete, or transitively unresolved access forces conservative scheduler serialization.

## Errors and requirements

Seiyaku and reusable modules declare payloadless nominal `error enum` types.
Each variant declares an explicit nonzero `u32` code, unique within that enum;
different enums may use the same codes. The type identity binds the locked
package, source unit, and enum name. The variant schema is hashed separately;
link order never determines identity. Exported errors and structs resolve through
the locked module graph. The signed interface includes the complete descriptors.

`require(condition, error)` takes both arguments positionally and aborts with
that exact nominal error value. `Option.expect(error)` uses the same rejection
identity and returns the contained value without a placeholder or sentinel. Rejections preserve the error identity, variant
schema hash and code, as well as the originating contract and symbolic variant,
through nested calls and rollback. A wrong identity, schema or undeclared code
rejects. Free-form failure strings are not part of the release contract.

```kotodama
seiyaku Vault {
    error enum VaultError {
        ZeroDeposit = 1,
        NotReady = 2,
    }

    state int balance;

    hajimari() {
        balance = 0;
    }

    kotoage fn deposit(int amount) authorize("CanDeposit") {
        require(amount > 0, VaultError::ZeroDeposit);
        balance = balance + amount;
    }

    view fn ready() -> bool {
        return balance > 0;
    }
}
```

Assertions intended only for local tests or diagnostics must not replace public seiyaku errors.

## Local test mode

`#[test]` functions, `fixture` declarations, `koto_test` targets, and the
`test::` builtin namespace exist only when the compiler driver explicitly
selects test mode. A production `check` or `build` rejects these constructs
with `E_TEST_ONLY_PRODUCTION`; it never removes them silently before semantic
analysis or artifact hashing. Typed HIR records whether test capabilities were
enabled, and production code generation rejects test-capable HIR as well.

The `koto test` driver is the explicit test-mode boundary. It compiles the full
suite in test mode, then derives a test-free runtime seiyaku when the target has
an invocable public or lifecycle declaration. A pure unit-test target containing
only private helpers and `#[test]` functions needs no runtime artifact; its
tests, coverage, and profile data run from the test projection. This runner-only
derivation is not available to ordinary production builds. The two projections
retain separate immutable prepared artifacts, compiler reports, and code hashes.
The test projection is a generic IVM 1.1 harness without deployable `CNTR` or
`DBG1` sections. Its compiler-owned interface is carried beside the immutable
image, checked against the current ABI hash, and structurally validates the
terminal `HALT` through the reserved `__koto_test_return` descriptor. Production
admission accepts only IVM 1.1 contracts with an embedded interface, and rejects
both the generic test profile and that selector. Host-private
`0x00FE0001..=0x00FE0005` helpers require the crate-private test loader plus an
explicit host opt-in (the runner supplies `KotoTestHost`), remain outside ABI v1
and its hash, and cannot be enabled by public VM loaders or a permissive custom
host.
Typed fixture values use the same constructors as seiyaku code, including
`AccountId::parse`, `AssetDefinitionId::parse`, `DomainId::parse`,
`Name::parse`, and `Json::parse`; flat fixture-only constructor aliases are
errors.

## Namespaced host API

Source code uses namespaced capabilities. Representative roots are:

- `context::authority`, `context::block_height`, and other immutable call context
- `context::seiyaku_subject`, `context::seiyaku_address`, and
  `context::kotoage` for the branded execution identity and selected public or
  lifecycle declaration
- `ledger::asset::transfer`, `ledger::asset::mint`, and `ledger::asset::burn`
- `ledger::account::set_detail`
- `ledger::query::seiyaku_manifest` and `ledger::query::seiyaku_instance`
- `ledger::seiyaku::grant_kotoage` and
  `ledger::seiyaku::revoke_kotoage` for the current immutable seiyaku address
  and an exact kotoage selector
- `state::get`, `state::set`, and `state::delete`
- `bytes::len(value)` for the exact payload length of a first-class `bytes`
  value; it does not accept `Json`, IDs, strings, or generic pointer-ABI values
- `crypto::sha256`, `crypto::sha3`, and signature/proof operations
- `math::wrapping_add`, `math::wrapping_sub`, `math::wrapping_mul`, and
  `math::wrapping_neg` for explicitly modular 512-bit integer arithmetic
- `debug::info` for diagnostics
- `test::assert`, `test::assert_eq`, `test::invoke_kotoage`, and
  `test::invoke_kotoage_as` in test builds only

Flat aliases are errors. Allocation, heap growth, raw pointers, direct syscall variants, opaque instruction submission, and compiler `*_direct` helpers are not source APIs. In particular, `tlv_len` and `codec::tlv_len` remain internal; source uses only the typed `bytes::len`. The canonical builtin registry defines each capability's signature, effect, syscall, access behavior, gas class, and permitted execution modes.

The integer helpers `math::isqrt(value)`, `math::abs(value)`, and binary
`math::min(left:, right:)`, `math::max(left:, right:)`,
`math::div_ceil(left:, right:)`, `math::gcd(left:, right:)`, and
`math::mean(left:, right:)` operate over the complete signed 512-bit domain.
Compiler folding and typed runtime syscalls share the primitive algorithms.
See [numeric semantics](kotodama_numeric_v1.md) for checked boundaries and
staged limb-work charging; operands never narrow to machine integers.

Compiler-owned lifecycle and code-operation labels use the branded
`seiyaku::deactivate_instance`, `seiyaku::remove_code`,
`seiyaku::register_code`, `seiyaku::register_bytes`, and
`seiyaku::activate_instance` spellings. They remain compiler-internal and
cannot be called from source. The English `contract::` root is never a
Kotodama source namespace, and raw `contract::call`/`seiyaku::call` sugar does
not exist. English feature-concept builtin spellings such as
`context::contract_address`, `context::entrypoint`,
`ledger::query::contract_manifest`, and `test::invoke_entrypoint` are likewise
rejected rather than retained as compatibility aliases.

## Secrets and ZK seiyaku

A ZK seiyaku explicitly requests the ZK execution capability through its build
configuration. Private input is represented only as `Secret<int>`,
`Secret<decimal>`, or `Secret<quantity>`. A private input must initialize an
explicitly typed binding; its canonical Norito record carries the matching
nominal kind plus the complete schema-bound numeric frame. The compiler emits
that requested kind, and the host rejects a mismatch before allocating opaque
private VM memory.

The V1 source declassifier is `crypto::valcom`. Both operands must be typed
secrets. It binds the nominal kind and every byte of each canonical numeric TLV,
derives full-width BLS12-381 scalars without `u64` truncation, and returns the
complete compressed Pedersen point as a public `int`. The scalar `POSEIDON2`
and `POSEIDON6` opcodes are internal proof gadgets that reject private
operands. ABI V1 has no register-level BLS12-381 public-key, commitment, or
curve operations; full-width typed syscall boundaries provide those semantics.

Secrets cannot influence public control flow, public returns, logs, error
selection, state keys, state values, ledger writes, host queries, seiyaku calls,
ordinary arithmetic, comparisons, collection indices, or assertions. They
cannot appear in public parameters or return types. The legacy invocation-local
`u64` nullifier helper is not a durable V1 source capability.

`Secret<T>` and `GET_PRIVATE_INPUT` execute only in local compiler tests and in
explicitly provisioned prover/test hosts. Ordinary production consensus
dispatch rejects every seiyaku selector whose bytecode-reachable call graph
reads a private input, including a read hidden in a helper. This fail-closed
boundary is enforced again by consensus `CoreHost`, which rejects
`GET_PRIVATE_INPUT` during quote preparation and direct execution even if
selector resolution is bypassed. It remains until a proof-carrying invocation
statement binds the seiyaku address and code hash, seiyaku selector, public
arguments, authority and chain,
state root and exact read/write sets, outputs and events, gas schedule and
ceiling, and circuit and verifier-key versions.

Raw private witness bytes must never enter a signed transaction, `IvmProved`
payload, overlay, public argument record, or deterministic validator replay.
Validators receive only the complete public statement and its proof once that
production proof path exists.

The compiler performs fail-closed information-flow analysis across the complete call graph.

## Resource limits

The compiler rejects inputs exceeding any V1 hard limit:

| Resource | Limit |
|---|---:|
| UTF-8 source | 1 MiB |
| Tokens, including EOF | 250,000 |
| Delimiter/parse nesting | 256 |
| Resolved named-type nesting | 256 |
| Expanded local struct nodes | 250,000 |
| Collection iteration | 64 items |
| Signed argument record | 1 MiB |
| Complete nested-return TLV | 1 MiB (1,048,537-byte record + 39-byte envelope) |
| Typed module graph | 512 sources / 16 MiB total |
| Default artifact cycle ceiling | 1,000,000 |

The chain's committed admission ceiling is authoritative. The
`ivm_max_cycles_upper_bound` field of the committed
`pipeline_validity_policy_v1` parameter is a mandatory positive integer
(default `1_000_000`); an authorized `SetParameter` changes it from the next
block, a zero value is rejected, and neither a node configuration file nor an
environment variable can set or disable it. The selected positive
cycle ceiling is embedded in the execution header and therefore covered by the
canonical artifact hash.

## Tooling and build configuration

`koto` is the only source-language command in V1:

```text
koto check seiyaku.ko
koto check --project kotodama.project.json
koto build seiyaku.ko --max-cycles 1000000
koto build --project kotodama.project.json
koto build --format sarif seiyaku.ko
koto check --zk proof_seiyaku.ko
koto build --zk proof_seiyaku.ko
koto test seiyaku.test.ko
koto fmt seiyaku.ko
koto doc seiyaku.ko
koto explain K0001
koto lsp --project kotodama.project.json
koto lsp --zk --project zk.project.json
```

`--zk` is an explicit build capability, not source metadata. It is required for
`Secret<T>` and the approved proof/commitment operations; ordinary builds reject
those constructs. `koto check|build|doc|lsp` and `musubi build` pass this policy to the same in-process compiler session.
It does not make ABI, vector, or pointer policy selectable.

`koto fmt` and LSP formatting consume the compiler's lossless token stream.
They refuse syntactically invalid input, preserve comments and literal spelling,
and canonicalize four-space indentation, declaration spacing, operators, and
block layout with a 100-column target. A comma-delimited construct expanded
over multiple lines has a trailing comma. Formatting is deterministic and
idempotent, and fails rather than producing a source larger than the mandatory
1 MiB limit. `koto fmt --check` performs no writes.
LSP validation analyzes reusable `module Name` files without artifact
generation, but it never invents imports or exports from the set of open
documents. `koto lsp --project kotodama.project.json` loads the same exact
locked graph as `check` and `build`; open buffers overlay their matching
canonical project files while unopened files are read from that graph. Without
`--project`, open documents have standalone-source validation semantics and cross-file
calls report `E_PROJECT_MANIFEST_REQUIRED` rather than appearing valid only in
the editor.
Positional `koto check` paths are independent sources: one seiyaku has
an empty import graph, reusable modules are checked without linking, multiple
seiyaku roots are rejected, and mixing a root with modules requires `--project`.
`koto check --project` and `koto build --project` consume the same exact locked
graph; neither command scans sibling files or treats source order as authority.
A multi-source `koto check --format json|sarif` invocation emits exactly one
machine-readable document with the combined, deterministically ordered
diagnostic set. LSP
framing, individual documents, open-document count, and aggregate retained text
all have explicit bounds; rejected updates are not retained as stale formatter
input.

The compiler-owned `EditorSnapshot` retains source/package identities, resolved
symbols and lexical bindings, exact argument-label ranges, typed expression
facts, and canonical callable signatures. LSP completion filters by source,
scope, explicit import/export graph, and receiver type. Argument templates use
the declaration's positional-only prefix and optional named parameters. Optional
receivers offer `expect`, `unwrap_or`, and presence checks, including after
chained reads such as `Requests.get(id).`; signatures retain the extracted
payload type. Result receivers offer their supported extraction and status
methods without advertising `Option.expect`. Hover and
signature help expose types and effect/permission metadata; definition,
references, and rename use resolved identities. Rename rechecks the complete
source and export graph and verifies that every reference retains its resolver
identity, preventing capture while allowing names in disjoint scopes. A local
project manifest owns its contained module sources: renaming an export updates
its exact JSON string token together with declarations, references and call labels.
Unrelated strings and import aliases are unchanged. External graphs without local
manifest authority remain immutable. LSP edits include open-document versions,
including unsaved manifest buffers; changed unopened sources or manifests require
a reload. Incomplete graphs cannot produce rename edits.
Completion-only recovery never returns a compilable recovered AST.
The server invalidates its bounded snapshot on document versions and source or
project-manifest changes, and all protocol ranges use UTF-16 coordinates.
An independent input reader registers cancellation and increasing document
versions while analysis runs. The dispatcher checks request validity before
analysis and before publishing the buffered result: cancellation returns LSP
`-32800`, and a superseding document or project change returns `-32801`.
Obsolete diagnostic batches are discarded; committed batches include open
document versions and clear diagnostics for previously published closed files.
Pending input is limited to 64 messages and 16 MiB, with at most 65 active or
queued request IDs. Cancellation of unknown/completed IDs retains no state.
Exceeding an input bound closes the transport rather than accumulating work.

Human diagnostics capture immutable source text when their exact spans are
produced. Bounded source excerpts underline the selected bytes using deterministic
Unicode 15.1 display widths and four-column tab stops, including Japanese and
combining characters.
Related locations and help are projected into LSP diagnostics. JSON and SARIF
retain canonical structured ranges and do not embed source contents.
Compiler lint locations come from the same parser-owned declaration, binding,
statement, and expression ranges. Warnings from one source share its immutable
text and use the same diagnostic projection in `koto`, LSP, and
`musubi check`, including dependencies that are not open in the editor.

The local-only test helper requires
`test::expect_reject_as(actor:, kotoage:, arguments:, expected:)`. The expected
value is a nominal error variant (descriptor identity, schema hash, and enum-local
code) or a compiler-owned `test::Rejection` stage/trap selector. Invocation
permission, argument-schema rejection, and runtime permission are distinct
selectors. The explicitly broad helper is
`test::expect_any_reject_as(actor:, kotoage:, arguments:)`. Both use the existing
private test syscall: r13 carries a canonical Norito expectation in a Blob;
r14 and r15 are zero. Production admission does not enable test syscalls.
Nested execution checkpoints are restored before accepting a rejection or
reporting a mismatch.

`musubi new <directory> --namespace <namespace>` creates a contract package
with `Musubi.toml`, a contract, four standalone tests, README, and ignore rules.
`musubi check`, `musubi build`, and `musubi test` consume the package's exact
declared source and dependency graph. Network bindings select the exact client
context and contract alias for deployment and views. These package declarations
are distinct from the lower-level compiler source graph below; no additional
app manifest participates in package builds.

The project graph is canonical Norito JSON. Every field is explicit, version 1
is the only accepted schema, source paths are relative to and contained by the
manifest directory, and package identities are exact locked strings:

```json
{
  "version": 1,
  "root": "contracts/app.ko",
  "imports": [{"alias": "Math", "package": "example/math@1.0.0"}],
  "packages": [{
    "identity": "example/math@1.0.0",
    "modules": ["modules/math.ko"],
    "exports": ["value"],
    "imports": []
  }]
}
```

Unknown or duplicate fields, duplicate sources/exports, path escapes, unknown
packages, import cycles, undeclared aliases, and unexported calls fail closed.
Locked package names use nonempty `/`-separated ASCII components matching
`[A-Za-z0-9_][A-Za-z0-9_.-]*`, optionally followed by one `@revision` with the
same component grammar. Revisions retain their exact spelling and are not
interpreted as version ranges. Exported structs carry
`package::SourceUnit::Struct` in public and durable schemas; the complete name
is at most 1024 ASCII bytes, and both declaration components must be canonical
unreserved source type names. Aliases never enter this identity. Qualified
identities containing the compiler-private `__kotodama_link_` substring are
invalid. Contract-owned structs keep their declared name, including declarations
in fragments. Root-local module structs carry
`local::<64 lowercase hexadecimal digits>::SourceUnit::Struct`. The digest binds
the root contract owner and the canonical project-relative module path, excluding
absolute paths, consumer aliases and source contents. Compute it with `Hash::new`
over the domain bytes `iroha:kotodama:local-module:v1\0`, followed by the UTF-8
fields `root`, the root seiyaku name, and the canonical relative module path;
each field has a preceding unsigned 64-bit little-endian byte length. Encode the
32-byte digest as lowercase hexadecimal. The same owner prefix applies to local
module error enums. Package-owned local modules
retain their package identity even when reached through a path import. Schema
hashes bind the exact name and field schema, so changing a locked package identity
changes the schema.

Diagnostic spans keep package identity separate from the logical source path,
so two locked packages may both own `src/lib.ko` without ambiguous JSON, SARIF,
or human output.

`koto build --format human|json|sarif` and `musubi build --format
human|json|sarif` use the same canonical diagnostic bundle. Typed-module link
failures retain all semantic fields rather than embedding a rendered error in a
wrapper string. Imported-call failures point at the exact resolver-owned call
name, and ambiguous exports label every conflicting function declaration.

The test driver supports deterministic discovery and selection:

```text
koto test list seiyaku.test.ko
koto test run --filter exact_test_name --exact --jobs 4 --seed 7 seiyaku.test.ko
koto test run --format json seiyaku.test.ko
koto test run --junit target/kotodama-tests.xml seiyaku.test.ko
koto test run --zk zk_seiyaku.test.ko
```

The Rust compiler library behind `koto` is canonical. Musubi calls that library
in process. Their physical paths are normalized to
project-relative `/` names. In the absence of an explicit project manifest, the
deterministic V1 default is the selected root with no inferred imports,
wildcard exports, or sibling modules. Content-addressed build
authentication runs before parsing or typed-HIR linking, so an unchanged
project performs no compiler work and rewrites no outputs. Node.js calls the
compiler asynchronously through `iroha_js_host`; browsers use an explicit
compiler-service client. SDK adapters enforce the same 1 MiB UTF-8 source limit
before native or network dispatch. There is no independent JavaScript compiler
or offline browser compiler.

ABI version, vector width, execution-mode bits, and compiler features are not
source declarations or user-selectable language metadata. Build configuration
may request a permitted execution capability such as ZK and may select a
positive cycle ceiling no greater than node admission policy. Source-level
`meta` blocks are errors. The manifest's hash-covered `features_bitmap` is
derived from the execution header and currently mirrors only ZK and
deterministic VECTOR capability; it never advertises host SIMD, Metal, or CUDA
availability.

## Seiyaku artifact

The canonical `code_hash` is a domain-separated hash of the complete deployable `.to` image: every execution-header field, the embedded seiyaku interface (CNTR), typed literals, and executable code.

Debug information and source maps are forbidden inside deployable artifacts. They are hash-keyed sidecars whose `artifact_hash` identifies the exact `.to` image. Every native source segment carries its graph-stable `source_id`, logical source path, exact half-open UTF-8 byte range, and the corresponding one-based line and Unicode-scalar column; generated instructions without a source range are identified separately rather than borrowing a neighboring span.

Nodes validate direct control-flow targets, allowed ABI-v1 syscalls, pointer-ABI types, interface structure, code/ABI hashes, and signed manifest equality. Compiler fingerprints are informational and are not security claims.

## Example

```kotodama
seiyaku Counter {
    state int value;

    hajimari() {
        value = 0;
    }

    kotoage fn increment(int delta) -> int authorize("CanIncrementCounter") {
        let int next = value + delta;
        value = next;
        return next;
    }

    view fn current() -> int {
        return value;
    }
}
```

The repository documentation check discovers and compiles every tracked
`kotodama` or `ko` code fence and documented `*.ko` heredoc below the roots in
`kotodama_v1_docs.json`. Grammar-derived keyword and operator tables feed
documentation, formatting, syntax highlighting, and LSP completion so those
surfaces cannot define independent dialects.
