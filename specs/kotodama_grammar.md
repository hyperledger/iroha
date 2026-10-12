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
Those eight spellings are first-class keywords, not compatibility aliases. The
two spellings of a feature are the same token and may be mixed freely, even
within one file; no tool normalizes or prefers either script. Other non-ASCII
text is permitted only inside strings and comments; English `contract`,
`entry`, `init`, and `upgrade` are ordinary identifiers, not Kotodama V1
keywords. Where they stand in place of a declaration keyword
(`contract Name {`, `init() { ... }`, `pub fn`, `entry fn`), they and similar
English concept words are rejected with `E_ENGLISH_DECLARATION_WORD`, which
offers both spellings of the branded keyword (inside a module, whose public
surface is `export`, `pub fn` is answered with `export fn`); as ordinary names
(`fn init()`) they remain valid identifiers.

| Keyword | Reading | Literal meaning | Role |
| --- | --- | --- | --- |
| `seiyaku` / `誓約` | せいやく | solemn pledge | Declares the deployable unit compiled to one IVM `.to` artifact |
| `kotoage` / `言挙げ` | ことあげ | raising one's words | Declares an authorized, state-changing public function of a seiyaku |
| `hajimari` / `始まり` | はじまり | beginning | Declares the one-shot activation hook that initializes durable state |
| `kaizen` / `改善` | かいぜん | improvement | Declares the migration hook run once when an active seiyaku's code is replaced in place |

Tokens are separated by ASCII whitespace or by the ideographic space U+3000
that Japanese input methods insert; `koto fmt` rewrites U+3000 to an ASCII
space. Other Unicode spaces are rejected (`E_NON_ASCII_WHITESPACE`), and
full-width forms of ASCII characters such as `（`, `；` or `ａ` are rejected
outside strings and comments (`E_FULLWIDTH_ASCII`). Characters that make
reviewed text read differently from what compiles are rejected anywhere in a
source file, including comments and string literals: the bidirectional
controls U+202A–U+202E, U+2066–U+2069, U+200E, U+200F, and U+061C
(`E_BIDI_CONTROL_CHARACTER`) and the line separators U+2028, U+2029, and U+0085
(`E_UNICODE_LINE_SEPARATOR`). A string that needs one of them spells it with a
`\u{...}` escape.

An adjacent block of `///` comments documents the following declaration.
The text is Markdown: one optional space after `///` is stripped, and a bare
`///` keeps a paragraph break. Ordinary comments, blank source lines, and
intervening declarations end the block. `////` and `//!` are ordinary comments.
The parser binds this prose to the declaration's source identity, including
exported module declarations; hover and completion preserve it through imports.
`koto doc` includes authored entrypoint prose in Markdown and in each JSON source
signature's `documentation` field. Formatting preserves the comment text and
attachment. These comments do not become contract metadata or affect execution.

The following lexical tables are generated from
`crates/kotodama_lang/grammar/v1.lex`; edits belong in that machine-readable
grammar rather than in this rendered copy or an editor grammar.

<!-- BEGIN GENERATED: kotodama-v1-keywords -->
| Spelling | Token |
| --- | --- |
| `as` | `As` |
| `permission` | `Permission` |
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
| `event` | `Event` |
| `emit` | `Emit` |
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
whitespace      = U+0009 | U+000A | U+000B | U+000C | U+000D | U+0020 | U+3000 ;
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

seiyaku-item    = struct | data-enum | error-enum | event | constant | state | function | kotoage
                | view | hajimari | kaizen | trigger | include | import ;
module-item     = exported-item | include | import ;
exported-item   = "export"? (struct | data-enum | error-enum | constant | function) ;
include         = "include" string-literal ";" ;
import          = "import" string-literal "as" identifier ";"
                | "import" seiyaku-keyword string-literal "as" identifier ";"
                | "import" "type" string-literal "from" identifier "as" identifier ";" ;
```

A source unit may include bare declaration fragments with `include "./state.ko";`.
Includes expand declarations at the directive position and share the owning
contract or module's functions, types, constants and state. Each fragment has one
owner. Include cycles and duplicate declarations are errors. A fragment has no
`seiyaku` or `module` wrapper and is parsed only through an explicit include or
fragment-formatting operation. Fragment declarations must be valid for the owner;
module fragments cannot introduce contract state, events or entrypoints.

`import "./math.ko" as arithmetic;` imports a named local module. Only declarations
marked `export` are accessible through `arithmetic::name`; functions remain ordinary
private functions for runtime-entrypoint purposes. Types, enums and constants
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
    view fn answer() authorize(anyone) -> int { twice(arithmetic::SCALE) }
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

String literals passed to the typed identifier constructors (`AccountId`,
`AssetDefinitionId`, `AssetId`, `NftId`, `DomainId`, `DataSpaceId`, and `Name`)
are validated during semantic analysis with the same parsers lowering uses, so
`koto check` and editors report them as `E_INVALID_ID_LITERAL` on the literal.
Account literals are checked against the compilation's chain discriminant; a
literal encoded for another network reports both discriminants, and a literal
whose katakana were widened by an input method receives a fix to the canonical
half-width spelling (`ヰ` and `ヱ` have no half-width form and stay as they are).
Alias-shaped account literals containing `@` are resolved by the host at
execution time and are not validated statically. A call through a
compiler-owned namespace such as `context::`, `ledger::`, `math::`, `Option::`,
or `Result::` that names no builtin is `E_UNKNOWN_BUILTIN`, never an import
error; such roots can never be import aliases. The diagnostic suggests the
closest builtin and points English concept spellings such as
`context::entrypoint` at their branded names (`context::kotoage`).

## Native events

```ebnf
event           = "event" identifier "{" (event-declaration-field | field-separator)* "}" ;
event-declaration-field = type identifier ;
field-separator = "," | ";" ;
emit-statement  = "emit" identifier "{" event-fields? "}" ";" ;
event-fields    = event-field ("," event-field)* ","? ;
event-field     = identifier (":" expression)? ;
```

An event declares a seiyaku-owned payload, including when declared in an included
fragment. Its fields use the same type-first declarations as a struct. The
formatter separates declaration fields with commas; the shared field parser also
accepts semicolons and optional separators between complete type/name pairs. Emission
uses an exact record literal: `emit Transfer { from: sender, amount: total };`.
Record shorthand is valid when the field and value names match. Every field must
appear exactly once. Field expressions run once in written order; the resulting
values are placed in declaration order for the canonical public value-record ABI.
There is no JSON construction or alternative event encoder.

Event declarations are not ordinary value types or constructors. A reusable
payload shape belongs in a struct and can be an event field. Payloads may contain
ordinary enums, errors as values, products, bounded lists, `Option` and `Result`,
subject to public schema limits. `Json`, `StateCursor`, durable state handles and
private values are forbidden at every nesting level. Empty event records are valid.
Modules cannot declare or export events. Module types used by an event retain
their complete nominal identity, including their locked package identity.

The signed manifest and embedded interface contain the same required `events`
table, sorted uniquely by event name, with at most 256 declarations and 64 KiB of
canonical declaration bytes. Each descriptor includes the exact public payload
schema with a `Unit::EventName` struct root. The `emit` syscall receives its table
ordinal and canonical typed value words; the host validates and captures those
values through the shared public record machinery and attaches authenticated
execution provenance. Events participate in transaction rollback.

Emission is a mutating host effect. Kotoage functions, lifecycle hooks and their
private helpers may emit; a view is rejected if any reachable helper emits.

## Declarations

```ebnf
struct          = "struct" identifier "{" (field (("," | ";") field)* ("," | ";")?)? "}" ;
field           = type identifier ;

data-enum       = "enum" identifier "{" variant (("," | ";") variant)* ("," | ";")? "}" ;
variant         = identifier "=" integer-literal ;
error-enum      = "error" "enum" identifier "{"
                  error-variant (("," | ";") error-variant)* ("," | ";")?
                  "}" ;
error-variant   = error-message? identifier "=" integer-literal ;
error-message   = "#[" "message" "(" string-literal ")" "]" ;

constant        = "const" type identifier "=" expression ";" ;
state           = "state" type identifier ";" ;

function        = "fn" identifier parameters return-type? block ;
kotoage         = kotoage-keyword "fn" identifier parameters authorization return-type? block ;
kotoage-keyword = "kotoage" | "言挙げ" ;
view            = "view" "fn" identifier parameters authorization return-type? block ;
hajimari        = hajimari-keyword parameters block ;
hajimari-keyword = "hajimari" | "始まり" ;
kaizen          = kaizen-keyword parameters block ;
kaizen-keyword  = "kaizen" | "改善" ;
authorization   = "authorize" "(" ("anyone" | identifier) ")" ;
permission      = "permission" identifier ";" ;
shared-permission = "import" "permission" string-literal "as" identifier ";" ;
parameters      = "(" (parameter ("," parameter)*)? ")" ;
parameter       = type "_"? identifier ;
return-type     = "->" type ;

trigger         = "trigger" identifier "->" trigger-call "{"
                  trigger-filter trigger-option* "}" ;
trigger-call    = identifier ;
trigger-filter  = "on" (time-filter | execute-filter | data-filter | pipeline-filter) ";"? ;
trigger-option  = "repeats" ("indefinitely" | integer-literal) ";"
                | "authority" (identifier | string-literal) ";"
                | "metadata" "{" metadata-entry* "}" ";"? ;
metadata-entry  = (identifier | string-literal) ":" expression ";" ;
time-filter     = "time" ("pre_commit" | "schedule" "(" "start_ms" ":" expression
                  ("," "period_ms" ":" expression)? ","? ")") ;
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
and `clamp(7, minimum: 0, maximum: 10)`. Builtin calls follow the single
argument-label rule in [Namespaced host API](#namespaced-host-api).
Declaration types always precede names; the retired `name: Type` form is a
syntax error with a type-first diagnostic, reported once for each declaration
written that way with a fix that swaps it to `Type name`. Every enum variant has an explicit,
non-zero `u32` code, and names and codes are unique within the
enum. Missing types, unknown types, duplicate declarations, reserved names,
ambiguous resolution, recursive value types, duplicate parameters, and
shadowing are compile errors. Shadowing includes a parameter or local that
reuses the name of any seiyaku-level declaration, such as a parameter `stake`
in a seiyaku that also declares `kotoage fn stake(...)`. The diagnostic names
the colliding declaration as it is spelled and labels where it is declared; the
rejected binding still resolves its own later uses, so one collision produces
one error rather than a cascade of unknown-name errors.

A `kotoage fn`/`言挙げ fn` mutates or submits ledger state. Both it and a
`view fn` require an explicit `authorize(...)` clause before the return type.
`authorize(anyone)` permits every caller; `authorize(Admin)` refers to a
declared permission. `permission Admin;` declares an instance-scoped role,
whose grants bind the immutable contract address and the declared name.
`import permission "ChainToken" as Treasury;` explicitly imports a shared chain
permission; only that exact token name with a canonical JSON-null payload
authorizes the call. A typed permission carrying a payload is a different
authority and cannot match this import.

The signed manifest authenticates the complete declaration table and each
entrypoint’s typed authorization. Authorization is checked at runtime and is
separate from compiler-derived effects and operation-specific host authority.
The current instance owner or a holder of the exact scoped role may grant or
revoke it while it remains declared by the current code. To delegate through a
contract call, the contract’s subject account must itself hold the role; the
caller’s entrypoint authority is insufficient. Lifecycle declarations never
accept source-level authorization: ABI V1 binds both `hajimari`/`始まり` and
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

A trigger declaration binds a named event filter to a local `kotoage fn`/`言挙げ fn`
callback. Private functions, views, lifecycle hooks, unknown names, and namespaced
callbacks are rejected. A module import does not authenticate a deployed seiyaku
interface, so `library::callback` cannot bypass this rule.

Time, data, and pipeline callbacks take no parameters. Data-event payloads do not
have a uniform typed argument schema; callbacks may inspect the current event with
`context::trigger_event()`, which returns `Json`. Time and pipeline events provide
an empty object. An execute-trigger callback may declare typed public parameters:
the event's explicit argument object must have exactly those field names and
canonical values, and the runtime converts it into the same schema-bound Norito
record used for ordinary calls before starting the VM.

Schedules require labelled compile-time integer expressions:
`on time schedule(start_ms: START, period_ms: 60 * 1_000);`. `start_ms` is Unix-epoch
milliseconds in `0..=18446744073709551615`; `period_ms` is milliseconds in
`1..=18446744073709551615`. Omitting `period_ms` creates a one-shot schedule.
Positional schedule arguments and dynamic expressions are rejected. `repeats`
defaults to `indefinitely` and may instead specify an exact count.

The optional `authority` identifies the account executing the callback and must be
a canonical domainless AccountId literal. Without an explicit authority, manifest
activation uses the seiyaku's bound subject account. That account must hold the
callback's declared permission, unless it authorizes `anyone`, and the permissions
for its ledger operations. Trigger metadata cannot provide a fixed
`contract_payload` to replace event arguments. The runtime authenticates the
selected callback and its schema before dispatch; no null pointer or numeric zero
means “re-read JSON trigger arguments.”

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
| Durable `StateMap` scalar key leaves (ordered) | `int`, `decimal`, `quantity`, `bool`, `string`, `bytes`, `DataSpaceId`, `AccountId`, `AssetDefinitionId`, `AssetId`, `NftId`, `DomainId`, `Name` |
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
`fn total(quantity amount) -> quantity` is valid. Functions, parameters,
locals, state, and constants share one value namespace, so a parameter may not
reuse the name of its own or any other function: `fn amount(quantity amount)`
is a shadowing error.
Unit is written `()` in both type and value position. Omitted return annotations
mean `()`, and an omitted return value is the same canonical Unit value. Unit
occupies one zero scalar word and renders as JSON `null`; schemas carry an
explicit Unit node. It composes inside structs, lists, `Option`, `Result`, durable
state, and public argument/return records. Nonzero Unit words reject. `(T)` is
not a one-element tuple type; ordinary tuple types contain at least two elements.
Payloadless declared ordinary and error enums, `ListError`, and `NumericError` are nominal
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

V1 supports `if`/`else`, `return`, and compiler-proven bounded `for` loops. It rejects `while`, `loop` and three-clause `for (init; condition; step)` headers (`E_UNSUPPORTED_LOOP`), recursion, indirect source calls, and loops whose bound cannot be proven. A counted loop is written `for i in range(N)`; `..` appears only in struct patterns, so `0..10` is not a range (`E_RANGE_SYNTAX`, with a `range(N)` fix when the start is `0`).

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
conversion. The lowercase placeholder constructors, mis-cased paths such as
`Option::Some`, and bare `Some(x)`, `None`, `Ok(x)`, and `Err(x)` are syntax
errors (`E_LEGACY_SUM_CONSTRUCTOR`) with fixes to the canonical spelling. A
match has no `_` wildcard arm (`E_MATCH_WILDCARD`).

Ordinary function calls accept a positional prefix followed by optional named
arguments. Named arguments may appear in any order; argument expressions always
evaluate left to right in source order. A positional argument after a named
argument, a name for a positional-only parameter, a duplicate argument, or a
missing required argument is an error.
Keywords are contextual argument labels immediately before `:`, so canonical
builtins can use labels such as `trigger:`. This does not make keywords valid
local binding names. Call labels depend only on the signature and are included in package interface
fingerprints. Builtin label requirements come from the registry's call policy;
builtin label punning is sugar for the labelled call and never changes a
fingerprint. Structs are
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

## Option and Result error bridges

| Receiver | Method | Result | Failing branch |
| --- | --- | --- | --- |
| `Option<T>` | `ok_or(error: E)` | `Result<T, E>` | Replace `none` with `err(error)`. |
| `Result<T, Old>` | `or_err(error: E)` | `Result<T, E>` | Discard the original error and replace it with `error`. |
| `Option<T>` or `Result<T, Old>` | `expect(error: E)` | `T` | Reject the invocation with the supplied nominal error. |

`E` must be a declared or compiler-owned nominal error enum. Every method
accepts either its positional error argument or `error:`. Each receiver is
evaluated once. The error expression is evaluated only for `none` or `err`;
the successful payload is preserved without reading an inactive payload or
constructing a placeholder. `or_err` deliberately replaces the old error;
`expect` deliberately rejects with the supplied error instead of the old one.
Postfix `?` requires the resulting error type to match the enclosing `Result`
exactly. `unwrap_or(default)` and `unwrap_err_or(default)` continue to evaluate
their value defaults eagerly.

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

Like every pure helper, the binary forms accept positional operands or their
declared `left:`/`right:` labels. These are the complete V1 modular-arithmetic
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

Like every receiver method, these accept positional arguments or their
declared labels (`divisor:`, `scale:`, `mode:`); labels keep the two numeric
operands distinct at the call site. `rounding-mode` denotes one of the seven
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

At user-function arguments and returns, `List<T, N>` widens to `List<T, M>`
when `N <= M` and `T` is exactly identical. A strict increase allocates a fresh
outer list, evaluates the source once, and copies its active elements. Mutating
that outer list cannot change the source list's length or slots; copied element
values retain their normal semantics, including shared nested List handles.
Return branches receive the declared return context. This conversion does not
apply to local annotations, struct fields, durable-state writes, nested element
types, or narrowing capacities. A fresh full literal immediately followed by a
checked `push` of a literal is rejected as provably full; uncertain lengths are
checked at runtime, and `try_push` remains the explicit recoverable operation.

The bounded API includes `len`, `get(index) -> Option<T>`,
`set(index: int, value: T) -> ()`, `push(value) -> ()`,
`try_set(index: int, value: T) -> Result<(), ListError>`,
`try_push(value) -> Result<(), ListError>`, `pop() -> Option<T>`, `contains`,
`take(constant_limit)`, and bounded `enumerate`. Like every receiver method,
List methods accept positional arguments or their declared labels, so
`xs.set(0, value)` and `xs.set(index: 0, value: value)` are the same call.
All four writes and `pop` require a mutable `var`
receiver or a struct/tuple field chain rooted in that local `var`. Temporary
products and durable state values are not mutable List receivers. Checked `set`/`push` abort and revert the invocation with the same
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
    view fn build(AccountId account_id, string label) authorize(anyone) -> Json {
        json {
            owner: account_id,
            amount: 1.25,
            labels: json ["primary", label],
        }
    }
}
```

Like a struct literal, a `json { ... }` object is not recognised directly in
the head of an `if`, `match`, or `for` (`for x in json { ... }` iterates a
local named `json`); parenthesize it there.

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
getters are receiver methods that return `Option<T>`: `.get_int(key)`,
`.get_decimal(key)` and `.get_quantity(key)` for the three numeric domains,
`.get_string(key)` and `.get_bool(key)` for JSON strings and booleans, plus
`.get_json`, `.get_name`, `.get_account_id`, `.get_asset_definition_id`,
`.get_nft_id` and `.get_bytes_hex`. The key is a `Name` or a string literal; a
literal key is validated as a `Name` at compile time, so
`value.get_int("count")` and `value.get_int(Name::parse("count"))` are the same
call. Retired numeric getter spellings are errors.

A getter returns `Option::none` only when the key is absent from the JSON
object. A present field of the wrong JSON type aborts the invocation with the
host trap `DecodeError` instead of reading as absent: for example a JSON number
token where `.get_int` requires a canonical decimal string such as `"5"`, a
quoted `"true"` read by `.get_bool`, or a number read by `.get_string`. A
non-object receiver aborts the same way. The numeric getters never accept JSON
number tokens, because a client that encodes integers as floating-point numbers
may already have rounded them; exact values travel as canonical strings.

```kotodama
seiyaku Orders {
    view fn doubled_size() authorize(anyone) -> int {
        return order_size(json { size: 4, double: true });
    }

    fn order_size(Json order) -> int {
        let size = order.get_int("size").unwrap_or(0);
        if order.get_bool("double").unwrap_or(false) {
            return size * 2;
        }
        return size;
    }
}
```

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

`ledger::query::assets_of(account: owner, offset: 0, limit: 16)` returns the same
`QueryPage<AssetView>` projection restricted to that exact account. Filtering
precedes pagination; offsets count only matching assets. The account is typed,
so source callers do not construct a raw query request.


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
the receiver once and evaluates the error only on absence, then aborts before
reading the absent payload. `value.unwrap_or(default)` explicitly supplies an eager fallback;
`value.is_some()` and `value.is_none()` inspect presence. A fallback that must
only be evaluated on absence is written as a `match` over the returned
`Option<V>`. Rvalue indexing such
as `map[key]` and compound
indexed assignment such as `map[key] += value` are errors because both would
read a possibly absent value without handling `Option<V>`. Simple
`map[key] = value` remains the canonical per-key write form. The flat spelling
`get(map, key)` is not a StateMap operation; only the receiver form
`map.get(key)` invokes the intrinsic, while an unrelated user-declared function
named `get` resolves normally. `StateMap.remove(key)` returns the removed
`Option<V>` and is not permitted in views.

The complete StateMap helper surface is:

| Helper | Returns | Durable effect | In `view fn` |
| --- | --- | --- | --- |
| `map.get(key)` | `Option<V>` | read | yes |
| `map.contains(key)` | `bool` | read | yes |
| `map.get_or_insert(key, default)` | `V` | writes `default` when `key` is absent | no |
| `map.remove(key)` | `Option<V>` | delete | no |
| `map[key] = value` | `()` | write | no |
| `map.page(after, limit)`, `map.take(limit)` | `StatePage` | bounded read | yes |

`get_or_insert` evaluates `default` only when the key is absent, writes it, and
returns it; the write makes its caller a state writer for authorization and
access analysis. Like every receiver method these helpers accept positional
arguments or their declared labels. There is no implicit-default read: a
missing key is never read as zero.

Every scalar or aggregate state root
and every `StateMap` value is encoded once as one canonical, schema-bound record
under one durable key. Its domain-separated schema hash covers the exact type
and named-field layout; mismatched schemas, malformed typed leaves, invalid
active-only sums, and null active pointers are rejected. Nested `StateMap`
values and unsupported leaves are compile errors. V1 map keys may be `int`,
`decimal`, `quantity`, `bool`, `string`, `bytes`, or a typed Iroha identifier;
or a tuple of these scalar leaves, including nested tuples with at least two
elements. Structs, enums, `Json`, optional, result, secret, cursor, list and
nested-map keys are rejected. The complete key schema shares the bounded
node/depth limits of public values. For example,
`StateMap<(AccountId, (int, Name)), quantity>` is indexed by
`balances[(owner, (epoch, currency))]`.
Numeric keys are canonicalized before hashing and ordering, so equivalent
decimal spellings cannot create distinct keys. Durable paths are the distinct
nominal `StatePath` storage type, transported to IVM state syscalls as canonical
Norito bytes rather than as `Name` pointers. Physical V1 map paths retain the
form `Name-base/<reversible lowercase hexadecimal canonical key-record bytes>`.
Every scalar or tuple key uses `StateValueRecordV1` with its complete key-schema
hash; the scalar and tuple cases use the same encoder and decoder,
so path order is canonical encoded-byte order, not numeric or tuple
lexicographic order. `StateCursor<K>` carries a domain-separated hash of the
complete scalar or tuple `K` schema as well as the map/value schema and instance
binding; a cursor cannot resume a map with a different key layout.
Map keys are capped at 4 KiB, map bases retain the 255-byte `Name` bound,
complete paths are capped at 16 KiB, and iteration pages are canonical
`Vec<StatePath>` values limited to 64 items. The source helper
`base.path(key)` therefore returns `bytes` containing a framed `StatePath`;
passing a `Name` directly to `state::get`, `state::set`, `state::delete`,
`state::contains`, `state::len`, or `state::count` is a type error.

Record updates keep the absence check and durable write explicit:

```kotodama
seiyaku Notebook {
    permission Revise;
    error enum NoteError { Missing = 1 }
    struct Note { int nonce, bytes commitment }
    state StateMap<Name, Note> Notes;
    const NoteError MISSING = NoteError::Missing;

    kotoage fn revise(Name id, bytes commitment) authorize(Revise) {
        var note = Notes.get(id).expect(MISSING);
        note.nonce += 1;
        note.commitment = commitment;
        Notes[id] = note;
    }
}
```

Compiler-derived access metadata is advisory until independently verified from bytecode. Unknown, dynamic, incomplete, or transitively unresolved access forces conservative scheduler serialization.

## Nominal enums

`enum Status { Active = 1, Paused = 2 }` declares ordinary data. Both ordinary
and `error enum` variants require explicit, unique nonzero `u32` codes and unique
names, with at most 256 variants per type. Payload variants, generic enums and
wildcard match arms are rejected. Every `match` must cover every variant of its
exact nominal type; equal codes in two enum types do not make them assignable.

Enum identity binds its declaring package, source unit and name. Import aliases
do not change it. Ordinary enums compose inside structs, tuples, lists, `Option`,
`Result`, state values and public arguments/results. JSON carries the exact
variant-name string, such as `"Active"`; numbers, qualified paths and unknown
names reject. Signed `enum_types` declarations are separate from `error_types`
and include types used only by stored state. Changing a stored enum's identity,
variant names or codes changes its durable schema and fails upgrade compatibility.

Only `error enum` variants may supply `require`, aborting `expect`, or an exact
rejection expectation. Ordinary enums may be either payload of `Result<T, E>`;
returning `Result::err(Status::Paused)` remains a typed recoverable outcome.
Ordinary variants reject `#[message(...)]` and never enter the rejection catalogue.

## Errors and requirements

Seiyaku and reusable modules declare payloadless nominal `error enum` types.
Each variant declares an explicit nonzero `u32` code, unique within that enum;
different enums may use the same codes. The type identity binds the locked
package, source unit, and enum name. The variant schema is hashed separately;
link order never determines identity. Exported errors and structs resolve through
the locked module graph. The signed interface includes the complete descriptors.

`require(condition, error)` takes both arguments positionally (or labelled) and aborts with
that exact nominal error value. `Option.expect(error)` and `Result.expect(error)` use the same rejection
identity and returns the contained value without a placeholder or sentinel. Rejections preserve the error identity, variant
schema hash and code, as well as the originating contract and symbolic variant,
through nested calls and rollback. A wrong identity, schema or undeclared code
rejects. Free-form failure strings are not part of the release contract.

An externally invoked function returning an outer `Result<T, E>` commits its
effects only on `Result::ok`. Returning `Result::err` rolls back that invocation's
state and ledger effects, including effects of successful calls it made, and
returns the error value to its caller. The caller may handle that value and
continue. A Result nested inside another returned value remains ordinary data.
Private helper returns have no independent transaction boundary. `require`
rejection or a VM fault instead aborts execution and propagates through callers.
Rollback retains consumed gas and reads that selected a recoverable error; it
never consumes a pending lifecycle transition. Local tests, debug execution,
simulation, and deployed calls use these same rules.

An imported contract interface comes from an admitted `.to` artifact in the
owning source inventory: `import seiyaku "./pool.to" as Pool;`. The compiler never
fetches an interface from the network. `Pool::at(address: address)` binds that
interface to a canonical contract-address byte string. The resulting opaque
reference exposes only the imported contract's public `view` and `kotoage`
methods, for example `pool.quote(amount: amount)`. Every argument requires
its declared name and exact nominal type. The receiver and argument expressions
run once in written order; the compiler arranges their values in declaration
order for the shared typed argument table. The host checks the destination's
active code hash against the imported artifact before entering it, and returns
through the shared typed result table. Lifecycle hooks are unavailable as methods.
A view may call an imported view; it cannot call an imported kotoage, including
through a private helper. References are private values and cannot appear in a
public interface, durable state, native JSON, a List, or a sum payload.

Own-unit public types are available as `Pool::Payload` and `Pool::Status`.
Module-owned public types use `Pool::Module::Type` when that path is unambiguous.
Their canonical identity always retains the declaring unit, package and locked
revision. If two imported identities have the same display path, neither receives
that ambiguous short binding. Bind the exact identity explicitly, for example
`import type "data@1.0.0::Data::Status" from Pool as OldStatus;`. The identity must
occur in that contract's public argument or return schemas; matching fields or
variant codes do not substitute for nominal identity. Explicit type aliases must
be unique in their owning source unit.

Nested seiyaku calls share the current invocation's durable-state overlay.
Ledger instructions remain queued until root execution succeeds and are not
applied to the ledger query snapshot during nested execution. The immediate
caller is the calling seiyaku's subject account, so nested authorization never
inherits the original transaction signer's permissions. An address already active
on the invocation stack cannot be entered again, including through a view or
another seiyaku; the call is rejected before the callee runs. At most 32 nested
calls are permitted. A later call to an address whose previous call has completed
is permitted. These rules are unconditional in V1.

```kotodama
seiyaku Vault {
    permission CanDeposit;
    error enum VaultError {
        ZeroDeposit = 1,
        NotReady = 2,
    }

    state int balance;

    hajimari() {
        balance = 0;
    }

    kotoage fn deposit(int amount) authorize(CanDeposit) {
        require(amount > 0, VaultError::ZeroDeposit);
        balance = balance + amount;
    }

    view fn ready() authorize(anyone) -> bool {
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
Tests therefore live in a standalone module, conventionally
`tests/<name>.test.ko`, that names the seiyaku under test:

```kotodama bundle
// file: tests/vault.test.ko
module VaultTests {
    koto_test { target: "../contracts/vault.ko" }

    fixture tellers {
        actor("alice");
        grant_seiyaku_permission("alice", "Teller");
        grant_seiyaku_lifecycle_permission("alice", "hajimari");
    }

    #[test(fixture = "tellers")]
    fn withdraw_reduces_balance() {
        test::invoke_kotoage_as(actor: "alice", kotoage: "hajimari", arguments: {});
        let left = test::invoke_kotoage_as(
            actor: "alice",
            kotoage: "withdraw",
            arguments: {amount: 30},
        );
        test::assert_eq(actual: left, expected: 70, message: "withdraw returns the new balance");
    }
}
// file: contracts/vault.ko
seiyaku Vault {
    permission Teller;
    error enum VaultError { Insufficient = 1 }
    state int balance;

    hajimari() { balance = 100; }

    kotoage fn withdraw(int amount) authorize(Teller) -> int {
        require(amount > 0 && amount <= balance, VaultError::Insufficient);
        balance = balance - amount;
        return balance;
    }
}
```

A standalone test module may declare only private functions, `#[test]`
functions, structs, error enums, constants, and fixtures. `test::` builtins are
available in `#[test]` functions and in the module's private helpers, which never
reach a deployable artifact; a private helper of the seiyaku itself cannot call
them. `koto check` checks a `koto_test` module in test mode against its target
instead of rejecting it.

The `koto test` driver is the explicit test-mode boundary. It compiles the full
suite in test mode, then derives a test-free runtime seiyaku when the target has
an invocable public or lifecycle declaration. A pure unit-test target containing
only private helpers and `#[test]` functions needs no runtime artifact; its
tests, coverage, and trace data run from the test projection. This runner-only
derivation is not available to ordinary production builds. The two projections
retain separate immutable prepared artifacts, compiler reports, and code hashes.
The test projection is a generic IVM 1.1 harness without deployable `CNTR` or
`DBG1` sections. Its compiler-owned interface is carried beside the immutable
image, checked against the current ABI hash, and structurally validates the
terminal `HALT` through the reserved `__koto_test_return` descriptor. Production
admission accepts only IVM 1.1 contracts with an embedded interface, and rejects
both the generic test profile and that selector. Host-private
`0x00FE0001..=0x00FE000A` helpers require the crate-private test loader plus an
explicit host opt-in (the runner supplies `KotoTestHost`), remain outside ABI v1
and its hash, and cannot be enabled by public VM loaders or a permissive custom
host.

### Assertions

`test::assert(condition, message:)` takes a `bool` and an optional `string` or
`int` message. `test::assert_eq(actual:, expected:, message:)` accepts any two
values of one equality-comparable type under the same rules as `==`, including
`decimal`, `quantity`, identifiers, `Option`, `Result`, bounded `List`, tuples,
and structs; an unsuffixed numeric literal takes the other operand's numeric
type. Test-mode lowering embeds a canonical `kotodama_lang::testing::AssertionSite`
record (source identity, byte range, literal message, compared type) and, only
on failure, passes it with both values encoded as canonical state-value records
and their schema to the host-private assertion helper `0x00FE0006`. The runner
reports the exact `file:line:column`, the asserted source text, the message, and
the actual and expected values in Kotodama literal syntax; an `AccountId` equal
to a fixture actor is annotated with the actor's name.

### Seiyaku calls and lifecycle

`test::invoke_kotoage(kotoage:, arguments:)` calls a kotoage, view, or lifecycle
declaration as the current caller; `test::invoke_kotoage_as(actor:, ...)` calls
it as a fixture actor. Calls use the production runtime artifact and the
canonical argument boundary. `arguments` is a closed typed record, for example
`arguments: { amount: 30, status: Status::Active }`; `{}` selects a target with
no parameters. Field names and exact nominal types are checked against the target
at compile time. Field shorthand (`{ amount }`) is allowed. Missing, duplicate,
unknown, or wrongly typed fields are errors; JSON payloads are not accepted.
Expressions run once in source order, then their captured values are arranged
in declared parameter order. The host captures that table with the shared
canonical public-value collector and constructs the signed-schema argument
record, including nested structs, enums, `Option`, `Result`, and bounded lists.
No JSON conversion sits between the test and its target.

The private invocation syscall uses r10 for the optional fixture actor, r11 for
the target selector, r12/r13 for argument table base/word count, and r14/r15 for
result table base/word count. A zero-parameter target requires a zero base and
zero words. Native events use the same declared event schema and value capture
as production; the harness retains local diagnostic events with no chain
provenance. Failed calls and returned `Err` discard their events and state.

The harness models the seiyaku lifecycle. When the target declares
`hajimari`/`始まり`, every other call and view is rejected as a lifecycle
violation until the test invokes `hajimari`, and a second `hajimari` call is
rejected as a replay. Lifecycle declarations are selected as `"hajimari"` and
`"kaizen"` whichever spelling declared them, as in the signed interface; a
selector written as `"始まり"` or `"改善"` is rejected with that hint. The
harness stages an actual in-place replacement only when its fixture uses
`upgrade_from("previous.to")`. Without that action no `kaizen`/`改善` transition
is pending, so calling `kaizen` is rejected. A failed migration retains the
pending transition and rolls back its state changes; a successful migration
must initialize every added scalar state field. Durable state read directly by
a test before `hajimari` is uninitialized.

`test::set_block_height(height:)`, `test::advance_blocks(count:)`, and
`test::set_transaction_time_ms(time_ms:)` change the block height and
transaction time that later seiyaku calls observe through
`context::block_height()` and `context::transaction_time_ms()`. They use
host-private helpers `0x00FE0007`, `0x00FE0008`, and `0x00FE0009` and exist only
in test mode.

### Fixtures

```ebnf
fixture-decl   = "fixture" identifier "{" fixture-action* "}" ;
fixture-action = identifier "(" (expression ("," expression)* ","?)? ")" ";"? ;
```

`#[test(fixture = "name")]` applies a fixture's actions, in order, to a fresh
world before the test runs. Wherever an action takes an account, it accepts a
declared actor alias such as `"alice"`, the string `"seiyaku_subject"` for the
seiyaku's own account, or `AccountId::parse("...")`. Numeric arguments accept
literals, `const` names, and `+`, `-`, `*` over them. Typed fixture values use
the same constructors as seiyaku code, including `AccountId::parse`,
`AssetDefinitionId::parse`, `DomainId::parse`, `Name::parse`, and
`Json::parse`; flat fixture-only constructor aliases are errors. A failing
action is reported at its `file:line:column`, and an unknown fixture at the
test that names it; misspelt fixture, action, and actor names suggest the
closest declared one.

Tests refer to actors by alias. `test::actor_account(actor:)` returns an
actor's `AccountId` for assertions and argument records,
`test::actor_public_key(actor:)` its Ed25519 public key, and
`test::actor_sign(actor:, payload:)` an Ed25519 signature over `payload` by an
actor whose key is known (a derived actor, or one declared with a seed).

| Action | Effect |
| --- | --- |
| `actor(alias)` | Declare an actor whose Ed25519 key is derived deterministically from the alias and the chain discriminant. |
| `actor(alias, account[, seed])` | Declare an actor bound to an explicit account; a 32-byte `"0x..."` seed must derive that account and enables signing. |
| `caller(account)` | Make `account` the current caller of `test::invoke_kotoage`. |
| `register_account(account)` | Register an account. |
| `register_account_alias(alias, account[, dataspace])` | Bind an account alias. |
| `register_domain(domain)` | Register a domain. |
| `register_asset_definition(asset_definition[, mintability])` | Register an asset definition (`"infinitely"`, `"once"`, or `"not"`). |
| `set_balance(account, asset_definition, amount)` | Register the asset definition if needed and mint `amount`. |
| `set_account_metadata(account, key, value)` | Set one account metadata entry. |
| `grant_permission([account,] permission)` | Grant a permission token to `account`, or to the current caller. |
| `grant_seiyaku_permission(account, permission)` | Grant one declared instance-scoped role of this seiyaku. |
| `grant_seiyaku_lifecycle_permission(account, hook)` | Grant `CanInvokeContractEntrypoint` for one declared runtime lifecycle hook of this seiyaku. |
| `grant_seiyaku_effect_permission(permission)` | Grant a permission to the seiyaku's own account. |
| `grant_seiyaku_transfer_effect_permission(account, asset_definition, dataspace)` | Let the seiyaku transfer `account`'s balance of `asset_definition`. |
| `state_set(path, value)` | Seed one durable-state value directly. |
| `upgrade_from("previous.to")` | Capture an admitted prior artifact, validate seeded old state and stage replacement by the current target at the same address. Initialize old scalar state with `state_set` before this action; invoke the current `kaizen` to complete migration. |
| `vrf_epoch_seed(epoch, seed)` | Seed one exact unsigned 64-bit epoch with a 32-byte literal or hex string in this diagnostic fixture. Missing epochs remain `Option::none()`; no latest-epoch fallback. |
| `public_input(name, value)` | Provide a named public input to every call. |

`grant_seiyaku_permission` resolves a declared instance-scoped permission name.
Generic `grant_permission` names explicit chain markers or effect permissions:
`read_assets:<account>`, `add_signatory:<account>`, `remove_signatory:<account>`,
`set_account_quorum:<account>`, `set_account_metadata:<account>`,
`mint_asset:<asset_definition>`, `burn_asset:<asset_definition>`,
`transfer_asset:<asset_definition>`, and `register_zk_asset:<asset_definition>`,
or a typed `Json::parse` permission object.

### Reports

Each test result names the test's own file and `line:column`, the execution gas
of the code under test (the seiyaku calls it made, or the test itself for a pure
unit-test target; transaction admission fees are excluded), and its cycles; the
JSON report also lists every seiyaku call with its gas and cycles, and the JUnit
report records gas and cycles as test-case properties. `koto test run
--gas-report` adds a per-kotoage table of calls and minimum, mean, and maximum
gas. A failure has one kind: assertion, seiyaku call rejected (nominal error
enum and variant), permission denied, numeric fault (named by its
`kotodama::NumericError` variant), out of gas, invalid argument tables (host-boundary failures),
decode error, lifecycle violation,
unexpected outcome of `test::expect_reject_as`, test harness error, or another
VM trap. A failing `test::` helper call (a seiyaku call, a rejection
expectation, or an actor lookup) is reported at the call's own
`file:line:column` with its source text: test-mode lowering passes a canonical
`kotodama_lang::testing::TestCallSite` record to the host-private helper
`0x00FE000A` immediately before the call. Failures inside seiyaku calls also
name the seiyaku function and its declaration location. `koto test` exits with
status `11` when at least one test failed.

`koto test coverage` reports which functions of the seiyaku under test executed
and how many instructions each executed across the selected tests, counting only
seiyaku execution (the nested calls, or the test projection of a pure unit-test
target). A declared function that the compiler inlined into its callers or
omitted as unused has no code of its own; it is listed as such and never counted
as covered. `koto test trace` prints every executed instruction,
grouped into the test function and each seiyaku call, with the function and
its declaration location and only the registers the instruction changed;
`--format json` emits one object per instruction.

## Namespaced host API

Source code uses namespaced capabilities. Representative roots are:

- `context::authority`, `context::block_height`,
  `context::transaction_time_ms`, and other immutable call context
- `context::seiyaku_subject`, `context::seiyaku_address`, and
  `context::kotoage` for the branded execution identity and selected public or
  lifecycle declaration
- `ledger::asset::register`, `ledger::asset::transfer`, `ledger::asset::mint`,
  and `ledger::asset::burn`
- `ledger::account::set_metadata` and `ledger::nft::set_metadata`
- `ledger::role::register`, `ledger::role::unregister`, `ledger::role::grant`,
  and `ledger::role::revoke`
- `ledger::query::seiyaku_manifest` and `ledger::query::seiyaku_instance`
- `ledger::seiyaku::grant_permission` and
  `ledger::seiyaku::revoke_permission` for the current immutable seiyaku address
  and a declared instance-scoped permission
- `state::get`, `state::set`, `state::delete`, and `state::contains`
- `bytes::len(value)` for the exact payload length of a first-class `bytes`
  value; it does not accept `Json`, IDs, strings, or generic pointer-ABI values
- `crypto::sha256`, `crypto::sha3`, `crypto::verify_signature`,
  `crypto::sm2::verify`, and proof operations
- `math::wrapping_add`, `math::wrapping_sub`, `math::wrapping_mul`, and
  `math::wrapping_neg` for explicitly modular 512-bit integer arithmetic
- `debug::info` for diagnostics
- `test::assert`, `test::assert_eq`, `test::invoke_kotoage`, and
  `test::invoke_kotoage_as` in test builds only

Flat aliases are errors. Allocation, heap growth, raw pointers, direct syscall variants, opaque instruction submission, and compiler `*_direct` helpers are not source APIs. In particular, `tlv_len` and `codec::tlv_len` remain internal; source uses only the typed `bytes::len`. The canonical builtin registry defines each capability's signature, effect, syscall, access behavior, gas class, permitted execution modes, and call policy.

### Typed value and text utilities

`codec::encode(value)` returns bytes containing the canonical framed Norito
`EntrypointReturnRecordV1` for the value's exact public schema. It accepts typed
records, tuples, enums, Options, Results, bounded Lists, Json and public scalar
values. Execution-local secrets, imported contract references, state handles
and cursors are rejected recursively. Encoding evaluates the value once and
uses the same funded capture as calls and events.

`bytes::concat(left, right)` concatenates byte sequences. `string::concat(left,
right)` concatenates UTF-8 strings. `string::len(value)` counts UTF-8 bytes;
`string::as_bytes(value)` exposes those exact bytes. `string::from_bytes(value)`
returns `Option<string>` and returns `None` for invalid UTF-8. These functions
are metered and bounded by the host's allocation limits.

`string::from(value)` accepts only `bool`, `int`, `decimal`, `quantity`, `string`
and `Name`, using their canonical textual representation. Identity types use
`codec::encode` for deterministic bytes; pure formatting does not consult
network address configuration.

### Private receiver helpers

A private function can be called as `receiver.helper(...)` when its first
parameter has the receiver's exact type. The normal call-boundary widening from
`List<T, N>` to `List<T, M>` also applies when `N < M`. That first parameter is
supplied by the receiver; remaining arguments follow the function's declared
labels. A matching private helper takes precedence over a builtin method of the
same name. A helper whose first parameter does not accept the receiver leaves
the builtin method available. Imported contract members always use their
admitted interface. The receiver and remaining arguments evaluate once, in
source order.

`crypto::vrf::epoch_seed(epoch: int) -> Option<bytes>` reads only the requested
epoch. A present result contains exactly 32 bytes; an unavailable epoch returns
`None`. Negative epochs and values above `u64::MAX` fail the checked host
boundary. There is no implicit latest-epoch fallback or encoded request payload.

### Argument labels

Every builtin call follows one rule, published by the registry's call policy:

1. A label equal to the declared parameter name is always accepted.
2. Single-argument calls, receiver methods (`map.get_or_insert(key, 0)`,
   `xs.set(0, value)`, `amount.div_round(divisor, 2, Rounding::floor)`) and pure
   helpers (`math::*`, `require`, the numeric conversions) also accept
   positional arguments.
3. Every other builtin requires its labels. This covers each multi-argument
   `ledger::*` mutation, where same-typed arguments such as `source` and
   `destination` must not be swapped silently, and helpers with several inputs
   of one type such as `crypto::verify_signature` and `state::set`.

A bare identifier spelled exactly like the label of the slot it fills
satisfies that label: `ledger::nft::mint(nft, owner)` is the call
`ledger::nft::mint(nft: nft, owner: owner)`, while `ledger::nft::mint(owner,
nft)` is rejected. A punned identifier is written without `:`, so like any
positional argument it must precede the first `label: value` argument. Punning
is pure syntax; it produces the same typed call and never changes an interface
fingerprint. A rejected positional argument reports
`E_NAMED_ARGUMENTS_REQUIRED` with the fully labelled call as a fix-it.

<!-- BEGIN GENERATED: kotodama-v1-builtin-call-policy -->
| Builtin | Required labels |
| --- | --- |
| `axt::touch` | `dataspace:`, `manifest:` |
| `crypto::sm2::verify` | `message:`, `signature:`, `public_key:`, `distid:` (optional) |
| `crypto::sm4_ccm::open` | `key:`, `nonce:`, `aad:`, `payload:`, `tag_length:` (optional) |
| `crypto::sm4_ccm::seal` | `key:`, `nonce:`, `aad:`, `payload:`, `tag_length:` (optional) |
| `crypto::sm4_gcm::open` | `key:`, `nonce:`, `aad:`, `payload:` |
| `crypto::sm4_gcm::seal` | `key:`, `nonce:`, `aad:`, `payload:` |
| `crypto::valcom` | `left:`, `right:` |
| `crypto::verify_signature` | `message:`, `signature:`, `public_key:`, `scheme:` |
| `json::set_account_id` | `object:`, `key:`, `value:` |
| `ledger::account::add_signatory` | `account:`, `signatory:` |
| `ledger::account::recovery::approve` | `alias:`, `request_generation:` |
| `ledger::account::recovery::cancel` | `alias:`, `request_generation:` |
| `ledger::account::recovery::finalize` | `alias:`, `request_generation:` |
| `ledger::account::recovery::propose` | `alias:`, `replacement:`, `request_generation:` |
| `ledger::account::remove_signatory` | `account:`, `signatory:` |
| `ledger::account::set_metadata` | `account:`, `key:`, `value:` |
| `ledger::account::set_quorum` | `account:`, `quorum:` |
| `ledger::asset::balance` | `account:`, `asset_definition:` |
| `ledger::asset::burn` | `account:`, `asset_definition:`, `amount:` |
| `ledger::asset::mint` | `account:`, `asset_definition:`, `amount:` |
| `ledger::asset::register` | `asset_definition:`, `name:`, `spec:`, `mintable:` |
| `ledger::asset::set_holding_limit` | `account:`, `asset_definition:`, `limit:` |
| `ledger::asset::set_transfer_availability` | `account:`, `asset_definition:`, `expected_revision:`, `incoming:`, `outgoing:`, `reason:` |
| `ledger::asset::set_transfer_daily_limit` | `account:`, `asset_definition:`, `cap:` |
| `ledger::asset::transfer` | `source:`, `destination:`, `asset_definition:`, `amount:`, `dataspace:` (optional) |
| `ledger::domain::transfer` | `source:`, `domain:`, `destination:` |
| `ledger::escrow::open_dispute` | `offer:`, `evidence:` (optional) |
| `ledger::escrow::open_offer` | `offer:`, `asset_definition:`, `amount:`, `evidence:` (optional) |
| `ledger::escrow::resolve_dispute` | `offer:`, `buyer_amount:`, `seller_amount:`, `evidence:` (optional) |
| `ledger::governance::build_submit_ballot` | `election_id:`, `ciphertext:`, `nullifier:`, `backend:`, `proof:`, `verification_key:` |
| `ledger::nft::mint` | `nft:`, `owner:` |
| `ledger::nft::set_metadata` | `nft:`, `key:`, `value:` |
| `ledger::nft::transfer` | `source:`, `nft:`, `destination:` |
| `ledger::permission::grant` | `account:`, `permission:` |
| `ledger::permission::revoke` | `account:`, `permission:` |
| `ledger::query::accounts` | `offset:`, `limit:` |
| `ledger::query::asset_definitions` | `offset:`, `limit:` |
| `ledger::query::assets` | `offset:`, `limit:` |
| `ledger::query::assets_of` | `account:`, `offset:`, `limit:` |
| `ledger::query::domains` | `offset:`, `limit:` |
| `ledger::query::nfts` | `offset:`, `limit:` |
| `ledger::role::grant` | `account:`, `role:` |
| `ledger::role::register` | `role:`, `permissions:` |
| `ledger::role::revoke` | `account:`, `role:` |
| `ledger::seiyaku::grant_permission` | `account:`, `permission:` |
| `ledger::seiyaku::revoke_permission` | `account:`, `permission:` |
| `ledger::trigger::set_enabled` | `trigger:`, `enabled:` |
| `state::set` | `path:`, `value:` |
<!-- END GENERATED: kotodama-v1-builtin-call-policy -->

### Assets

`ledger::asset::register(asset_definition:, name:, spec:, mintable:)` registers
exactly the definition it names. `name` is the human-readable display name;
`spec` is the data model's numeric spec, written with its constructors
`NumericSpec::unconstrained()`, `NumericSpec::integer()`, or
`NumericSpec::fractional(scale)` with a constant scale in `0..=28`; `mintable`
is one variant of the data model's `Mintable` enum: `Mintable::Infinitely`,
`Mintable::Once`, `Mintable::Not`, or `Mintable::Limited(tokens)` with a
constant positive token budget. Like `ListError::IndexOutOfBounds`, the
compiler-owned `Mintable` and `SignatureScheme` enums write payloadless
variants as paths and the payload variant as a call. These are compile-time
values written directly at the call: integers, runtime values, and a value used
anywhere else are `E_NOMINAL_ARGUMENT`, and `NumericSpec`, `Mintable`, and
`SignatureScheme` cannot be declared as source names. Registration never
mints: issue the initial supply with `ledger::asset::mint` afterwards.

```kotodama
seiyaku RoseIssuer {
    permission RegisterAssetDefinition;
    kotoage fn issue(AssetDefinitionId rose, AccountId treasury) authorize(RegisterAssetDefinition) {
        ledger::asset::register(
            asset_definition: rose,
            name: "Rose",
            spec: NumericSpec::fractional(2),
            mintable: Mintable::Once,
        );
        ledger::asset::mint(account: treasury, asset_definition: rose, amount: 1000);
    }
}
```

`ledger::asset::transfer(source:, destination:, asset_definition:, amount:)`
moves a globally scoped balance. The optional trailing `dataspace:` argument
selects the balance bucket of a dataspace-restricted definition. A restricted
definition transferred without `dataspace:` is rejected by the host; it never
falls back to an ambient or universal dataspace, and a global definition
ignores a supplied dataspace. `DataSpaceId::parse` takes the decimal dataspace
number, for example `DataSpaceId::parse("7")`.

### Typed flags, schemes and selectors

Flags are `bool` (`ledger::trigger::set_enabled(trigger:, enabled: true)`).
`crypto::verify_signature(message:, signature:, public_key:, scheme:)` takes a
compile-time `SignatureScheme::Ed25519`, `SignatureScheme::Secp256k1`, or
`SignatureScheme::MlDsa`, which the compiler maps to the host's scheme codes
`1`, `2`, and `3`; an integer or any other value is `E_NOMINAL_ARGUMENT`, so an
unknown scheme cannot be expressed. SM2 keeps its own verifier,
`crypto::sm2::verify`, because it takes an optional distinguishing identifier.
The `permission:` argument of
`ledger::seiyaku::grant_permission`/`revoke_permission` is a declared permission
identifier, such as `Admin`, resolved at compile time. It must name an
instance-scoped declaration in the current seiyaku or its `include` fragments;
unknown names and imported shared chain permissions are rejected. Reusable
modules cannot declare or export instance permission authority. These operations
use a canonical `Name` pointer and bind the grant to the executing contract
address. Runtime lifecycle dispatch uses its separate exact-selector token.

### Call context

`context::authority()` is the immediate caller. For a top-level transaction or
trigger call it is the transaction or trigger authority; inside a seiyaku
called by another seiyaku it is the calling seiyaku's subject account
(`context::seiyaku_subject()` of the caller), never the original signer.
`context::seiyaku_subject()` is the executing seiyaku's own account.
`context::seiyaku_address()` returns the canonical address literal as UTF-8
`bytes`, the same representation accepted by an imported seiyaku's `at(address:)`.

`context::transaction_time_ms()` is the logical execution time. For a
transaction call it is the signed transaction's creation time, which the
signer chooses within the node's admission tolerance; do not treat it as an
independent clock for deadlines that the signer must not influence. Trigger
calls receive the block-header creation time. Test hosts use an explicitly
configured value that defaults to `0`. No host reads wall-clock time, and
there is no separate block clock for transaction calls because the enclosing
block is not finalized while they execute. `context::block_height()` is the
height of the block being built.

### Diagnostics

`debug::info(value)` is diagnostics only. It has no ledger or durable-state
effect, so views and the helpers they call may log. Hosts charge its gas and
record the value only in development and test builds; release nodes discard it
deterministically.

### Reserved names

Only names that source can refer to are reserved for declarations. Compiler
lowering names such as `min`, `authority`, `chain_id` or `mint_asset` are not
source names. Private helpers and public selectors may use them. Typed calls
retain distinct user-function, builtin and compiler-intrinsic identities, so
`fn min(...)` and `math::min(...)` remain different operations. Method spellings
such as `expect` and `is_some` may also name ordinary private helpers; method
calls resolve through their receiver. The compile-time value types `NumericSpec`,
`Mintable`, and `SignatureScheme` are reserved like other compiler-owned type
names.

`math::min(left, right)` and `math::max(left, right)` accept identical `int`,
`decimal`, or `quantity` operand types and return that same type. `math::abs(value)`
also preserves the numeric type; quantities are already non-negative. Operands
evaluate once in source order, including labelled arguments. Numeric kinds are
not mixed implicitly.

`math::isqrt(value)`, `math::div_ceil(dividend, divisor)`, `math::gcd(left, right)`
and `math::mean(left, right)` remain integer-only over the complete signed
512-bit domain. `mean` does not introduce an implicit decimal rounding rule.
Compiler folding and runtime integer syscalls share the primitive algorithms.
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

`koto` compiles and inspects explicit standalone sources. `musubi` owns project
configuration, locked package resolution, and project-wide commands through
`Musubi.toml` and `Musubi.lock`:

```text
koto check seiyaku.ko
musubi check --manifest-path Musubi.toml
koto build seiyaku.ko --max-cycles 1000000
musubi build --manifest-path Musubi.toml
koto build --format sarif seiyaku.ko
koto check --zk proof_seiyaku.ko
koto build --zk proof_seiyaku.ko
koto test seiyaku.test.ko
koto test run --gas-report --junit report.xml seiyaku.test.ko
koto test list --format json seiyaku.test.ko
koto test coverage seiyaku.test.ko
koto test trace --filter withdraw seiyaku.test.ko
koto fmt seiyaku.ko
koto fmt --check .
koto doc seiyaku.ko
koto explain K0001
koto explain unused-parameter
koto explain 言挙げ
koto explain --list
musubi lsp --manifest-path Musubi.toml
musubi lsp --manifest-path Musubi.toml --contract treasury --zk
koto lsp --source-root contracts
```

Every subcommand prints its options with `--help`/`-h`; `koto --version` prints
the toolchain version, the `kotodama_lang` compiler fingerprint, the IVM
bytecode target, and the ABI v1 hash. Options are spelled the same way on every
subcommand: `--format`, `--source-root`, `--chain-discriminant`
(the account-address chain discriminant of the target network: `AccountId`
literals must be encoded for it and `koto test` derives fixture actors from it;
it defaults to `753`), and `--zk`. Unknown options print
the subcommand's usage. The exit status follows `musubi`: `0` success, `2`
usage error, `8` compiler diagnostics, formatting drift, or a `--verify`
mismatch, `10` a file that cannot be read or written, `11` a test suite that
ran with at least one failing test, and `70` an internal toolchain error. `koto check` checks a `koto_test` module in test mode
against its target. `koto fmt` accepts files and directories; a directory is
searched recursively for `*.ko` files, skipping hidden and `target`
directories, and the default is the current directory. `koto explain` accepts a
diagnostic code, a lint name, or a branded keyword in either spelling and prints
the registered summary, help, worked examples when registered, and the
specification section; `--format markdown` renders a reference page with one
anchor per code. `koto doc` renders each public declaration in source syntax
with its authorization, an example JSON argument record, and access analysis,
and lists compiler-owned list and numeric errors separately from the seiyaku's
own error enums.

`--zk` is an explicit build capability, not source metadata. It is required for
`Secret<T>` and the approved proof/commitment operations; ordinary builds reject
those constructs. `koto check|build|doc|lsp` and `musubi check|build|test|lsp --zk` pass this policy to the same in-process compiler session.
It does not make ABI, vector, or pointer policy selectable.

`koto fmt` and LSP formatting consume the compiler's lossless token stream and
the parser's syntax roles. They refuse syntactically invalid input, preserve
comments and literal spelling, and keep each branded keyword in the script
written at that site. A comment that follows a token on the same line stays a
trailing comment of that token: a line comment follows any `,` or `;` that ends
the token's member or statement, while a block comment on that line stays ahead
of it (`amount /* in nanos */, fee`). A block comment that leads code on its
line stays with that code, and an attribute stays on its own line above the
item or error variant it annotates. Formatting canonicalizes four-space
indentation, declaration spacing, operators, and block layout with a
100-column target: an argument list, parameter list, tuple or list literal
that does not fit is laid out one item per line, a declaration head breaks its
parameter list first and keeps `authorize(Role) -> T` together, and a
statement or condition that still does not fit breaks before its
lowest-precedence top-level operators, or, when it has none, before each call
of a method chain with two or more calls; a continuation line that still does
not fit breaks again before its own lowest-precedence operators, one level
deeper. A statement with no other break point
moves its value onto a continuation line after `=` or `=>`, and a line break
forced by a comment inside a statement continues it one level deeper. Struct fields, error variants and
`match` arms, and struct literals and JSON objects with more than one member,
are laid out one member per line, while a struct pattern stays on one line
whenever it fits; struct fields, error variants and `koto_test` entries are
separated by `,`, and trigger fields and fixture actions end with `;` unless
they end with a block (`on data ... { ... }`, `metadata { ... }`), which takes
none, so each field and action starts its own line. A comma-delimited
construct laid out over multiple lines has a trailing comma (tuples excepted)
and a single-line one has none. At most one blank line between members or
declarations is kept, and parentheses around a whole `if` condition are
removed. Formatting is deterministic and idempotent, and fails rather than
producing a source larger than the mandatory 1 MiB limit. `koto fmt --check`
performs no writes.
LSP validation analyzes reusable `module Name` files without artifact generation.
`musubi lsp --manifest-path Musubi.toml` resolves the same authenticated package
graph as project builds and tests. Open source and editable local manifest
buffers overlay their corresponding files; unopened sources come from the
resolved graph. Locked dependency exports stay read-only. Diagnostics retain
the target and package identities when a module participates in several graphs.
Navigation requires a unique graph or explicit `--contract` selection; a bare
name must be unique, while `namespace/package::target` identifies a target
unambiguously. The server never picks the first package identity arbitrarily.

`koto lsp --source-root <dir>` handles standalone sources. Each open seiyaku is
validated with its declared `include` and `import` closure, as `koto check`
does. The set of open documents never establishes imports or exports. Positional
`koto check` accepts a single seiyaku root and its local closure, or reusable
modules checked independently; multiple roots or a root mixed with unrelated
modules fail with explicit diagnostics. Package imports and exported package
APIs belong in `Musubi.toml`, resolved through Musubi. There is no second JSON
project format. Multi-source diagnostic output is one deterministic JSON or
SARIF document. LSP framing, individual documents, open-document count, and
aggregate retained text have explicit bounds; rejected updates are not retained
as stale formatter input.

The compiler-owned `EditorSnapshot` retains source/package identities, resolved
symbols and lexical bindings, exact argument-label ranges, typed expression
facts, and canonical callable signatures. LSP completion filters by source,
scope, explicit import/export graph, and receiver type, and by syntactic
position: a file's top level offers only `seiyaku`/`誓約` and `module`; a
source-unit body offers declarations (`fn`, `view fn`, `kotoage fn`/`言挙げ fn`,
`hajimari`/`始まり`, `kaizen`/`改善`, `state`, `const`, `struct`, `error enum`,
`permission`, `import permission`,
`trigger`, `include`, `import`, and `export` in modules); a function body
offers statements, visible locals, callable private functions, types, and
builtins. Runtime functions are never offered as callees. Both spellings of a
branded keyword are always offered as adjacent items, the Japanese item also
filters on the romanized spelling, and neither script is preferred. Argument
templates use the declaration's positional-only prefix and optional named
parameters. Optional receivers offer `ok_or`, `expect`, `unwrap_or`, and presence checks,
including after chained reads such as `Requests.get(id).`, and member
completion works mid-statement (`let x = Scores.`, `require(Scores.`,
`return Scores.`): completion-only recovery also terminates the statement,
closes its open delimiters, or isolates the receiver. Candidates never depend
on the partially typed word, so completion lists are complete. Signatures
retain the extracted payload type. Result receivers offer `or_err`, `expect`, eager extraction, and status methods. Hover,
completion and signature help render declarations in source syntax with the
keyword spelling written at the declaration (`言挙げ fn bump(int delta) authorize(CanBump) -> int`), branded keywords with the shared glossary entry, and
builtins with their registry summary, access class, effects, mode, and call
policy in words. The server also provides the document outline, workspace
symbols, highlights, folding ranges, semantic tokens (one `brandedKeyword` type
for both spellings of every branded keyword), and a "Run test" code lens on each
`#[test]` function whose command arguments are
`koto test run --filter <name> --exact <source>`. A standalone test module with
`koto_test { target: ... }` is checked in compiler test mode against its target,
and its plain `kotoage: "name"` selector strings are references to the target's
`kotoage`/`言挙げ` or `view fn` declaration, so definition, references,
completion, and rename include them; a seiyaku's editor graph attaches the test
modules that target it. Definition,
references, and rename use resolved identities. Rename rechecks the complete
source and export graph and verifies that every reference retains its resolver
identity, preventing capture while allowing names in disjoint scopes. A local
project manifest owns its contained module sources: renaming an export updates
its exact JSON string token together with declarations, references and call labels.
Unrelated strings and import aliases are unchanged. External graphs without local
manifest authority remain immutable. LSP edits include open-document versions,
including unsaved manifest buffers; changed unopened sources or manifests require
a reload. Incomplete graphs cannot produce rename edits; the refusal names the
first blocking diagnostic, and a non-ASCII new name is refused because V1
identifiers are ASCII.
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
combining characters. Locations are shown as `path:line:column` of the span's
start, with the excerpt underlining its extent; complete ranges and exact byte
ranges appear only in JSON and SARIF. Messages render tokens with
their source spelling and echo a branded keyword exactly as written at the
diagnosed site (`言挙げ function ...`), while lists of expected keywords name
both spellings (`` `kotoage`/`言挙げ` ``). A missing terminator such as `;` is
reported at the insertion point after the previous token. Each diagnostic
carries site-specific help; the registry help of its code is a fallback.
Machine-applicable fixes have exact ranges; when more than one replacement is
equally valid, such as the two spellings of a branded keyword, the first is the
preferred fix and the rest are listed as alternatives. Near-miss keyword
suggestions use a bounded edit distance with deterministic tie-breaking; the
same bounded matcher suggests locals, types, functions, struct fields, error
variants, argument labels, and builtins, and unknown argument labels are all
reported together with the callee's declared names. Semantic diagnostics carry
site-specific help: operators are named by their source symbols, expected and
found types are rendered in source syntax, a mismatch on an unannotated local
labels the `let` that inferred its type, and view-purity errors (`K2004`) point
at the offending statement or call with labels along the call chain. Every
violating view is reported. Within one function, a failing statement that
introduces no binding (or an annotated `let`) is skipped so later independent
errors are also reported, up to eight per function; and a function whose body
fails name resolution does not hide type errors in other functions of a
single-file check.
Related locations and help are projected into LSP diagnostics; rendered source
excerpts are not repeated in LSP messages. Code actions are limited to
diagnostics that touch the requested range, have short titles naming the edit,
and offer alternative fixes as non-preferred actions. The `initialize` response
reports `serverInfo` with the `koto` version. JSON and SARIF
retain canonical structured ranges and do not embed source contents. Their
`message` is always the canonical English text; a translation, when the
locale has one, is carried in a separate `localized` object. Human output uses
a translation only when it covers the message and help together, so one
diagnostic never mixes languages. SARIF lists one rule per diagnostic code with
the registry summary and help, and carries fixes in standard `fixes` objects.
Compiler lint locations come from the same parser-owned declaration, binding,
statement, and expression ranges. Warnings from one source share its immutable
text and use the same diagnostic projection in `koto`, LSP, and
`musubi check`, including dependencies that are not open in the editor.

Lints have stable slugs and `K50xx` codes:

| Code | Slug | Finding |
| --- | --- | --- |
| `K5001` | `unused-state` | durable state is never used |
| `K5002` | `state-shadowed` | a declaration shadows durable state |
| `K5003` | `unused-parameter` | a private function parameter is never used |
| `K5004` | `unreachable-return` | a statement follows `return` |
| `K5005` | `duplicate-pointer-literal` | the same typed literal appears more than once in a seiyaku; declare it once as a `const` |
| `K5006` | `unused-pointer-constructor` | a constructed typed value is discarded |
| `K5007` | `nonliteral-trigger-spec` | a trigger specification is not a literal |
| `K5008` | `nonliteral-state-path` | a raw state path is not a literal |
| `K5009` | `opaque-access-hints` | host access the scheduler cannot describe precisely; the transaction is scheduled conservatively |
| `K5010` | `unpersisted-state-copy` | a copy read from a `StateMap` entry or whole state value is changed but never written back |
| `K5011` | `kotoage-without-effects` | a kotoage/言挙げ performs no state, ledger, or host effects and can be a `view fn` |
| `K5012` | `exact-division` | `decimal`/`quantity` `/` by a non-constant divisor, which reverts on non-terminating quotients |
| `K5013` | `unused-local` | a local binding is never read |
| `K5014` | `dead-store` | a stored value is overwritten before it is read |
| `K5015` | `underscore-public-parameter` | a public parameter name starts with `_` and becomes the argument key |
| `K5016` | `never-mutated-var` | a `var` binding is read but never reassigned or mutated; declare it with `let` |
| `K5017` | `unused-private-fn` | a private `fn` that nothing in its seiyaku or module calls (exported module functions and `_`-prefixed names are exempt) |
| `K5018` | `seiyaku-without-entrypoint` | a seiyaku/誓約 declares no kotoage, `view fn`, or lifecycle hook, so nothing can call it |

Effects for `K5011` are computed conservatively: calls to imported functions
count as effects. `K5003` covers private `fn` parameters only, where a leading
`_` keeps an unused parameter deliberately. Parameters of kotoage/言挙げ, view,
and lifecycle declarations are argument keys of the public interface, so they
are never reported as unused and a leading `_` on them only changes the key
(`K5015`). `K5014` does not report a store followed by a `break` or `continue`
before the overwrite, since leaving the loop keeps the first value live.
Fixes never choose a rounding mode or scale for `K5012`; the
help names `div_round`, `ratio_round`, and `mul_div_round`. Each lint has a
level of `allow`, `warn` (the default), or `deny`, configured per slug, and a
deny-warnings mode promotes every warning to an error. A denied finding fails
the check. `koto check` takes repeatable `--allow`, `--warn`, and `--deny <slug>`
flags and `--deny-warnings`. `musubi check|build|test|lsp` read the `[lints]`
table with the same keys from the package's `Musubi.toml` (or the workspace
root's); build, check and test also accept `--deny-warnings`. An unknown slug is an error that
names the closest lint.

The local-only test helper requires
`test::expect_reject_as(actor:, kotoage:, arguments:, expected:)`. The expected
value is a nominal error variant (descriptor identity, schema hash, and enum-local
code) or a compiler-owned `test::Rejection` stage/trap selector. Invocation
permission, argument-schema rejection, and runtime permission are distinct
selectors. The explicitly broad helper is
`test::expect_any_reject_as(actor:, kotoage:, arguments:)`. Both use the existing
private test syscall: r12/r13 carry the typed argument table base and word count;
r14 carries a canonical Norito expectation in a Blob and r15 is zero. Production admission does not enable test syscalls.
Nested execution checkpoints are restored before accepting a rejection or
reporting a mismatch.

`musubi new <directory> [--namespace <namespace>]` creates a contract package
with `Musubi.toml`, a counter seiyaku named after the package (state, `hajimari`,
an authorized `kotoage fn`, a `view fn` and an error enum), four standalone tests
including `test::expect_reject_as`, a README, and ignore rules for `target/`. The
namespace defaults to `local`, which `musubi publish` refuses until the package names
a registry namespace. `musubi check`,
`musubi build`, and `musubi test` consume the package's exact declared source and
dependency graph. Without a selected network binding they compile for the
data-model default account-address profile (SORA, `0x02F1` = 753), the same default
as `koto`; a binding or `--chain-discriminant` selects another profile. Network
bindings select the exact client context and contract alias for deployment and
views. `musubi deploy --activate [--args <JSON>]` checks the arguments against the
hook's schema before signing, then runs the deployed seiyaku's `hajimari`/`始まり`
hook as a recoverable call after the deployment is Applied; without it, `musubi
deploy` prints the exact activation command, with a `<type>` placeholder for each
hook parameter.
`musubi deploy --artifact <file.to> --artifact-manifest <file.manifest.json>`
deploys a prebuilt artifact only when the locked package source reproduces it.
Musubi constructs the compiler's in-memory source graph from these declarations
and the lockfile. That graph carries exact package identities, sources, imports,
and individual exports; it has no separate persisted authoring format.
Unknown or duplicate manifest fields, duplicate sources/exports, path escapes,
unknown packages, import cycles, undeclared aliases and unexported calls fail
closed. Source companions are loaded only through explicit directives and their
canonical ownership boundaries.
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

`koto build --format human|json|sarif` and `musubi check|build|test --format
human|json|sarif` use the same canonical diagnostic bundle; Musubi JSON embeds the
canonical records under `error.diagnostics`, and a failing test exits with
`MUSUBI_E_TEST_FAILED` (status 11) rather than the compiler category. Musubi names
sources of local workspace packages by their workspace-relative path without a
package identity; registry package sources keep their identity. Compilation failures
of `musubi test` preserve the same structured diagnostics, including source spans,
labels and fixes. Typed-module link failures retain those fields through resolution. Imported-call failures point at the exact resolver-owned call
name, and ambiguous exports label every conflicting function declaration.

The test driver supports deterministic discovery and selection:

```text
koto test list tests/seiyaku.test.ko
koto test run --filter exact_test_name --exact --jobs 4 --seed 7 tests/seiyaku.test.ko
koto test run --format json tests/seiyaku.test.ko
koto test run --junit target/kotodama-tests.xml tests/seiyaku.test.ko
koto test run --gas-report tests/seiyaku.test.ko
koto test coverage tests/seiyaku.test.ko
koto test trace --filter exact_test_name tests/seiyaku.test.ko
koto test run --zk tests/zk_seiyaku.test.ko
```

`koto test <source>` is `koto test run <source>`. Without `--source-root`, a
standalone test module's source root is the nearest directory containing both
the module and its `koto_test` target. `--format` selects `human`, `json`, or
`junit` on stdout; `--junit <file>` additionally writes a JUnit report. Every
result names the test's file and `line:column`, its execution gas and cycles;
`--gas-report` adds a per-kotoage table of calls and minimum, mean, and maximum
gas. `coverage` reports which seiyaku functions the selected tests executed,
counting only seiyaku execution. `trace` prints each executed instruction
grouped into the test function and each seiyaku call, with the function, its
declaration location, and the registers the instruction changed (`--format
json` emits one object per instruction).

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

Debug information and source maps are forbidden inside deployable artifacts. They are hash-keyed sidecars whose `artifact_hash` identifies the exact `.to` image. Every native source segment carries its graph-stable `source_id`, logical source path, exact half-open UTF-8 byte range, and the corresponding one-based line and Unicode-scalar column; generated instructions without a source range are identified separately rather than borrowing a neighboring span. The sidecar partitions emitted PC ranges into `source_kind: "statement"` segments and `source_kind: "function"` gaps for generated prologues, epilogues and control transfers. Statement origins survive SSA optimization and helper inlining without changing executable bytes. `koto test trace` and local fault symbolization use these same ranges; function coverage continues to use the complete function intervals.

Nodes validate direct control-flow targets, allowed ABI-v1 syscalls, pointer-ABI types, interface structure, code/ABI hashes, and signed manifest equality. Compiler fingerprints are informational and are not security claims.

## Example

```kotodama
seiyaku Counter {
    permission CanIncrementCounter;
    state int value;

    hajimari() {
        value = 0;
    }

    kotoage fn increment(int delta) authorize(CanIncrementCounter) -> int {
        let int next = value + delta;
        value = next;
        return next;
    }

    view fn current() authorize(anyone) -> int {
        return value;
    }
}
```

The repository documentation check discovers and compiles every tracked
`kotodama` or `ko` code fence and documented `*.ko` heredoc below the roots in
`kotodama_v1_docs.json`. Grammar-derived keyword and operator tables feed
documentation, formatting, syntax highlighting, and LSP completion so those
surfaces cannot define independent dialects.
