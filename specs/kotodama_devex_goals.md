# Kotodama syntax and developer experience completion

This ledger continues the interrupted Kotodama syntax and developer-experience
critique and implementation. It complements [the V1 design](kotodama_v1_redesign.md)
and [VM completion](kotodama_ivm_completion.md); implementation and release
qualification remain separate outcomes.

## Design constraints

- Ship one first-release language and ABI V1. Delete replaced implementations,
  source spellings, flags and decoders instead of adding compatibility paths.
- Preserve `seiyaku`/`誓約`, `kotoage`/`言挙げ`, `hajimari`/`始まり` and
  `kaizen`/`改善`. Each pair denotes one token; freely mixed spellings are valid.
  Formatting preserves the author's spelling and tooling teaches both.
- Design for IVM, deterministic execution and authenticated Iroha state. Test
  controls remain private to the test harness and never become node settings.
- Make authority explicit. Named permissions must be declared and scoped to the
  authenticated contract instance; open entrypoints must opt in explicitly.
- A recoverable `Result::err` at a public mutation boundary rolls back that
  invocation and its descendants while preserving its typed error value and gas
  charges. Calls into an already active contract instance are rejected, including
  views. Ordinary helper functions retain normal value semantics.

## Goals

| ID | Outcome and owner | Completion evidence | State |
| --- | --- | --- | --- |
| KDX1 | Compiler, editor and CLI integration — Kotodama/toolchain | All recovered diagnostic, lint, formatter and editor handoffs reconciled; structured diagnostics survive source resolution and test compilation; typed VM faults retain their tag, program counter, code hash and selector for source symbolization; matching compiler/CLI/LSP regression suites pass. Large-source checks stay within frontend budgets. | Complete |
| KDX2 | One coherent builtin and SDK surface — surface/hosts/SDK | Host behavior matches signatures; labels and typed flags agree across compiler and hosts; cursors round-trip through native JSON; removed APIs have no operational consumers; client arguments and digests use the same canonical schema conversion. | Complete |
| KDX3 | Explicit contract authority — compiler/model/executor | Declared instance-scoped permissions, explicit open access, owner-authorized grants and revocation; typo, cross-instance, confused-deputy and lifecycle tests; no arbitrary string authorization path. | Complete |
| KDX4 | Atomic nested calls — Core/IVM/test harness | Error returns roll back callee and descendant changes; success commits once; active-instance re-entry rejects; gas, nominal errors and caller identity survive every path. Matching production-host and harness tests. | Complete |
| KDX5 | Cohesive language values and calls — compiler/ABI | Plain enums and exhaustive patterns, Option/Result bridges, branded path segments and typed test calls have one documented syntax, complete schemas, deterministic lowering and positive/negative runtime tests. Internal builtin identity no longer reserves private helper names. | Complete |
| KDX6 | Contract interfaces, events and upgrades — compiler/Core | Imported complete artifacts are carried in immutable, package-owned source inventories; typed calls bind the exact live code hash and entrypoint ordinal before effects. Native events preserve signed schemas, invocation provenance, ordered rollback and the original allocation owner through committed Network and callback outputs. Upgrade checks reject incompatible stored schemas and require initialization of new scalar state. No synthetic event provenance or unchecked call path. | Complete |
| KDX7 | Project and test workflow — Musubi/toolchain | One developer-facing project contract and consistent defaults/flags; test failures retain source locations and typed values; lifecycle replacement tests, statement-level traces and documented fixture controls. Replaced project/tooling paths removed. | Complete |
| KDX8 | Authoring material — compiler/docs | Current language tour, branded glossary, generated builtin reference, testing and deploy/grant/activation flow in `iroha-docs`; all examples and documentation fences compile and format. Local source-coupled specifications agree. | Complete |
| KDX9 | Canonical artifacts — compiler/ABI/release | Regenerate source seals, syntax tables, ABI/gas/proof inventories, native capture fixtures and every owned `.to`/manifest through their producers; retired artifacts rejected. | Complete |
| KDX10 | Independent acceptance — integration/release | Adversarial review, affected crate and SDK suites, strict lint and documentation guards, then feasible workspace gates. Four-validator execution and installed native/SDK artifact qualification use the same candidate. Missing external evidence remains explicitly open. | Open |

## Current completion boundary

The compiler, language, authority, call, event, lifecycle, SDK surface and
project-workflow implementation goals are complete against matching component
and API regressions. JavaScript decodes the exact native state-vector envelope,
statement-level source maps and structured diagnostic companions; retired shapes
are rejected. The JavaScript current-compiler fixture is regenerated from
its exact Rust and JavaScript source closure and passes canonical Rust admission.
KDX10 keeps current-candidate native SDK, four-validator, full-workspace and
release-artifact qualification explicit; component results do not close those
gates. Native component test results belong to the candidate's validation record,
not an assertion of release readiness.

The recovered 156 findings include alternatives and judgment calls, rather than
156 literal implementation requirements. The retained authoring choices are:

- Trigger `metadata { key: value; }` entries remain semicolon-terminated, matching
  the trigger statement grammar. They are not another spelling of a JSON literal.
- Leading underscores on public parameter names produce the configurable K5015
  warning. Soracloud's runtime interface still requires `_request_body` and
  `_request_meta`; changing those keys requires one coordinated runtime and
  template change, not a source-only rename.
- `Option.expect`, `Result.expect`, `Option.ok_or` and `Result.or_err` provide
  the explicit error bridges. The pool's rejecting Option match now uses
  `expect` with the same nominal error; it needs no dummy return value or new
  diverging `reject` expression. No general never-typed expression is added.
- StateMap scans use lexicographic canonical encoded-byte order, including tuple
  keys. This order is documented; scanning does not itself emit an ordering lint
  or imply numeric ordering.
- `context::kotoage` and `test::invoke_kotoage(kotoage: ...)` retain the branded
  selector vocabulary for all declared entrypoint kinds. Documentation identifies
  the selected kind explicitly; test selectors are checked at compile time and
  arguments use typed records. Declaration syntax still distinguishes public
  mutations, views and lifecycle hooks.

The general typed contract-call path now joins the compiler, immutable source
inventory, production host and funded harness. The fixed two-quantity and raw
untyped call paths are removed. Statement provenance survives optimization and
inlining independently of executable bytes. Native events flow through committed
outputs; lifecycle fixtures exercise actual artifact replacement and initialization.

The recovered library and binding gaps now have compiler and runtime implementations:
public typed value encoding, byte/string operations, exact optional epoch seeds,
composite map keys, typed client generation and scoped asset queries. Scalar and
tuple map keys use one canonical schema-bound record; cursors bind the complete
key schema. Matching compiler, IVM, Core and API regressions validate allocation ownership,
host gas quotes, canonical values and current compiled artifacts. Installed
native SDK validation remains distinct.

Compiler-side metadata parsing uses the same canonical codecs as manifest
serialization through a focused module boundary. It no longer imports the full
`norito.js` ledger codec module; source-custody checks follow the complete local
parser dependency graph so the generated fixture cannot retain a stale validator.

The canonical compiler and tooling suites, generated source guards and owned
contract artifacts are current. The nine public documentation routes and their
180 translated pages pass compiler, translation, site-build and link checks.
The updated utility and commit/reveal examples are included. ABI, gas, proof
inventories and native compiler captures have been regenerated by their owners;
this establishes artifact consistency, not proof or release qualification.
The production API, cross-contract lifecycle, emitted-event history and diagnostic
regressions pass. KDX10 owns qualification of the affected native SDK artifacts.
Strict component lint is clear for the language, surface, admission and toolchain;
unrelated Musubi publication/deployment and IVM runtime lint findings remain.
Unrelated repository failures remain separate from this language change.
