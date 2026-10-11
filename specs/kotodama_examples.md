# Kotodama V1 examples

These examples use the branded V1 declaration vocabulary. The normative grammar is
[`kotodama_grammar.md`](./kotodama_grammar.md); the canonical syscall and
pointer-ABI tables are in [`ivm_syscalls.md`](./ivm_syscalls.md).

Every deployable `.ko` file contains exactly one named `seiyaku`/`誓約` unit. Reusable
source contains one `module` and is linked at typed HIR before the deployable
artifact is emitted.

## Check and build

Use the unified Rust compiler driver:

```sh
koto check examples/hello/hello.ko
koto build examples/hello/hello.ko \
  --max-cycles 1000000 \
  --out target/examples/hello.to \
  --manifest-out target/examples/hello.manifest.json
```

ABI v1 is unconditional. Source cannot select an ABI, vector width, or
execution feature. `--max-cycles` selects a positive ceiling, up to node
admission policy, that is embedded in the execution header and covered by the
artifact hash.

ZK contracts are checked, built, and documented with `--zk`. The flag selects a
compiler capability; the source still cannot override execution-header metadata.

## State, errors, entries, and views

`hajimari`/`始まり` establishes scalar state. Mutating public calls use
`kotoage fn`/`言挙げ fn` and an explicit caller permission. Read-only calls use
`view fn`; views are public unless they also declare `authorize`.

```kotodama
seiyaku Counter {
    permission CanIncrementCounter;
    error enum CounterError {
        NonPositiveDelta = 1,
    }

    state int value;

    hajimari() {
        value = 0;
    }

    kotoage fn increment(int delta) authorize(CanIncrementCounter) -> int {
        require(delta > 0, CounterError::NonPositiveDelta);
        let int next = value + delta;
        value = next;
        return next;
    }

    view fn current() authorize(anyone) -> int {
        return value;
    }
}
```

Error variants have explicit, stable, non-zero `int` codes. Public failures use
`require(condition, Error::Variant)`; free-form strings are not a seiyaku error
protocol. Arithmetic is checked, so `value + delta` deterministically fails and
reverts if it overflows. Use an explicit `math::wrapping_*` operation only when
modular arithmetic is the intended protocol.

## Record updates without extraction boilerplate

Keep related fields in one record. `get(id).expect(Error::Missing)` handles
absence with a typed rejection; a mutable local updates selected fields before
one explicit durable write. Ordinary helper calls accept positional arguments,
record literals accept same-name field shorthand, and numeric literals inherit
the `quantity` type from their context. The runtime regression owner is
`crates/ivm/tests/kotodama_simple_contracts.rs`.

```kotodama
seiyaku Proposals {
    permission CreateProposal;
    permission FinalizeProposal;
    error enum Failure { Missing = 1, NotPending = 2, InvalidAmount = 3, Exists = 4 }
    struct Proposal { quantity amount, int status, int finalized_at_ms }
    state StateMap<Name, Proposal> Requests;

    kotoage fn create(Name id, quantity amount) authorize(CreateProposal) {
        require(amount > 0, Failure::InvalidAmount);
        require(!Requests.contains(id), Failure::Exists);
        Requests[id] = Proposal { amount, status: 1, finalized_at_ms: 0 };
    }

    kotoage fn finalize(Name id, int finalized_at_ms) authorize(FinalizeProposal) {
        var request = Requests.get(id).expect(Failure::Missing);
        require(request.status == 1, Failure::NotPending);
        request.status = 2;
        request.finalized_at_ms = finalized_at_ms;
        Requests[id] = request;
    }
}
```

## Namespaced ledger operations

Host capabilities are namespaced. Typed constructors produce validated
pointer-ABI values; source cannot allocate host memory, construct raw pointers,
select direct syscalls, or submit opaque instruction bytes.

```kotodama
seiyaku TransferDemo {
    permission AssetTransferRole;
    kotoage fn transfer() authorize(AssetTransferRole) {
        ledger::asset::transfer(
            source: AccountId::parse("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"),
            destination: AccountId::parse("sorauﾛ1NfｷgﾉﾓﾉBｦKﾌﾘﾒoﾇﾂﾛrG81ﾋjWﾎﾕVncwﾌSｱ3pﾘﾋﾉhUS9Q76"),
            asset_definition: AssetDefinitionId::parse("62Fk4FPcMuLvW5QjDGNF2a4jAmjM"),
            amount: 10,
        );
    }
}
```

The `authorize` permission is caller authorization. It does not replace the
host's operation-specific authorization, and it is separate from the
compiler-derived effect and scheduler-access summaries.

The same named-permission check is mandatory for direct calls, nested calls,
trigger authorities, block overlay prepasses and rebuilds, and proved-overlay
replay. A prepared overlay carries the requirement and checks live state again
before applying any queued instruction or durable write; grants, revokes, and
role changes share a scheduler authorization dependency.

## Triggers

A trigger names its callback in the declaration header. Its event filter and
repeat policy are declarative manifest data; the callback remains an ordinary
typed kotoage declaration.

```kotodama
seiyaku ScheduledSettlement {
    permission CanSettle;
    kotoage fn settle() authorize(CanSettle) {
        debug::info("settlement tick");
    }

    trigger hourly -> settle {
        on time schedule(start_ms: 0, period_ms: 60 * 60 * 1_000);
        repeats indefinitely;
        metadata {
            purpose: "settlement";
        }
    }
}
```

Trigger filters also cover explicit trigger execution, supported ledger data
events, and approved transaction or block pipeline events. Trigger authority
and lifecycle policy are enforced by the runtime.

## Durable maps

`StateMap<K, V>` is host-backed durable state. `get` returns `Option<V>` so an
absent key cannot be confused with a zero value. Writes and removals operate on
one key, preserving scheduler precision. Iteration follows canonical Norito key
order and must be compiler-proven bounded; V1 admits at most 64 items.

In-memory `Map`, implicit defaults, unbounded iteration, recursive calls, and
`while` are not V1 language features.

## Modules

A reusable source has this shape:

```kotodama
module QuantityRules {
    fn is_positive(quantity amount) -> bool {
        return amount > 0;
    }
}
```

Modules are resolved and type-checked once in the content-addressed build graph,
then linked at HIR. Kotodama has no wildcard imports or textual AST rewriting.

## Boundary arguments and artifacts

Torii and CLI users may supply JSON keyed by parameter name. The boundary
converts that object into one canonical Norito argument record, capped
inclusively at 1 MiB. For a prepared call, the host validates the trusted flat
schema and derives its conservative maximum aggregate and pointer-allocation
bound before decoding the untrusted record. The signed wire lengths and that
bound must be affordable first; the host then validates and decodes the record
exactly once. Default hosts acquire that record through the metered
`entrypoint_argument_record` public input as `NoritoBytes`; admitted hosts may
provide the prepared owner directly. `trigger_event_json` independently exposes
the actual firing `Json`, never the argument record. Missing record inputs
are refused without falling back to the event key. The complete signed record
remains host-owned, and the public
wrapper receives only its domain-separated binding plus typed ABI words. The
host preflights the complete aligned allocation sequence: pointer TLVs and the
word table prefer INPUT and spill into owned HEAP, while raw `List` and sum
storage is always owned HEAP. Raw decode-syscall quotes use only bounded
record/schema envelope lengths and reserve the full HEAP before either payload
is authenticated.

`code_hash` is a domain-separated hash of the complete deployable `.to`,
including every execution-header field, CNTR, literals, and code. Source maps
and debug information are hash-keyed sidecars, not unhashed deployable
sections. Nodes independently validate control flow and derive transitive
effects/access instead of trusting compiler claims in CNTR.

For larger checked-in examples, see `examples/`,
`crates/ivm/docs/examples/`, and `crates/kotodama_lang/src/samples/`. The
machine-readable [`kotodama_v1_docs.json`](./kotodama_v1_docs.json) policy
identifies the normative grammar and documentation roots. CI discovers every
tracked `kotodama`/`ko` fence and documented `*.ko` heredoc below those roots.
