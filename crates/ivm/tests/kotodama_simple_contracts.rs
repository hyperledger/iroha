//! Execute concise contract syntax through the real compiler and IVM ABI.
use ivm::{CoreHost, IVM, ProgramMetadata, VMError};
use kotodama_lang::compiler::Compiler;

mod common;

fn load(source: &str) -> (IVM, Vec<u8>) {
    let code = Compiler::new()
        .compile_source(source)
        .expect("compile concise contract");
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CoreHost::new());
    vm.load_program(&code).expect("load concise contract");
    common::select_kotodama_entrypoint(&mut vm, &code, "run");
    (vm, code)
}

#[test]
fn expect_preserves_zero_empty_bytes_names_and_aggregate_state() {
    let (mut vm, _) = load(
        r#"seiyaku SimpleState { permission WriteState;
            error enum StateError { Missing = 1101 }
            const Name KEY = Name::parse("note");
            struct Note { int nonce, bytes commitment, Name source, bool active }
            state StateMap<Name, Note> Notes;
            state StateMap<Name, int> Nonces;
            state StateMap<Name, bytes> Evidence;

            kotoage fn run() authorize(WriteState) -> bool {
                Notes[KEY] = Note {
                    nonce: 0, commitment: b"", source: KEY, active: false
                };
                Nonces[KEY] = 0;
                Evidence[KEY] = b"";
                let note = Notes.get(KEY).expect(StateError::Missing);
                let Option<Name> source = Option::some(note.source);
                return note.nonce == 0 && note.commitment == b"" && !note.active
                    && source.expect(StateError::Missing) == KEY
                    && Nonces.get(KEY).expect(StateError::Missing) == 0
                    && Evidence.get(KEY).expect(StateError::Missing) == b"";
            }
        }"#,
    );
    vm.run().expect("extract present state values");
    assert_eq!(vm.public_call_result_word(0), Ok(1));
}

#[test]
fn expect_absence_aborts_with_the_authenticated_nominal_error() {
    for ty in ["int", "bytes", "Name", "Note", "()"] {
        let source = format!(
            r#"seiyaku MissingState {{
                error enum StateError {{ Missing = 1101 }}
                struct Note {{ int nonce, bytes commitment }}
                view fn run() authorize(anyone) -> {ty} {{
                    let Option<{ty}> absent = Option::none;
                    return absent.expect(StateError::Missing);
                }}
            }}"#
        );
        let (mut vm, code) = load(&source);
        let metadata = ProgramMetadata::parse(&code).expect("parse signed interface");
        let descriptor = metadata
            .contract_interface
            .as_ref()
            .expect("contract interface")
            .error_types
            .iter()
            .find(|error| error.identity == "MissingState::StateError")
            .expect("declared nominal error descriptor");
        let error = vm
            .run()
            .expect_err("missing state must abort")
            .split_metered()
            .1;
        assert_eq!(
            error,
            VMError::ContractAbort {
                contract: "MissingState".into(),
                name: "Missing".to_owned(),
                error_type: descriptor.identity.clone(),
                schema_hash: descriptor.schema_hash(),
                code: 1101,
                message: None,
            },
            "missing {ty} must preserve the nominal error identity"
        );
    }
}

#[test]
fn expect_evaluates_a_stateful_receiver_once() {
    let (mut vm, _) = load(
        r#"seiyaku Once { permission WriteState;
            error enum StateError { Missing = 1101 }
            state StateMap<int, int> Calls;
            fn next() -> Option<int> {
                let count = Calls.get(0).unwrap_or(0) + 1;
                Calls[0] = count;
                return Option::some(count);
            }
            kotoage fn run() authorize(WriteState) -> bool {
                let value = next().expect(StateError::Missing);
                return value == 1 && Calls.get(0).expect(StateError::Missing) == 1;
            }
        }"#,
    );
    vm.run().expect("execute receiver once");
    assert_eq!(vm.public_call_result_word(0), Ok(1));
}

#[test]
fn expect_evaluates_its_nominal_error_once_after_the_receiver() {
    let (mut vm, _) = load(
        r#"seiyaku EvaluationOrder { permission WriteState;
            error enum Failure { Missing = 1 }
            state StateMap<int, int> Trace;
            fn present() -> Option<int> {
                Trace[0] = 1;
                return Option::some(7);
            }
            fn missing() -> Failure {
                Trace[0] = Trace.get(0).unwrap_or(0) * 10 + 2;
                return Failure::Missing;
            }
            kotoage fn run() authorize(WriteState) -> bool {
                let value = present().expect(missing());
                return value == 7 && Trace.get(0).unwrap_or(0) == 12;
            }
        }"#,
    );
    vm.run()
        .expect("evaluate receiver and error in source order");
    assert_eq!(vm.public_call_result_word(0), Ok(1));
}

#[test]
fn expect_rejects_untyped_errors_and_nonoptional_receivers() {
    for (expression, expected) in [
        ("value.expect(1)", "requires a nominal error enum value"),
        (
            "value.expect(\"missing\")",
            "requires a nominal error enum value",
        ),
        ("value.expect()", "expects one nominal error argument"),
        (
            "value.expect(Failure::Missing, Failure::Missing)",
            "expects one nominal error argument",
        ),
        ("(1).expect(Failure::Missing)", "receiver must be Option<T>"),
        (
            "result.expect(Failure::Missing)",
            "receiver must be Option<T>",
        ),
    ] {
        let binding = if expression.starts_with("result") {
            "let Result<int, Failure> result = Result::ok(1);"
        } else {
            "let Option<int> value = Option::some(1);"
        };
        let source = format!(
            "seiyaku Invalid {{ error enum Failure {{ Missing = 1 }} view fn run() authorize(anyone) -> int {{ {binding} return {expression}; }} }}"
        );
        let error = Compiler::new()
            .compile_source(&source)
            .expect_err("invalid extraction must fail at compile time");
        assert!(
            error.contains(expected),
            "unexpected diagnostic for {expression}: {error}"
        );
    }
}

#[test]
fn hex_prefixed_strings_remain_text_through_json_calls_and_state() {
    for bindings in [
        r#"let text = "0x6162"; let binary = b"ab";"#,
        r#"let binary = b"ab"; let text = "0x6162";"#,
    ] {
        let source = format!(
            r#"seiyaku LiteralText {{ permission WriteState;
                error enum Failure {{ Missing = 1 }}
                state StateMap<int, string> Texts;
                state StateMap<string, int> Keys;
                fn echo(string text) -> string {{ return text; }}
                kotoage fn run() authorize(WriteState) -> Json {{
                    {bindings}
                    Texts[1] = text;
                    Keys[text] = 11;
                    Keys["ab"] = 22;
                    return json {{
                        text: text,
                        binary: binary,
                        copied: echo(text),
                        stored: Texts.get(1).expect(Failure::Missing),
                        literal_key: Keys.get(text).expect(Failure::Missing),
                        copied_key: Keys.get(echo(text)).expect(Failure::Missing),
                        other_key: Keys.get("ab").expect(Failure::Missing),
                        empty_prefix: "0x",
                        odd_prefix: "0x1",
                        nonhex_prefix: "0xzz",
                        nested: json {{ raw: b"0x6162" }},
                    }};
                }}
            }}"#,
        );
        let (mut vm, _) = load(&source);
        vm.run().expect("retain source text and explicit bytes");
        let pointer = vm
            .public_call_result_word(0)
            .expect("completed JSON result");
        let json: iroha_primitives::json::Json =
            norito::decode_from_bytes(vm.validate_tlv(pointer).expect("JSON envelope").payload)
                .expect("decode native JSON");
        let actual: norito::json::Value = json.try_into_any_norito().expect("JSON value");
        assert_eq!(
            actual,
            norito::json!({
                "text": "0x6162",
                "binary": "0x6162",
                "copied": "0x6162",
                "stored": "0x6162",
                "literal_key": "11",
                "copied_key": "11",
                "other_key": "22",
                "empty_prefix": "0x",
                "odd_prefix": "0x1",
                "nonhex_prefix": "0xzz",
                "nested": { "raw": "0x307836313632" },
            }),
            "literal pool ordering must not conflate strings with hex-encoded bytes"
        );
    }
}

#[test]
fn concise_proposal_transition_preserves_record_state_and_nominal_rejections() {
    let source = r#"seiyaku Proposals { permission WriteState;
        error enum Failure { Missing = 1, NotPending = 2, InvalidAmount = 3, Exists = 4 }
        struct Proposal {
            quantity amount, bytes approval_alias, int status, int finalized_at_ms
        }
        state StateMap<int, Proposal> Requests;
        fn create(int id, quantity amount, bytes approval_alias) {
            require(amount > 0, Failure::InvalidAmount);
            require(!Requests.contains(id), Failure::Exists);
            Requests[id] = Proposal { amount, approval_alias, status: 1, finalized_at_ms: 0 };
        }
        fn finalize(int id, int finalized_at_ms) {
            var request = Requests.get(id).expect(Failure::Missing);
            require(request.status == 1, Failure::NotPending);
            request.status = 2;
            request.finalized_at_ms = finalized_at_ms;
            Requests[id] = request;
        }
        kotoage fn run() authorize(WriteState) -> bool {
            create(1, 25, b"approval");
            finalize(1, 100);
            ACTION
            let saved = Requests.get(1).expect(Failure::Missing);
            return saved.amount == 25 && saved.approval_alias == b"approval"
                && saved.status == 2 && saved.finalized_at_ms == 100;
        }
    }"#;
    for (action, rejected) in [
        ("", None),
        ("finalize(2, 100);", Some(("Missing", 1))),
        ("finalize(1, 101);", Some(("NotPending", 2))),
        ("create(2, 0, b\"approval\");", Some(("InvalidAmount", 3))),
        ("create(1, 30, b\"replacement\");", Some(("Exists", 4))),
    ] {
        let (mut vm, code) = load(&source.replace("ACTION", action));
        if let Some((name, code_value)) = rejected {
            let metadata = ProgramMetadata::parse(&code).expect("proposal metadata");
            let descriptor = metadata
                .contract_interface
                .as_ref()
                .expect("proposal interface")
                .error_types
                .iter()
                .find(|error| error.identity == "Proposals::Failure")
                .expect("proposal nominal error");
            assert_eq!(
                vm.run()
                    .expect_err("invalid proposal must reject")
                    .split_metered()
                    .1,
                VMError::ContractAbort {
                    contract: "Proposals".into(),
                    name: name.into(),
                    error_type: descriptor.identity.clone(),
                    schema_hash: descriptor.schema_hash(),
                    code: code_value,
                    message: None,
                }
            );
        } else {
            vm.run().expect("execute concise proposal lifecycle");
            assert_eq!(vm.public_call_result_word(0), Ok(1));
        }
    }
}

#[test]
fn positional_and_named_calls_preserve_source_evaluation_order() {
    let (mut vm, _) = load(
        r#"seiyaku SimpleCalls { permission WriteState;
            state StateMap<int, int> Calls;
            fn next() -> int {
                let count = Calls.get(0).unwrap_or(0) + 1;
                Calls[0] = count;
                return count;
            }
            fn pair(int left, int right) -> int { return left * 10 + right; }
            kotoage fn run() authorize(WriteState) -> bool {
                let positional = pair(next(), next());
                let named = pair(right: next(), left: next());
                return positional == 12 && named == 43
                    && Calls.get(0).unwrap_or(0) == 4;
            }
        }"#,
    );
    vm.run().expect("execute positional and named calls");
    assert_eq!(vm.public_call_result_word(0), Ok(1));
}

#[test]
fn mutable_record_fields_roundtrip_without_changing_other_fields() {
    let (mut vm, _) = load(
        r#"seiyaku RecordUpdates { permission WriteState;
            error enum StateError { Missing = 1101 }
            struct Consent { int nonce, bool approved }
            struct Note { Name source, bytes commitment, Consent consent }
            state StateMap<int, Note> Notes;

            kotoage fn run() authorize(WriteState) -> bool {
                Notes[1] = Note {
                    source: Name::parse("invoice"), commitment: b"original",
                    consent: Consent { nonce: 0, approved: false }
                };
                var note = Notes.get(1).expect(StateError::Missing);
                let original = note;
                note.consent.nonce = 1;
                note.consent.approved = true;
                note.commitment = b"approved";
                Notes[1] = note;
                let saved = Notes.get(1).expect(StateError::Missing);
                return saved.consent.nonce == 1 && saved.consent.approved
                    && saved.commitment == b"approved"
                    && saved.source == Name::parse("invoice")
                    && original.consent.nonce == 0 && !original.consent.approved
                    && original.commitment == b"original";
            }
        }"#,
    );
    vm.run().expect("mutate and persist selected record fields");
    assert_eq!(vm.public_call_result_word(0), Ok(1));
}

#[test]
fn record_fields_preserve_mutability_and_type_checks() {
    for body in [
        "let note = Note { nonce: 0 }; note.nonce = 1;",
        "var note = Note { nonce: 0 }; note.nonce = true;",
    ] {
        let source = format!(
            "seiyaku Immutable {{ struct Note {{ int nonce }} view fn run() authorize(anyone) {{ {body} }} }}"
        );
        assert!(
            Compiler::new().compile_source(&source).is_err(),
            "invalid record mutation must be rejected: {body}"
        );
    }
}

#[test]
fn wide_records_cross_stack_table_windows_without_corrupting_fields() {
    let fields = (0..40)
        .map(|index| format!("int f{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let initial = (0..40)
        .map(|index| format!("f{index}: {index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let checks = (0..40)
        .map(|index| {
            let expected = match index {
                0 => 100,
                39 => 139,
                other => other,
            };
            format!("saved.f{index} == {expected}")
        })
        .collect::<Vec<_>>()
        .join(" && ");
    let source = format!(
        r#"seiyaku WideRecord {{ permission WriteState;
            error enum StateError {{ Missing = 1101 }}
            struct Record {{ {fields} }}
            state StateMap<int, Record> Records;
            fn adjust(Record original) -> Record {{
                var updated = original;
                updated.f0 += 100;
                updated.f39 += 100;
                return updated;
            }}
            kotoage fn run() authorize(WriteState) -> bool {{
                Records[0] = Record {{ {initial} }};
                let original = Records.get(0).expect(StateError::Missing);
                Records[0] = adjust(original);
                let saved = Records.get(0).expect(StateError::Missing);
                return {checks} && original.f0 == 0 && original.f39 == 39;
            }}
        }}"#
    );
    let (mut vm, _) = load(&source);
    vm.run()
        .expect("transfer all fields across stack table windows");
    assert_eq!(vm.public_call_result_word(0), Ok(1));
}

#[test]
fn record_updates_survive_control_flow_merges_and_evaluate_rhs_once() {
    let (mut vm, _) = load(
        r#"seiyaku RecordFlow { permission WriteState;
            struct Consent { int nonce, bool approved }
            struct Note { bytes evidence, Consent consent }
            state StateMap<int, int> Calls;
            fn next() -> int {
                let count = Calls.get(0).unwrap_or(0) + 1;
                Calls[0] = count;
                return count;
            }
            kotoage fn run() authorize(WriteState) -> bool {
                var note = Note {
                    evidence: b"retained", consent: Consent { nonce: 0, approved: false }
                };
                for i in range(3) {
                    if i == 1 {
                        note.consent.approved = true;
                    }
                    note.consent.nonce += next();
                }
                return note.consent.nonce == 6 && note.consent.approved
                    && note.evidence == b"retained" && Calls.get(0).unwrap_or(0) == 3;
            }
        }"#,
    );
    vm.run()
        .expect("merge record field updates across branches and loops");
    assert_eq!(vm.public_call_result_word(0), Ok(1));
}

#[test]
fn durable_record_fields_observe_updates_from_effectful_helpers() {
    let (mut vm, _) = load(
        r#"seiyaku DurableRecord { permission WriteState;
            struct Counter { int count, bytes evidence }
            state Counter Current;
            hajimari() { Current = Counter { count: 0, evidence: b"original" }; }
            fn bump() { Current.count += 1; }
            kotoage fn run() authorize(WriteState) -> bool {
                Current = Counter { count: 0, evidence: b"original" };
                Current.count = 2;
                bump();
                return Current.count == 3 && Current.evidence == b"original";
            }
        }"#,
    );
    vm.run()
        .expect("read durable fields after an effectful helper");
    assert_eq!(vm.public_call_result_word(0), Ok(1));
}

#[test]
fn nested_tuple_record_swaps_survive_continue_and_break() {
    let (mut vm, _) = load(
        r#"seiyaku RecordControl {
            struct Note { int value, bytes evidence, bool approved }
            view fn run() authorize(anyone) -> bool {
                var pair = (
                    Note { value: 1, evidence: b"first", approved: false },
                    Note { value: 2, evidence: b"second", approved: false }
                );
                let original = pair;
                var iterations = 0;
                for i in range(4) {
                    let left = pair.0;
                    let right = pair.1;
                    pair.0 = right;
                    pair.1 = left;
                    iterations += 1;
                    if i == 0 { continue; }
                    if i == 2 { break; }
                    pair.0.approved = true;
                }
                return iterations == 3
                    && pair.0.value == 2 && pair.0.evidence == b"second" && !pair.0.approved
                    && pair.1.value == 1 && pair.1.evidence == b"first" && pair.1.approved
                    && original.0.value == 1 && !original.0.approved
                    && original.1.value == 2 && !original.1.approved;
            }
        }"#,
    );
    vm.run()
        .expect("copy overlapping product fields through continue and break edges");
    assert_eq!(vm.public_call_result_word(0), Ok(1));
}
