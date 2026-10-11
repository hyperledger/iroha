#[test]
fn public_entrypoint_loads_one_prepared_table_word_per_parameter() {
    let src = r#"
            seiyaku Demo { permission Entry;
                kotoage fn run(
                    int count,
                    int total,
                    bool ready,
                    string text,
                    Name label,
                    AssetId asset,
                    DomainId domain,
                    DataSpaceId dataspace,
                    bytes bytes
                ) authorize(Entry) {
                    let _count = count;
                    let _total = total;
                    let _ready = ready;
                    let _text = text;
                    let _label = label;
                    let _asset = asset;
                    let _domain = domain;
                    let _dataspace = dataspace;
                    let _bytes = bytes;
                }
            }
        "#;
    let prog = parse(src).expect("parse parameterized entrypoint");
    let typed = analyze(&prog).expect("analyze parameterized entrypoint");
    let ir = lower(&typed).expect("lower parameterized entrypoint");
    let wrapper = ir
        .functions
        .iter()
        .find(|function| function.name == "run")
        .expect("wrapper function");
    let mut record_decodes = 0;
    let mut table_loads = 0;
    let mut json_field_getters = 0;
    let TypedItem::Function(function) = &typed.items[0];
    let decoded_schema = entrypoint_argument_schema(&function.param_types).expect("schema");
    for block in &wrapper.blocks {
        for instr in &block.instrs {
            match instr {
                Instr::DirectHelperSyscall { syscall, .. }
                    if *syscall == ivm_abi::syscalls::SYSCALL_DECODE_ARGUMENT_RECORD =>
                {
                    record_decodes += 1;
                }
                Instr::LoadVar { .. } => table_loads += 1,
                Instr::JsonGetNumeric { .. }
                | Instr::JsonGetJson { .. }
                | Instr::JsonGetName { .. }
                | Instr::JsonGetAccountId { .. }
                | Instr::JsonGetAssetDefinitionId { .. }
                | Instr::JsonGetNftId { .. }
                | Instr::JsonGetBlobHex { .. } => json_field_getters += 1,
                _ => {}
            }
        }
    }
    assert_eq!(
        record_decodes, 0,
        "host decodes the complete record before entry"
    );
    assert_eq!(table_loads, 9, "one fixed table load per parameter");
    assert_eq!(
        json_field_getters, 0,
        "wrapper must not re-decode JSON per field"
    );
    let schema = decoded_schema.expect("compiler-emitted Norito schema");
    assert_eq!(
        schema
            .fields
            .iter()
            .map(|field| {
                let [ivm_abi::entrypoint::EntrypointValueTypeNodeV1::Leaf(kind)] =
                    field.ty.nodes.as_slice()
                else {
                    panic!("scalar test parameter must use one leaf node");
                };
                (&*field.name, *kind)
            })
            .collect::<Vec<_>>(),
        vec![
            ("count", ivm_abi::entrypoint::EntrypointValueKindV1::Int),
            ("total", ivm_abi::entrypoint::EntrypointValueKindV1::Int),
            ("ready", ivm_abi::entrypoint::EntrypointValueKindV1::Bool),
            ("text", ivm_abi::entrypoint::EntrypointValueKindV1::String),
            ("label", ivm_abi::entrypoint::EntrypointValueKindV1::Name),
            ("asset", ivm_abi::entrypoint::EntrypointValueKindV1::AssetId),
            (
                "domain",
                ivm_abi::entrypoint::EntrypointValueKindV1::DomainId
            ),
            (
                "dataspace",
                ivm_abi::entrypoint::EntrypointValueKindV1::DataSpaceId
            ),
            ("bytes", ivm_abi::entrypoint::EntrypointValueKindV1::Blob),
        ]
    );
}
#[test]
fn public_aggregate_arguments_cross_internal_calls_as_flat_words() {
    let src = r#"
            seiyaku Demo {
                struct Request { int count, bool ready }

                view fn run(
                    Request request,
                    (int, bool) pair,
                    Option<int> maybe,
                    Result<int, bool> outcome
                ) authorize(anyone) -> int {
                    return request.count + pair.0
                        + maybe.unwrap_or(0) + outcome.unwrap_or(0);
                }
            }
        "#;
    let prog = parse(src).expect("parse aggregate entrypoint");
    let typed = analyze(&prog).expect("analyze aggregate entrypoint");
    let ir = lower(&typed).expect("lower aggregate entrypoint");
    let implementation = ir
        .functions
        .iter()
        .find(|function| function.name == "run")
        .expect("direct public implementation");
    assert_eq!(implementation.params.len(), 6);
    assert!(
        implementation
            .params
            .iter()
            .all(|name| name.starts_with("$abi$")),
        "aggregate implementation parameters must use collision-proof compiler names"
    );
    assert_eq!(
        implementation
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .filter(|instr| matches!(instr, Instr::TuplePack { .. }))
            .count(),
        2,
        "only product shapes are rebuilt; Option and Result remain raw handles"
    );
}
