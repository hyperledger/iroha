//! Exact scalar/tuple key identity, canonical bytes and original-budget refusal.

use super::*;
use ivm_abi::state_value::StateValueRecordV1;

fn encoded(ty: &Embedded, atoms: Vec<Atom>) -> Vec<u8> {
    let schema = state_map_key_schema(ty).unwrap();
    norito::encode_canonical(&StateValueRecordV1 {
        schema_hash: state_value_schema_hash_v1(&norito::encode_canonical(&schema).unwrap()),
        atoms,
    })
    .unwrap()
}
fn pointer(kind: PointerType, value: &[u8]) -> Atom {
    Atom::Pointer(pointer_abi::encode_tlv(kind, value).unwrap())
}
fn integer(value: i128) -> Atom {
    Atom::Pointer(
        ivm_abi::numeric_tlv::encode_int(&iroha_primitives::bigint::BigInt::from_i128(value))
            .unwrap(),
    )
}

#[test]
fn key_schema_accepts_only_bounded_scalar_and_nonempty_tuple_products() {
    let ty = Embedded::Tuple(vec![
        Embedded::Int,
        Embedded::Tuple(vec![Embedded::Bool, Embedded::Name]),
    ]);
    let schema = state_map_key_schema(&ty).unwrap();
    assert!(matches!(
        schema.nodes.as_slice(),
        [
            Node::Tuple { arity: 2 },
            Node::Leaf(Kind::Int),
            Node::Tuple { arity: 2 },
            Node::Leaf(Kind::Bool),
            Node::Leaf(Kind::Name),
        ]
    ));
    for invalid in [
        Embedded::Tuple(vec![]),
        Embedded::Tuple(vec![Embedded::Bool]),
        Embedded::Json,
        Embedded::Unit,
        Embedded::Option(Box::new(Embedded::Bool)),
        Embedded::Tuple(vec![Embedded::Bool, Embedded::Json]),
        Embedded::Tuple(vec![Embedded::Bool; MAX_STATE_VALUE_NODES]),
    ] {
        assert!(state_map_key_schema(&invalid).is_err(), "{invalid:?}");
    }
    let maximum = Embedded::Tuple(vec![Embedded::Bool; MAX_STATE_VALUE_NODES - 1]);
    assert_eq!(
        state_map_key_schema(&maximum).unwrap().nodes.len(),
        MAX_STATE_VALUE_NODES
    );
}

#[test]
fn key_schemas_are_the_same_schemas_used_by_the_durable_value_codec() {
    for ty in [
        Embedded::Bool,
        Embedded::Int,
        Embedded::Decimal,
        Embedded::Quantity,
        Embedded::String,
        Embedded::Bytes,
        Embedded::AccountId,
        Embedded::AssetDefinitionId,
        Embedded::AssetId,
        Embedded::DomainId,
        Embedded::NftId,
        Embedded::Name,
        Embedded::DataSpaceId,
        Embedded::Tuple(vec![
            Embedded::Int,
            Embedded::Tuple(vec![Embedded::Bool, Embedded::Name]),
        ]),
    ] {
        assert_eq!(
            state_map_key_schema(&ty).unwrap(),
            ivm_abi::state_value::state_value_schema_for_embedded_type_v1(&ty).unwrap(),
            "{ty:?}",
        );
    }
}

#[test]
fn tuple_records_bind_order_shape_and_every_nominal_leaf() {
    let vm = IVM::new(1_000_000);
    let ty = Embedded::Tuple(vec![
        Embedded::Int,
        Embedded::Tuple(vec![Embedded::Bool, Embedded::Name]),
    ]);
    let name: Name = "merchant".parse().unwrap();
    let atoms = vec![
        integer(7),
        Atom::Bool(true),
        pointer(PointerType::Name, &norito::encode_canonical(&name).unwrap()),
    ];
    let valid = encoded(&ty, atoms.clone());
    validate_key_record(&vm, &ty, &valid).unwrap();
    let regrouped = Embedded::Tuple(vec![Embedded::Int, Embedded::Bool, Embedded::Name]);
    assert!(validate_key_record(&vm, &regrouped, &valid).is_err());
    let reordered = Embedded::Tuple(vec![
        Embedded::Bool,
        Embedded::Tuple(vec![Embedded::Int, Embedded::Name]),
    ]);
    assert!(validate_key_record(&vm, &reordered, &valid).is_err());
    for invalid in [
        vec![integer(7), Atom::Tag(true), atoms[2].clone()],
        vec![
            integer(7),
            Atom::Bool(true),
            pointer(PointerType::Blob, b"merchant"),
        ],
        atoms[..2].to_vec(),
        {
            let mut values = atoms;
            values.push(Atom::Bool(false));
            values
        },
    ] {
        assert!(validate_key_record(&vm, &ty, &encoded(&ty, invalid)).is_err());
    }
    let bytes = encoded(&Embedded::Bytes, vec![pointer(PointerType::Blob, &[0xff])]);
    validate_key_record(&vm, &Embedded::Bytes, &bytes).unwrap();
    let invalid_utf8 = encoded(&Embedded::String, vec![pointer(PointerType::Blob, &[0xff])]);
    assert!(validate_key_record(&vm, &Embedded::String, &invalid_utf8).is_err());
}

#[test]
fn scalar_keys_require_the_same_canonical_record_and_reject_retired_pointer_carriers() {
    let source = "seiyaku Map { state StateMap<int,bool> Values; view fn read() authorize(anyone) -> bool { true } }";
    let code = kotodama_lang::compiler::Compiler::new()
        .compile_source(source)
        .unwrap();
    let mut vm = IVM::new(1_000_000);
    vm.load_program(&code).unwrap();
    let base = "Values".parse().unwrap();
    let record = encoded(&Embedded::Int, vec![integer(7)]);
    let path = canonical_typed_state_map_path(&vm, &base, &record).unwrap();
    assert_eq!(path.as_ref(), format!("Values/{}", hex::encode(&record)));
    let Atom::Pointer(retired) = integer(7) else {
        unreachable!()
    };
    assert!(canonical_typed_state_map_path(&vm, &base, &retired).is_err());
    assert!(validate_key_record(&vm, &Embedded::Int, &record[..record.len() - 1]).is_err());
    let mut tailed = record.clone();
    tailed.push(0);
    assert!(validate_key_record(&vm, &Embedded::Int, &tailed).is_err());
    let mut corrupt = record;
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(validate_key_record(&vm, &Embedded::Int, &corrupt).is_err());
    assert!(
        validate_key_record(
            &vm,
            &Embedded::Bool,
            &norito::encode_canonical(&1i64).unwrap()
        )
        .is_err()
    );
}

#[test]
fn key_record_bound_is_exact_and_all_physical_paths_sort_by_encoded_bytes() {
    let vm = IVM::new(1_000_000);
    let ty = Embedded::Bytes;
    let mut lower = 0;
    let mut upper = syscalls::STATE_MAP_MAX_KEY_BYTES;
    while lower < upper {
        let midpoint = (lower + upper).div_ceil(2);
        let record = encoded(&ty, vec![pointer(PointerType::Blob, &vec![0xA5; midpoint])]);
        if record.len() <= syscalls::STATE_MAP_MAX_KEY_BYTES {
            lower = midpoint;
        } else {
            upper = midpoint - 1;
        }
    }
    let valid = encoded(&ty, vec![pointer(PointerType::Blob, &vec![0xA5; lower])]);
    assert_eq!(valid.len(), syscalls::STATE_MAP_MAX_KEY_BYTES);
    validate_key_record(&vm, &ty, &valid).unwrap();
    let oversized = encoded(
        &ty,
        vec![pointer(PointerType::Blob, &vec![0xA5; lower + 1])],
    );
    assert!(validate_key_record(&vm, &ty, &oversized).is_err());
    let base: Name = "Entries".parse().unwrap();
    let tuple = Embedded::Tuple(vec![Embedded::Int, Embedded::Bool]);
    let mut records: Vec<_> = [3, -1, 0]
        .into_iter()
        .map(|value| encoded(&tuple, vec![integer(value), Atom::Bool(true)]))
        .collect();
    let mut paths: Vec<_> = records
        .iter()
        .map(|record| canonical_state_map_path(&base, record).unwrap().to_string())
        .collect();
    records.sort();
    paths.sort();
    assert_eq!(
        paths,
        records
            .iter()
            .map(|record| format!("Entries/{}", hex::encode(record)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn key_decode_refuses_before_copying_and_retries_the_original_pool() {
    let pool = iroha_allocation::AllocationBudget::new(256 * 1024 * 1024);
    let vm = IVM::try_new_with_memory_budget(1_000_000, &pool).unwrap();
    let key = encoded(&Embedded::Bool, vec![Atom::Bool(true)]);
    let original = key.as_ptr();
    let baseline = pool.reserved_bytes();
    pool.set_limit_bytes(baseline);
    let error = validate_key_record(&vm, &Embedded::Bool, &key).unwrap_err();
    assert!(matches!(error, VMError::AllocationDeferred(_)));
    assert_eq!(error.metered_gas(), None);
    assert_eq!(key.as_ptr(), original);
    assert_eq!(pool.reserved_bytes(), baseline);
    pool.set_limit_bytes(256 * 1024 * 1024);
    validate_key_record(&vm, &Embedded::Bool, &key).unwrap();
    assert_eq!(key.as_ptr(), original);
    assert_eq!(pool.reserved_bytes(), baseline);
    drop(vm);
    assert_eq!(pool.reserved_bytes(), 0);
}
