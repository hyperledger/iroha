use std::{fmt::Write as _, str::FromStr, sync::mpsc, thread};

use eyre::Result;
use iroha_client::data_model::{prelude::*, transaction::WasmSmartContract};
use parity_scale_codec::Encode as _;
use serde_json::json;
use test_network::*;
use test_samples::{ALICE_ID, BOB_ID};

/// Return string containing exported memory, dummy allocator, and
/// host function imports which you can embed into your wasm module.
///
/// Memory is initialized with the given hex encoded string value
// NOTE: It's expected that hex value is of even length
#[allow(clippy::integer_division)]
pub fn wasm_template(hex_val: &str) -> String {
    format!(
        r#"
        ;; Import host function to execute instruction
        (import "iroha" "{execute_instruction}"
            (func $exec_isi (param i32 i32) (result i32)))

        ;; Import host function to execute query
        (import "iroha" "{execute_query}"
            (func $exec_query (param i32 i32) (result i32)))

        ;; Embed ISI into WASM binary memory
        (memory (export "{memory_name}") 1)
        (data (i32.const 0) "{hex_val}")

        ;; Variable which tracks total allocated size
        (global $mem_size (mut i32) i32.const {hex_len})

        ;; Export mock allocator to host. This allocator never frees!
        (func (export "{alloc_fn_name}") (param $size i32) (result i32)
            global.get $mem_size

            (global.set $mem_size
                (i32.add (global.get $mem_size) (local.get $size)))
        )

        ;; Export mock deallocator to host. This allocator does nothing!
        (func (export "{dealloc_fn_name}") (param $size i32) (param $len i32)
           nop)
        "#,
        memory_name = "memory",
        alloc_fn_name = "_iroha_smart_contract_alloc",
        dealloc_fn_name = "_iroha_smart_contract_dealloc",
        execute_instruction = "execute_instruction",
        execute_query = "execute_query",
        hex_val = escape_hex(hex_val),
        hex_len = hex_val.len() / 2,
    )
}

fn escape_hex(hex_val: &str) -> String {
    let mut isi_hex = String::with_capacity(3 * hex_val.len());

    for (i, c) in hex_val.chars().enumerate() {
        if i % 2 == 0 {
            isi_hex.push('\\');
        }

        isi_hex.push(c);
    }

    isi_hex
}
fn produce_instructions() -> Vec<InstructionBox> {
    let domains = (0..4)
        .map(|domain_index: usize| Domain::new(domain_index.to_string().parse().expect("Valid")));

    domains
        .into_iter()
        .map(Register::domain)
        .map(InstructionBox::from)
        .collect::<Vec<_>>()
}

#[test]
fn instruction_execution_should_produce_events() -> Result<()> {
    transaction_execution_should_produce_events(produce_instructions(), 10_665)
}

#[test]
fn wasm_execution_should_produce_events() -> Result<()> {
    #![allow(clippy::integer_division)]
    let isi_hex: Vec<String> = produce_instructions()
        .into_iter()
        .map(|isi| isi.encode())
        .map(hex::encode)
        .collect();

    let mut ptr_offset = 0;
    let mut isi_calls = String::new();
    for isi in &isi_hex {
        let ptr_len = isi.len();

        // It's expected that hex values are of even length
        write!(
            isi_calls,
            "(call $exec_isi (i32.const {ptr_offset}) (i32.const {ptr_len}))
             drop",
            ptr_offset = ptr_offset / 2,
            ptr_len = ptr_len / 2,
        )?;

        ptr_offset += ptr_len;
    }

    let wat = format!(
        r#"
        (module
            {wasm_template}

            ;; Function which starts the smartcontract execution
            (func (export "{main_fn_name}") (param)
                {isi_calls}))
        "#,
        main_fn_name = "_iroha_smart_contract_main",
        wasm_template = wasm_template(&isi_hex.concat()),
        isi_calls = isi_calls
    );

    transaction_execution_should_produce_events(
        WasmSmartContract::from_compiled(wat.into_bytes()),
        10_615,
    )
}

fn transaction_execution_should_produce_events(
    executable: impl Into<Executable>,
    port: u16,
) -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(port).start_with_runtime();
    wait_for_genesis_committed(&[client.clone()], 0);

    // spawn event reporter
    let listener = client.clone();
    let (init_sender, init_receiver) = mpsc::channel();
    let (event_sender, event_receiver) = mpsc::channel();
    let event_filter = DataEventFilter::Any;
    thread::spawn(move || -> Result<()> {
        let event_iterator = listener.listen_for_events([event_filter])?;
        init_sender.send(())?;
        for event in event_iterator {
            event_sender.send(event)?
        }
        Ok(())
    });

    // submit transaction to produce events
    init_receiver.recv()?;
    let transaction = client.build_transaction(executable, UnlimitedMetadata::new());
    client.submit_transaction_blocking(&transaction)?;

    // assertion
    iroha_logger::info!("Listening for events");
    for i in 0..4_usize {
        let event: DataEvent = event_receiver.recv()??.try_into()?;
        iroha_logger::info!("Event: {:?}", event);
        assert!(matches!(event, DataEvent::Domain(_)));
        if let DataEvent::Domain(domain_event) = event {
            assert!(matches!(domain_event, DomainEvent::Created(_)));

            if let DomainEvent::Created(created_domain) = domain_event {
                let domain_id = DomainId::new(i.to_string().parse().expect("Valid"));
                assert_eq!(domain_id, *created_domain.id());
            }
        }
    }

    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn produce_multiple_events() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_645).start_with_runtime();
    wait_for_genesis_committed(&[client.clone()], 0);

    // Spawn event reporter
    let listener = client.clone();
    let (init_sender, init_receiver) = mpsc::channel();
    let (event_sender, event_receiver) = mpsc::channel();
    let event_filter = DataEventFilter::Any;
    thread::spawn(move || -> Result<()> {
        let event_iterator = listener.listen_for_events([event_filter])?;
        init_sender.send(())?;
        for event in event_iterator {
            event_sender.send(event)?
        }
        Ok(())
    });

    // Wait for event listener
    init_receiver.recv()?;

    // Registering role
    let alice_id = ALICE_ID.clone();
    let role_id = RoleId::from_str("TEST_ROLE")?;
    let token_1 = Permission::new(
        "CanRemoveKeyValueInAccount".parse()?,
        json!({ "account_id": alice_id }).into(),
    );
    let token_2 = Permission::new(
        "CanSetKeyValueInAccount".parse()?,
        json!({ "account_id": alice_id }).into(),
    );
    let role = iroha_client::data_model::role::Role::new(role_id.clone())
        .add_permission(token_1.clone())
        .add_permission(token_2.clone());
    let instructions = [Register::role(role.clone())];
    client.submit_all_blocking(instructions)?;

    // Grants role to Bob
    let bob_id = BOB_ID.clone();
    let grant_role = Grant::role(role_id.clone(), bob_id.clone());
    client.submit_blocking(grant_role)?;

    // Unregister role
    let unregister_role = Unregister::role(role_id.clone());
    client.submit_blocking(unregister_role)?;

    // Inspect produced events
    let event: DataEvent = event_receiver.recv()??.try_into()?;
    assert!(matches!(event, DataEvent::Role(_)));
    if let DataEvent::Role(role_event) = event {
        assert!(matches!(role_event, RoleEvent::Created(_)));

        if let RoleEvent::Created(created_role) = role_event {
            assert_eq!(created_role.id(), role.id());
            assert!(created_role
                .permissions()
                .eq([token_1.clone(), token_2.clone()].iter()));
        }
    }

    let expected_domain_events: Vec<DataEvent> = [
        DataEvent::Domain(DomainEvent::Account(AccountEvent::PermissionAdded(
            AccountPermissionChanged {
                account_id: bob_id.clone(),
                permission_id: token_1.id.clone(),
            },
        ))),
        DataEvent::Domain(DomainEvent::Account(AccountEvent::PermissionAdded(
            AccountPermissionChanged {
                account_id: bob_id.clone(),
                permission_id: token_2.id.clone(),
            },
        ))),
        DataEvent::Domain(DomainEvent::Account(AccountEvent::RoleGranted(
            AccountRoleChanged {
                account_id: bob_id.clone(),
                role_id: role_id.clone(),
            },
        ))),
        DataEvent::Domain(DomainEvent::Account(AccountEvent::PermissionRemoved(
            AccountPermissionChanged {
                account_id: bob_id.clone(),
                permission_id: token_1.id,
            },
        ))),
        DataEvent::Domain(DomainEvent::Account(AccountEvent::PermissionRemoved(
            AccountPermissionChanged {
                account_id: bob_id.clone(),
                permission_id: token_2.id,
            },
        ))),
        DataEvent::Domain(DomainEvent::Account(AccountEvent::RoleRevoked(
            AccountRoleChanged {
                account_id: bob_id,
                role_id: role_id.clone(),
            },
        ))),
        DataEvent::Role(RoleEvent::Deleted(role_id)),
    ]
    .into_iter()
    .map(Into::into)
    .collect();

    for expected_event in expected_domain_events {
        let event = event_receiver.recv()??.try_into()?;
        assert_eq!(expected_event, event);
    }

    Ok(())
}
