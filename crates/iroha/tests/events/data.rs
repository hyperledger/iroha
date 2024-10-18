use std::fmt::Write as _;

use assert_matches::assert_matches;
use eyre::Result;
use futures_util::StreamExt;
use iroha::data_model::{prelude::*, transaction::WasmSmartContract};
use iroha_executor_data_model::permission::{
    account::CanModifyAccountMetadata, domain::CanModifyDomainMetadata,
};
use iroha_test_network::*;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use parity_scale_codec::Encode as _;
use tokio::task::spawn_blocking;

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

#[tokio::test]
async fn instruction_execution_should_produce_events() -> Result<()> {
    transaction_execution_should_produce_events(produce_instructions()).await
}

#[tokio::test]
async fn wasm_execution_should_produce_events() -> Result<()> {
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

    transaction_execution_should_produce_events(WasmSmartContract::from_compiled(wat.into_bytes()))
        .await
}

async fn transaction_execution_should_produce_events(
    executable: impl Into<Executable> + Send,
) -> Result<()> {
    let network = NetworkBuilder::new().start().await?;
    let mut events_stream = network
        .client()
        .listen_for_events_async([DataEventFilter::Any])
        .await?;

    {
        let client = network.client();
        let tx = client.build_transaction(executable, <_>::default());
        spawn_blocking(move || client.submit_transaction_blocking(&tx)).await??;
    }

    for i in 0..4 {
        let event = events_stream
            .next()
            .await
            .expect("there are at least 4 events")?;

        let domain = assert_matches!(
            event,
            EventBox::Data(DataEvent::Domain(DomainEvent::Created(domain))) => domain
        );
        assert_eq!(domain.id().name().as_ref(), i.to_string())
    }

    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn produce_multiple_events() -> Result<()> {
    let network = NetworkBuilder::new().start().await?;
    let mut events_stream = network
        .client()
        .listen_for_events_async([DataEventFilter::Any])
        .await?;

    // Register role
    let role_id = "TEST_ROLE".parse::<RoleId>()?;
    let permission_1 = CanModifyAccountMetadata {
        account: ALICE_ID.clone(),
    };
    let permission_2 = CanModifyDomainMetadata {
        domain: ALICE_ID.domain().clone(),
    };
    let role = Role::new(role_id.clone(), ALICE_ID.clone())
        .add_permission(permission_1.clone())
        .add_permission(permission_2.clone());
    let register_role = Register::role(role.clone());

    // Grant the role to Bob
    let bob_id = BOB_ID.clone();
    let grant_role = Grant::account_role(role_id.clone(), BOB_ID.clone());

    // Unregister the role
    let unregister_role = Unregister::role(role_id.clone());

    {
        let client = network.client();
        spawn_blocking(move || {
            client.submit_all_blocking::<InstructionBox>([
                register_role.into(),
                grant_role.into(),
                unregister_role.into(),
            ])
        })
        .await??;
    }

    // Inspect produced events
    let event: DataEvent = events_stream.next().await.unwrap()?.try_into()?;
    assert!(matches!(event, DataEvent::Role(_)));
    if let DataEvent::Role(role_event) = event {
        assert!(matches!(role_event, RoleEvent::Created(_)));

        if let RoleEvent::Created(created_role) = role_event {
            assert_eq!(created_role.id(), role.id());
            assert!(created_role.permissions().eq([
                permission_1.clone().into(),
                permission_2.clone().into()
            ]
            .iter()));
        }
    }

    if let DataEvent::Domain(DomainEvent::Account(AccountEvent::RoleGranted(event))) =
        events_stream.next().await.unwrap()?.try_into()?
    {
        assert_eq!(*event.account(), *ALICE_ID);
        assert_eq!(*event.role(), role_id);
    } else {
        panic!("Expected event is not an AccountEvent::RoleGranted")
    }

    if let DataEvent::Domain(DomainEvent::Account(AccountEvent::RoleGranted(event))) =
        events_stream.next().await.unwrap()?.try_into()?
    {
        assert_eq!(*event.account(), bob_id);
        assert_eq!(*event.role(), role_id);
    } else {
        panic!("Expected event is not an AccountEvent::RoleGranted")
    }

    if let DataEvent::Domain(DomainEvent::Account(AccountEvent::RoleRevoked(event))) =
        events_stream.next().await.unwrap()?.try_into()?
    {
        assert_eq!(*event.account(), bob_id);
        assert_eq!(*event.role(), role_id);
    } else {
        panic!("Expected event is not an AccountEvent::RoleRevoked")
    }

    if let DataEvent::Domain(DomainEvent::Account(AccountEvent::RoleRevoked(event))) =
        events_stream.next().await.unwrap()?.try_into()?
    {
        assert_eq!(*event.account(), *ALICE_ID);
        assert_eq!(*event.role(), role_id);
    } else {
        panic!("Expected event is not an AccountEvent::RoleRevoked")
    }

    if let DataEvent::Role(RoleEvent::Deleted(event)) =
        events_stream.next().await.unwrap()?.try_into()?
    {
        assert_eq!(event, role_id);
    } else {
        panic!("Expected event is not an RoleEvent::Deleted")
    }

    Ok(())
}
