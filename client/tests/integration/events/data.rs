#![allow(clippy::restriction)]
use std::{fmt::Write as _, str::FromStr, sync::mpsc, thread};

use eyre::Result;
use iroha_core::smartcontracts::wasm;
use iroha_data_model::{prelude::*, transaction::WasmSmartContract};
use parity_scale_codec::Encode;
use test_network::*;

use crate::wasm::utils::wasm_template;

fn produce_instructions() -> Vec<Instruction> {
    let domains = (0..4)
        .map(|domain_index: usize| Domain::new(domain_index.to_string().parse().expect("Valid")));

    let registers: [Instruction; 4] = domains
        .into_iter()
        .map(RegisterBox::new)
        .map(Instruction::from)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // TODO: should we re-introduce the DSL?
    vec![
        // domain "0"
        // pair
        //      domain "1"
        //      if false fail else sequence
        //          domain "2"
        //          domain "3"
        registers[0].clone(),
        Pair::new::<Instruction, _>(
            registers[1].clone(),
            IfInstruction::with_otherwise(
                false,
                FailBox::new("unreachable"),
                SequenceBox::new(vec![registers[2].clone(), registers[3].clone()]),
            ),
        )
        .into(),
    ]
}

#[test]
fn instruction_execution_should_produce_events() -> Result<()> {
    let instructions = produce_instructions().into();
    transaction_execution_should_produce_events(instructions)
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
            "(call $exec_isi (i32.const {ptr_offset}) (i32.const {ptr_len}))",
            ptr_offset = ptr_offset / 2,
            ptr_len = ptr_len / 2,
        )?;

        ptr_offset = ptr_len;
    }

    let wat = format!(
        r#"
        (module
            {wasm_template}

            ;; Function which starts the smartcontract execution
            (func (export "{main_fn_name}") (param)
                {isi_calls}))
        "#,
        main_fn_name = wasm::export::WASM_MAIN_FN_NAME,
        wasm_template = wasm_template(&isi_hex.concat()),
        isi_calls = isi_calls
    );

    transaction_execution_should_produce_events(Executable::Wasm(WasmSmartContract {
        raw_data: wat.into_bytes(),
    }))
}

fn transaction_execution_should_produce_events(executable: Executable) -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    // spawn event reporter
    let listener = client.clone();
    let (init_sender, init_receiver) = mpsc::channel();
    let (event_sender, event_receiver) = mpsc::channel();
    let event_filter = DataEventFilter::AcceptAll.into();
    thread::spawn(move || -> Result<()> {
        let event_iterator = listener.listen_for_events(event_filter)?;
        init_sender.send(())?;
        for event in event_iterator {
            event_sender.send(event)?
        }
        Ok(())
    });

    // submit transaction to produce events
    init_receiver.recv()?;
    let transaction = client
        .build_transaction(executable, UnlimitedMetadata::new())
        .unwrap();
    client.submit_transaction_blocking(transaction)?;

    // assertion
    for i in 0..4_usize {
        let domain_id = DomainId::new(i.to_string().parse().expect("Valid"));
        let expected_event = DomainEvent::Created(domain_id).into();
        let event: DataEvent = event_receiver.recv()??.try_into()?;
        assert_eq!(event, expected_event);
    }

    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn produce_multiple_events() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    // Spawn event reporter
    let listener = client.clone();
    let (init_sender, init_receiver) = mpsc::channel();
    let (event_sender, event_receiver) = mpsc::channel();
    let event_filter = DataEventFilter::AcceptAll.into();
    thread::spawn(move || -> Result<()> {
        let event_iterator = listener.listen_for_events(event_filter)?;
        init_sender.send(())?;
        for event in event_iterator {
            event_sender.send(event)?
        }
        Ok(())
    });

    // Wait for event listener
    init_receiver.recv()?;

    // Registering role
    let role_id = <Role as Identifiable>::Id::from_str("TEST_ROLE")?;
    let token_1 = PermissionToken::new("test_permission_token_1".parse().expect("valid"));
    let token_2 = PermissionToken::new("test_permission_token_2".parse().expect("valid"));
    let permission_token_definition_1 =
        PermissionTokenDefinition::new(token_1.definition_id().clone());
    let permission_token_definition_2 =
        PermissionTokenDefinition::new(token_2.definition_id().clone());
    let role = iroha_data_model::role::Role::new(role_id.clone())
        .add_permission(token_1.clone())
        .add_permission(token_2.clone());
    let instructions = [
        RegisterBox::new(permission_token_definition_1.clone()).into(),
        RegisterBox::new(permission_token_definition_2.clone()).into(),
        RegisterBox::new(role).into(),
    ];
    client.submit_all_blocking(instructions)?;

    // Grants role to Alice
    let alice_id = <Account as Identifiable>::Id::from_str("alice@wonderland")?;
    let grant_role = GrantBox::new(role_id.clone(), alice_id.clone());
    client.submit_blocking(grant_role)?;

    // Unregister role
    let unregister_role = UnregisterBox::new(role_id.clone());
    client.submit_blocking(unregister_role)?;

    // Inspect produced events
    let expected_events: Vec<DataEvent> = [
        WorldEvent::PermissionToken(PermissionTokenEvent::DefinitionCreated(
            permission_token_definition_1,
        )),
        WorldEvent::PermissionToken(PermissionTokenEvent::DefinitionCreated(
            permission_token_definition_2,
        )),
        WorldEvent::Role(RoleEvent::Created(role_id.clone())),
        WorldEvent::Domain(DomainEvent::Account(AccountEvent::PermissionAdded(
            AccountPermissionChanged {
                account_id: alice_id.clone(),
                permission_id: token_1.definition_id().clone(),
            },
        ))),
        WorldEvent::Domain(DomainEvent::Account(AccountEvent::PermissionAdded(
            AccountPermissionChanged {
                account_id: alice_id.clone(),
                permission_id: token_2.definition_id().clone(),
            },
        ))),
        WorldEvent::Domain(DomainEvent::Account(AccountEvent::RoleGranted(
            AccountRoleChanged {
                account_id: alice_id.clone(),
                role_id: role_id.clone(),
            },
        ))),
        WorldEvent::Domain(DomainEvent::Account(AccountEvent::PermissionRemoved(
            AccountPermissionChanged {
                account_id: alice_id.clone(),
                permission_id: token_1.definition_id().clone(),
            },
        ))),
        WorldEvent::Domain(DomainEvent::Account(AccountEvent::PermissionRemoved(
            AccountPermissionChanged {
                account_id: alice_id.clone(),
                permission_id: token_2.definition_id().clone(),
            },
        ))),
        WorldEvent::Domain(DomainEvent::Account(AccountEvent::RoleRevoked(
            AccountRoleChanged {
                account_id: alice_id,
                role_id: role_id.clone(),
            },
        ))),
        WorldEvent::Role(RoleEvent::Deleted(role_id)),
    ]
    .into_iter()
    .flat_map(WorldEvent::flatten)
    .collect();

    for expected_event in expected_events {
        let event = event_receiver.recv()??.try_into()?;
        assert_eq!(expected_event, event);
    }

    Ok(())
}
