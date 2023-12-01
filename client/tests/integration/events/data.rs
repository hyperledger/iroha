use std::{fmt::Write as _, str::FromStr, sync::mpsc, thread};

use eyre::Result;
use iroha_client::data_model::{prelude::*, transaction::WasmSmartContract};
use parity_scale_codec::Encode as _;
use serde_json::json;
use test_network::*;

use crate::wasm::utils::wasm_template;

fn produce_instructions() -> Vec<InstructionExpr> {
    let domains = (0..4)
        .map(|domain_index: usize| Domain::new(domain_index.to_string().parse().expect("Valid")));

    let registers: [InstructionExpr; 4] = domains
        .into_iter()
        .map(RegisterExpr::new)
        .map(InstructionExpr::from)
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
        PairExpr::new(
            registers[1].clone(),
            ConditionalExpr::with_otherwise(
                false,
                Fail::new("unreachable"),
                SequenceExpr::new([registers[2].clone(), registers[3].clone()]),
            ),
        )
        .into(),
    ]
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
    client.submit_transaction_blocking(&transaction)?;

    // assertion
    for i in 0..4_usize {
        let event: DataEvent = event_receiver.recv()??.try_into()?;
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
    let alice_id = AccountId::from_str("alice@wonderland")?;
    let role_id = RoleId::from_str("TEST_ROLE")?;
    let token_1 = PermissionToken::new(
        "CanRemoveKeyValueInUserAccount".parse()?,
        &json!({ "account_id": alice_id }),
    );
    let token_2 = PermissionToken::new(
        "CanSetKeyValueInUserAccount".parse()?,
        &json!({ "account_id": alice_id }),
    );
    let role = iroha_client::data_model::role::Role::new(role_id.clone())
        .add_permission(token_1.clone())
        .add_permission(token_2.clone());
    let instructions = [RegisterExpr::new(role.clone())];
    client.submit_all_blocking(instructions)?;

    // Grants role to Bob
    let bob_id = AccountId::from_str("bob@wonderland")?;
    let grant_role = GrantExpr::new(role_id.clone(), bob_id.clone());
    client.submit_blocking(grant_role)?;

    // Unregister role
    let unregister_role = UnregisterExpr::new(role_id.clone());
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
        WorldEvent::Domain(DomainEvent::Account(AccountEvent::PermissionAdded(
            AccountPermissionChanged {
                account_id: bob_id.clone(),
                permission_id: token_1.definition_id.clone(),
            },
        ))),
        WorldEvent::Domain(DomainEvent::Account(AccountEvent::PermissionAdded(
            AccountPermissionChanged {
                account_id: bob_id.clone(),
                permission_id: token_2.definition_id.clone(),
            },
        ))),
        WorldEvent::Domain(DomainEvent::Account(AccountEvent::RoleGranted(
            AccountRoleChanged {
                account_id: bob_id.clone(),
                role_id: role_id.clone(),
            },
        ))),
        WorldEvent::Domain(DomainEvent::Account(AccountEvent::PermissionRemoved(
            AccountPermissionChanged {
                account_id: bob_id.clone(),
                permission_id: token_1.definition_id,
            },
        ))),
        WorldEvent::Domain(DomainEvent::Account(AccountEvent::PermissionRemoved(
            AccountPermissionChanged {
                account_id: bob_id.clone(),
                permission_id: token_2.definition_id,
            },
        ))),
        WorldEvent::Domain(DomainEvent::Account(AccountEvent::RoleRevoked(
            AccountRoleChanged {
                account_id: bob_id,
                role_id: role_id.clone(),
            },
        ))),
        WorldEvent::Role(RoleEvent::Deleted(role_id)),
    ]
    .into_iter()
    .flat_map(WorldEvent::flatten)
    .collect();

    for expected_event in expected_domain_events {
        let event = event_receiver.recv()??.try_into()?;
        assert_eq!(expected_event, event);
    }

    Ok(())
}
