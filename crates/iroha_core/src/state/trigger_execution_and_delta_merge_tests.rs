#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn time_trigger_precommit_executes_and_emits_time_event() -> Result<()> {
    use iroha_data_model::events::time::{ExecutionTime, TimeEventFilter};
    let world = World::with(
        [Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&ALICE_ID)],
        [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        [],
    );
    let tkey: Name = "tick".parse().unwrap();
    let trigger_id: TriggerId = "tick_once".parse().unwrap();
    let t = Trigger::new(
        trigger_id.clone(),
        Action::new(
            vec![InstructionBox::from(SetKeyValue::account(
                ALICE_ID.clone(),
                tkey.clone(),
                Json::from(norito::json!(1)),
            ))],
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            TimeEventFilter::new(ExecutionTime::PreCommit),
        )
        .expect("trigger action fixture satisfies validation invariants"),
    );
    let genesis_instructions = vec![Register::trigger(t).into()];
    let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 0);
    config.genesis_key = ALICE_KEYPAIR.clone();
    config.genesis_instructions = genesis_instructions;
    let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config).unwrap();
    chain.take_events().unwrap();
    let state = Arc::clone(chain.state());
    chain.commit_at(2, Vec::new());
    let mut events = chain.take_events().unwrap();
    // Exactly one Time event and a single TriggerCompleted notification
    let time_count = events
        .iter()
        .filter(|e| matches!(e, EventBox::Time(_)))
        .count();
    assert_eq!(time_count, 1, "expected exactly one Time event");
    let completed: Vec<_> = events
        .iter()
        .filter_map(|e| {
            if let EventBox::TriggerCompleted(ev) = e {
                Some(ev)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        completed.len(),
        1,
        "expected exactly one TriggerCompleted event for the time trigger"
    );
    use iroha_data_model::events::trigger_completed::TriggerCompletedOutcome;
    let completion = completed[0];
    assert_eq!(completion.trigger_id(), &trigger_id);
    assert!(matches!(
        completion.outcome(),
        TriggerCompletedOutcome::Success
    ));
    // Data event: account metadata inserted for ALICE (tick=1)
    let meta_insert_count = events
        .iter()
        .filter(|e| {
            if let EventBox::Data(ev) = e
                && let iroha_data_model::events::data::prelude::DataEvent::Account(
                    iroha_data_model::events::data::prelude::AccountEvent::MetadataInserted(mc),
                ) = ev.as_ref()
            {
                return *mc.target() == *ALICE_ID
                    && mc.key() == &tkey
                    && mc.value() == &Json::from(norito::json!(1));
            }
            false
        })
        .count();
    assert_eq!(
        meta_insert_count, 1,
        "expected exactly one MetadataInserted event for tick"
    );
    // Negative cases: no asset add/remove events should be present
    assert!(events.iter().all(|e| {
        if let EventBox::Data(ev) = e
            && let iroha_data_model::events::data::prelude::DataEvent::Domain(
                iroha_data_model::events::data::prelude::DomainEvent::Asset(
                    iroha_data_model::events::data::prelude::ScopedAsset {
                        event: iroha_data_model::events::data::prelude::AssetEvent::Added(_),
                        ..
                    },
                ),
            ) = ev.as_ref()
        {
            return false;
        }
        true
    }));
    assert!(events.iter().all(|e| {
        if let EventBox::Data(ev) = e
            && let iroha_data_model::events::data::prelude::DataEvent::Domain(
                iroha_data_model::events::data::prelude::DomainEvent::Asset(
                    iroha_data_model::events::data::prelude::ScopedAsset {
                        event: iroha_data_model::events::data::prelude::AssetEvent::Removed(_),
                        ..
                    },
                ),
            ) = ev.as_ref()
        {
            return false;
        }
        true
    }));
    // Negative: no metadata removal for the same key
    assert!(events.iter().all(|e| {
        if let EventBox::Data(ev) = e
            && let iroha_data_model::events::data::prelude::DataEvent::Account(
                iroha_data_model::events::data::prelude::AccountEvent::MetadataRemoved(mc),
            ) = ev.as_ref()
        {
            return !(*mc.target() == *ALICE_ID && mc.key() == &tkey);
        }
        true
    }));
    // Publish the applied block and its exact membership before borrowing a view.
    // A world-only fixture commit cannot consume staged block metadata.
    // And the effect should be visible
    let tick_val = state
        .view()
        .world
        .map_account(&ALICE_ID, |a| a.value().metadata().get(&tkey).cloned())
        .unwrap();
    assert_eq!(tick_val, Some(Json::from(norito::json!(1))));
    // Drain any remaining events to keep tests isolated
    events.clear();
    Ok(())
}

#[test]
fn time_trigger_revalidates_a_sibling_replaced_after_matching() {
    use iroha_data_model::events::time::{ExecutionTime, TimeEventFilter};

    let world = World::with(
        [Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&ALICE_ID)],
        [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        [],
    );
    let time_origin_ms = 1_000;

    let replacer_id: TriggerId = "a_time_sibling_replacer".parse().unwrap();
    let victim_trigger_id: TriggerId = "b_time_sibling_replaced".parse().unwrap();
    let replacement_executed: Name = "time_replacement_executed".parse().unwrap();

    let mut genesis_instructions = Vec::<InstructionBox>::new();
    {
        let replacement = Trigger::new(
            victim_trigger_id.clone(),
            Action::new(
                vec![InstructionBox::from(SetKeyValue::account(
                    ALICE_ID.clone(),
                    replacement_executed.clone(),
                    Json::from(norito::json!(true)),
                ))],
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                TimeEventFilter::new(ExecutionTime::PreCommit),
            )
            .expect("replacement time-trigger action"),
        );
        let replacer = Trigger::new(
            replacer_id,
            Action::new(
                vec![
                    InstructionBox::from(Unregister::trigger(victim_trigger_id.clone())),
                    InstructionBox::from(Register::trigger(replacement)),
                ],
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                TimeEventFilter::new(ExecutionTime::PreCommit),
            )
            .expect("time-trigger sibling replacer action"),
        );
        let original_sibling = Trigger::new(
            victim_trigger_id.clone(),
            Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                TimeEventFilter::new(ExecutionTime::PreCommit),
            )
            .expect("original time-trigger sibling action"),
        );
        genesis_instructions.push(Register::trigger(replacer).into());
        genesis_instructions.push(Register::trigger(original_sibling).into());
    }
    let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 0);
    config.genesis_key = ALICE_KEYPAIR.clone();
    config.genesis_instructions = genesis_instructions;
    let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config).unwrap();
    chain.take_events().unwrap();
    let state = Arc::clone(chain.state());
    assert!(
        state
            .view()
            .latest_block()
            .expect("completed original State read")
            .unwrap()
            .header()
            .creation_time()
            < Duration::from_millis(time_origin_ms + 1)
    );
    let block2 = chain.proposal(Some(time_origin_ms + 2), Vec::new());
    chain.commit_proposal(
        block2,
        crate::sumeragi::test_chain::Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::default(),
    );
    let _ = chain.take_events().unwrap();

    {
        let view = state.view();
        let account = view.world.account(&ALICE_ID).expect("alice account");
        assert!(
            account.metadata().get(&replacement_executed).is_none(),
            "a replacement registered after ID matching must not execute in the same block",
        );
        let replacement = view
            .world
            .triggers()
            .time_triggers()
            .get(&victim_trigger_id)
            .expect("replacement sibling must remain registered");
        assert_eq!(replacement.repeats(), &Repeats::Exactly(1));
    }

    let block3 = chain.proposal(Some(time_origin_ms + 3), Vec::new());
    chain.commit_proposal(
        block3,
        crate::sumeragi::test_chain::Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::default(),
    );
    let _ = chain.take_events().unwrap();

    let view = state.view();
    let account = view.world.account(&ALICE_ID).expect("alice account");
    assert_eq!(
        account.metadata().get(&replacement_executed),
        Some(&Json::from(norito::json!(true))),
        "the replacement becomes eligible in the following block",
    );
}
#[test]
fn native_time_replay_refuses_a_foreign_genesis_without_publishing() {
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    let mut source = CertifiedTestChain::start(TestChainConfig::new(World::new(), 0)).unwrap();
    source.commit_at(2, Vec::new());
    let mut foreign = TestChainConfig::new(World::new(), 0);
    foreign.genesis_key = ALICE_KEYPAIR.clone();
    let mut target = CertifiedTestChain::start(foreign).unwrap();
    let original = target.state().latest_block_hash_fast();
    assert!(target.replay_from(&source).is_err());
    assert_eq!(target.height(), 1);
    assert_eq!(target.state().latest_block_hash_fast(), original);
}

#[test]
fn scheduled_time_trigger_retry_succeeds_once_and_consumes_repeats_on_success() {
    use iroha_data_model::events::trigger_completed::TriggerCompletedOutcome;
    use iroha_data_model::trigger::action::TimeTriggerRetryPolicy;
    let trigger_id: TriggerId = "time_retry_once".parse().unwrap();
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "retrycoin".parse().unwrap(),
    );
    let alice_asset_id = AssetId::new(asset_definition_id.clone(), ALICE_ID.clone());
    let retry_policy = TimeTriggerRetryPolicy {
        max_retries: NonZeroU32::new(1).unwrap(),
        retry_after_ms: NonZeroU64::new(5).unwrap(),
    };
    let world = World::with(
        [Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&ALICE_ID)],
        [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        [],
    );
    let time_origin_ms = 1_000;

    let mut genesis_instructions = Vec::<InstructionBox>::new();
    {
        let action = Action::new(
            vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                alice_asset_id.clone(),
            ))],
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            TimeEventFilter::new(ExecutionTime::Schedule(Schedule::starting_at(
                Duration::from_millis(time_origin_ms + 1),
            ))),
        )
        .expect("trigger action fixture satisfies validation invariants")
        .with_retry_policy(retry_policy)
        .expect("scheduled trigger fixture accepts its retry policy");
        genesis_instructions
            .push(Register::trigger(Trigger::new(trigger_id.clone(), action)).into());
    }
    let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 0);
    config.genesis_key = ALICE_KEYPAIR.clone();
    config.genesis_instructions = genesis_instructions;
    let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config).unwrap();
    chain.take_events().unwrap();
    let state = Arc::clone(chain.state());
    assert!(
        state
            .view()
            .latest_block()
            .expect("completed original State read")
            .unwrap()
            .header()
            .creation_time()
            < Duration::from_millis(time_origin_ms + 1)
    );
    let block2 = chain.proposal(Some(time_origin_ms + 6), Vec::new());
    {
        let view = state.view();
        assert!(
            view.time_triggers_due_for_block(&block2.header()),
            "scheduled retry trigger should be due for block2"
        );
    }
    chain.commit_proposal(
        block2,
        crate::sumeragi::test_chain::Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::default(),
    );
    let events2 = chain.take_events().unwrap();
    let completions2: Vec<_> = events2
        .iter()
        .filter_map(|event| match event {
            EventBox::TriggerCompleted(event) if event.trigger_id() == &trigger_id => Some(event),
            _ => None,
        })
        .collect();
    assert_eq!(
        completions2.len(),
        1,
        "expected one failed completion, events: {events2:#?}"
    );
    assert!(matches!(
        completions2[0].outcome(),
        TriggerCompletedOutcome::Failure(_)
    ));
    {
        let view = state.view();
        let action = view
            .world
            .triggers()
            .time_triggers()
            .get(&trigger_id)
            .expect("trigger should remain registered after first failure");
        assert_eq!(action.repeats, Repeats::Exactly(1));
        assert_eq!(
            action.retry_state,
            Some(TimeTriggerRetryState {
                retries_used: 1,
                next_retry_at_ms: time_origin_ms + 11,
            })
        );
    }
    let transaction = chain.sign(
        &ALICE_KEYPAIR,
        [Register::asset_definition(AssetDefinition::numeric(
            asset_definition_id.clone(),
            "retrycoin",
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(DomainId::try_new("wonderland", "universal").unwrap()),
        ))
        .into()],
        time_origin_ms + 7,
    );
    assert_eq!(
        chain.commit_at(time_origin_ms + 8, vec![transaction]),
        vec![true]
    );
    let events3 = chain.take_events().unwrap();
    assert!(!events3.iter().any(|event| matches!(event, EventBox::TriggerCompleted(completion) if completion.trigger_id() == &trigger_id)), "quiet retry interval must not execute early");
    let block4 = chain.proposal(Some(time_origin_ms + 12), Vec::new());
    chain.commit_proposal(
        block4,
        crate::sumeragi::test_chain::Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::default(),
    );
    let events4 = chain.take_events().unwrap();
    let completions4: Vec<_> = events4
        .iter()
        .filter_map(|event| match event {
            EventBox::TriggerCompleted(event) if event.trigger_id() == &trigger_id => Some(event),
            _ => None,
        })
        .collect();
    assert_eq!(completions4.len(), 1, "expected one retry completion");
    assert!(matches!(
        completions4[0].outcome(),
        TriggerCompletedOutcome::Success
    ));
    let view = state.view();
    let alice_asset = view
        .world
        .asset(&alice_asset_id)
        .expect("retry should mint the asset after the definition is registered");
    assert_eq!(&**alice_asset.value(), &Quantity::from(1_u32));
    assert!(
        view.world.triggers().ids().get(&trigger_id).is_none(),
        "one-shot trigger should be removed after successful retry"
    );
}
#[test]
fn scheduled_time_trigger_retry_budget_exhaustion_unregisters_trigger() {
    use iroha_data_model::events::trigger_completed::TriggerCompletedOutcome;
    use iroha_data_model::trigger::action::TimeTriggerRetryPolicy;
    let trigger_id: TriggerId = "time_retry_exhausted".parse().unwrap();
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "exhaustcoin".parse().unwrap(),
    );
    let alice_asset_id = AssetId::new(asset_definition_id.clone(), ALICE_ID.clone());
    let retry_policy = TimeTriggerRetryPolicy {
        max_retries: NonZeroU32::new(1).unwrap(),
        retry_after_ms: NonZeroU64::new(5).unwrap(),
    };
    let world = World::with(
        [Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&ALICE_ID)],
        [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        [],
    );
    let time_origin_ms = 1_000;

    let mut genesis_instructions = Vec::<InstructionBox>::new();
    {
        let action = Action::new(
            vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                alice_asset_id.clone(),
            ))],
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            TimeEventFilter::new(ExecutionTime::Schedule(Schedule::starting_at(
                Duration::from_millis(time_origin_ms + 1),
            ))),
        )
        .expect("trigger action fixture satisfies validation invariants")
        .with_retry_policy(retry_policy)
        .expect("scheduled trigger fixture accepts its retry policy");
        genesis_instructions
            .push(Register::trigger(Trigger::new(trigger_id.clone(), action)).into());
    }
    let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 0);
    config.genesis_key = ALICE_KEYPAIR.clone();
    config.genesis_instructions = genesis_instructions;
    let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config).unwrap();
    chain.take_events().unwrap();
    let state = Arc::clone(chain.state());
    assert!(
        state
            .view()
            .latest_block()
            .expect("completed original State read")
            .unwrap()
            .header()
            .creation_time()
            < Duration::from_millis(time_origin_ms + 1)
    );
    let block2 = chain.proposal(Some(time_origin_ms + 6), Vec::new());
    {
        let view = state.view();
        assert!(
            view.time_triggers_due_for_block(&block2.header()),
            "scheduled retry trigger should be due for block2"
        );
    }
    chain.commit_proposal(
        block2,
        crate::sumeragi::test_chain::Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::default(),
    );
    let events2 = chain.take_events().unwrap();
    let completions2: Vec<_> = events2
        .iter()
        .filter_map(|event| match event {
            EventBox::TriggerCompleted(event) if event.trigger_id() == &trigger_id => Some(event),
            _ => None,
        })
        .collect();
    assert_eq!(
        completions2.len(),
        1,
        "expected first failure event, events: {events2:#?}"
    );
    assert!(matches!(
        completions2[0].outcome(),
        TriggerCompletedOutcome::Failure(_)
    ));
    {
        let view = state.view();
        let action = view
            .world
            .triggers()
            .time_triggers()
            .get(&trigger_id)
            .expect("trigger should still exist while retry budget remains");
        assert_eq!(action.repeats, Repeats::Exactly(1));
        assert_eq!(
            action.retry_state,
            Some(TimeTriggerRetryState {
                retries_used: 1,
                next_retry_at_ms: time_origin_ms + 11,
            })
        );
    }
    let block3 = chain.proposal(Some(time_origin_ms + 12), Vec::new());
    chain.commit_proposal(
        block3,
        crate::sumeragi::test_chain::Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::default(),
    );
    let events3 = chain.take_events().unwrap();
    let completions3: Vec<_> = events3
        .iter()
        .filter_map(|event| match event {
            EventBox::TriggerCompleted(event) if event.trigger_id() == &trigger_id => Some(event),
            _ => None,
        })
        .collect();
    assert_eq!(completions3.len(), 1, "expected exhausted retry failure");
    assert!(matches!(
        completions3[0].outcome(),
        TriggerCompletedOutcome::Failure(_)
    ));
    let view = state.view();
    assert!(
        view.world.triggers().ids().get(&trigger_id).is_none(),
        "trigger should be unregistered after retry budget exhaustion"
    );
    assert!(
        view.world.asset(&alice_asset_id).is_err(),
        "failed trigger must not mint any asset"
    );
}
#[test]
fn periodic_time_trigger_drops_missed_ticks_while_retry_pending() {
    use iroha_data_model::events::trigger_completed::TriggerCompletedOutcome;
    use iroha_data_model::trigger::action::TimeTriggerRetryPolicy;
    let trigger_id: TriggerId = "time_retry_periodic".parse().unwrap();
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").unwrap(),
        "periodiccoin".parse().unwrap(),
    );
    let alice_asset_id = AssetId::new(asset_definition_id.clone(), ALICE_ID.clone());
    let retry_policy = TimeTriggerRetryPolicy {
        max_retries: NonZeroU32::new(1).unwrap(),
        retry_after_ms: NonZeroU64::new(5).unwrap(),
    };
    let world = World::with(
        [Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&ALICE_ID)],
        [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        [],
    );
    let time_origin_ms = 1_000;

    let mut genesis_instructions = Vec::<InstructionBox>::new();
    {
        let action = Action::new(
            vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                alice_asset_id.clone(),
            ))],
            Repeats::Exactly(3),
            ALICE_ID.clone(),
            TimeEventFilter::new(ExecutionTime::Schedule(
                Schedule::starting_at(Duration::from_millis(time_origin_ms + 1))
                    .with_period(Duration::from_millis(4)),
            )),
        )
        .expect("trigger action fixture satisfies validation invariants")
        .with_retry_policy(retry_policy)
        .expect("scheduled trigger fixture accepts its retry policy");
        genesis_instructions
            .push(Register::trigger(Trigger::new(trigger_id.clone(), action)).into());
    }
    let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 0);
    config.genesis_key = ALICE_KEYPAIR.clone();
    config.genesis_instructions = genesis_instructions;
    let mut chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config).unwrap();
    chain.take_events().unwrap();
    let state = Arc::clone(chain.state());
    assert!(
        state
            .view()
            .latest_block()
            .expect("completed original State read")
            .unwrap()
            .header()
            .creation_time()
            < Duration::from_millis(time_origin_ms + 1)
    );
    let block2 = chain.proposal(Some(time_origin_ms + 2), Vec::new());
    {
        let view = state.view();
        assert!(
            view.time_triggers_due_for_block(&block2.header()),
            "periodic retry trigger should be due for block2"
        );
    }
    chain.commit_proposal(
        block2,
        crate::sumeragi::test_chain::Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::default(),
    );
    let events2 = chain.take_events().unwrap();
    let completions2: Vec<_> = events2
        .iter()
        .filter_map(|event| match event {
            EventBox::TriggerCompleted(event) if event.trigger_id() == &trigger_id => Some(event),
            _ => None,
        })
        .collect();
    assert_eq!(
        completions2.len(),
        1,
        "expected initial failure, events: {events2:#?}"
    );
    assert!(matches!(
        completions2[0].outcome(),
        TriggerCompletedOutcome::Failure(_)
    ));
    {
        let view = state.view();
        let action = view
            .world
            .triggers()
            .time_triggers()
            .get(&trigger_id)
            .expect("periodic trigger should stay registered after first failure");
        assert_eq!(action.repeats, Repeats::Exactly(3));
        assert_eq!(
            action.retry_state,
            Some(TimeTriggerRetryState {
                retries_used: 1,
                next_retry_at_ms: time_origin_ms + 7,
            })
        );
    }
    let transaction = chain.sign(
        &ALICE_KEYPAIR,
        [Register::asset_definition(AssetDefinition::numeric(
            asset_definition_id.clone(),
            "periodiccoin",
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(DomainId::try_new("wonderland", "universal").unwrap()),
        ))
        .into()],
        time_origin_ms + 5,
    );
    assert_eq!(
        chain.commit_at(time_origin_ms + 6, vec![transaction]),
        vec![true]
    );
    let events3 = chain.take_events().unwrap();
    let completed_during_retry = events3.iter().any(|event| {
        matches!(event, EventBox::TriggerCompleted(event) if event.trigger_id() == &trigger_id)
    });
    assert!(
        !completed_during_retry,
        "scheduled ticks must be suppressed while retry is pending"
    );
    {
        let view = state.view();
        let action = view
            .world
            .triggers()
            .time_triggers()
            .get(&trigger_id)
            .expect("trigger should remain pending after suppressed block");
        assert_eq!(action.repeats, Repeats::Exactly(3));
        assert_eq!(
            action.retry_state,
            Some(TimeTriggerRetryState {
                retries_used: 1,
                next_retry_at_ms: time_origin_ms + 7,
            })
        );
    }
    let block4 = chain.proposal(Some(time_origin_ms + 8), Vec::new());
    chain.commit_proposal(
        block4,
        crate::sumeragi::test_chain::Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::default(),
    );
    let events4 = chain.take_events().unwrap();
    let completions4: Vec<_> = events4
        .iter()
        .filter_map(|event| match event {
            EventBox::TriggerCompleted(event) if event.trigger_id() == &trigger_id => Some(event),
            _ => None,
        })
        .collect();
    assert_eq!(completions4.len(), 1, "expected retry success");
    assert!(matches!(
        completions4[0].outcome(),
        TriggerCompletedOutcome::Success
    ));
    {
        let view = state.view();
        let alice_asset = view
            .world
            .asset(&alice_asset_id)
            .expect("retry success should mint exactly once");
        assert_eq!(&**alice_asset.value(), &Quantity::from(1_u32));
        let action = view
            .world
            .triggers()
            .time_triggers()
            .get(&trigger_id)
            .expect("periodic trigger should remain after successful retry");
        assert_eq!(action.repeats, Repeats::Exactly(2));
        assert_eq!(action.retry_state, None);
    }
    let block5 = chain.proposal(Some(time_origin_ms + 10), Vec::new());
    chain.commit_proposal(
        block5,
        crate::sumeragi::test_chain::Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::default(),
    );
    let events5 = chain.take_events().unwrap();
    let completions5: Vec<_> = events5
        .iter()
        .filter_map(|event| match event {
            EventBox::TriggerCompleted(event) if event.trigger_id() == &trigger_id => Some(event),
            _ => None,
        })
        .collect();
    assert_eq!(
        completions5.len(),
        1,
        "expected next scheduled tick only once"
    );
    assert!(matches!(
        completions5[0].outcome(),
        TriggerCompletedOutcome::Success
    ));
    let view = state.view();
    let alice_asset = view
        .world
        .asset(&alice_asset_id)
        .expect("periodic trigger should mint the next scheduled tick");
    assert_eq!(&**alice_asset.value(), &Quantity::from(2_u32));
    let action = view
        .world
        .triggers()
        .time_triggers()
        .get(&trigger_id)
        .expect("periodic trigger should still have one repeat left");
    assert_eq!(action.repeats, Repeats::Exactly(1));
    assert_eq!(action.retry_state, None);
}
#[test]
fn ivm_trigger_respects_pipeline_cycle_cap() {
    use iroha_data_model::{
        events::execute_trigger::{ExecuteTriggerEvent, ExecuteTriggerEventFilter},
        transaction::{Executable, IvmBytecode},
        trigger::{
            Trigger,
            action::{Action, Repeats},
        },
    };
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let mut state = authenticate_trigger_fixture(State::new(World::default(), kura, query_handle));
    let mut pipeline = state.pipeline.clone();
    pipeline.ivm_max_cycles_upper_bound = NonZeroU64::new(1).expect("one is non-zero");
    state.set_pipeline(pipeline);
    let block = ValidBlock::new_unverified_for_tests(
        state
            .view()
            .latest_block()
            .expect("completed original State read")
            .expect("original trigger parent")
            .as_ref()
            .clone(),
    );
    let mut state_block = state.block(block.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    Register::account(new_sample_account(&ALICE_ID))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    let trigger_id: TriggerId = "ivm_gas_guard".parse().unwrap();
    let mut raw = Vec::new();
    // Two ADD instructions cost two cycles in total, exceeding the configured cap of one.
    raw.extend_from_slice(
        &ivm::encoding::wide::encode_rr(ivm::instruction::wide::arithmetic::ADD, 3, 1, 2)
            .to_le_bytes(),
    );
    raw.extend_from_slice(
        &ivm::encoding::wide::encode_rr(ivm::instruction::wide::arithmetic::ADD, 3, 1, 2)
            .to_le_bytes(),
    );
    raw.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut bytecode = assemble_ivm_header(&raw);
    bytecode[8..16].copy_from_slice(&1_u64.to_le_bytes());
    let bytecode = IvmBytecode::from_compiled(bytecode);
    let filter = ExecuteTriggerEventFilter::new()
        .for_trigger(trigger_id.clone())
        .under_authority(ALICE_ID.clone());
    let action = Action::new(
        Executable::Ivm(bytecode),
        Repeats::Exactly(1),
        ALICE_ID.clone(),
        filter,
    )
    .expect("trigger action fixture satisfies validation invariants");
    Register::trigger(Trigger::new(trigger_id.clone(), action))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply_callback_for_testing()
        .expect("capture successful component callbacks");
    state_block.commit_world_overlay_for_testing().unwrap();
    let block = trigger_component_block(&state, 2);
    let mut state_block = state.block(block.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    // This authenticated global component callback explicitly carries the same
    // universal dataspace that the real internal output producer captures.
    assert!(matches!(
        crate::executor::root_scope::execution_root_scope(&mut stx),
        Ok(iroha_data_model::block::consensus::SumeragiRootScope::Global)
    ));
    assert!(crate::executor::root_scope::captured_dataspace(&mut stx).is_err());
    stx.current_dataspace_id = Some(iroha_model_base::topology::DataSpaceId::UNIVERSAL);
    stx.world.current_dataspace_id = Some(iroha_model_base::topology::DataSpaceId::UNIVERSAL);
    assert_eq!(
        crate::executor::root_scope::captured_dataspace(&mut stx).unwrap(),
        iroha_model_base::topology::DataSpaceId::UNIVERSAL
    );
    let evt = ExecuteTriggerEvent {
        trigger_id: trigger_id.clone(),
        authority: ALICE_ID.clone(),
        args: Json::default(),
    };
    let err = stx
        .execute_called_trigger(&trigger_id, &evt)
        .expect_err("trigger should exhaust the configured gas budget");
    let TransactionRejectionReason::Validation(ValidationFail::IvmFault(fault)) = err else {
        panic!("cycle exhaustion must retain its structured execution fault: {err:?}");
    };
    assert_eq!(
        fault.kind,
        iroha_data_model::executor::fault::IvmFaultKindV1::ExceededMaxCycles
    );
    assert_eq!(
        fault.site.selector,
        iroha_data_model::executor::fault::IvmInvocationSelectorV1::Generic
    );
    assert_eq!(
        fault.site.position,
        iroha_data_model::executor::fault::IvmFaultPositionV1::Execute { pc_offset: 4 }
    );
}
#[test]
fn generic_trigger_resolution_retains_original_allocation_refusal() {
    use iroha_allocation::AllocationRefusal;
    use iroha_data_model::{
        events::time::{ExecutionTime, TimeEventFilter},
        transaction::{Executable, IvmBytecode},
        trigger::{
            Trigger,
            action::{Action, Repeats},
        },
    };

    let _limits = ivm::ivm_cache::CacheLimitsGuard::new(ivm::ivm_cache::CacheLimits {
        capacity: 0,
        max_bytes: 0,
        max_decoded_ops: 0,
    });
    let state = State::new(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let block = new_dummy_block_with_payload(|header| {
        header.set_height(NonZeroU64::new(1).unwrap());
        header.creation_time_ms = 1;
    });
    let mut state_block = state.block(block.as_ref().header());
    let mut transaction = state_block.transaction();
    Register::account(new_sample_account(&ALICE_ID))
        .execute(&ALICE_ID, &mut transaction)
        .unwrap();
    let bytecode = IvmBytecode::from_compiled(assemble_ivm_header(
        &encoding::wide::encode_halt().to_le_bytes(),
    ));
    let blob_hash = HashOf::new(&bytecode);
    Register::trigger(Trigger::new(
        "generic_allocation_refusal".parse().unwrap(),
        Action::new(
            Executable::Ivm(bytecode),
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            TimeEventFilter::new(ExecutionTime::PreCommit),
        )
        .unwrap(),
    ))
    .execute(&ALICE_ID, &mut transaction)
    .unwrap();
    let budget = state.ivm_execution_budget();
    let original_limit = budget.limit_bytes();
    budget.set_limit_bytes(0);
    assert!(transaction.resolve_ivm_trigger_program(&blob_hash).is_err());
    let reason = transaction
        .borrow_execution_deferral()
        .expect("original local refusal");
    assert!(matches!(
        reason.allocation_refusal(),
        Some(AllocationRefusal::ExceedsLimit { limit_bytes: 0, .. })
    ));
    let original_reason = reason.reason();
    let original_allocation = reason.allocation_refusal().unwrap().clone();
    drop(reason);
    assert_eq!(transaction.last_tx_gas_used, 0);
    budget.set_limit_bytes(original_limit);
    assert!(matches!(
        transaction.resolve_ivm_trigger_program(&blob_hash),
        Ok(Some(ResolvedIvmTriggerProgram::Generic(_)))
    ));
    let retained = transaction.borrow_execution_deferral().unwrap();
    assert_eq!(retained.reason(), original_reason);
    assert_eq!(retained.allocation_refusal(), Some(&original_allocation));
}

#[test]
fn ivm_time_trigger_reuses_cache_across_blocks() {
    if crate::unit_test_support::run_in_isolated_harness(
        "state::tests::ivm_time_trigger_reuses_cache_across_blocks",
    ) {
        return;
    }
    // Positive reuse requires enabled retention throughout both owner lifetimes.
    let _cache_limits = ivm::ivm_cache::CacheLimitsGuard::new(ivm::ivm_cache::CacheLimits {
        capacity: iroha_config::parameters::defaults::pipeline::CACHE_SIZE,
        max_bytes: iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_BYTES,
        max_decoded_ops: iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_DECODED_OPS,
    });
    use iroha_data_model::{
        events::time::{ExecutionTime, TimeEventFilter},
        transaction::{Executable, IvmBytecode},
        trigger::{
            Trigger,
            action::{Action, Repeats},
        },
    };
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(World::default(), kura, query_handle);
    let block1 = new_dummy_block_with_payload(|h| {
        h.set_height(NonZeroU64::new(1).unwrap());
        h.creation_time_ms = 1;
    });
    let mut state_block = state.block(block1.as_ref().header());
    let mut stx = state_block.transaction();
    Register::domain(Domain::new(
        DomainId::try_new("wonderland", "universal").unwrap(),
    ))
    .execute(&ALICE_ID, &mut stx)
    .unwrap();
    Register::account(new_sample_account(&ALICE_ID))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    let trigger_id: TriggerId = "ivm_time_cache".parse().unwrap();
    let mut raw = Vec::new();
    raw.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let bytecode = IvmBytecode::from_compiled(assemble_ivm_header(&raw));
    let trigger = Trigger::new(
        trigger_id,
        Action::new(
            Executable::Ivm(bytecode),
            Repeats::Exactly(2),
            ALICE_ID.clone(),
            TimeEventFilter::new(ExecutionTime::PreCommit),
        )
        .expect("trigger action fixture satisfies validation invariants"),
    );
    Register::trigger(trigger)
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    stx.apply();
    state_block.commit_world_overlay_for_testing().unwrap();
    let state = authenticate_trigger_fixture(state);
    let block2 = trigger_component_block(&state, 2);
    let (state_block2, recording, outputs, _) =
        crate::state::run_empty_network_owner_fixture(&state, block2.as_ref());
    assert_eq!(outputs.len(), 1);
    assert!(
        matches!(&outputs[0], iroha_data_model::block::execution_output::ExecutionOutputV1::Time(row) if row.result.is_ok())
    );
    state_block2.commit_world_overlay_for_testing().unwrap();
    let after_first = state.trigger_ivm_cache.lock().stats();
    drop(recording);
    let block3 = trigger_component_block(&state, 3);
    let (state_block3, _recording, outputs, _) =
        crate::state::run_empty_network_owner_fixture(&state, block3.as_ref());
    assert_eq!(outputs.len(), 1);
    assert!(
        matches!(&outputs[0], iroha_data_model::block::execution_output::ExecutionOutputV1::Time(row) if row.result.is_ok())
    );
    state_block3.commit_world_overlay_for_testing().unwrap();
    let after_second = state.trigger_ivm_cache.lock().stats();
    assert!(
        after_second.metadata_hits > after_first.metadata_hits,
        "warm generic trigger must resolve its retained summary without parsing"
    );
    assert!(
        after_second.runtime_hits > after_first.runtime_hits,
        "warm generic trigger must check out its retained dirty-reset runtime"
    );
    assert_eq!(
        after_second.artifact_hashes, after_first.artifact_hashes,
        "warm generic trigger must not hash or copy its stored program"
    );
    assert_eq!(
        after_second.preparations, after_first.preparations,
        "warm generic trigger must not parse, validate, or predecode its program again"
    );
    assert_eq!(
        after_second.prepared_loads, after_first.prepared_loads,
        "warm generic trigger must not load its program into another VM"
    );
    assert_eq!(
        after_second.template_builds, after_first.template_builds,
        "warm generic trigger must not reconstruct its runtime template"
    );
}
#[test]
fn contract_query_cache_isolated_and_reuses_owned_runtime() {
    // Positive reuse requires enabled retention throughout both owner lifetimes.
    let _cache_limits = ivm::ivm_cache::CacheLimitsGuard::new(ivm::ivm_cache::CacheLimits {
        capacity: iroha_config::parameters::defaults::pipeline::CACHE_SIZE,
        max_bytes: iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_BYTES,
        max_decoded_ops: iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_DECODED_OPS,
    });
    use iroha_data_model::smart_contract::manifest::EntryPointKind;
    const GAS_LIMIT: u64 = 10_000;
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(World::default(), kura, query_handle);
    let mut program = ivm::ProgramMetadata::default().encode();
    let interface = ivm::EmbeddedContractInterfaceV1 {
        events: Vec::new(),
        enum_types: Vec::new(),
        permissions: Vec::new(),
        callables: vec![crate::ivm_test_support::unit_callable(0)],
        seiyaku_name: "QueryCacheFixture".to_owned(),
        compiler_fingerprint: "iroha-core-state-tests".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
            name: "inspect".to_owned(),
            kind: EntryPointKind::View,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".to_owned()),
            return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
            }),
            authorization: iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
            entry_pc: 0,
        }],
        error_messages: Vec::new(),
        error_types: Vec::new(),
        states: Vec::new(),
    };
    program.extend_from_slice(&interface.encode_section());
    program.extend_from_slice(&crate::ivm_test_support::unit_return());
    let code_hash = ivm::contract_code_hash(&program);
    let first = state
        .prepare_contract_query_program(code_hash, &program)
        .expect("cold preparation");
    let allocation = {
        let mut runtime = first
            .checkout_runtime(GAS_LIMIT, ivm::Memory::HEAP_MAX_SIZE)
            .expect("cold runtime");
        let allocation = runtime
            .memory
            .load_region(0, 1)
            .expect("code memory")
            .as_ptr();
        runtime.set_register(7, 99);
        runtime
            .memory
            .preload_input(0, &[0xA5])
            .expect("dirty input page");
        allocation
    };
    // A trusted content-addressed hit neither reads nor reparses the byte
    // slice. The empty slice makes accidental fallback validation fail.
    let second = state
        .prepare_contract_query_program(code_hash, &[])
        .expect("content-addressed hit");
    let runtime = second
        .checkout_runtime(GAS_LIMIT, ivm::Memory::HEAP_MAX_SIZE)
        .expect("warm runtime");
    assert_eq!(runtime.register(7), 0);
    assert_eq!(runtime.remaining_gas(), GAS_LIMIT);
    assert_eq!(
        runtime
            .memory
            .load_region(0, 1)
            .expect("code memory")
            .as_ptr(),
        allocation
    );
    assert_eq!(
        runtime
            .memory
            .load_region(0x0020_0000, 1)
            .expect("input memory"),
        &[0]
    );
    drop(runtime);
    let summary_stats = state.contract_query_ivm_cache_stats();
    let prepared_stats = state.contract_query_prepared_cache_stats();
    assert_eq!(summary_stats.metadata_misses, 1);
    assert_eq!(summary_stats.metadata_hits, 1);
    assert_eq!(prepared_stats.runtime_misses, 1);
    assert_eq!(prepared_stats.runtime_hits, 1);
    assert_eq!(prepared_stats.runtime_prepared_loads, 1);
    assert_eq!(prepared_stats.runtime_template_builds, 1);
    assert_eq!(prepared_stats.runtime_dirty_resets, 2);
    assert_eq!(
        state.trigger_ivm_cache.lock().stats().metadata_misses,
        0,
        "public query preparation must not churn the consensus trigger cache"
    );
}
#[test]
fn execute_called_trigger_fails_closed_on_missing_bytecode_with_warm_prepared_artifact() {
    use iroha_data_model::{
        events::execute_trigger::{ExecuteTriggerEvent, ExecuteTriggerEventFilter},
        transaction::{Executable, IvmBytecode},
        trigger::{
            Trigger,
            action::{Action, Repeats},
        },
    };
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let mut state = State::new(World::default(), kura, query_handle);
    let trigger_id: TriggerId = "missing_bytecode_by_call".parse().unwrap();
    let program = kotodama_lang::compiler::Compiler::new()
        .compile_source(
            r"
seiyaku MissingBytecodeTrigger { permission missing_bytecode_probe;
  kotoage fn main(int marker) authorize(missing_bytecode_probe) {
let _marker = marker;
  }
}
",
        )
        .expect("compile missing-bytecode trigger probe");
    let code_hash = ivm::contract_code_hash(&program);
    state
        .pipeline_ivm_prepared_cache
        .read()
        .get_or_prepare(code_hash, &program)
        .expect("prewarm authenticated trigger artifact");
    let bytecode = IvmBytecode::from_compiled(program);
    let blob_hash = HashOf::new(&bytecode);
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    {
        let mut stx = state_block.transaction_for_callback_testing();
        Register::domain(Domain::new(
            DomainId::try_new("wonderland", "universal").unwrap(),
        ))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
        Register::account(new_sample_account(&ALICE_ID))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let action = Action::new(
            Executable::Ivm(bytecode),
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(ALICE_ID.clone()),
        )
        .expect("trigger action fixture satisfies validation invariants");
        Register::trigger(Trigger::new(trigger_id.clone(), action))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply_callback_for_testing()
            .expect("capture successful component callbacks");
    }
    state_block.commit_world_overlay_for_testing().unwrap();
    assert!(
        state.world.triggers.remove_contract_for_test(blob_hash),
        "contract entry should be removed for test setup"
    );
    assert!(
        state
            .pipeline_ivm_prepared_cache
            .read()
            .get(code_hash)
            .is_some(),
        "adversarial fixture must retain a warm prepared artifact"
    );
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    let mut stx = state_block.transaction_for_callback_testing();
    let event = ExecuteTriggerEvent {
        trigger_id: trigger_id.clone(),
        authority: ALICE_ID.clone(),
        args: Json::default(),
    };
    let err = stx
        .execute_called_trigger(&trigger_id, &event)
        .expect_err("missing bytecode should reject trigger execution");
    let err_debug = format!("{err:?}");
    assert!(
        err_debug.contains("missing trigger bytecode"),
        "unexpected error: {err_debug}"
    );
    drop(stx);
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    assert!(
        view.world.triggers().ids().get(&trigger_id).is_some(),
        "failed execution should not unregister the trigger in the rolled-back transaction"
    );
}
#[test]
fn execute_trigger_isi_rejects_depleted_entry_and_prunes_trigger() {
    use iroha_data_model::{
        events::execute_trigger::ExecuteTriggerEventFilter,
        trigger::{
            Trigger,
            action::{Action, Repeats},
        },
    };
    use iroha_executor_data_model::permission::trigger::CanExecuteTrigger;
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(World::default(), kura, query_handle);
    let trigger_id: TriggerId = "depleted_by_call".parse().unwrap();
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    {
        let mut stx = state_block.transaction();
        Register::domain(Domain::new(
            DomainId::try_new("wonderland", "universal").unwrap(),
        ))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
        Register::account(new_sample_account(&ALICE_ID))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(new_sample_account(&BOB_ID))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let action = Action::new(
            Vec::<InstructionBox>::new(),
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(ALICE_ID.clone()),
        )
        .expect("trigger action fixture satisfies validation invariants");
        Register::trigger(Trigger::new(trigger_id.clone(), action))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let permission: Permission = CanExecuteTrigger {
            trigger: trigger_id.clone(),
        }
        .into();
        Grant::account_permission(permission, BOB_ID.clone())
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
    }
    state_block.commit_world_overlay_for_testing().unwrap();
    {
        let mut trigger_block = state.world.triggers.block();
        let mut trigger_tx = trigger_block.transaction();
        let updated = trigger_tx.inspect_by_id_mut(&trigger_id, |action| {
            action.set_repeats(Repeats::Exactly(0));
        });
        assert!(
            updated.is_some(),
            "trigger should be present for corruption"
        );
        trigger_tx.apply();
        trigger_block.commit();
    }
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    let mut stx = state_block.transaction();
    assert!(
        stx.can_execute_trigger_for(&BOB_ID, &trigger_id),
        "fixture must prime the stale permission cache",
    );
    let err = ExecuteTrigger::new(trigger_id.clone())
        .execute(&BOB_ID, &mut stx)
        .expect_err("depleted trigger should be rejected");
    assert!(matches!(err, Error::Find(FindError::Trigger(id)) if id == trigger_id));
    stx.apply();
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    assert!(
        view.world.triggers().ids().get(&trigger_id).is_none(),
        "depleted trigger should be removed"
    );
    let permission: Permission = CanExecuteTrigger {
        trigger: trigger_id.clone(),
    }
    .into();
    assert!(
        !view
            .world
            .account_permissions()
            .get(&*BOB_ID)
            .is_some_and(|permissions| permissions.contains(&permission)),
        "depleted-trigger cleanup must remove the stale account permission",
    );
}
#[test]
fn execute_called_trigger_rejects_disabled_trigger() {
    use iroha_data_model::events::execute_trigger::{
        ExecuteTriggerEvent, ExecuteTriggerEventFilter,
    };
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(World::default(), kura, query_handle);
    let trigger_id: TriggerId = "disabled_by_call".parse().unwrap();
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    {
        let mut stx = state_block.transaction();
        Register::domain(Domain::new(
            DomainId::try_new("wonderland", "universal").unwrap(),
        ))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
        Register::account(new_sample_account(&ALICE_ID))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let mut metadata = Metadata::default();
        metadata.insert(
            crate::smartcontracts::isi::triggers::TRIGGER_ENABLED_METADATA_KEY
                .parse::<Name>()
                .expect("valid metadata key"),
            Json::from(false),
        );
        let action = Action::new(
            Vec::<InstructionBox>::new(),
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(ALICE_ID.clone()),
        )
        .expect("trigger action fixture satisfies validation invariants")
        .with_metadata(metadata);
        Register::trigger(Trigger::new(trigger_id.clone(), action))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
    }
    state_block.commit_world_overlay_for_testing().unwrap();
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    let mut stx = state_block.transaction();
    let event = ExecuteTriggerEvent {
        trigger_id: trigger_id.clone(),
        authority: ALICE_ID.clone(),
        args: Json::default(),
    };
    let err = stx
        .execute_called_trigger(&trigger_id, &event)
        .expect_err("disabled trigger should be rejected");
    match err {
        TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::Find(FindError::Trigger(id)),
        )) => assert_eq!(id, trigger_id),
        other => panic!("unexpected rejection: {other:?}"),
    }
    stx.apply();
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    assert!(
        view.world.triggers().ids().get(&trigger_id).is_some(),
        "disabled trigger should remain registered"
    );
}
#[test]
fn execute_called_trigger_rejects_numeric_zero_enabled_trigger() {
    use iroha_data_model::events::execute_trigger::{
        ExecuteTriggerEvent, ExecuteTriggerEventFilter,
    };
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(World::default(), kura, query_handle);
    let trigger_id: TriggerId = "numeric_zero_by_call".parse().unwrap();
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    {
        let mut stx = state_block.transaction();
        Register::domain(Domain::new(
            DomainId::try_new("wonderland", "universal").unwrap(),
        ))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
        Register::account(new_sample_account(&ALICE_ID))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let mut metadata = Metadata::default();
        metadata.insert(
            crate::smartcontracts::isi::triggers::TRIGGER_ENABLED_METADATA_KEY
                .parse::<Name>()
                .expect("valid metadata key"),
            Json::from(0_u64),
        );
        let action = Action::new(
            Vec::<InstructionBox>::new(),
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(ALICE_ID.clone()),
        )
        .expect("trigger action fixture satisfies validation invariants")
        .with_metadata(metadata);
        Register::trigger(Trigger::new(trigger_id.clone(), action))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
    }
    state_block.commit_world_overlay_for_testing().unwrap();
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    let mut stx = state_block.transaction();
    let event = ExecuteTriggerEvent {
        trigger_id: trigger_id.clone(),
        authority: ALICE_ID.clone(),
        args: Json::default(),
    };
    let err = stx
        .execute_called_trigger(&trigger_id, &event)
        .expect_err("numeric-zero enabled trigger should be rejected");
    match err {
        TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::Find(FindError::Trigger(id)),
        )) => assert_eq!(id, trigger_id),
        other => panic!("unexpected rejection: {other:?}"),
    }
    stx.apply();
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    let trigger = view
        .world
        .triggers()
        .by_call_triggers()
        .get(&trigger_id)
        .expect("disabled trigger should remain registered");
    assert_eq!(trigger.repeats(), &Repeats::Exactly(1));
    assert!(
        view.world
            .triggers()
            .active_by_call_trigger_ids()
            .get(&trigger_id)
            .is_none(),
        "numeric-zero enabled trigger must not appear active"
    );
}
#[test]
fn execute_called_trigger_rejects_malformed_enabled_trigger() {
    use iroha_data_model::events::execute_trigger::{
        ExecuteTriggerEvent, ExecuteTriggerEventFilter,
    };
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(World::default(), kura, query_handle);
    let trigger_id: TriggerId = "malformed_enabled_by_call".parse().unwrap();
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    {
        let mut stx = state_block.transaction();
        Register::domain(Domain::new(
            DomainId::try_new("wonderland", "universal").unwrap(),
        ))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
        Register::account(new_sample_account(&ALICE_ID))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        let mut metadata = Metadata::default();
        metadata.insert(
            crate::smartcontracts::isi::triggers::TRIGGER_ENABLED_METADATA_KEY
                .parse::<Name>()
                .expect("valid metadata key"),
            Json::from(norito::json!({"malformed": true})),
        );
        let action = Action::new(
            Vec::<InstructionBox>::new(),
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(ALICE_ID.clone()),
        )
        .expect("trigger action fixture satisfies validation invariants")
        .with_metadata(metadata);
        Register::trigger(Trigger::new(trigger_id.clone(), action))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
    }
    state_block.commit_world_overlay_for_testing().unwrap();
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    let mut stx = state_block.transaction();
    let event = ExecuteTriggerEvent {
        trigger_id: trigger_id.clone(),
        authority: ALICE_ID.clone(),
        args: Json::default(),
    };
    let err = stx
        .execute_called_trigger(&trigger_id, &event)
        .expect_err("malformed enabled metadata should fail closed");
    match err {
        TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::Find(FindError::Trigger(id)),
        )) => assert_eq!(id, trigger_id),
        other => panic!("unexpected rejection: {other:?}"),
    }
    stx.apply();
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    let trigger = view
        .world
        .triggers()
        .by_call_triggers()
        .get(&trigger_id)
        .expect("disabled trigger should remain registered");
    assert_eq!(trigger.repeats(), &Repeats::Exactly(1));
    assert!(
        view.world
            .triggers()
            .active_by_call_trigger_ids()
            .get(&trigger_id)
            .is_none(),
        "malformed enabled trigger must not appear active"
    );
}
#[test]
fn execute_data_triggers_dfs_skips_disabled_trigger() {
    use iroha_data_model::prelude::DataEvent;
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(World::default(), kura, query_handle);
    let trigger_id: TriggerId = "disabled_data_trigger".parse().unwrap();
    let flag_key: Name = "flag".parse().expect("valid name");
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    {
        let mut stx = state_block.transaction();
        Register::domain(Domain::new(
            DomainId::try_new("wonderland", "universal").unwrap(),
        ))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
        Register::account(new_sample_account(&ALICE_ID))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.world.add_account_permission(
            &ALICE_ID,
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: ALICE_ID.clone(),
            }
            .into(),
        );
        let mut metadata = Metadata::default();
        metadata.insert(
            crate::smartcontracts::isi::triggers::TRIGGER_ENABLED_METADATA_KEY
                .parse::<Name>()
                .expect("valid metadata key"),
            Json::from(false),
        );
        let action = Action::new(
            vec![InstructionBox::from(SetKeyValue::account(
                ALICE_ID.clone(),
                flag_key.clone(),
                Json::from(true),
            ))],
            Repeats::Indefinitely,
            ALICE_ID.clone(),
            data_pre::DataEventFilter::Any,
        )
        .expect("trigger action fixture satisfies validation invariants")
        .with_metadata(metadata);
        Register::trigger(Trigger::new(trigger_id.clone(), action))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
    }
    state_block.commit_world_overlay_for_testing().unwrap();
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    let mut stx = state_block.transaction();
    let event = data_pre::DomainEvent::Created(
        Domain::new(DomainId::try_new("alpha", "universal").unwrap()).build(&ALICE_ID),
    );
    stx.world
        .internal_event_buf
        .push(SharedDataEvent::from(DataEvent::Domain(event)));
    let steps = stx
        .execute_data_triggers_dfs(&ALICE_ID)
        .expect("disabled trigger should be skipped");
    assert!(steps.is_empty(), "disabled trigger should not execute");
    stx.apply();
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    assert!(
        view.world.triggers().ids().get(&trigger_id).is_some(),
        "disabled trigger should remain registered"
    );
    let flag_val = view
        .world
        .map_account(&ALICE_ID, |account| {
            account.value().metadata().get(&flag_key).cloned()
        })
        .unwrap();
    assert!(flag_val.is_none(), "disabled trigger must not mutate state");
}
#[test]
fn execute_data_triggers_dfs_skips_numeric_zero_and_malformed_enabled_triggers() {
    use iroha_data_model::prelude::DataEvent;
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(World::default(), kura, query_handle);
    let numeric_trigger_id: TriggerId = "numeric_zero_data_trigger".parse().unwrap();
    let malformed_trigger_id: TriggerId = "malformed_enabled_data_trigger".parse().unwrap();
    let numeric_flag: Name = "numeric_data_flag".parse().expect("valid name");
    let malformed_flag: Name = "malformed_data_flag".parse().expect("valid name");
    let enabled_key = crate::smartcontracts::isi::triggers::TRIGGER_ENABLED_METADATA_KEY
        .parse::<Name>()
        .expect("valid metadata key");
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    {
        let mut stx = state_block.transaction();
        Register::domain(Domain::new(
            DomainId::try_new("wonderland", "universal").unwrap(),
        ))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
        Register::account(new_sample_account(&ALICE_ID))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.world.add_account_permission(
            &ALICE_ID,
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: ALICE_ID.clone(),
            }
            .into(),
        );
        for (trigger_id, flag_key, enabled_value) in [
            (
                numeric_trigger_id.clone(),
                numeric_flag.clone(),
                Json::from(0_u64),
            ),
            (
                malformed_trigger_id.clone(),
                malformed_flag.clone(),
                Json::from(norito::json!([true])),
            ),
        ] {
            let mut metadata = Metadata::default();
            metadata.insert(enabled_key.clone(), enabled_value);
            let action = Action::new(
                vec![InstructionBox::from(SetKeyValue::account(
                    ALICE_ID.clone(),
                    flag_key,
                    Json::from(true),
                ))],
                Repeats::Exactly(1),
                ALICE_ID.clone(),
                data_pre::DataEventFilter::Any,
            )
            .expect("trigger action fixture satisfies validation invariants")
            .with_metadata(metadata);
            Register::trigger(Trigger::new(trigger_id, action))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
        }
        stx.apply();
    }
    state_block.commit_world_overlay_for_testing().unwrap();
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    let mut stx = state_block.transaction();
    let event = data_pre::DomainEvent::Created(
        Domain::new(DomainId::try_new("alpha", "universal").unwrap()).build(&ALICE_ID),
    );
    stx.world
        .internal_event_buf
        .push(SharedDataEvent::from(DataEvent::Domain(event)));
    let steps = stx
        .execute_data_triggers_dfs(&ALICE_ID)
        .expect("disabled data triggers should be skipped");
    assert!(
        steps.is_empty(),
        "numeric-zero and malformed data triggers must not execute"
    );
    stx.apply();
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    let account = view.world.account(&ALICE_ID).expect("alice account");
    assert!(
        account.metadata().get(&numeric_flag).is_none(),
        "numeric-zero data trigger must not mutate state"
    );
    assert!(
        account.metadata().get(&malformed_flag).is_none(),
        "malformed-enabled data trigger must not mutate state"
    );
    for trigger_id in [&numeric_trigger_id, &malformed_trigger_id] {
        let trigger = view
            .world
            .triggers()
            .data_triggers()
            .get(trigger_id)
            .expect("disabled trigger should remain registered");
        assert_eq!(trigger.repeats(), &Repeats::Exactly(1));
        assert!(
            view.world
                .triggers()
                .active_data_trigger_ids()
                .get(trigger_id)
                .is_none(),
            "disabled data trigger must not appear active"
        );
    }
}
#[test]
fn depleted_data_trigger_is_pruned_before_event_scan_without_mutating_state() {
    use iroha_data_model::prelude::DataEvent;
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(World::default(), kura, query_handle);
    let trigger_id: TriggerId = "depleted_data_trigger".parse().unwrap();
    let flag_key: Name = "depleted_data_flag".parse().expect("valid name");
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    {
        let mut stx = state_block.transaction();
        Register::domain(Domain::new(
            DomainId::try_new("wonderland", "universal").unwrap(),
        ))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
        Register::account(new_sample_account(&ALICE_ID))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.world.add_account_permission(
            &ALICE_ID,
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: ALICE_ID.clone(),
            }
            .into(),
        );
        let action = Action::new(
            vec![InstructionBox::from(SetKeyValue::account(
                ALICE_ID.clone(),
                flag_key.clone(),
                Json::from(true),
            ))],
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            data_pre::DataEventFilter::Any,
        )
        .expect("trigger action fixture satisfies validation invariants");
        Register::trigger(Trigger::new(trigger_id.clone(), action))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply();
    }
    state_block.commit_world_overlay_for_testing().unwrap();
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    let mut stx = state_block.transaction();
    stx.decrease_trigger_repeats_and_cleanup(&trigger_id);
    assert!(
        stx.world.triggers.ids().get(&trigger_id).is_none(),
        "repeat depletion must remove the trigger before bounded event scanning"
    );
    let event = data_pre::DomainEvent::Created(
        Domain::new(DomainId::try_new("alpha", "universal").unwrap()).build(&ALICE_ID),
    );
    stx.world
        .internal_event_buf
        .push(SharedDataEvent::from(DataEvent::Domain(event)));
    let steps = stx
        .execute_data_triggers_dfs(&ALICE_ID)
        .expect("depleted trigger should be pruned without error");
    assert!(steps.is_empty(), "depleted trigger must not execute");
    stx.apply();
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    assert!(
        view.world.triggers().ids().get(&trigger_id).is_none(),
        "depleted data trigger should be pruned"
    );
    let flag_val = view
        .world
        .map_account(&ALICE_ID, |account| {
            account.value().metadata().get(&flag_key).cloned()
        })
        .unwrap();
    assert!(
        flag_val.is_none(),
        "depleted data trigger must not mutate state"
    );
}
#[test]
fn execute_data_triggers_dfs_clears_events_without_triggers() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new(World::default(), kura, query_handle);
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    let mut stx = state_block.transaction();
    Register::domain(Domain::new(
        DomainId::try_new("wonderland", "universal").unwrap(),
    ))
    .execute(&ALICE_ID, &mut stx)
    .unwrap();
    Register::account(new_sample_account(&ALICE_ID))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    let flag_key: Name = "flag".parse().expect("valid name");
    SetKeyValue::account(ALICE_ID.clone(), flag_key, Json::from(norito::json!(true)))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
    assert!(
        !stx.world.internal_event_buf.is_empty(),
        "expected data events from metadata update"
    );
    assert!(
        stx.world.triggers.data_triggers().is_empty(),
        "test should run without data triggers"
    );
    let steps = stx
        .execute_data_triggers_dfs(&ALICE_ID)
        .expect("no triggers should yield ok result");
    assert!(steps.is_empty(), "no data triggers should execute");
    assert!(
        stx.world.internal_event_buf.is_empty(),
        "buffered events should be cleared when no triggers are registered"
    );
    stx.apply();
    state_block.commit_world_overlay_for_testing().unwrap();
}
#[test]
fn execute_data_triggers_dfs_uses_registered_trigger_authority() {
    use iroha_primitives::json::Json;
    use iroha_test_samples::{ALICE_ID, BOB_ID};
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = authenticate_trigger_fixture(State::new(World::default(), kura, query_handle));
    state
        .lane_manifests
        .read()
        .ensure_lane_ready(LaneId::SINGLE)
        .expect("the existing test State owns its active default Network route");
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
    let flag_key: Name = "trigger_authority".parse().unwrap();
    let trigger_id: TriggerId = "data_trigger_registered_authority".parse().unwrap();
    let header = state
        .view()
        .latest_block()
        .expect("completed original State read")
        .expect("original trigger parent")
        .header();
    let mut state_block = state.block(header);
    {
        let mut stx = state_block.transaction_for_callback_testing();
        seed_trigger_domain_name_lease(
            &mut stx,
            &ALICE_ID,
            &DomainId::try_new("wonderland", "universal").expect("asset-owning domain"),
        );
        Register::domain(Domain::new(
            DomainId::try_new("wonderland", "universal").unwrap(),
        ))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
        Register::account(new_sample_account(&ALICE_ID))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        Register::account(new_sample_account(&BOB_ID))
            .execute(&BOB_ID, &mut stx)
            .unwrap();
        stx.world.add_account_permission(
            &ALICE_ID,
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: BOB_ID.clone(),
            }
            .into(),
        );
        Register::asset_definition(AssetDefinition::numeric(
            asset_def_id.clone(),
            "rose",
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(DomainId::try_new("wonderland", "universal").unwrap()),
        ))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
        let data_trigger = Trigger::new(
            trigger_id.clone(),
            Action::new(
                vec![InstructionBox::from(SetKeyValue::account(
                    BOB_ID.clone(),
                    flag_key.clone(),
                    Json::from(norito::json!("ok")),
                ))],
                Repeats::Exactly(1),
                BOB_ID.clone(),
                data_pre::DataEventFilter::Asset(
                    data_pre::AssetEventFilter::new().for_asset(asset_id.clone()),
                ),
            )
            .expect("trigger action fixture satisfies validation invariants"),
        );
        Register::trigger(data_trigger)
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply_callback_for_testing()
            .expect("capture successful component callbacks");
    }
    state_block.commit_world_overlay_for_testing().unwrap();
    let header = trigger_component_block(&state, 2).as_ref().header();
    let signed = signed_callback_boundary_source(
        &state,
        &header,
        vec![Mint::asset_quantity(1_u32, asset_id.clone()).into()],
    );
    let signed_hash = signed.hash();
    let source = {
        let (parent, cadence, max_clock_drift, limits) = {
            let view = state.view();
            let parent = view
                .latest_block()
                .expect("completed original Network trigger parent read")
                .expect("original Network trigger parent");
            let height = parent.header().height().get().checked_add(1).unwrap();
            let cadence = Duration::from_millis(
                view.world()
                    .consensus_schedule()
                    .ready(height)
                    .expect("original schedule authorizes the Network trigger successor")
                    .params
                    .block_time_ms,
            );
            (
                parent,
                cadence,
                view.world().parameters().sumeragi().max_clock_drift(),
                view.world().parameters().transaction(),
            )
        };
        let time = parent
            .header()
            .creation_time()
            .checked_add(cadence)
            .unwrap()
            .max(
                signed
                    .creation_time()
                    .checked_add(Duration::from_millis(1))
                    .unwrap(),
            );
        let (_, time_source) = iroha_primitives::time::TimeSource::new_mock(time);
        let accepted = AcceptedTransaction::accept_with_time_source(
            signed,
            state.network_id_ref(),
            max_clock_drift,
            limits,
            state.crypto().as_ref(),
            &time_source,
        )
        .expect("accept the original signed Mint source");
        crate::sumeragi::payload::assemble(
            &state,
            crate::sumeragi::payload::Assembly {
                parent: &parent,
                view: 0,
                cadence,
                proposed_time: std::time::Duration::ZERO,
            },
            &[accepted],
        )
        .expect("assemble actual committed routing and source-bound execution context")
    };
    assert_eq!(
        source.external_transactions().next().unwrap().hash(),
        signed_hash
    );
    assert!(!source.has_results());
    // Removing the context from the actual proposal must still refuse before Mint
    // or its registered Data callback. The positive fixture obtains that context
    // from the production assembler rather than supplying its own route constants.
    {
        let mut missing = source.clone();
        missing.set_execution_context(None);
        assert_ne!(missing.hash(), source.hash());
        assert_eq!(
            missing.external_transactions().next().unwrap().hash(),
            signed_hash
        );
        let (mut refused, _recording) = ValidBlock::start_component_execution(&missing, &state)
            .expect("record the original missing-context negative before effects");
        let fragments = refused.committed_fragment_count();
        refused
            .reserve_ordinary_execution_outputs(&missing)
            .expect("retain the original contextless source for admission refusal");
        assert!(matches!(
            refused.execute_ordinary_output_plan(&missing, None),
            Err(super::ExecutionOutputAttemptError::Owner(reason))
                if reason == "Network source has an invalid execution context"
        ));
        assert_eq!(refused.committed_fragment_count(), fragments);
        assert!(refused.retained_execution_outputs_for_test().is_err());
        assert!(
            refused
                .world
                .map_account(&BOB_ID, |account| account
                    .value()
                    .metadata()
                    .get(&flag_key)
                    .cloned())
                .unwrap()
                .is_none()
        );
        assert!(refused.world.assets.get(&asset_id).is_none());
    }
    let (mut state_block, _recording) = ValidBlock::start_component_execution(&source, &state)
        .expect("capture original signed Mint source before any effects");
    state_block
        .reserve_ordinary_execution_outputs(&source)
        .expect("reserve actual signed Mint source output");
    state_block
        .execute_ordinary_output_plan(&source, None)
        .expect("execute and fit actual Network callback before State apply");
    let outputs = state_block.retained_execution_outputs_for_test().unwrap();
    let [iroha_data_model::block::execution_output::ExecutionOutputV1::Network(output)] = outputs
    else {
        panic!("exactly one real Network source, with no internal actions");
    };
    let steps = output
        .result
        .as_ref()
        .expect("data trigger should run under its registered authority");
    assert_eq!(steps.len(), 1, "expected one data trigger execution");
    assert_eq!(steps[0].id, trigger_id);
    assert_eq!(output.completions.len(), 1);
    assert_eq!(output.completions[0].trigger_id, trigger_id);
    assert_eq!(output.completions[0].callback_index, 0);
    assert_eq!(
        output.completions[0].outcome,
        iroha_data_model::events::trigger_completed::TriggerCompletedOutcome::Success
    );
    state_block.commit_world_overlay_for_testing().unwrap();
    let flag_value = state
        .view()
        .world
        .map_account(&BOB_ID, |account| {
            account.value().metadata().get(&flag_key).cloned()
        })
        .unwrap();
    assert_eq!(flag_value, Some(Json::from(norito::json!("ok"))));
}
#[test]
fn execute_data_triggers_dfs_skips_missing_trigger_after_bytecode_drop() {
    use iroha_data_model::{
        prelude::DataEvent,
        transaction::{Executable, IvmBytecode},
        trigger::{
            Trigger,
            action::{Action, Repeats},
        },
    };
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let mut state = State::new(World::default(), kura, query_handle);
    let trigger_id: TriggerId = "missing_bytecode_data".parse().unwrap();
    let mut raw = Vec::new();
    raw.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let bytecode = IvmBytecode::from_compiled(assemble_ivm_header(&raw));
    let blob_hash = HashOf::new(&bytecode);
    let header = BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0);
    let mut state_block = state.block(header);
    {
        let mut stx = state_block.transaction_for_callback_testing();
        Register::domain(Domain::new(
            DomainId::try_new("wonderland", "universal").unwrap(),
        ))
        .execute(&ALICE_ID, &mut stx)
        .unwrap();
        Register::account(new_sample_account(&ALICE_ID))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.world.add_account_permission(
            &ALICE_ID,
            iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                authority: ALICE_ID.clone(),
            }
            .into(),
        );
        let action = Action::new(
            Executable::Ivm(bytecode),
            Repeats::Indefinitely,
            ALICE_ID.clone(),
            data_pre::DataEventFilter::Any,
        )
        .expect("trigger action fixture satisfies validation invariants");
        Register::trigger(Trigger::new(trigger_id.clone(), action))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
        stx.apply_callback_for_testing()
            .expect("capture successful component callbacks");
    }
    state_block.commit_world_overlay_for_testing().unwrap();
    assert!(
        state.world.triggers.remove_contract_for_test(blob_hash),
        "contract entry should be removed for test setup"
    );
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 0, 0);
    let alpha_domain: DomainId = DomainId::try_new("alpha", "universal").unwrap();
    let beta_domain: DomainId = DomainId::try_new("beta", "universal").unwrap();
    let callback_source = signed_callback_boundary_source(
        &state,
        &header,
        vec![
            Register::domain(Domain::new(alpha_domain.clone())).into(),
            Register::domain(Domain::new(beta_domain.clone())).into(),
        ],
    );
    let mut state_block = state.block(header);
    let mut stx = state_block.transaction();
    stx.current_entrypoint_index = Some(0);
    stx.tx_call_hash = Some(Hash::from(callback_source.hash_as_entrypoint()));
    stx.current_tx_hash = Some(callback_source.hash());
    let event_a = data_pre::DomainEvent::Created(Domain::new(alpha_domain).build(&ALICE_ID));
    let event_b = data_pre::DomainEvent::Created(Domain::new(beta_domain).build(&ALICE_ID));
    stx.world
        .internal_event_buf
        .push(SharedDataEvent::from(DataEvent::Domain(event_a)));
    stx.world
        .internal_event_buf
        .push(SharedDataEvent::from(DataEvent::Domain(event_b)));
    let err = stx
        .execute_data_triggers_dfs(&ALICE_ID)
        .expect_err("missing bytecode should reject data-trigger execution");
    let err_debug = format!("{err:?}");
    assert!(
        err_debug.contains("missing trigger bytecode"),
        "unexpected error: {err_debug}"
    );
    drop(stx);
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    assert!(
        view.world.triggers().ids().get(&trigger_id).is_some(),
        "rolled-back missing-bytecode execution should leave repair/deserialization to prune"
    );
}
