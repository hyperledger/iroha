//! Genuine signed-genesis/H2 returned-context custody and final registration admission.

use super::*;

#[test]
fn native_amx_returned_global_context_keeps_every_original_graph_charge_until_retirement() {
    let config = global_config();
    let chain_id = config.chain_id.clone();
    let key = config.genesis_key.clone();
    let mut global = CertifiedTestChain::start(config).unwrap();
    let signed =
        global.sign(
            &key,
            [iroha_data_model::isi::Log::new(
                iroha_logger::Level::INFO,
                "returned context H2".into(),
            )
            .into()],
            1_499,
        );
    assert_eq!(global.commit_at(1_500, vec![signed]), vec![true]);
    let genesis_wire = global.committed(1).block().encode_wire().unwrap();
    let successor_wire = global.committed(2).block().encode_wire().unwrap();
    let expected = authenticated_genesis(global.genesis())
        .unwrap()
        .into_parts()
        .0;
    let budget = global.state().ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let baseline = budget.reserved_bytes();
    let original_limit = budget.limit_bytes();
    let owner = super::super::authenticated_global_source(
        &chain_id,
        global.network_id(),
        &genesis_wire,
        &successor_wire,
        &budget,
    )
    .unwrap();
    let returned = owner.canonical();
    assert_eq!(returned.instance, global.instance().0);
    assert_eq!(returned.current, expected);
    assert!(returned.previous.is_none());
    let committee_pointer = returned.current.committee.as_ptr();
    let key_pointers = returned
        .current
        .committee
        .iter()
        .map(|member| member.validator.public_key().to_bytes().1.as_ptr())
        .collect::<Vec<_>>();
    let pop_pointers = returned
        .current
        .committee
        .iter()
        .map(|member| member.proof_of_possession.as_ptr())
        .collect::<Vec<_>>();
    let member_count = returned.current.committee.len();
    let payload_bytes = returned
        .current
        .committee
        .iter()
        .try_fold(
            std::alloc::Layout::array::<
                iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1,
            >(returned.current.committee.capacity())
            .unwrap()
            .size(),
            |bytes, member| {
                bytes
                    .checked_add(
                        member
                            .validator
                            .public_key()
                            .retained_allocation_layout()
                            .size(),
                    )
                    .and_then(|bytes| {
                        bytes.checked_add(
                            std::alloc::Layout::array::<u8>(member.proof_of_possession.capacity())
                                .unwrap()
                                .size(),
                        )
                    })
            },
        )
        .unwrap();
    let ledger_bytes = std::alloc::Layout::array::<AllocationCharge>(1 + 2 * member_count)
        .unwrap()
        .size();
    let demand = payload_bytes + ledger_bytes;
    assert_eq!(
        budget.reserved_bytes(),
        baseline + demand,
        "returned native AMX context must retain exact original-pool committee/key/PoP custody after genuine H2",
    );
    assert_eq!(owner.allocation_bytes(), Some(demand));
    assert!(owner.belongs_to(&budget));
    let foreign = AllocationBudget::new(budget.limit_bytes());
    assert!(!owner.belongs_to(&foreign));
    budget.set_limit_bytes(budget.reserved_bytes());
    let refused = budget
        .try_reserve(std::alloc::Layout::new::<u8>())
        .unwrap_err();
    let release = match refused {
        iroha_allocation::AllocationRefusal::Capacity { release, .. } => release,
        other => {
            panic!("retained actual context must keep its original release refusal: {other:?}")
        }
    };
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(registration.poll_wait(&release, &mut context).is_pending());
    assert_eq!(
        owner.canonical().current.committee.as_ptr(),
        committee_pointer
    );
    for (index, member) in owner.canonical().current.committee.iter().enumerate() {
        assert_eq!(
            member.validator.public_key().to_bytes().1.as_ptr(),
            key_pointers[index]
        );
        assert_eq!(member.proof_of_possession.as_ptr(), pop_pointers[index]);
    }
    assert_eq!(owner.canonical().current, expected);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), baseline);
    assert!(registration.poll_wait(&release, &mut context).is_ready());
    registration.cancel();
    budget.set_limit_bytes(original_limit);
    let retry = super::super::authenticated_global_source(
        &chain_id,
        global.network_id(),
        &genesis_wire,
        &successor_wire,
        &budget,
    )
    .unwrap();
    assert_eq!(retry.canonical().current, expected);
    assert!(retry.belongs_to(&budget));
    drop(retry);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn native_amx_returned_context_final_registration_refusal_keeps_original_graph_and_retry_pool() {
    let config = global_config();
    let chain_id = config.chain_id.clone();
    let key = config.genesis_key.clone();
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let signed = chain.sign(
        &key,
        [
            iroha_data_model::isi::Log::new(iroha_logger::Level::INFO, "registration H2".into())
                .into(),
        ],
        1_499,
    );
    assert_eq!(chain.commit_at(1_500, vec![signed]), vec![true]);
    let genesis = chain.committed(1).block().encode_wire().unwrap();
    let successor = chain.committed(2).block().encode_wire().unwrap();
    let budget = chain.state().ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let before_returned = budget.reserved_bytes();
    let global = super::super::authenticated_global_source(
        &chain_id,
        chain.network_id(),
        &genesis,
        &successor,
        &budget,
    )
    .unwrap();
    let custody = super::super::custody(chain.network_id());
    let baseline = budget.reserved_bytes();
    let original_limit = budget.limit_bytes();
    let pointer = global.canonical().current.committee.as_ptr();
    let source = || super::super::retained::RegistrationSource {
        dataspace: FIRST,
        global: &global,
        global_genesis: &genesis,
        global_successor: &successor,
        global_chain_label: chain_id.as_str().as_bytes(),
        custody: &custody,
    };
    let positive = RetainedNativeAmx::admit_registration(source(), &budget).unwrap();
    let demand = positive.allocation_bytes().unwrap();
    assert!(positive.belongs_to(&budget));
    assert!(
        !positive.is_authenticated(),
        "physical admission cannot confer signed execution authority"
    );
    assert_eq!(budget.reserved_bytes(), baseline + demand);
    let expected = positive.canonical().unwrap();
    assert_eq!(expected.participant.global, *global.canonical());
    assert_ne!(
        expected.participant.global.current.committee.as_ptr(),
        pointer
    );
    let expected_wire = norito::encode_canonical(expected).unwrap();
    drop(positive);
    assert_eq!(budget.reserved_bytes(), baseline);
    budget.set_limit_bytes(baseline + demand - 1);
    let refused = RetainedNativeAmx::admit_registration(source(), &budget).unwrap_err();
    let release = match refused {
        super::super::retained::GraphError::Admission(
            iroha_allocation::AllocationRefusal::Capacity {
                requested_bytes,
                reserved_bytes,
                limit_bytes,
                release,
            },
        ) => {
            assert_eq!(requested_bytes, demand);
            assert_eq!(reserved_bytes, baseline);
            assert_eq!(limit_bytes, baseline + demand - 1);
            release
        }
        other => {
            panic!("complete final admission must retain its exact original refusal: {other:?}")
        }
    };
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(global.canonical().current.committee.as_ptr(), pointer);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(registration.poll_wait(&release, &mut context).is_pending());
    budget.set_limit_bytes(original_limit);
    assert!(registration.poll_wait(&release, &mut context).is_ready());
    registration.cancel();
    let foreign = AllocationBudget::new(original_limit);
    assert!(matches!(
        RetainedNativeAmx::admit_registration(source(), &foreign),
        Err(super::super::retained::GraphError::Invalid(_))
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    let retry = RetainedNativeAmx::admit_registration(source(), &budget).unwrap();
    assert_eq!(
        norito::encode_canonical(retry.canonical().unwrap()).unwrap(),
        expected_wire
    );
    assert_eq!(budget.reserved_bytes(), baseline + demand);
    assert_eq!(global.canonical().current.committee.as_ptr(), pointer);
    drop(global);
    assert_eq!(budget.reserved_bytes(), before_returned + demand);
    drop(retry);
    assert_eq!(budget.reserved_bytes(), before_returned);
}
