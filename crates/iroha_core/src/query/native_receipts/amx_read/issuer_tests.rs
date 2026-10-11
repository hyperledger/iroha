//! Genuine native certification and refused original-descriptor issuance, without a State borrow.

use std::{cell::Cell, fs, path::PathBuf};

use iroha_allocation::{AllocationBudget, AllocationRefusal, ChargedBufferError};
use iroha_data_model::{
    block::SignedBlock,
    isi::sumeragi_amx::{BeginAmxV1, RegisterAmxDataspaceV1},
    sumeragi_amx::{AmxForeignInstanceV1, AmxLegV1, AmxRecordKind, AmxRecordV1, AmxTransactionV1},
    sumeragi_finality::{authenticated_genesis, test_fixtures::NativeFinalityFixture},
};
use iroha_model_base::topology::DataSpaceId;

use super::{
    NativeAmxRecordProofErrorV1 as Error, NativeAmxRecordProofIssuedV1 as Issued,
    NativeAmxRecordProofPollV1 as Poll,
};
use crate::{
    query::{native_context_archive::NativeContextArchiveError, native_receipts::amx_record_proof},
    state::{NativeExecutionProjectionV1, StateReadOnly, World},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};

// The genuine canonical transaction is committed by an independent native test-chain owner.
// No issued carrier, proof, context frame or paid graph is installed by this helper.
pub(super) fn committed_source(count: usize) -> (CertifiedTestChain, [u8; 32], PathBuf) {
    committed_source_with_npos(count, None)
}

fn committed_source_with_npos(
    count: usize,
    npos: Option<iroha_data_model::parameter::system::SumeragiNposParameters>,
) -> (CertifiedTestChain, [u8; 32], PathBuf) {
    assert!((1..=iroha_data_model::sumeragi_amx::MAX_AMX_PENDING).contains(&count));
    let mut config = TestChainConfig::new(World::new(), 1_000);
    if let Some(policy) = npos {
        use iroha_data_model::parameter::{
            Parameter,
            system::{SumeragiConsensusMode, SumeragiParameter},
        };
        policy.validate().unwrap();
        config.consensus_mode = SumeragiConsensusMode::Npos;
        config.genesis_parameters.extend([
            Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
                policy.epoch_length_blocks,
            )),
            Parameter::Custom(policy.into_custom_parameter()),
        ]);
    }
    config.genesis_instructions = [21, 22]
        .into_iter()
        .map(|id| {
            let child = NativeFinalityFixture::start(&format!("issued-amx-source-{id}"));
            RegisterAmxDataspaceV1 {
                dataspace: DataSpaceId::new(id),
                instance: child.verifier().instance().0,
                anchor: norito::encode_canonical(
                    &authenticated_genesis(child.genesis())
                        .map(|genesis| genesis.into_parts().0)
                        .unwrap(),
                )
                .unwrap(),
            }
            .into()
        })
        .collect();
    let authority = config.genesis_key.clone();
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let transaction = AmxTransactionV1 {
        legs: [21, 22]
            .into_iter()
            .map(|id| AmxLegV1 {
                dataspace: DataSpaceId::new(id),
                payload: vec![7],
            })
            .collect(),
        deadline: 3,
        nonce: [7; 32],
    };
    let tx = transaction.id().unwrap();
    let instructions: Vec<iroha_data_model::isi::InstructionBox> = (0..count)
        .map(|index| {
            let mut additional = transaction.clone();
            if index != 0 {
                additional.nonce = [0; 32];
                additional.nonce[..8].copy_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
            }
            BeginAmxV1 {
                transaction: additional,
            }
            .into()
        })
        .collect();
    let signed = chain.sign(&authority, instructions, 1_999);
    assert_eq!(chain.commit_at(2_000, vec![signed]), vec![true]);
    let paths = fs::read_dir(chain.kura().store_root().join("native-contexts"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "nrt"))
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("00000000000000000002-")
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1);
    (chain, tx, paths.into_iter().next().unwrap())
}

// Custody assertions use borrowed/scalar identities only; no proof fields are copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProofIdentity {
    result: *const u8,
    participants: *const DataSpaceId,
    bytes: usize,
}
fn proof_identity(
    proof: &iroha_data_model::sumeragi_amx::AllocatedAmxRecordProofV1,
) -> ProofIdentity {
    let canonical = proof.canonical();
    let AmxRecordV1::Begin(begin) = &canonical.record else {
        panic!("independently committed Begin source");
    };
    ProofIdentity {
        result: canonical.block.result_preimage.as_ptr(),
        participants: begin.participants.as_ptr(),
        bytes: proof.allocation_bytes().unwrap(),
    }
}

struct ReplacedNamespace {
    original: PathBuf,
    retained: PathBuf,
    replaced: Cell<bool>,
}
impl ReplacedNamespace {
    fn new(chain: &CertifiedTestChain) -> Self {
        let original = chain.kura().store_root().join("native-contexts");
        let retained = chain.kura().store_root().join("issued-original-namespace");
        assert!(!retained.exists());
        Self {
            original,
            retained,
            replaced: Cell::new(false),
        }
    }
    fn replace(&self) {
        assert!(!self.replaced.replace(true));
        fs::rename(&self.original, &self.retained).unwrap();
        fs::create_dir(&self.original).unwrap();
    }
    fn restore(&self) {
        assert!(self.replaced.get());
        fs::remove_dir(&self.original).unwrap();
        fs::rename(&self.retained, &self.original).unwrap();
        self.replaced.set(false);
    }
}
impl Drop for ReplacedNamespace {
    fn drop(&mut self) {
        if self.replaced.get() {
            let _ = fs::remove_dir(&self.original);
            let _ = fs::rename(&self.retained, &self.original);
        }
    }
}

#[test]
fn owned_issuer_retains_first_refused_archive_descriptor_after_original_view_drop() {
    let (chain, tx, archive) = committed_source(1);
    let original_file = fs::read(&archive).unwrap();
    let view = chain.state().view();
    let budget = chain.state().ivm_execution_budget();
    let mut read = amx_record_proof(&view, 2, AmxRecordKind::Begin, tx);
    // Complete actual certification before applying pool pressure so the causal refusal is
    // the genuine first archive poll, not an unrelated earlier prefix/scratch refusal.
    read.acquire_original_source().unwrap();
    assert!(
        !read
            .source
            .as_ref()
            .unwrap()
            .read
            .as_ref()
            .unwrap()
            .has_pinned_source()
    );
    let carrier: *const SignedBlock = read
        .source
        .as_ref()
        .unwrap()
        .certified
        .as_ref()
        .unwrap()
        .block()
        .as_ref();
    let retained = budget.reserved_bytes();
    let pressure = budget
        .try_reserve_bytes(budget.limit_bytes() - retained)
        .unwrap();
    let expected = budget.try_reserve_bytes(original_file.len()).unwrap_err();
    assert!(matches!(expected, AllocationRefusal::Capacity { .. }));
    let Issued::Refused {
        mut original,
        cause,
    } = read.try_issue().unwrap()
    else {
        panic!("occupied original frame pool must issue its exact refused job");
    };
    let Error::Archive(NativeContextArchiveError::Allocation(ChargedBufferError::Admission(
        actual,
    ))) = cause
    else {
        panic!("actual original archive Capacity must remain typed: {cause:?}");
    };
    assert_eq!(actual, expected);
    assert!(
        original.source.read.as_ref().unwrap().has_pinned_source(),
        "owned issuer must retain the first refused archive descriptor"
    );
    assert!(original.acquired_frame().is_none());
    assert!(original.source.budget.same_pool(&budget));
    assert!(std::ptr::eq::<SignedBlock>(
        original.source.certified.as_ref().unwrap().block().as_ref(),
        carrier
    ));
    assert_eq!(
        budget.reserved_bytes(),
        budget.limit_bytes(),
        "issuance does not refund prefix/source charges within the original State borrow"
    );
    assert!(read.source.is_none());
    assert!(
        read.chain.is_some(),
        "the borrowed verifier retires only at normal scoped drop"
    );
    assert!(read.try_issue().is_err());
    drop(read);
    drop(view);

    let retained_path = archive.with_extension("issued-original");
    fs::rename(&archive, &retained_path).unwrap();
    fs::write(&archive, vec![0; original_file.len()]).unwrap();
    drop(pressure);
    let baseline = budget.reserved_bytes();
    assert!(matches!(original.poll().unwrap(), Poll::Pending));
    let prefix = original.acquired_frame().unwrap();
    assert!(!prefix.is_empty() && prefix.len() <= 4096);
    assert_eq!(
        prefix,
        &original_file[..prefix.len()],
        "owned issuer must retain the first refused archive descriptor"
    );
    let pointer = prefix.as_ptr();
    while original.acquired_frame().unwrap().len() < original_file.len() {
        assert!(matches!(original.poll().unwrap(), Poll::Pending));
        assert_eq!(original.acquired_frame().unwrap().as_ptr(), pointer);
    }
    assert_eq!(original.acquired_frame().unwrap(), original_file);
    assert_eq!(budget.reserved_bytes(), baseline + original_file.len());
    let proof = original.complete().unwrap().unwrap();
    assert!(proof.belongs_to(&budget));
    let foreign = AllocationBudget::new(budget.limit_bytes());
    assert!(!proof.belongs_to(&foreign));
    let tracker = AmxForeignInstanceV1::new(
        chain.instance().0,
        authenticated_genesis(chain.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(tracker.verify_record(proof.canonical()).unwrap().height, 2);
    assert!(matches!(&proof.canonical().record, AmxRecordV1::Begin(begin) if begin.tx == tx));
    assert!(original.complete().is_err(), "delivery remains one-shot");
    let before_drop = budget.reserved_bytes();
    let bytes = proof.allocation_bytes().unwrap();
    drop(proof);
    assert_eq!(budget.reserved_bytes(), before_drop - bytes);
    // The archive frame, projection and issued certificate retire at their normal owner
    // drops; native prefix internals remain a separate accounting boundary.
    drop(original);
    fs::remove_file(&archive).unwrap();
    fs::rename(&retained_path, &archive).unwrap();
}

#[test]
fn owned_issuer_preserves_partial_frame_and_same_pool_without_an_extra_poll() {
    let count = 4096 / iroha_data_model::sumeragi_amx::AMX_RECORD_WITNESS_KEY_BYTES + 1;
    let (chain, tx, archive) = committed_source(count);
    let original_file = fs::read(&archive).unwrap();
    assert!(original_file.len() > 4096);
    let view = chain.state().view();
    let budget = chain.state().ivm_execution_budget();
    let mut read = amx_record_proof(&view, 2, AmxRecordKind::Begin, tx);
    assert!(matches!(read.poll().unwrap(), Poll::Pending));
    let prefix = read.acquired_frame().unwrap();
    let length = prefix.len();
    let pointer = prefix.as_ptr();
    let before_issue = budget.reserved_bytes();
    let pressure = budget
        .try_reserve_bytes(budget.limit_bytes() - before_issue)
        .unwrap();
    let mut issued = None;
    let allocations =
        crate::test_allocations::allocations_during(|| issued = Some(read.try_issue()));
    let Issued::Acquired(mut original) = issued.unwrap().unwrap() else {
        panic!("previously acquired prefix must move without a new poll");
    };
    assert_eq!(allocations, 0);
    assert_eq!(original.acquired_frame().unwrap().len(), length);
    assert_eq!(original.acquired_frame().unwrap().as_ptr(), pointer);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    assert!(original.source.budget.same_pool(&budget));
    drop(read);
    drop(view);
    drop(pressure);
    let retained = budget.reserved_bytes();
    while original.acquired_frame().unwrap().len() < original_file.len() {
        assert!(matches!(original.poll().unwrap(), Poll::Pending));
        assert_eq!(original.acquired_frame().unwrap().as_ptr(), pointer);
        assert_eq!(budget.reserved_bytes(), retained);
    }
    assert_eq!(original.acquired_frame().unwrap(), original_file);
    let proof = original.complete().unwrap().unwrap();
    assert!(proof.belongs_to(&budget));
    let tracker = AmxForeignInstanceV1::new(
        chain.instance().0,
        authenticated_genesis(chain.genesis())
            .map(|genesis| genesis.into_parts().0)
            .unwrap(),
    )
    .unwrap();
    tracker.verify_record(proof.canonical()).unwrap();
}

#[test]
fn owned_issuer_keeps_missing_uncertified_and_armed_probe_sources_in_borrower() {
    let (chain, tx, archive) = committed_source(1);
    let retained_path = archive.with_extension("missing-original");
    fs::rename(&archive, &retained_path).unwrap();
    let view = chain.state().view();
    let mut read = amx_record_proof(&view, 2, AmxRecordKind::Begin, tx);
    assert!(
        matches!(read.try_issue(), Err(Error::Archive(NativeContextArchiveError::Io(ref cause))) if cause.kind() == std::io::ErrorKind::NotFound)
    );
    assert!(read.source.is_some());
    assert!(read.source.as_ref().unwrap().certified.is_some());
    assert!(
        !read
            .source
            .as_ref()
            .unwrap()
            .read
            .as_ref()
            .unwrap()
            .has_pinned_source()
    );
    fs::rename(&retained_path, &archive).unwrap();
    let Issued::Acquired(mut original) = read.try_issue().unwrap() else {
        panic!("restoring the exact unselected file permits ordinary acquisition");
    };
    assert!(original.complete().unwrap().is_some());

    let mut uncertified = amx_record_proof(&view, 3, AmxRecordKind::Begin, tx);
    assert!(matches!(uncertified.try_issue(), Err(Error::Chain(_))));
    assert!(uncertified.source.as_ref().unwrap().certified.is_none());
    assert!(uncertified.source.as_ref().unwrap().read.is_none());
    let called = Cell::new(false);
    let mut probed = amx_record_proof(&view, 2, AmxRecordKind::Decision, tx);
    assert!(matches!(probed.poll().unwrap(), Poll::Pending));
    let pointer = probed.acquired_frame().unwrap().as_ptr();
    probed
        .probe_portable_prepared_once(|proof| {
            assert!(proof.is_none());
            called.set(true);
        })
        .unwrap();
    assert!(matches!(
        probed.try_issue(),
        Err(Error::Source(
            "borrowed portable observer must finish before detach"
        ))
    ));
    assert!(!called.get());
    assert_eq!(probed.acquired_frame().unwrap().as_ptr(), pointer);
    assert!(probed.source.is_some());
    assert!(probed.complete().unwrap().is_none());
    assert!(called.get());
    assert!(
        probed.try_issue().is_err(),
        "completed authenticated absence cannot be reissued"
    );
}

#[test]
fn owned_issuer_carries_final_namespace_refusal_without_rebuilding_completed_graph() {
    let (chain, tx, _) = committed_source(1);
    let replacement = ReplacedNamespace::new(&chain);
    let view = chain.state().view();
    let budget = chain.state().ivm_execution_budget();
    let observed = Cell::new(None);
    let mut read = amx_record_proof(&view, 2, AmxRecordKind::Begin, tx);
    read.probe_portable_prepared_once(|proof| {
        observed.set(Some(proof_identity(proof.as_ref().unwrap())));
        replacement.replace();
    })
    .unwrap();
    assert!(matches!(
        read.complete(),
        Err(Error::Archive(NativeContextArchiveError::Io(_)))
    ));
    let retained = budget.reserved_bytes();
    let Issued::Refused {
        mut original,
        cause,
    } = read.try_issue().unwrap()
    else {
        panic!("a final namespace refusal remains explicit during ownership transfer");
    };
    assert!(
        matches!(cause, Error::Archive(NativeContextArchiveError::Io(ref error)) if error.kind() == std::io::ErrorKind::Other && error.to_string() == "native context record identity changed")
    );
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(
        proof_identity(original.source.portable.as_ref().unwrap().as_ref().unwrap()),
        observed.get().unwrap()
    );
    drop(read);
    drop(view);
    assert!(matches!(
        original.complete(),
        Err(Error::Archive(NativeContextArchiveError::Io(_)))
    ));
    replacement.restore();
    let pressure = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    let mut completed = None;
    let allocations = norito::with_decode_limits_scope(limits, || {
        crate::test_allocations::allocations_during(|| completed = Some(original.complete()))
    });
    assert_eq!(allocations, 0);
    let proof = completed.unwrap().unwrap().unwrap();
    assert_eq!(proof_identity(&proof), observed.get().unwrap());
    assert!(proof.belongs_to(&budget));
    assert!(original.complete().is_err());
    let before_drop = budget.reserved_bytes();
    drop(proof);
    assert_eq!(
        budget.reserved_bytes(),
        before_drop - observed.get().unwrap().bytes
    );
    drop(pressure);
}

#[test]
fn owned_issuer_retains_original_decoder_refusal_and_rejects_substituted_carrier_fields() {
    let (chain, tx, archive) = committed_source(1);
    let original_file = fs::read(&archive).unwrap();
    let mut changed: NativeExecutionProjectionV1 =
        norito::decode_canonical(&original_file).unwrap();
    changed.carrier_hash = iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
        b"foreign issued AMX carrier",
    ));
    fs::write(&archive, norito::encode_canonical(&changed).unwrap()).unwrap();
    let view = chain.state().view();
    let budget = chain.state().ivm_execution_budget();
    let mut read = amx_record_proof(&view, 2, AmxRecordKind::Begin, tx);
    let Issued::Acquired(mut original) = read.try_issue().unwrap() else {
        panic!("acquiring untrusted bytes is distinct from authenticating the carrier fields");
    };
    let pointer = original.acquired_frame().unwrap().as_ptr();
    drop(read);
    drop(view);
    let retained = budget.reserved_bytes();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    assert!(
        matches!(norito::with_decode_limits_scope(limits, || original.complete()), Err(Error::Codec(ref cause)) if cause.decode_resource_error().is_some())
    );
    assert_eq!(original.acquired_frame().unwrap().as_ptr(), pointer);
    assert_eq!(
        budget.reserved_bytes(),
        retained,
        "refused decode retires only its temporary plan, retaining the original frame"
    );
    assert!(matches!(
        original.complete(),
        Err(Error::Source(
            "archive differs from the certified carrier or original pool"
        ))
    ));
    fs::write(&archive, original_file).unwrap();
    assert!(matches!(
        original.complete(),
        Err(Error::Source(
            "archive differs from the certified carrier or original pool"
        ))
    ));
    assert_eq!(original.acquired_frame().unwrap().as_ptr(), pointer);
    assert!(original.source.budget.same_pool(&budget));
}

#[test]
fn public_amx_initial_shell_refusal_retains_original_genesis_frame_without_reread() {
    let (chain, tx, _) = committed_source(1);
    let view = chain.state().view();
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    let decoder = norito::core::DecodeBudgetContext::try_new_owned(
        norito::canonical_decode_limits(chain.kura().native_context_archive_max_bytes().get()),
        &budget,
    )
    .unwrap();
    let expected = *view.block_hashes().get(0).unwrap();
    let length = decoder
        .with(|| chain.kura().native_frame_read(1, expected))
        .unwrap()
        .unwrap()
        .wire_len();
    let bytes = usize::try_from(length).unwrap();
    // The real original extent fits; the original prepaid shared control does not.
    let pressure = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes() - bytes)
        .unwrap();
    let mut read = amx_record_proof(&view, 2, AmxRecordKind::Begin, tx);
    chain.kura().reset_canonical_query_reads_for_test();
    let first = decoder.with(|| read.try_issue());
    let Err(Error::Chain(crate::execution_attempt::ExecutionAttemptError::Deferred(first))) = first
    else {
        panic!("initial native shared control must return its genuine original-pool refusal");
    };
    let cause = first.allocation_refusal().unwrap().clone();
    assert!(matches!(cause, AllocationRefusal::Capacity { .. }));
    let original_reads = chain.kura().canonical_query_reads_for_test();
    assert_eq!(original_reads, (1, length));

    // Derive the legitimate retry metadata work through the same exact native owner.
    // Keeping the raw frame does not remove current journal/slot checks or their debit.
    let before = decoder.consumed_allocated_bytes();
    decoder
        .with(|| chain.kura().native_frame_read(1, expected))
        .unwrap()
        .unwrap();
    let metadata = decoder.consumed_allocated_bytes() - before;
    assert_eq!(
        chain.kura().canonical_query_reads_for_test(),
        original_reads
    );
    let consumed = decoder.consumed_allocated_bytes();
    let repeated = decoder.with(|| read.try_issue());
    let Err(Error::Chain(crate::execution_attempt::ExecutionAttemptError::Deferred(repeated))) =
        repeated
    else {
        panic!("the same occupied original shared control must remain a local refusal");
    };
    assert!(matches!(
        repeated.allocation_refusal(),
        Some(AllocationRefusal::Capacity { .. })
    ));
    assert_eq!(
        chain.kura().canonical_query_reads_for_test(),
        original_reads,
        "initial AMX certification must retain the exact genesis frame across refusal"
    );
    assert_eq!(repeated.allocation_refusal(), Some(&cause));
    assert_eq!(decoder.consumed_allocated_bytes() - consumed, metadata);
    drop(pressure);

    let Issued::Acquired(mut original) = decoder.with(|| read.try_issue()).unwrap() else {
        panic!("released original control must finish the same native acquisition");
    };
    drop(read);
    drop(view);
    let proof = decoder.with(|| original.complete()).unwrap().unwrap();
    assert!(proof.belongs_to(&budget));
    let AmxRecordV1::Begin(begin) = &proof.canonical().record else {
        panic!("original independently committed Begin proof");
    };
    assert_eq!(begin.tx, tx);
    drop(proof);
    drop(original);
    drop(decoder);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn public_amx_initial_acquired_genesis_refuses_relocated_pinned_slot_without_reread() {
    let (chain, tx, _) = committed_source(1);
    let view = chain.state().view();
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    let decoder = norito::core::DecodeBudgetContext::try_new_owned(
        norito::canonical_decode_limits(chain.kura().native_context_archive_max_bytes().get()),
        &budget,
    )
    .unwrap();
    let expected = *view.block_hashes().get(0).unwrap();
    let length = decoder
        .with(|| chain.kura().native_frame_read(1, expected))
        .unwrap()
        .unwrap()
        .wire_len();
    let pressure = budget
        .try_reserve_bytes(
            budget.limit_bytes() - budget.reserved_bytes() - usize::try_from(length).unwrap(),
        )
        .unwrap();
    let mut read = amx_record_proof(&view, 2, AmxRecordKind::Begin, tx);
    chain.kura().reset_canonical_query_reads_for_test();
    assert!(matches!(decoder.with(|| read.try_issue()),
        Err(Error::Chain(crate::execution_attempt::ExecutionAttemptError::Deferred(ref local)))
            if matches!(local.allocation_refusal(), Some(AllocationRefusal::Capacity { .. }))));
    let frame = read
        .initialization
        .as_ref()
        .unwrap()
        .frame_for_test()
        .unwrap();
    let pointer = frame.as_slice().as_ptr();
    assert!(frame.belongs_to(&budget));
    let original_reads = chain.kura().canonical_query_reads_for_test();
    assert_eq!(original_reads, (1, length));
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());

    // Change only the actual start coordinate in the same original index inode. The
    // retained bytes do not authorize replacement slot geometry or another read.
    let mut store = crate::kura::BlockStore::new(crate::kura::Kura::canonical_storage_path(
        &chain.kura().store_root(),
    ));
    let slot = store.read_block_index(0).unwrap();
    assert_eq!(slot.length, length);
    store
        .write_block_index(0, slot.start.checked_add(1).unwrap(), slot.length)
        .unwrap();
    let refused = decoder.with(|| read.try_issue());
    // Restore before asserting, including when an unexpected error was returned.
    store.write_block_index(0, slot.start, slot.length).unwrap();
    assert!(
        matches!(
            refused,
            Err(Error::Chain(
                crate::execution_attempt::ExecutionAttemptError::Rejected(
                    crate::sumeragi::certified_chain::ChainReadError::NotInView { height: 1 }
                )
            )),
        ),
        "acquired genesis bytes must still refuse a changed original slot"
    );
    assert_eq!(
        chain.kura().canonical_query_reads_for_test(),
        original_reads
    );
    let frame = read
        .initialization
        .as_ref()
        .unwrap()
        .frame_for_test()
        .unwrap();
    assert_eq!(frame.as_slice().as_ptr(), pointer);
    assert!(frame.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    assert!(matches!(decoder.with(|| read.try_issue()),
        Err(Error::Chain(crate::execution_attempt::ExecutionAttemptError::Deferred(ref local)))
            if matches!(local.allocation_refusal(), Some(AllocationRefusal::Capacity { .. }))));
    assert_eq!(
        chain.kura().canonical_query_reads_for_test(),
        original_reads
    );
    drop(pressure);
    let Issued::Acquired(mut original) = decoder.with(|| read.try_issue()).unwrap() else {
        panic!(
            "restoring the original slot and releasing capacity must resume that original source"
        );
    };
    drop(read);
    drop(view);
    let proof = decoder.with(|| original.complete()).unwrap().unwrap();
    assert!(proof.belongs_to(&budget));
    assert!(matches!(&proof.canonical().record, AmxRecordV1::Begin(begin) if begin.tx == tx));
    drop(proof);
    drop(original);
    drop(decoder);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn public_amx_signed_policy_retains_completed_npos_stage_on_metadata_refusal() {
    use iroha_data_model::{
        block::{SharedSignedBlock, decode_framed_signed_block},
        isi::SetParameter,
        parameter::{Parameter, system::SumeragiNposParameters},
        sumeragi_finality::{GenesisReadError, signed_genesis_consensus_metadata},
        transaction::Executable,
    };
    use norito::core::{DecodeBudgetContext, with_decode_limits_scope};

    let (chain, tx, _) = committed_source_with_npos(1, Some(SumeragiNposParameters::default()));
    let view = chain.state().view();
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    let limits =
        norito::canonical_decode_limits(chain.kura().native_context_archive_max_bytes().get());
    let bounded = |allocated| {
        norito::DecodeLimits::new(
            limits.max_sequence_elements(),
            limits.max_field_bytes(),
            limits.max_total_elements(),
            allocated,
            limits.max_nesting_depth(),
        )
    };
    let expected = *view.block_hashes().get(0).unwrap();
    let reference = DecodeBudgetContext::try_new_owned(limits, &budget).unwrap();
    // This is the actual original native source/prelude/body path, not Kura's cached body.
    // Its shared shell is admitted before the sole canonical body decoder, as in the owner.
    let (original_slot, raw, body) = reference.with(|| {
        let slot = chain
            .kura()
            .native_frame_read(1, expected)
            .unwrap()
            .unwrap();
        let raw = slot
            .read_original(slot.wire_len(), &budget)
            .unwrap()
            .unwrap();
        let shell = SharedSignedBlock::reserve(&budget).unwrap();
        let body = shell.initialize(decode_framed_signed_block(raw.as_slice()).unwrap());
        assert_eq!(body.hash(), expected);
        assert!(body.belongs_to(&budget) && raw.belongs_to(&budget));
        body.validate_proposal_commitments().unwrap();
        (slot, raw, body)
    });
    let acquisition = reference.consumed_allocated_bytes();
    let policy = body
        .external_transactions()
        .find_map(|transaction| {
            let Executable::Instructions(instructions) = transaction.instructions() else {
                panic!("genuine signed genesis has explicit instructions");
            };
            instructions.iter().find_map(|instruction| {
                let set = instruction.as_any().downcast_ref::<SetParameter>()?;
                let Parameter::Custom(custom) = set.inner() else {
                    return None;
                };
                (custom.id() == &SumeragiNposParameters::parameter_id()).then_some(custom)
            })
        })
        .unwrap();
    let before = reference.consumed_allocated_bytes();
    assert!(
        reference
            .with(|| SumeragiNposParameters::from_custom_parameter(policy))
            .unwrap()
            .is_some()
    );
    let completed_policy = reference.consumed_allocated_bytes() - before;
    assert!(
        completed_policy > 0,
        "original signed NPoS policy must actually decode"
    );

    // Derive both real decoder failure debits from this exact signed body. Zero extra
    // allocation refuses each original JSON object preflight; no forged error is installed.
    let before = reference.consumed_allocated_bytes();
    let policy_refusal = reference.with(|| {
        with_decode_limits_scope(bounded(0), || {
            SumeragiNposParameters::from_custom_parameter(policy)
        })
    });
    assert!(matches!(
        policy_refusal,
        Err(norito::json::Error::DecodeResource(
            norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
        ))
    ));
    let failed_policy = reference.consumed_allocated_bytes() - before;
    let before = reference.consumed_allocated_bytes();
    let metadata_refusal = reference
        .with(|| with_decode_limits_scope(bounded(0), || signed_genesis_consensus_metadata(&body)));
    assert!(matches!(
        metadata_refusal,
        Err(GenesisReadError::Json(norito::json::Error::DecodeResource(
            norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
        )))
    ));
    let failed_metadata = reference.consumed_allocated_bytes() - before;
    assert_ne!(
        failed_policy, failed_metadata,
        "the genuine signed policy and metadata refusal debits must distinguish this fixture"
    );
    let wire_len = original_slot.wire_len();
    // Compare with the original persisted carrier, including its execution result.
    // The test chain's signed pre-execution genesis is not that complete native frame.
    let original_wire = raw.as_slice().to_vec();
    budget.with_deferred_refund_notifications(|_| {
        drop(body);
        drop(raw);
    });
    drop(reference);
    assert_eq!(budget.reserved_bytes(), baseline);

    let decoder = DecodeBudgetContext::try_new_owned(limits, &budget).unwrap();
    let first_allowance =
        usize::try_from(acquisition.checked_add(completed_policy).unwrap()).unwrap();
    let mut read = amx_record_proof(&view, 2, AmxRecordKind::Begin, tx);
    chain.kura().reset_canonical_query_reads_for_test();
    let before = decoder.consumed_allocated_bytes();
    let first =
        decoder.with(|| with_decode_limits_scope(bounded(first_allowance), || read.try_issue()));
    assert!(
        matches!(first,
        Err(Error::Chain(crate::execution_attempt::ExecutionAttemptError::Deferred(ref local)))
            if local.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity
                && local.allocation_refusal().is_none()),
        "only original JSON metadata refusal after admitted policy is causal: {:?}",
        first.as_ref().err()
    );
    assert_eq!(
        decoder.consumed_allocated_bytes() - before,
        acquisition
            .checked_add(completed_policy)
            .unwrap()
            .checked_add(failed_metadata)
            .unwrap(),
        "first public attempt must complete the original policy before its metadata refusal"
    );
    assert!(read.chain.is_none());
    let stage = read.initialization.as_ref().unwrap();
    let body = stage.body_for_test().unwrap();
    let body_pointer: *const SignedBlock = body.as_ref();
    assert!(body.belongs_to(&budget));
    let frame = stage.frame_for_test().unwrap();
    let raw_pointer = frame.as_slice().as_ptr();
    assert!(frame.belongs_to(&budget));
    assert_eq!(body.hash(), expected);
    assert_eq!(frame.as_slice(), original_wire.as_slice());
    let original_reads = chain.kura().canonical_query_reads_for_test();
    assert_eq!(original_reads, (1, wire_len));
    let retained = budget.reserved_bytes();

    // The same cumulative owner remains installed. Derive mandatory current slot debit,
    // then admit only that prelude on retry: a retained policy must reach metadata again.
    let before = decoder.consumed_allocated_bytes();
    let current_slot = decoder
        .with(|| chain.kura().native_frame_read(1, expected))
        .unwrap()
        .unwrap();
    assert!(original_slot.same_original_slot(&current_slot));
    let slot_recheck = decoder.consumed_allocated_bytes() - before;
    let before = decoder.consumed_allocated_bytes();
    let repeated = decoder.with(|| {
        with_decode_limits_scope(bounded(usize::try_from(slot_recheck).unwrap()), || {
            read.try_issue()
        })
    });
    assert!(
        matches!(repeated,
        Err(Error::Chain(crate::execution_attempt::ExecutionAttemptError::Deferred(ref local)))
            if local.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity
                && local.allocation_refusal().is_none()),
        "the retry must preserve original typed JSON refusal: {:?}",
        repeated.as_ref().err()
    );
    let stage = read.initialization.as_ref().unwrap();
    assert!(std::ptr::eq::<SignedBlock>(
        stage.body_for_test().unwrap().as_ref(),
        body_pointer
    ));
    assert_eq!(
        stage.frame_for_test().unwrap().as_slice().as_ptr(),
        raw_pointer
    );
    assert!(stage.body_for_test().unwrap().belongs_to(&budget));
    assert!(stage.frame_for_test().unwrap().belongs_to(&budget));
    assert_eq!(
        chain.kura().canonical_query_reads_for_test(),
        original_reads
    );
    assert_eq!(
        budget.reserved_bytes(),
        retained,
        "public AMX retry must retain the completed original signed NPoS policy before metadata refusal: original funded policy backing was lost"
    );
    let repeated_debit = decoder.consumed_allocated_bytes() - before;
    assert_eq!(
        repeated_debit,
        slot_recheck.checked_add(failed_metadata).unwrap(),
        "public AMX retry must retain the completed original signed NPoS policy before metadata refusal; original metadata={failed_metadata}, repeated policy={failed_policy}, refusal={:?}",
        repeated.as_ref().err()
    );

    // Lift only the test-local restriction; the original cumulative context and source
    // still authenticate every prefix, target/archive, namespace and proof exactly once.
    let Issued::Acquired(mut original) = decoder.with(|| read.try_issue()).unwrap() else {
        panic!("unrestricted original signed source must issue its actual retained proof job");
    };
    drop(read);
    drop(view);
    let proof = decoder.with(|| original.complete()).unwrap().unwrap();
    assert!(proof.belongs_to(&budget));
    assert!(matches!(&proof.canonical().record, AmxRecordV1::Begin(begin) if begin.tx == tx));
    assert!(original.complete().is_err());
    drop(proof);
    drop(original);
    drop(decoder);
    assert_eq!(budget.reserved_bytes(), baseline);
}
