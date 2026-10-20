//! Metadata reads authenticate the original source without acquiring full payload custody.

use super::*;

fn metadata_allocation(f: &Fixture) -> usize {
    let budget = &f.store.execution_budget;
    let before = budget.reserved_bytes();
    let decoded = certificate_read::CertificateRead::new(f.executed.clone(), budget.clone())
        .complete(budget)
        .unwrap_or_else(|_| panic!("genuine certificate"));
    let bytes = budget.reserved_bytes() - before;
    drop(decoded);
    assert_eq!(budget.reserved_bytes(), before);
    bytes
}

#[test]
fn metadata_reads_finish_without_payload_or_rs16_allocation() {
    let f = fixture();
    stage(&f, f.executed.clone());
    f.store.append(&f.body, &f.qc).unwrap();
    let budget = &f.store.execution_budget;
    let before = budget.reserved_bytes();
    budget.set_limit_bytes(before + metadata_allocation(&f));

    // This exact limit admits the canonical certificate table and its owner, with no room
    // for even the projected proposal. Every public metadata adapter must finish anyway.
    let entry = f.store.entry(2).unwrap().unwrap();
    assert_eq!(entry.manifest.header, *f.body.header());
    assert_eq!(entry.manifest.availability, *f.body.availability());
    assert_eq!(entry.commit_qc, f.qc);
    assert!(f.store.read.lock().is_none());
    drop(entry);
    assert_eq!(budget.reserved_bytes(), before);
    assert_eq!(f.store.header(2).unwrap(), Some(f.body.header().clone()));
    assert_eq!(
        f.store.certified(2).unwrap(),
        Some((f.body.header().clone(), f.qc.clone()))
    );
    assert_eq!(f.store.tip().unwrap().unwrap().commit_qc, f.qc);
    assert_eq!(
        f.store.recent_headers(3).unwrap(),
        vec![f.body.header().clone()]
    );
    let entries = f.store.entries(2, 4, u32::MAX).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].manifest.header, *f.body.header());
    assert_eq!(entries[0].commit_qc, f.qc);
    drop(entries);
    assert_eq!(budget.reserved_bytes(), before);
    assert_eq!(
        f.store.committed_body(2).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    budget.set_limit_bytes(1 << 27);
    assert_eq!(f.store.committed_body(2).unwrap().unwrap().0, f.body);
}

#[test]
fn metadata_request_retains_in_progress_body_projection_on_refusal() {
    let f = fixture();
    stage(&f, f.executed.clone());
    f.store.append(&f.body, &f.qc).unwrap();
    let budget = &f.store.execution_budget;
    let before = budget.reserved_bytes();
    budget.set_limit_bytes(before + metadata_allocation(&f));
    assert_eq!(
        f.store.committed_body(2).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    let held = budget.reserved_bytes();
    for height in [2, 3, 2] {
        assert_eq!(
            f.store.entry(height).unwrap_err().io_kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(budget.reserved_bytes(), held);
        assert_eq!(f.store.read.lock().as_ref().unwrap().height(), 2);
    }
    budget.set_limit_bytes(1 << 27);
    assert_eq!(f.store.entry(2).unwrap().unwrap().commit_qc, f.qc);
    assert!(f.store.read.lock().is_none());
    assert_eq!(budget.reserved_bytes(), before);
}

#[test]
fn metadata_reads_reject_bad_qc_result_and_canonical_manifest_signatures() {
    for mutation in 0..4 {
        let f = fixture();
        let original = f.executed.commit_certificate().unwrap();
        let mut header = f.body.header().clone();
        let mut qc = f.qc.clone();
        let mut result = original.result_preimage().to_vec();
        let mut table = f.body.availability().as_slice().to_vec();
        match mutation {
            0 => qc.agg_sig.0[0] ^= 1,
            1 => result[0] ^= 1,
            2 => *table.last_mut().unwrap() ^= 1,
            3 => header.payload_hash.0[0] ^= 1,
            _ => unreachable!(),
        }
        let table = AvailabilityFrame::from_untrusted(table).unwrap();
        let certificate = commit_certificate(
            &header,
            &qc,
            result,
            norito::encode_canonical(&table).unwrap(),
        )
        .unwrap();
        let block = f
            .executed
            .as_ref()
            .clone()
            .with_commit_certificate(Some(certificate));
        f.store
            .kura
            .store_block(
                iroha_data_model::block::SharedSignedBlock::reserve(&f.store.execution_budget)
                    .unwrap()
                    .initialize(block),
            )
            .unwrap();
        for read in [f.store.entry(2), f.store.tip()] {
            assert_eq!(
                read.unwrap_err().io_kind(),
                io::ErrorKind::InvalidData,
                "mutation {mutation}"
            );
        }
        assert!(f.store.certified(2).is_err());
        assert!(f.store.header(2).is_err());
        assert!(f.store.recent_headers(1).is_err());
        assert!(f.store.entries(2, 1, u32::MAX).is_err());
        assert!(f.store.read.lock().is_none());
    }
}

#[test]
fn metadata_authority_refusal_can_resume_as_full_body_with_original_source() {
    let f = fixture();
    stage(&f, f.executed.clone());
    f.store.append(&f.body, &f.qc).unwrap();
    let config = f.schedule.config.lock().take();
    assert_eq!(
        f.store.entry(2).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    let held = f.store.execution_budget.reserved_bytes();
    assert_eq!(
        f.store.committed_body(2).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(f.store.execution_budget.reserved_bytes(), held);
    *f.schedule.config.lock() = config;
    let (body, qc) = f.store.committed_body(2).unwrap().unwrap();
    assert_eq!(body, f.body);
    assert_eq!(qc, f.qc);
    assert!(f.store.read.lock().is_none());
}

#[test]
fn metadata_authority_refusal_keeps_height_until_the_original_read_finishes() {
    let f = fixture();
    stage(&f, f.executed.clone());
    f.store.append(&f.body, &f.qc).unwrap();
    let config = f.schedule.config.lock().take();
    assert_eq!(
        f.store.entry(2).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    let held = f.store.execution_budget.reserved_bytes();
    assert_eq!(
        f.store.entry(3).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(f.store.read.lock().as_ref().unwrap().height(), 2);
    assert_eq!(f.store.execution_budget.reserved_bytes(), held);
    *f.schedule.config.lock() = config;
    assert!(f.store.entry(3).unwrap().is_none());
    assert!(f.store.read.lock().is_none());
    assert_eq!(f.store.entry(2).unwrap().unwrap().commit_qc, f.qc);
}

#[test]
fn metadata_streamed_proposal_check_rejects_other_payload_with_genuine_qc_and_manifest() {
    use crate::sumeragi::crypto::KeyPairSigner;
    use iroha_allocation::ChargedBuffer;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_sumeragi::{
        availability::{PayloadAuthoring, PayloadBytes},
        crypto::Signer,
    };

    let f = fixture();
    let budget = &f.store.execution_budget;
    let config = f.body.source().config();
    let mut signers: Vec<_> = (1..=4)
        .map(|seed| {
            KeyPairSigner::new(&KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal)).unwrap()
        })
        .collect();
    signers.sort_by(|a, b| a.public_key().as_bytes().cmp(b.public_key().as_bytes()));
    let mut bytes = f.body.payload().as_slice().to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    let mut backing = ChargedBuffer::new(bytes.len(), budget).unwrap();
    backing.append(&bytes).unwrap();
    let payload = PayloadBytes::from_charged(backing, budget)
        .unwrap_or_else(|_| panic!("original test payload owner"));
    let mut header = f.body.header().clone();
    header.payload_hash = iroha_sumeragi::preimage::payload_hash(&*f.store.hasher, &bytes);
    header.availability_digest = Hash32::ZERO;
    let proposer = usize::try_from(header.proposer).unwrap();
    let authored = PayloadAuthoring::new(header, payload)
        .complete(
            f.schedule.instance,
            config,
            budget,
            &*f.store.hasher,
            &signers[proposer],
        )
        .unwrap_or_else(|_| panic!("genuine signed manifest of a different proposal"));
    let mut qc = f.qc.clone();
    qc.block_hash = authored.body.header().hash(&*f.store.hasher);
    let shares: Vec<_> = signers[..3]
        .iter()
        .map(|signer| signer.sign(&qc.preimage()).unwrap())
        .collect();
    qc.agg_sig = f.store.hasher.aggregate(&shares).unwrap();
    let certificate = commit_certificate(
        authored.body.header(),
        &qc,
        f.executed
            .commit_certificate()
            .unwrap()
            .result_preimage()
            .to_vec(),
        norito::encode_canonical(authored.body.availability()).unwrap(),
    )
    .unwrap();
    let changed = f
        .executed
        .as_ref()
        .clone()
        .with_commit_certificate(Some(certificate));
    execution::validate(&changed, f.store.root_scope).unwrap();
    committed_read::certified_source(
        &*f.schedule,
        &*f.store.hasher,
        2,
        authored.body.header(),
        &qc,
    )
    .unwrap();
    f.store
        .kura
        .store_block(
            iroha_data_model::block::SharedSignedBlock::reserve(budget)
                .unwrap()
                .initialize(changed),
        )
        .unwrap();
    let error = f.store.entry(2).unwrap_err();
    assert_eq!(error.io_kind(), io::ErrorKind::InvalidData);
    assert!(
        error
            .to_string()
            .contains("stored proposal differs from its certified header")
    );
    assert!(f.store.committed_body(2).is_err());
}
