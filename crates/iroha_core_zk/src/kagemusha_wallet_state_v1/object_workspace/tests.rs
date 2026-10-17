//! Logical staging, bounded ownership, exact recovery and durable acknowledgment controls.

use super::*;
use std::collections::BTreeMap;

#[derive(Default)]
struct Memory {
    objects: BTreeMap<[u8; 32], Vec<u8>>,
    writes: Vec<[u8; 32]>,
    reads: usize,
    fail_read: bool,
    fail_write: Option<usize>,
    wrong_ack: bool,
}
impl ObjectStore for Memory {
    fn read_object(&mut self, key: &[u8; 32], maximum: usize) -> Result<Vec<u8>, Error> {
        self.reads += 1;
        if self.fail_read {
            return Err(Error::Storage(std::io::Error::other("unavailable")));
        }
        let bytes = self.objects.get(key).ok_or(Error::WitnessLost("absent"))?;
        if bytes.len() > maximum {
            return Err(Error::WitnessLost("oversize"));
        }
        Ok(bytes.clone())
    }
    fn write_object(&mut self, bytes: &[u8], maximum: usize) -> Result<[u8; 32], Error> {
        assert!(bytes.len() <= maximum);
        let key = digest(bytes);
        self.writes.push(key);
        self.objects.insert(key, bytes.to_vec());
        if self.fail_write == Some(self.writes.len()) {
            return Err(Error::Storage(std::io::Error::other("uncertain after put")));
        }
        Ok(if self.wrong_ack { [0xff; 32] } else { key })
    }
}
fn limits(bytes: usize, items: usize) -> WorkspaceLimits {
    WorkspaceLimits {
        max_bytes: bytes,
        max_objects: items,
    }
}
fn owned(bytes: &[u8]) -> ([u8; 32], PrivateArchiveBytes) {
    (
        digest(bytes),
        PrivateArchiveBytes::from_guarded(Zeroizing::new(bytes.to_vec())),
    )
}

#[test]
fn durable_adapter_preserves_acknowledged_writes() {
    let mut memory = Memory::default();
    let key = memory.stage_object(b"durable", 7).unwrap();
    assert_eq!(memory.writes, [key]);
    assert_eq!(memory.read_staged_object(&key, 7).unwrap(), b"durable");
}

#[test]
fn discarded_draft_never_writes_and_reads_its_own_objects() {
    let mut memory = Memory::default();
    let source = memory.write_object(b"selected", 8).unwrap();
    memory.writes.clear();
    {
        let mut draft = DraftWorkspace::new(&mut memory, limits(7, 1));
        let staged = draft.stage_object(b"private", 7).unwrap();
        assert_eq!(draft.read_staged_object(&staged, 7).unwrap(), b"private");
        assert_eq!(draft.read_staged_object(&source, 8).unwrap(), b"selected");
        assert!(matches!(
            draft.read_staged_object(&staged, 6),
            Err(Error::WitnessLost(_))
        ));
    }
    assert!(memory.writes.is_empty());
    assert_eq!(memory.objects.len(), 1);
}

#[test]
fn byte_item_and_object_limits_precede_payload_retention() {
    let mut memory = Memory::default();
    let mut draft = DraftWorkspace::new(&mut memory, limits(3, 2));
    let key = draft.stage_object(b"abc", 3).unwrap();
    assert_eq!(draft.stage_object(b"abc", 3).unwrap(), key);
    assert!(matches!(
        draft.stage_object(b"x", 1),
        Err(Error::NotEnoughMemory)
    ));
    assert!(matches!(
        draft.stage_object(b"abc", 2),
        Err(Error::Invalid(_))
    ));
    draft.stage_object(b"", 0).unwrap();
    assert!(matches!(
        draft.stage_object(b"q", 1),
        Err(Error::NotEnoughMemory)
    ));
    let batch = draft.into_batch();
    assert_eq!(batch.bytes, 3);
    assert_eq!(batch.entries().len(), 2);
    assert!(memory.writes.is_empty());
    let mut no_items = DraftWorkspace::new(&mut memory, limits(100, 0));
    assert!(matches!(
        no_items.stage_object(b"", 0),
        Err(Error::NotEnoughMemory)
    ));
    assert!(no_items.into_batch().entries().is_empty());
}

#[test]
fn canonical_batch_moves_clearing_allocations_and_rejects_bad_records() {
    let mut memory = Memory::default();
    let mut draft = DraftWorkspace::new(&mut memory, limits(9, 3));
    for value in [b"ccc", b"aaa", b"bbb"] {
        draft.stage_object(value, 3).unwrap();
    }
    let batch = draft.into_batch();
    assert!(batch.entries().windows(2).all(|w| w[0].0 < w[1].0));
    let pointers: Vec<_> = batch.entries().iter().map(|(_, v)| v.as_ptr()).collect();
    let batch = ObjectBatch::from_owned(batch.into_owned(), limits(9, 3)).unwrap();
    assert_eq!(
        pointers,
        batch
            .entries()
            .iter()
            .map(|(_, v)| v.as_ptr())
            .collect::<Vec<_>>()
    );
    assert!(matches!(
        ObjectBatch::from_owned(vec![owned(b"x"), owned(b"x")], limits(2, 2)),
        Err(Error::WitnessLost(_))
    ));
    let mut wrong = owned(b"x");
    wrong.0[0] ^= 1;
    assert!(matches!(
        ObjectBatch::from_owned(vec![wrong], limits(1, 1)),
        Err(Error::WitnessLost(_))
    ));
    let mut reversed = batch.into_owned();
    reversed.reverse();
    assert!(matches!(
        ObjectBatch::from_owned(reversed, limits(9, 3)),
        Err(Error::WitnessLost(_))
    ));
    assert!(matches!(
        ObjectBatch::from_owned(vec![owned(b"long")], limits(3, 1)),
        Err(Error::NotEnoughMemory)
    ));
    assert!(matches!(
        ObjectBatch::from_owned(vec![owned(b"")], limits(0, 0)),
        Err(Error::NotEnoughMemory)
    ));
}

#[test]
fn source_failures_and_corrupt_content_never_become_absence() {
    let mut memory = Memory::default();
    let key = digest(b"source");
    memory.objects.insert(key, b"changed".to_vec());
    {
        let mut draft = DraftWorkspace::new(&mut memory, limits(10, 1));
        assert!(matches!(
            draft.read_staged_object(&key, 10),
            Err(Error::WitnessLost(_))
        ));
        assert!(matches!(
            draft.read_staged_object(&[0; 32], 10),
            Err(Error::WitnessLost(_))
        ));
    }
    memory.fail_read = true;
    let mut draft = DraftWorkspace::new(&mut memory, limits(10, 1));
    assert!(matches!(
        draft.read_staged_object(&key, 10),
        Err(Error::Storage(_))
    ));
}

#[test]
fn uncertain_materialization_retains_exact_batch_and_retries_all_bytes() {
    let mut memory = Memory::default();
    let mut draft = DraftWorkspace::new(&mut memory, limits(9, 3));
    for value in [b"one", b"two", b"end"] {
        draft.stage_object(value, 3).unwrap();
    }
    let batch = draft.into_batch();
    let ordered: Vec<_> = batch.entries().iter().map(|(k, _)| *k).collect();
    memory.fail_write = Some(2);
    assert!(matches!(
        batch.materialize(&mut memory),
        Err(Error::Storage(_))
    ));
    assert_eq!(memory.writes, ordered[..2]);
    assert_eq!(batch.entries().len(), 3);
    memory.fail_write = None;
    let _acknowledged = batch.materialize(&mut memory).unwrap();
    assert_eq!(memory.writes[2..], ordered);
    for (key, original) in batch.entries() {
        assert_eq!(memory.objects[key], original.as_slice());
    }
}

#[test]
fn materialization_refuses_a_wrong_durable_digest() {
    let mut memory = Memory::default();
    let batch = ObjectBatch::from_owned(vec![owned(b"a")], limits(1, 1)).unwrap();
    memory.wrong_ack = true;
    assert!(matches!(
        batch.materialize(&mut memory),
        Err(Error::WitnessLost(_))
    ));
    assert_eq!(batch.entries().len(), 1);
}

#[test]
fn read_back_rereads_every_materialized_original_without_writing() {
    let mut memory = Memory::default();
    let mut draft = DraftWorkspace::new(&mut memory, limits(9, 3));
    for value in [b"one", b"two", b"end"] {
        draft.stage_object(value, 3).unwrap();
    }
    let batch = draft.into_batch();
    let _acknowledged = batch.materialize(&mut memory).unwrap();
    let writes = memory.writes.clone();
    memory.reads = 0;
    batch.read_back(&mut memory).unwrap();
    assert_eq!(memory.reads, 3);
    assert_eq!(memory.writes, writes);
    assert_eq!(batch.entries().len(), 3);
}

#[test]
fn read_back_failures_and_corrupt_or_missing_content_never_succeed() {
    let mut memory = Memory::default();
    let batch = ObjectBatch::from_owned(vec![owned(b"aaa"), owned(b"bbb")], limits(6, 2)).unwrap();
    let _acknowledged = batch.materialize(&mut memory).unwrap();
    memory.fail_read = true;
    assert!(matches!(
        batch.read_back(&mut memory),
        Err(Error::Storage(_))
    ));
    memory.fail_read = false;
    let (first, second) = (batch.entries()[0].0, batch.entries()[1].0);
    memory.objects.insert(second, b"ccc".to_vec());
    assert!(matches!(
        batch.read_back(&mut memory),
        Err(Error::WitnessLost(_))
    ));
    memory.objects.insert(second, b"bbbb".to_vec());
    assert!(matches!(
        batch.read_back(&mut memory),
        Err(Error::WitnessLost(_))
    ));
    memory.objects.remove(&first);
    assert!(matches!(
        batch.read_back(&mut memory),
        Err(Error::WitnessLost(_))
    ));
    assert_eq!(batch.entries().len(), 2);
}

#[test]
fn read_only_replay_requires_existing_exact_bytes_without_growth() {
    let mut memory = Memory::default();
    let key = memory.write_object(b"selected", 8).unwrap();
    memory.writes.clear();
    {
        let mut replay = ReadOnlyWorkspace::new(&mut memory);
        assert_eq!(replay.stage_object(b"selected", 8).unwrap(), key);
        assert_eq!(replay.read_staged_object(&key, 8).unwrap(), b"selected");
        assert!(matches!(
            replay.stage_object(b"new", 3),
            Err(Error::WitnessLost(_))
        ));
        assert!(matches!(
            replay.stage_object(b"selected", 7),
            Err(Error::Invalid(_))
        ));
    }
    assert!(memory.writes.is_empty());
    assert_eq!(memory.objects.len(), 1);
}

#[test]
fn recovered_batch_replay_cannot_add_or_persist_an_object() {
    let mut memory = Memory::default();
    let batch = ObjectBatch::from_owned(vec![owned(b"retained")], limits(8, 1)).unwrap();
    {
        let mut replay = ReadOnlyWorkspace::with_batch(&mut memory, &batch);
        let key = replay.stage_object(b"retained", 8).unwrap();
        assert_eq!(replay.read_staged_object(&key, 8).unwrap(), b"retained");
        assert!(matches!(
            replay.read_staged_object(&key, 7),
            Err(Error::WitnessLost(_))
        ));
        assert!(matches!(
            replay.stage_object(b"other", 5),
            Err(Error::WitnessLost(_))
        ));
    }
    assert_eq!(memory.reads, 1);
    assert!(memory.writes.is_empty());
    assert!(memory.objects.is_empty());
}

#[test]
fn unwind_drops_private_draft_without_durable_effects() {
    let mut memory = Memory::default();
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut draft = DraftWorkspace::new(&mut memory, limits(7, 1));
        draft.stage_object(b"private", 7).unwrap();
        panic!("native refusal after staged write");
    }));
    assert!(failure.is_err());
    assert!(memory.objects.is_empty());
    assert!(memory.writes.is_empty());
}
