//! Persistent credit identities over the shared authenticated wallet map.

use super::{map_tree::PersistentMapV1, *};

#[derive(Debug, Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::CreditTree")]
pub(super) struct CreditTree {
    map: PersistentMapV1,
    identities: IndexRoot,
}

#[derive(Debug, Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::CreditIdentity")]
struct Identity {
    payment_digest: [u8; 32],
    burned: bool,
}
impl Default for CreditTree {
    fn default() -> Self {
        Self {
            map: PersistentMapV1::default(),
            identities: IndexRoot::default(),
        }
    }
}
impl CreditTree {
    pub fn root(&self) -> [u8; 32] {
        self.map.root()
    }

    pub fn record(
        &mut self,
        store: &mut impl ObjectStore,
        credit: &KagemushaWalletCreditDigestLeafV1,
    ) -> Result<KagemushaWalletCreditDigestRecordV1, Error> {
        valid(credit.field_items())?;
        if self.identities.get(store, &credit.credit_id)?.is_some() {
            // The first identity wins, but a missing/corrupt map cannot become a replay.
            let (_, leaf, opening) = self.opening(store, &credit.credit_id)?;
            return Ok(KagemushaWalletCreditDigestRecordV1::Present { leaf, opening });
        }
        let mut next = self.clone();
        let witness = next
            .map
            .insert(store, credit.credit_id, valid(credit.leaf_value())?)?;
        next.identities = next.identities.set(
            store,
            credit.credit_id,
            &archive::encode(&Identity {
                payment_digest: credit.payment_digest,
                burned: credit.burned,
            })?,
        )?;
        *self = next;
        Ok(KagemushaWalletCreditDigestRecordV1::Inserted { witness })
    }

    pub fn opening(
        &self,
        store: &mut impl ObjectStore,
        credit_id: &[u8; 32],
    ) -> Result<
        (
            KagemushaWalletCreditDigestLeafV1,
            KagemushaWalletIndexedLeafV1,
            KagemushaWalletIndexedOpeningV1,
        ),
        Error,
    > {
        let Some(bytes) = self.identities.get(store, credit_id)? else {
            // Authenticated map absence is required before reporting fold backlog.
            self.map.non_membership(store, credit_id)?;
            return Err(Error::FoldRequired);
        };
        let identity: Identity = archive::decode(&bytes)?;
        let credit = KagemushaWalletCreditDigestLeafV1 {
            credit_id: *credit_id,
            payment_digest: identity.payment_digest,
            burned: identity.burned,
        };
        let (leaf, opening) = self.map.membership(store, credit_id)?;
        if leaf.value != valid(credit.leaf_value())? {
            return Err(Error::WitnessLost("credit identity map binding"));
        }
        Ok((credit, leaf, opening))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persistent_tree_matches_native_insert_order_openings_and_first_identity() {
        let mut store = super::super::tests::MemoryArchive::new();
        let mut tree = CreditTree::default();
        let mut native = KagemushaWalletIndexedTreeV1::new();
        for number in [19u8, 7, 25, 2, 31, 11, 3, 9] {
            let mut id = [0; 32];
            id[0] = number;
            let mut payment = [0; 32];
            payment[0] = number + 42;
            let credit = KagemushaWalletCreditDigestLeafV1 {
                credit_id: id,
                payment_digest: payment,
                burned: number % 2 == 0,
            };
            tree.record(&mut store, &credit).expect("persistent insert");
            credit.record(&mut native).expect("native insert");
            assert_eq!(tree.root(), native.root());
            let (_, leaf, opening) = tree.opening(&mut store, &id).expect("persistent opening");
            assert_eq!(
                (leaf, opening),
                native.membership(&id).expect("native opening")
            );
            let first = tree.root();
            let changed = KagemushaWalletCreditDigestLeafV1 {
                burned: !credit.burned,
                payment_digest: id,
                ..credit
            };
            tree.record(&mut store, &changed)
                .expect("first identity remains");
            assert_eq!(tree.root(), first);
            assert_eq!(tree.opening(&mut store, &id).expect("opening").0, credit);
        }
    }
    #[test]
    fn draft_records_match_real_tree_for_both_burn_values_without_changing_selected_state() {
        let mut store = super::super::tests::MemoryArchive::new();
        let mut tree = CreditTree::default();
        let mut native = KagemushaWalletIndexedTreeV1::new();
        for number in [19u8, 7, 25, 2, 31, 11, 3, 9] {
            let mut id = [0; 32];
            id[0] = number;
            let mut payment = [0; 32];
            payment[0] = number + 42;
            let original = archive::encode(&tree).unwrap();
            for burned in [false, true] {
                let credit = KagemushaWalletCreditDigestLeafV1 {
                    credit_id: id,
                    payment_digest: payment,
                    burned,
                };
                let mut expected = native.clone();
                credit.record(&mut expected).unwrap();
                let mut draft = tree.clone();
                let paths = draft.record(&mut store, &credit).unwrap();
                assert_eq!(
                    paths.verify(&tree.root(), &credit).unwrap(),
                    expected.root()
                );
                assert_eq!(draft.root(), expected.root());
                assert_eq!(archive::encode(&tree).unwrap(), original);
            }
            let credit = KagemushaWalletCreditDigestLeafV1 {
                credit_id: id,
                payment_digest: payment,
                burned: number % 2 == 0,
            };
            tree.record(&mut store, &credit).unwrap();
            credit.record(&mut native).unwrap();
            let present = tree.record(&mut store, &credit).unwrap();
            let (leaf, opening) = native.membership(&id).unwrap();
            assert_eq!(
                present,
                KagemushaWalletCreditDigestRecordV1::Present { leaf, opening }
            );
            let changed = KagemushaWalletCreditDigestLeafV1 {
                burned: !credit.burned,
                payment_digest: id,
                ..credit
            };
            assert_eq!(
                present.verify(&tree.root(), &changed).unwrap(),
                native.root()
            );
        }
        let mut restored: CreditTree = archive::decode(&archive::encode(&tree).unwrap()).unwrap();
        assert_eq!(restored.root(), tree.root());
        let mut new_id = [0; 32];
        new_id[0] = 23;
        let credit = KagemushaWalletCreditDigestLeafV1 {
            credit_id: new_id,
            payment_digest: [1; 32],
            burned: false,
        };
        assert_eq!(
            restored.record(&mut store, &credit).unwrap(),
            tree.record(&mut store, &credit).unwrap()
        );
        assert_eq!(
            archive::encode(&restored).unwrap(),
            archive::encode(&tree).unwrap()
        );
    }
    #[test]
    fn failed_draft_credit_record_preserves_selected_descriptor_and_can_retry() {
        let tree = CreditTree::default();
        let original = archive::encode(&tree).unwrap();
        let mut draft = tree.clone();
        let mut store = FaultStore::new();
        store.fail = Some(0);
        let credit = sample_credit();
        assert!(matches!(
            draft.record(&mut store, &credit),
            Err(Error::Storage(_))
        ));
        assert_eq!(archive::encode(&draft).unwrap(), original);
        assert_eq!(archive::encode(&tree).unwrap(), original);
        store.fail = None;
        let witness = draft.record(&mut store, &credit).unwrap();
        assert_eq!(witness.verify(&tree.root(), &credit).unwrap(), draft.root());
        assert_eq!(
            draft.opening(&mut store, &credit.credit_id).unwrap().0,
            credit
        );
        assert_eq!(archive::encode(&tree).unwrap(), original);
    }
    struct FaultStore {
        inner: super::super::tests::MemoryArchive,
        writes: usize,
        fail: Option<usize>,
    }
    impl FaultStore {
        fn new() -> Self {
            Self {
                inner: super::super::tests::MemoryArchive::new(),
                writes: 0,
                fail: None,
            }
        }
    }
    impl ObjectStore for FaultStore {
        fn read_object(&mut self, key: &[u8; 32], max: usize) -> Result<Vec<u8>, Error> {
            self.inner.read_object(key, max)
        }
        fn write_object(&mut self, bytes: &[u8], max: usize) -> Result<[u8; 32], Error> {
            if self.fail == Some(self.writes) {
                return Err(Error::Storage(std::io::Error::other(
                    "uncertain credit publication",
                )));
            }
            self.writes += 1;
            self.inner.write_object(bytes, max)
        }
    }
    fn sample_credit() -> KagemushaWalletCreditDigestLeafV1 {
        let mut id = [0; 32];
        id[0] = 7;
        let mut payment = [0; 32];
        payment[0] = 11;
        KagemushaWalletCreditDigestLeafV1 {
            credit_id: id,
            payment_digest: payment,
            burned: false,
        }
    }
    #[test]
    fn publication_failure_at_map_or_identity_write_preserves_the_entire_credit_snapshot() {
        let credit = sample_credit();
        let mut store = FaultStore::new();
        let mut complete = CreditTree::default();
        complete.record(&mut store, &credit).unwrap();
        let write_count = store.writes;
        assert!(write_count > 7);
        for fail in [0, 7, write_count - 1] {
            let mut store = FaultStore::new();
            store.fail = Some(fail);
            let mut tree = CreditTree::default();
            let original = archive::encode(&tree).unwrap();
            assert!(matches!(
                tree.record(&mut store, &credit),
                Err(Error::Storage(_))
            ));
            assert_eq!(archive::encode(&tree).unwrap(), original);
            store.fail = None;
            assert!(matches!(
                tree.opening(&mut store, &credit.credit_id),
                Err(Error::FoldRequired)
            ));
            tree.record(&mut store, &credit).unwrap();
            let restored: CreditTree = archive::decode(&archive::encode(&tree).unwrap()).unwrap();
            assert_eq!(
                restored.opening(&mut store, &credit.credit_id).unwrap().0,
                credit
            );
            assert_eq!(restored.root(), complete.root());
        }
    }
    #[test]
    fn lost_or_mismatched_credit_metadata_never_becomes_backlog_or_successful_replay() {
        let credit = sample_credit();
        let mut store = FaultStore::new();
        let mut tree = CreditTree::default();
        tree.record(&mut store, &credit).unwrap();
        let original = tree.clone();
        tree.identities = IndexRoot::default();
        assert!(
            tree.opening(&mut store, &credit.credit_id)
                .is_err_and(|error| !matches!(error, Error::FoldRequired))
        );
        assert!(tree.record(&mut store, &credit).is_err());
        tree = original;
        tree.identities = tree
            .identities
            .set(
                &mut store,
                credit.credit_id,
                &archive::encode(&Identity {
                    payment_digest: credit.payment_digest,
                    burned: true,
                })
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            tree.opening(&mut store, &credit.credit_id),
            Err(Error::WitnessLost("credit identity map binding"))
        ));
        assert!(tree.record(&mut store, &credit).is_err());
    }
}
