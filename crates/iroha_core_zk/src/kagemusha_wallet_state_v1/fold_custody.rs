//! Source-selected local witnesses for the installed recursive operation owner.
//!
//! The fold may write immutable draft nodes, but cannot select a source or publish a
//! manifest. The coordinator compares the final roots with the fully verified Ω.

use super::{preparation_custody::SourceCustodyV1, *};

#[derive(Clone)]
pub(super) struct FoldSourcesV1 {
    pub(super) before: Option<SourceCustodyV1>,
    pub(super) after: SourceCustodyV1,
    pub(super) preparation: Option<transition_custody::PreparedTransitionV1>,
    pub(super) issued: IndexRoot,
    pub(super) anchors: IndexRoot,
    pub(super) epochs: IndexRoot,
}

struct Store<'a>(&'a mut dyn ObjectStore);
impl ObjectStore for Store<'_> {
    fn read_object(&mut self, key: &[u8; 32], maximum: usize) -> Result<Vec<u8>, Error> {
        self.0.read_object(key, maximum)
    }
    fn write_object(&mut self, bytes: &[u8], maximum: usize) -> Result<[u8; 32], Error> {
        self.0.write_object(bytes, maximum)
    }
}

#[cfg(test)]
mod tests;

/// Sealed historical originals, preserve-first credits and adjusted pending-map witnesses.
/// No constructor, arbitrary root setter or archive capability is public.
pub struct FoldCustodyV1<'a> {
    store: Store<'a>,
    before: Option<&'a ReleasedStep>,
    after: &'a ReleasedStep,
    before_source: Option<SourceCustodyV1>,
    after_source: SourceCustodyV1,
    preparation: Option<transition_custody::PreparedTransitionV1>,
    issued: IndexRoot,
    anchors: IndexRoot,
    epochs: IndexRoot,
    credits: credit_tree::CreditTree,
    credit: Option<(bool, KagemushaWalletCreditDigestRecordV1)>,
    pending: map_tree::PersistentMapV1,
    initial_pending: map_tree::PersistentMapV1,
    inserted: Option<KagemushaWalletIndexedInsertV1>,
    removed: Option<(KagemushaWalletIndexedRemoveV1, map_tree::PersistentMapV1)>,
}

impl<'a> FoldCustodyV1<'a> {
    pub(super) fn new(
        store: &'a mut dyn ObjectStore,
        before: Option<&'a ReleasedStep>,
        after: &'a ReleasedStep,
        sources: FoldSourcesV1,
        credits: credit_tree::CreditTree,
        pending: map_tree::PersistentMapV1,
    ) -> Result<Self, Error> {
        if before.is_some() != sources.before.is_some() {
            return Err(Error::WitnessLost("fold predecessor custody"));
        }
        if let Some((before, source)) = before.zip(sources.before.as_ref()) {
            source.require(store, &before.frozen.capsule.successor_state)?;
        }
        sources
            .after
            .require(store, &after.frozen.capsule.successor_state)?;
        pending.validate()?;
        Ok(Self {
            store: Store(store),
            before,
            after,
            before_source: sources.before,
            after_source: sources.after,
            preparation: sources.preparation,
            issued: sources.issued,
            anchors: sources.anchors,
            epochs: sources.epochs,
            credits,
            credit: None,
            initial_pending: pending.clone(),
            pending,
            inserted: None,
            removed: None,
        })
    }

    pub(super) fn preparation(
        &mut self,
    ) -> Result<
        (
            &NativeIntentV1,
            &[u8],
            &SourceCustodyV1,
            PreparationCustodyV1<'_>,
        ),
        Error,
    > {
        let plan = self
            .preparation
            .as_ref()
            .ok_or(Error::WitnessLost("fold native preparation"))?;
        let before = self
            .before
            .ok_or(Error::WitnessLost("fold native predecessor"))?;
        if plan.source != valid(before.frozen.capsule.capsule_digest())?
            || plan.request.kind() != self.after.frozen.capsule.kind
        {
            return Err(Error::WitnessLost("fold preparation source"));
        }
        let mut selected = self
            .before_source
            .clone()
            .ok_or(Error::WitnessLost("fold preparation snapshot"))?;
        let mut state = before.frozen.capsule.successor_state;
        if plan.request.kind().consumes_lineage() {
            state.core.pending_outgoing_root = self.initial_pending.root();
            selected.maps.replace_pending(self.initial_pending.clone());
        }
        let refresh = plan.request.refresh();
        let custody = PreparationCustodyV1::new(
            self.store.0,
            &selected,
            &state,
            plan.request.kind(),
            refresh,
            self.issued,
            self.anchors,
            self.epochs,
        )?;
        Ok((&plan.request, &plan.native, &plan.draft, custody))
    }

    /// The exact retained predecessor completion, not a reconstructed receipt.
    #[must_use]
    pub const fn predecessor(&self) -> Option<&ReleasedStep> {
        self.before
    }

    /// Read the predecessor's own historical original, including its enrollment set.
    ///
    /// # Errors
    /// No predecessor, missing witness, wrong state binding or unavailable storage.
    pub fn predecessor_original(
        &mut self,
        role: PreparationOriginalV1,
    ) -> Result<Option<Vec<u8>>, Error> {
        let source = self
            .before_source
            .as_ref()
            .ok_or(Error::WitnessLost("fold predecessor snapshot"))?;
        let before = self.before.ok_or(Error::WitnessLost("fold predecessor"))?;
        source.original(self.store.0, &before.frozen.capsule.successor_state, role)
    }

    /// Read the released successor's own original; renewal never rewrites history.
    ///
    /// # Errors
    /// Required original absent, corrupt binding or unavailable storage.
    pub fn successor_original(
        &mut self,
        role: PreparationOriginalV1,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.after_source.original(
            self.store.0,
            &self.after.frozen.capsule.successor_state,
            role,
        )
    }

    /// Current draft credit-digest root, initially the predecessor Ω root.
    #[must_use]
    pub fn credit_root(&self) -> [u8; 32] {
        self.credits.root()
    }

    /// Adjusted pending root. Archive's candidate removal is separate until Ω decides it.
    #[must_use]
    pub fn pending_root(&self) -> [u8; 32] {
        self.pending.root()
    }

    /// Derive Receive's actual membership-or-insert witness, preserving the first identity.
    /// The proposed burn bit is subsequently checked by the native relation and both Ω decides.
    ///
    /// # Errors
    /// Another operation, conflicting re-derivation, corrupt map or storage failure.
    pub fn credit_record(
        &mut self,
        burned: bool,
    ) -> Result<KagemushaWalletCreditDigestRecordV1, Error> {
        if let Some((previous, witness)) = self.credit {
            return if previous == burned {
                Ok(witness)
            } else {
                Err(Error::Invalid("changed fold burn proposal"))
            };
        }
        let capsule = &self.after.frozen.capsule;
        let KagemushaWalletEffectV1::Receive { credit_id, .. } = capsule.statement.effect else {
            return Err(Error::Invalid("fold credit role"));
        };
        let witness = self.credits.record(
            &mut self.store,
            &KagemushaWalletCreditDigestLeafV1 {
                credit_id,
                payment_digest: capsule.payment_digest,
                burned,
            },
        )?;
        self.credit = Some((burned, witness));
        Ok(witness)
    }

    /// Derive Send's descriptor insertion from its exact selected statement.
    ///
    /// # Errors
    /// Another operation, invalid descriptor, full map, duplicate or unavailable storage.
    pub fn pending_insert(&mut self) -> Result<KagemushaWalletIndexedInsertV1, Error> {
        if let Some(witness) = self.inserted {
            return Ok(witness);
        }
        let KagemushaWalletEffectV1::Send {
            credit_id,
            receiver_wallet_id,
            send_ordinal,
            amount,
            fee,
            request,
            ..
        } = self.after.frozen.capsule.statement.effect
        else {
            return Err(Error::Invalid("fold pending insertion role"));
        };
        let leaf = KagemushaWalletPendingOutgoingLeafV1 {
            credit_id,
            receiver_wallet_id,
            send_ordinal,
            amount,
            fee,
            request_digest: request,
        };
        let witness = self
            .pending
            .insert(&mut self.store, credit_id, valid(leaf.leaf_value())?)?;
        self.inserted = Some(witness);
        Ok(witness)
    }

    /// Derive Archive's candidate removal while retaining the no-op predecessor descriptor.
    /// The fully verified final public root chooses the successful or corrected-claim branch.
    ///
    /// # Errors
    /// Another operation, missing leaf, corrupt path or unavailable storage.
    pub fn pending_remove(&mut self) -> Result<KagemushaWalletIndexedRemoveV1, Error> {
        if let Some((witness, _)) = &self.removed {
            return Ok(*witness);
        }
        let KagemushaWalletEffectV1::ArchiveSent { credit_id, .. } =
            self.after.frozen.capsule.statement.effect
        else {
            return Err(Error::Invalid("fold pending removal role"));
        };
        let mut removed = self.pending.clone();
        let witness = removed.remove(&mut self.store, &credit_id)?;
        self.removed = Some((witness, removed));
        Ok(witness)
    }

    /// Authenticate Receive's Request-recorded blacklist query, including the safe zero query.
    /// This always opens the real local history map; latest policy cannot replace the Request.
    ///
    /// # Errors
    /// Another operation, missing/ambiguous Request original or unavailable/corrupt history.
    pub fn blacklist_history(
        &mut self,
    ) -> Result<
        (
            KagemushaWalletIndexedLeafV1,
            KagemushaWalletIndexedOpeningV1,
        ),
        Error,
    > {
        let capsule = &self.after.frozen.capsule;
        if capsule.kind != KagemushaWalletOperationKindV1::Receive {
            return Err(Error::Invalid("fold history role"));
        }
        let mut requests = capsule
            .retained_inputs
            .iter()
            .filter(|input| input.role == KagemushaWalletRetainedInputRoleV1::Request);
        let original = requests
            .next()
            .ok_or(Error::WitnessLost("fold Request original"))?;
        if requests.next().is_some() {
            return Err(Error::WitnessLost("duplicate fold Request"));
        }
        let request: KagemushaWalletRequestV1 = archive::decode(&original.bytes)?;
        let version = if request.body.receiver_blacklist_version != 0
            && request.body.receiver_blacklist_root != [0; 32]
        {
            request.body.receiver_blacklist_version
        } else {
            1
        };
        self.after_source.maps.history().member_or_low(
            &mut self.store,
            &kagemusha_wallet_field_from_u128_v1(u128::from(version)),
        )
    }

    pub(super) fn finish(
        self,
        public: &KagemushaWalletLineagePublicV1,
    ) -> Result<(credit_tree::CreditTree, map_tree::PersistentMapV1), Error> {
        if self.credits.root() != public.credit_digest_root {
            return Err(Error::Proof("fold credit custody root"));
        }
        let pending = if self.pending.root() == public.pending_outgoing_root {
            self.pending
        } else if let Some((_, removed)) = self.removed {
            if removed.root() != public.pending_outgoing_root {
                return Err(Error::Proof("fold removed pending root"));
            }
            removed
        } else {
            return Err(Error::Proof("fold pending custody root"));
        };
        Ok((self.credits, pending))
    }
}
