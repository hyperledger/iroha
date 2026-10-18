//! Source-selected local witnesses for the installed recursive operation owner.
//!
//! The fold may write immutable draft nodes, but cannot select a source or publish a
//! manifest. The coordinator compares the final roots with the fully verified Ω.

use sha2::{Digest as _, Sha256};

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

struct Store<'a>(&'a mut dyn ObjectWorkspace);
impl ObjectWorkspace for Store<'_> {
    fn read_staged_object(&mut self, key: &[u8; 32], maximum: usize) -> Result<Vec<u8>, Error> {
        self.0.read_staged_object(key, maximum)
    }
    fn stage_object(&mut self, bytes: &[u8], maximum: usize) -> Result<[u8; 32], Error> {
        self.0.stage_object(bytes, maximum)
    }
}

/// A SHA-256 sink for one canonical frame: the encoding is hashed as it is written, so no
/// intermediate buffer copies the private originals it may contain.
struct DigestWriter(Sha256);
impl std::io::Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn canonical_digest<T: norito::NoritoSerialize>(
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], Error> {
    let mut writer = DigestWriter(Sha256::new());
    writer.0.update(domain);
    norito::core::write_canonical_to_writer(value, &mut writer)
        .map_err(|_| Error::Invalid("fold source identity"))?;
    Ok(writer.0.finalize().into())
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
        store: &'a mut dyn ObjectWorkspace,
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
            source.require(store, &before.frozen.capsule.body().successor_state)?;
        }
        sources
            .after
            .require(store, &after.frozen.capsule.body().successor_state)?;
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
        if plan.source != before.frozen.capsule.custody_digest()
            || plan.request.kind() != self.after.frozen.capsule.body().kind
        {
            return Err(Error::WitnessLost("fold preparation source"));
        }
        let mut selected = self
            .before_source
            .clone()
            .ok_or(Error::WitnessLost("fold preparation snapshot"))?;
        let mut state = before.frozen.capsule.body().successor_state;
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
            // A fold replays committed steps; a later local list never refuses them.
            None,
        )?;
        Ok((&plan.request, &plan.native, &plan.draft, custody))
    }

    /// The exact retained predecessor completion, not a reconstructed receipt.
    #[must_use]
    pub const fn predecessor(&self) -> Option<&ReleasedStep> {
        self.before
    }

    /// SHA-256 identities of the canonical source records this view was built from: the
    /// predecessor's, the successor's, and the retained preparation (its request, native
    /// plan, source capsule and draft). Zero marks an absent predecessor or preparation. Only
    /// in-memory values are hashed; nothing is read from the store.
    ///
    /// # Errors
    /// A canonical encoding failure.
    pub(super) fn source_digests(&self) -> Result<[[u8; 32]; 3], Error> {
        let before = self
            .before_source
            .as_ref()
            .map(|source| canonical_digest(b"KAGEMUSHA fold source before v1", source))
            .transpose()?
            .unwrap_or([0; 32]);
        let after = canonical_digest(b"KAGEMUSHA fold source after v1", &self.after_source)?;
        let preparation = match &self.preparation {
            None => [0; 32],
            Some(plan) => {
                let mut digest = Sha256::new();
                digest.update(b"KAGEMUSHA fold source preparation v1");
                digest.update(canonical_digest(
                    b"KAGEMUSHA fold source request v1",
                    &plan.request,
                )?);
                digest.update(Sha256::digest(plan.native.as_slice()));
                digest.update(plan.source);
                digest.update(canonical_digest(
                    b"KAGEMUSHA fold source draft v1",
                    &plan.draft,
                )?);
                digest.finalize().into()
            }
        };
        Ok([before, after, preparation])
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
        source.original(
            self.store.0,
            &before.frozen.capsule.body().successor_state,
            role,
        )
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
            &self.after.frozen.capsule.body().successor_state,
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
        let KagemushaWalletEffectV1::Receive { credit_id, .. } = capsule.body().statement.effect
        else {
            return Err(Error::Invalid("fold credit role"));
        };
        let witness = self.credits.record(
            &mut self.store,
            &KagemushaWalletCreditDigestLeafV1 {
                credit_id,
                payment_digest: capsule.body().payment_digest,
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
        } = self.after.frozen.capsule.body().statement.effect
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
            self.after.frozen.capsule.body().statement.effect
        else {
            return Err(Error::Invalid("fold pending removal role"));
        };
        let mut removed = self.pending.clone();
        let witness = removed.remove(&mut self.store, &credit_id)?;
        self.removed = Some((witness, removed));
        Ok(witness)
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
