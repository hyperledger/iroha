//! The credential handle and the choice lock.

use core::fmt;

use iroha_data_model::{
    NetworkId,
    governance::anonymous_ballot::{
        BallotBodyContextV1, BallotChoiceV1, BallotScopeV1, CredentialCommitmentV1, Digest512,
        NullifierV1, ProofProfileIdV1, VoteAuthorizationV1,
        framing::{decode_enc, enc},
    },
};
use iroha_parliament_ballot_proof::{
    credential::CredentialSecret, framing::Digest64, vote::VoteStatement,
};
use zeroize::Zeroizing;

use super::{WalletErrorV1, disclosure::BallotDisclosureAcknowledgementV1};
use crate::{
    context::ScopedBallotContextV1,
    entropy::{EntropySource, OsEntropy},
    inputs::{ProofValueV1, body_digest_v1, proof_profile_v1},
};

/// Bytes of a credential secret.
pub const CREDENTIAL_SECRET_BYTES: usize = 48;

/// The choice lock of one credential in its scope: the complete public vote statement except
/// the proof, and its authorization digest `D_v`. It is the per-handle log entry the proof
/// profile requires before `auth_v` is disclosed.
///
/// Its canonical record ([`Self::record_bytes`]) is local, owner-only wallet state: it
/// links the credential to its nullifier and choice, so it is stored with the secret and
/// never transmitted. Its `Debug` output shows only the scope.
#[derive(Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_parliament_ballot::wallet::BallotIntentV1")]
pub struct BallotIntentV1 {
    /// Network of the ballot.
    pub network_id: NetworkId,
    /// Scope of the ballot.
    pub scope: BallotScopeV1,
    /// Proof profile.
    pub profile_id: ProofProfileIdV1,
    /// Sealed-list digest `R` the statement binds.
    pub list_digest: Digest512,
    /// Sealed seats `S`.
    pub seats: u16,
    /// `policy_hash` the statement binds.
    pub policy_hash: Digest512,
    /// The locked choice.
    pub vote: BallotChoiceV1,
    /// The credential's nullifier in the scope.
    pub nullifier: NullifierV1,
    /// The vote authorization value of the locked statement.
    pub auth_v: VoteAuthorizationV1,
    /// `D_v` of the locked statement.
    pub authorization_digest: Digest512,
}

impl fmt::Debug for BallotIntentV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BallotIntentV1")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl BallotIntentV1 {
    /// The canonical `Enc` record to persist.
    ///
    /// # Errors
    /// [`WalletErrorV1::Codec`] if the frame cannot be produced.
    pub fn record_bytes(&self) -> Result<Vec<u8>, WalletErrorV1> {
        Ok(enc(self)?)
    }

    /// Read a persisted record: exactly one canonical frame.
    ///
    /// # Errors
    /// [`WalletErrorV1::Codec`] for any other bytes.
    pub fn from_record_bytes(bytes: &[u8]) -> Result<Self, WalletErrorV1> {
        Ok(decode_enc(bytes)?)
    }

    /// The ballot identity `(scope, nullifier)` the lock reserves.
    pub fn identity(&self) -> (BallotScopeV1, NullifierV1) {
        (self.scope, self.nullifier)
    }
}

/// The lock held by a handle and whether its record was confirmed persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChoiceLock {
    intent: BallotIntentV1,
    persisted: bool,
}

/// One credential secret bound to one binding body, owned by the wallet.
///
/// Not `Clone`; its `Debug` output shows no secret, commitment or choice.
pub struct CredentialHandleV1 {
    secret: CredentialSecret,
    body_context: BallotBodyContextV1,
    body_digest: Digest64,
    commitment: CredentialCommitmentV1,
    lock: Option<ChoiceLock>,
}

impl fmt::Debug for CredentialHandleV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialHandleV1")
            .field("body_role", &self.body_context.body_role)
            .field("choice_locked", &self.lock.is_some())
            .finish_non_exhaustive()
    }
}

impl CredentialHandleV1 {
    /// A fresh credential for `body_context`, drawn from the operating system's random
    /// source.
    ///
    /// # Errors
    /// [`WalletErrorV1::Entropy`] if the random source fails (no credential exists then), and
    /// [`WalletErrorV1::Inputs`] for a body that is not a binding jury.
    pub fn generate_v1(body_context: BallotBodyContextV1) -> Result<Self, WalletErrorV1> {
        Self::generate_with(body_context, &mut OsEntropy)
    }

    /// [`Self::generate_v1`] with the secret drawn from `entropy`.
    pub(crate) fn generate_with<E: EntropySource>(
        body_context: BallotBodyContextV1,
        entropy: &mut E,
    ) -> Result<Self, WalletErrorV1> {
        let secret = CredentialSecret::fill_with(|buffer| entropy.fill(buffer))?;
        Self::from_secret(body_context, secret, None)
    }

    /// The credential with the secret `secret` exported earlier for `body_context`, and the
    /// choice lock record persisted with it, if any. The caller's copy of `secret` is the
    /// caller's to erase.
    ///
    /// # Errors
    /// [`WalletErrorV1::Inputs`] for a non-binding body, [`WalletErrorV1::Codec`] for a lock
    /// record that does not decode, and [`WalletErrorV1::ChoiceRecordMismatch`] for a lock of
    /// another credential or network.
    pub fn import_v1(
        body_context: BallotBodyContextV1,
        secret: &[u8; CREDENTIAL_SECRET_BYTES],
        persisted_lock_record: Option<&[u8]>,
    ) -> Result<Self, WalletErrorV1> {
        let lock = persisted_lock_record
            .map(BallotIntentV1::from_record_bytes)
            .transpose()?;
        Self::from_secret(
            body_context,
            CredentialSecret::from_bytes(secret),
            lock.as_ref(),
        )
    }

    fn from_secret(
        body_context: BallotBodyContextV1,
        secret: CredentialSecret,
        lock: Option<&BallotIntentV1>,
    ) -> Result<Self, WalletErrorV1> {
        let body_digest = body_digest_v1(&body_context)?.to_proof();
        let commitment = CredentialCommitmentV1::from_proof(&secret.commitment(&body_digest));
        if let Some(intent) = lock
            && (intent.network_id != body_context.network_id
                || NullifierV1::from_proof(&secret.nullifier(&intent.scope.to_proof()))
                    != intent.nullifier)
        {
            return Err(WalletErrorV1::ChoiceRecordMismatch);
        }
        Ok(Self {
            secret,
            body_context,
            body_digest,
            commitment,
            lock: lock.map(|intent| ChoiceLock {
                intent: *intent,
                persisted: true,
            }),
        })
    }

    /// The secret as erasing bytes, for the caller's owner-only storage.
    pub fn export_secret_v1(&self) -> Zeroizing<[u8; CREDENTIAL_SECRET_BYTES]> {
        Zeroizing::new(*self.secret.expose_bytes())
    }

    /// The body the credential is bound to.
    pub fn body_context(&self) -> &BallotBodyContextV1 {
        &self.body_context
    }

    /// The credential commitment `C` registered for the seat.
    pub fn commitment(&self) -> &CredentialCommitmentV1 {
        &self.commitment
    }

    /// The choice lock, if a choice is locked.
    pub fn choice_lock(&self) -> Option<&BallotIntentV1> {
        self.lock.as_ref().map(|lock| &lock.intent)
    }

    /// Whether the choice lock's record was confirmed persisted.
    pub fn is_choice_persisted(&self) -> bool {
        self.lock.is_some_and(|lock| lock.persisted)
    }

    /// Lock `vote` for `context`'s ballot after the voter acknowledged its disclosure, and
    /// return the lock to persist. Locking the same choice again returns the same lock;
    /// another choice is refused once a lock exists.
    ///
    /// # Errors
    /// [`WalletErrorV1::ForeignBody`], [`WalletErrorV1::DisclosureMismatch`],
    /// [`WalletErrorV1::NotOnSealedList`] or [`WalletErrorV1::ChoiceLocked`].
    pub fn lock_choice_v1(
        &mut self,
        context: &ScopedBallotContextV1,
        vote: BallotChoiceV1,
        acknowledgement: &BallotDisclosureAcknowledgementV1,
    ) -> Result<BallotIntentV1, WalletErrorV1> {
        self.check_ballot(context, acknowledgement)?;
        let intent = self.intent_for(context, vote)?;
        match &self.lock {
            Some(lock) if lock.intent == intent => Ok(intent),
            Some(_) => Err(WalletErrorV1::ChoiceLocked),
            None => {
                self.lock = Some(ChoiceLock {
                    intent,
                    persisted: false,
                });
                Ok(intent)
            }
        }
    }

    /// Confirm that the lock's record was persisted, by handing back the bytes read from
    /// storage. Proving is refused until this succeeds.
    ///
    /// # Errors
    /// [`WalletErrorV1::ChoiceNotLocked`] without a lock, and
    /// [`WalletErrorV1::ChoiceRecordMismatch`] or [`WalletErrorV1::Codec`] if the bytes are
    /// not exactly the lock's record.
    pub fn confirm_choice_persisted_v1(&mut self, record: &[u8]) -> Result<(), WalletErrorV1> {
        let Some(lock) = &mut self.lock else {
            return Err(WalletErrorV1::ChoiceNotLocked);
        };
        if BallotIntentV1::from_record_bytes(record)? != lock.intent {
            return Err(WalletErrorV1::ChoiceRecordMismatch);
        }
        lock.persisted = true;
        Ok(())
    }

    /// Check that the credential, the context and the acknowledgement belong together.
    pub(crate) fn check_ballot(
        &self,
        context: &ScopedBallotContextV1,
        acknowledgement: &BallotDisclosureAcknowledgementV1,
    ) -> Result<(), WalletErrorV1> {
        if self.body_context != *context.body_context() {
            return Err(WalletErrorV1::ForeignBody);
        }
        if !acknowledgement.matches(context) {
            return Err(WalletErrorV1::DisclosureMismatch);
        }
        self.position(context).map(|_| ())
    }

    /// The credential's secret position in the sealed list, found by the proof crate's
    /// constant-time scan.
    pub(crate) fn position(&self, context: &ScopedBallotContextV1) -> Result<u16, WalletErrorV1> {
        context
            .proof_list()
            .position(&self.commitment.to_proof())
            .ok_or(WalletErrorV1::NotOnSealedList)
    }

    /// The vote statement of `vote` in `context`, authorized by this credential.
    pub(crate) fn statement(
        &self,
        context: &ScopedBallotContextV1,
        vote: BallotChoiceV1,
    ) -> Result<VoteStatement, WalletErrorV1> {
        let profile = proof_profile_v1()?;
        Ok(VoteStatement::for_secret(
            &profile,
            &self.secret,
            self.body_digest,
            context.scope().to_proof(),
            context.proof_list(),
            vote.to_proof(),
            *context.proof_policy_hash(),
        )?)
    }

    /// The lock of `vote` in `context`.
    fn intent_for(
        &self,
        context: &ScopedBallotContextV1,
        vote: BallotChoiceV1,
    ) -> Result<BallotIntentV1, WalletErrorV1> {
        let profile = proof_profile_v1()?;
        let statement = self.statement(context, vote)?;
        Ok(BallotIntentV1 {
            network_id: *context.network_id(),
            scope: *context.scope(),
            profile_id: *context.profile_id(),
            list_digest: *context.list_digest(),
            seats: context.seats(),
            policy_hash: *context.policy_hash(),
            vote,
            nullifier: NullifierV1::from_proof(&statement.nullifier),
            auth_v: VoteAuthorizationV1::from_proof(&statement.auth_v),
            authorization_digest: Digest512::from_proof(&statement.authorization_digest(&profile)?),
        })
    }

    /// The persisted lock of `context`'s ballot, recomputed and checked against the
    /// credential: proving can only reproduce the locked statement.
    pub(crate) fn persisted_lock(
        &self,
        context: &ScopedBallotContextV1,
    ) -> Result<BallotIntentV1, WalletErrorV1> {
        let Some(lock) = self.lock else {
            return Err(WalletErrorV1::ChoiceNotLocked);
        };
        if !lock.persisted {
            return Err(WalletErrorV1::ChoiceNotPersisted);
        }
        if self.intent_for(context, lock.intent.vote)? != lock.intent {
            return Err(WalletErrorV1::ChoiceRecordMismatch);
        }
        Ok(lock.intent)
    }

    /// The secret, for proving.
    pub(crate) fn secret(&self) -> &CredentialSecret {
        &self.secret
    }

    /// An owned copy for a worker thread: a second erasing owner of the secret.
    pub(crate) fn duplicate(&self) -> Self {
        Self {
            secret: CredentialSecret::from_bytes(self.secret.expose_bytes()),
            body_context: self.body_context,
            body_digest: self.body_digest,
            commitment: self.commitment,
            lock: self.lock,
        }
    }
}

#[cfg(test)]
mod tests {
    use iroha_data_model::governance::types::ParliamentBody;

    use super::*;
    use crate::{
        entropy::ScriptedEntropy,
        test_support::{
            AYE_0, body_context, fixture_authorization, other_network_id, scoped_context,
            secret_bytes,
        },
        wallet::BallotDisclosureV1,
    };

    fn acknowledged() -> BallotDisclosureAcknowledgementV1 {
        BallotDisclosureV1::for_context_v1(&scoped_context())
            .acknowledge(&crate::wallet::DisclosureStatementV1::ALL)
            .expect("acknowledged")
    }

    fn member(index: u8) -> CredentialHandleV1 {
        CredentialHandleV1::import_v1(body_context(), &secret_bytes(index), None).expect("handle")
    }

    #[test]
    fn a_fresh_credential_comes_from_the_random_source() {
        let first = CredentialHandleV1::generate_v1(body_context()).expect("credential");
        let second = CredentialHandleV1::generate_v1(body_context()).expect("credential");
        assert_ne!(first.commitment(), second.commitment());
        assert_ne!(*first.export_secret_v1(), [0; 48]);
        let mut entropy = ScriptedEntropy::new([Some(secret_bytes(2).to_vec())]);
        let scripted =
            CredentialHandleV1::generate_with(body_context(), &mut entropy).expect("credential");
        assert_eq!(scripted.commitment(), member(2).commitment());
        // No entropy, no credential.
        let mut failing = ScriptedEntropy::new([None]);
        assert!(matches!(
            CredentialHandleV1::generate_with(body_context(), &mut failing),
            Err(WalletErrorV1::Entropy(_))
        ));
        let mut public = body_context();
        public.body_role = ParliamentBody::InterestPanel;
        assert!(matches!(
            CredentialHandleV1::generate_v1(public),
            Err(WalletErrorV1::Inputs(_))
        ));
    }

    #[test]
    fn export_and_import_round_trip_and_debug_hides_the_secret() {
        let handle = member(1);
        let exported = handle.export_secret_v1();
        assert_eq!(*exported, secret_bytes(1));
        let imported =
            CredentialHandleV1::import_v1(body_context(), &exported, None).expect("handle");
        assert_eq!(imported.commitment(), handle.commitment());
        assert_eq!(imported.body_context(), &body_context());
        assert_eq!(
            imported.duplicate().secret().expose_bytes(),
            handle.secret().expose_bytes()
        );
        let shown = format!("{handle:?}");
        assert!(!shown.contains("41") && !shown.contains(&handle.commitment().to_hex()[..16]));
        assert!(shown.contains("PolicyJury"));
    }

    #[test]
    fn the_choice_lock_is_fixed_persisted_and_restored() {
        let context = scoped_context();
        let mut handle = member(0);
        assert_eq!(handle.choice_lock(), None);
        assert_eq!(
            handle.persisted_lock(&context),
            Err(WalletErrorV1::ChoiceNotLocked)
        );
        let intent = handle
            .lock_choice_v1(&context, BallotChoiceV1::Aye, &acknowledged())
            .expect("locked");
        // The lock is the statement of the fixture ballot of the same member and choice.
        let fixture = fixture_authorization(AYE_0);
        assert_eq!(intent.identity(), (fixture.scope, fixture.nullifier));
        assert_eq!(intent.auth_v, fixture.auth_v);
        assert_eq!(intent.seats, 4);
        // Idempotent for the same choice; another choice is refused.
        assert_eq!(
            handle.lock_choice_v1(&context, BallotChoiceV1::Aye, &acknowledged()),
            Ok(intent)
        );
        assert_eq!(
            handle.lock_choice_v1(&context, BallotChoiceV1::Nay, &acknowledged()),
            Err(WalletErrorV1::ChoiceLocked)
        );
        // Not provable until the record is confirmed persisted.
        assert_eq!(
            handle.persisted_lock(&context),
            Err(WalletErrorV1::ChoiceNotPersisted)
        );
        assert!(!handle.is_choice_persisted());
        let record = intent.record_bytes().expect("record");
        assert_eq!(BallotIntentV1::from_record_bytes(&record), Ok(intent));
        let shown = format!("{intent:?}");
        assert!(shown.contains("scope") && !shown.contains(&intent.nullifier.to_hex()[..16]));
        let mut other = intent;
        other.vote = BallotChoiceV1::Nay;
        assert_eq!(
            handle.confirm_choice_persisted_v1(&other.record_bytes().expect("record")),
            Err(WalletErrorV1::ChoiceRecordMismatch)
        );
        assert!(matches!(
            handle.confirm_choice_persisted_v1(&record[1..]),
            Err(WalletErrorV1::Codec(_))
        ));
        handle
            .confirm_choice_persisted_v1(&record)
            .expect("confirmed");
        assert!(handle.is_choice_persisted());
        assert_eq!(handle.persisted_lock(&context), Ok(intent));
        // After a restart the persisted record restores the same lock.
        let mut restored =
            CredentialHandleV1::import_v1(body_context(), &secret_bytes(0), Some(&record))
                .expect("restored");
        assert!(restored.is_choice_persisted());
        assert_eq!(restored.choice_lock(), Some(&intent));
        assert_eq!(
            restored.lock_choice_v1(&context, BallotChoiceV1::Abstain, &acknowledged()),
            Err(WalletErrorV1::ChoiceLocked)
        );
        // Another credential cannot adopt the record.
        assert_eq!(
            CredentialHandleV1::import_v1(body_context(), &secret_bytes(1), Some(&record))
                .map(|handle| handle.is_choice_persisted()),
            Err(WalletErrorV1::ChoiceRecordMismatch)
        );
        let mut foreign_network = body_context();
        foreign_network.network_id = other_network_id();
        assert!(
            CredentialHandleV1::import_v1(foreign_network, &secret_bytes(0), Some(&record))
                .is_err()
        );
        let mut unlocked = member(3);
        assert_eq!(
            unlocked.confirm_choice_persisted_v1(&record),
            Err(WalletErrorV1::ChoiceNotLocked)
        );
    }

    #[test]
    fn locking_needs_the_right_body_acknowledgement_and_roster() {
        let context = scoped_context();
        let mut outsider =
            CredentialHandleV1::import_v1(body_context(), &[0x99; 48], None).expect("handle");
        assert_eq!(
            outsider.lock_choice_v1(&context, BallotChoiceV1::Aye, &acknowledged()),
            Err(WalletErrorV1::NotOnSealedList)
        );
        let mut confirmation_body = body_context();
        confirmation_body.body_role = ParliamentBody::ConfirmationJury;
        let mut foreign = CredentialHandleV1::import_v1(confirmation_body, &secret_bytes(0), None)
            .expect("handle");
        assert_eq!(
            foreign.lock_choice_v1(&context, BallotChoiceV1::Aye, &acknowledged()),
            Err(WalletErrorV1::ForeignBody)
        );
        // An acknowledgement of another instance's ballot does not cover this one.
        let other = ScopedBallotContextV1::new(
            context.context().clone(),
            iroha_data_model::governance::types::BodyInstanceId::new([0x04; 32]),
        )
        .expect("context");
        let elsewhere = BallotDisclosureV1::for_context_v1(&other)
            .acknowledge(&crate::wallet::DisclosureStatementV1::ALL)
            .expect("acknowledged");
        let mut handle = member(0);
        assert_eq!(
            handle.lock_choice_v1(&context, BallotChoiceV1::Aye, &elsewhere),
            Err(WalletErrorV1::DisclosureMismatch)
        );
        assert_eq!(handle.position(&context).map(|_| ()), Ok(()));
    }
}
