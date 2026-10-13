//! Provider-backed phone-control challenge, credential and provider policy.
//!
//! A verification provider checks control of a phone number with a fresh SMS
//! or carrier challenge and signs a short-lived [`PhoneControlCredentialV1`].
//! The credential binds the provider key, the network, the identifier
//! namespace, the complete RAM-LFE policy, the beneficiary account, one
//! challenge, a validity interval and a hiding commitment to the canonical
//! E.164 number. The provider learns the number. Validators, resolvers and
//! the ledger see the commitment only.
//!
//! The section "Provider-backed phone control" of
//! `specs/ram_lfe_execution_proof.md` is the specification. The number
//! commitment, the provider key identity and the signature rule are owned by
//! `iroha_crypto`.
//!
//! A credential is evidence of control at one instant. It does not prove that
//! the committed number is the encrypted input of a receipt, and it replaces
//! no execution, decryption or derivation proof. Nothing in Core, Torii or an
//! SDK consumes these types yet:
//!
//! - TODO(R.2): the private relation proves that the commitment a verified
//!   credential carries opens to the encrypted canonical input and to the
//!   keyed nullifier preimage.
//! - TODO(R.4): State registers [`PhoneControlProviderPolicyV1`], applies
//!   [`PhoneControlEvidenceV1::verify`] in the claim transition, consumes the
//!   challenge, applies the earliest expiry and evicts bindings of a revoked
//!   key.
//! - TODO(R.5): the one-call claim runs the provider challenge; the SDK and
//!   JSON forms of these records arrive with it.

use crate::{
    NetworkId,
    account::AccountId,
    identifier::IdentifierPolicyId,
    ram_lfe::{RamLfeProgramId, RamLfeReceiptV1, RamLfeReplayDomainV1},
};
use iroha_crypto::{
    Hash, KeyPair, PhoneControlError, PhoneControlProviderKeyIdV1, PhoneNumberCommitmentV1,
    PublicKey, RamLfePolicyCommitmentV1, Signature, phone_control_provider_sign,
    phone_control_provider_verify,
};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::vec::Vec;

const PROVIDER_POLICY_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.phone_control.provider_policy";
const CHALLENGE_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.phone_control.challenge";
const CREDENTIAL_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.phone_control.credential";

/// Blake2b and signature domains owned by the data model for provider-backed
/// phone control.
///
/// They extend `iroha_crypto::PHONE_CONTROL_V1_CRYPTO_DOMAINS` and the RAM-LFE
/// V1 tables; no domain of any table is a prefix of another.
pub const PHONE_CONTROL_V1_MODEL_DOMAINS: [&[u8]; 3] =
    [PROVIDER_POLICY_DOMAIN, CHALLENGE_DOMAIN, CREDENTIAL_DOMAIN];

/// Maximum number of keys one provider policy holds, in every state.
///
/// A retired key frees its slot when it is removed. A revoked key never
/// frees its slot, so this is also the number of revocations after which a
/// namespace can register no further key.
pub const PHONE_CONTROL_V1_MAX_PROVIDER_KEYS: usize = 32;

fn encoding_error(error: &norito::core::Error) -> PhoneControlError {
    PhoneControlError::Encoding(error.to_string())
}

fn canonical_frame<T: norito::NoritoSerialize>(value: &T) -> Result<Vec<u8>, PhoneControlError> {
    norito::encode_canonical(value).map_err(|error| encoding_error(&error))
}

fn canonical_commitment<T: norito::NoritoSerialize>(
    domain: &[u8],
    value: &T,
) -> Result<Hash, PhoneControlError> {
    Ok(Hash::new_from_chunks(&[domain, &canonical_frame(value)?]))
}

/// Lifecycle state of one provider key.
///
/// Every transition narrows what is admitted: it never makes a rejected
/// credential admissible and never restores an evicted binding.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::phone_control::PhoneControlProviderKeyStateV1")]
pub enum PhoneControlProviderKeyStateV1 {
    /// The key issues credentials from its activation on.
    Active,
    /// Rotated out. The key issues nothing from `retired_from_ms` on.
    ///
    /// Retirement is an issuance boundary. A credential issued earlier stays
    /// admissible until it expires, and no existing binding ends. The instant
    /// is never earlier than the ledger time of the transition that recorded
    /// it, so every credential admitted under the key was issued at or before
    /// it.
    Retired {
        /// First instant, in milliseconds, at which the key issues nothing.
        retired_from_ms: u64,
    },
    /// Revoked. No credential under the key is admissible, whatever its issue
    /// time, because a compromised key can backdate it. The state is terminal
    /// for the key identity.
    Revoked {
        /// Ledger time, in milliseconds, from which admissions under the key
        /// are not trusted. When the onset of a compromise is unknown, this is
        /// a conservative cutoff that covers every admission it may affect.
        compromised_from_ms: u64,
    },
}

/// One provider verification key and its lifecycle in committed State.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::phone_control::PhoneControlProviderKeyV1")]
pub struct PhoneControlProviderKeyV1 {
    /// Provider verification key: Ed25519 or ML-DSA-65.
    pub public_key: PublicKey,
    /// First instant, in milliseconds, at which the key may issue a
    /// credential. It is kept in every state.
    pub active_from_ms: u64,
    /// Lifecycle state.
    pub state: PhoneControlProviderKeyStateV1,
}

impl PhoneControlProviderKeyV1 {
    /// Return the identity of this key.
    ///
    /// # Errors
    /// Rejects a key that is neither Ed25519 nor ML-DSA-65.
    pub fn id(&self) -> Result<PhoneControlProviderKeyIdV1, PhoneControlError> {
        PhoneControlProviderKeyIdV1::commit(&self.public_key)
    }

    /// Reject a key record no provider policy may hold.
    ///
    /// # Errors
    /// Rejects an unsupported key algorithm and a retirement before activation.
    pub fn validate(&self) -> Result<(), PhoneControlError> {
        self.id()?;
        if let PhoneControlProviderKeyStateV1::Retired { retired_from_ms } = self.state
            && retired_from_ms < self.active_from_ms
        {
            return Err(PhoneControlError::InvalidProviderPolicy(
                "provider key retires before it becomes active",
            ));
        }
        Ok(())
    }

    /// Check that this key could issue a credential at `issued_at_ms`.
    ///
    /// # Errors
    /// Returns [`PhoneControlError::ProviderKeyRevoked`] for a revoked key at
    /// any issue time, [`PhoneControlError::ProviderKeyNotActive`] before
    /// activation and [`PhoneControlError::ProviderKeyRetired`] at or after
    /// retirement.
    pub const fn verify_issuance(&self, issued_at_ms: u64) -> Result<(), PhoneControlError> {
        match self.state {
            PhoneControlProviderKeyStateV1::Revoked { .. } => {
                Err(PhoneControlError::ProviderKeyRevoked)
            }
            _ if issued_at_ms < self.active_from_ms => Err(PhoneControlError::ProviderKeyNotActive),
            PhoneControlProviderKeyStateV1::Retired { retired_from_ms }
                if issued_at_ms >= retired_from_ms =>
            {
                Err(PhoneControlError::ProviderKeyRetired)
            }
            PhoneControlProviderKeyStateV1::Active
            | PhoneControlProviderKeyStateV1::Retired { .. } => Ok(()),
        }
    }

    // TODO(R.4): no State transition applies this rule yet. The claim lifecycle
    // stores, with every binding, the key identity and the ledger admission time
    // of its supporting credential, and evicts on revocation.
    /// Return whether revocation of this key evicts a binding.
    ///
    /// `admitted_at_ms` is the ledger time at which the credential that
    /// supports the binding was admitted, for a first claim and for every
    /// renewal. It is the ledger's time and not the credential's issue time,
    /// which a compromised key can forge.
    #[must_use]
    pub const fn evicts_binding(&self, admitted_at_ms: u64) -> bool {
        match self.state {
            PhoneControlProviderKeyStateV1::Revoked {
                compromised_from_ms,
            } => admitted_at_ms >= compromised_from_ms,
            PhoneControlProviderKeyStateV1::Active
            | PhoneControlProviderKeyStateV1::Retired { .. } => false,
        }
    }
}

/// Commitment to one complete [`PhoneControlProviderPolicyV1`].
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::phone_control::PhoneControlProviderPolicyCommitmentV1")]
pub struct PhoneControlProviderPolicyCommitmentV1(Hash);

impl PhoneControlProviderPolicyCommitmentV1 {
    /// Borrow the marked Iroha Blake2b digest.
    #[must_use]
    pub const fn as_hash(&self) -> &Hash {
        &self.0
    }
}

/// Provider trust policy of one identifier namespace, held in committed State.
///
/// It names the providers whose credentials the namespace admits and the two
/// lifetime bounds. Validators take every field from committed State. A
/// claimant and a provider supply none.
///
/// After registration the record changes only through its transitions:
/// [`Self::register_key`], [`Self::retire_key`], [`Self::revoke_key`],
/// [`Self::remove_retired_key`] and [`Self::set_lifetimes`]. Each takes the
/// consensus time of the block that applies it where the rule depends on
/// time, and the rules assume that this time never decreases. The fields are
/// public because the record is a plain Norito value; [`Self::validate`]
/// checks its shape and cannot check its history.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::phone_control::PhoneControlProviderPolicyV1")]
pub struct PhoneControlProviderPolicyV1 {
    /// Identifier namespace this policy governs.
    pub identifier_policy: IdentifierPolicyId,
    /// Longest admitted credential lifetime, in milliseconds. A binding never
    /// outlives its credential, so this also bounds how long a number stays
    /// bound without fresh control.
    pub max_credential_lifetime_ms: u64,
    /// Longest life of a binding counted from the issue time of its
    /// credential, in milliseconds. At most the credential lifetime.
    pub max_binding_lifetime_ms: u64,
    /// First instant, in milliseconds, at which every credential admitted
    /// under an earlier, longer credential lifetime has expired. Zero while
    /// the credential lifetime was never lowered. [`Self::set_lifetimes`]
    /// maintains it, and no retired key is removed before it.
    pub longer_credentials_expire_by_ms: u64,
    /// Provider keys in strictly ascending order of their identity.
    pub keys: Vec<PhoneControlProviderKeyV1>,
}

impl PhoneControlProviderPolicyV1 {
    /// Build a provider policy without keys.
    ///
    /// # Errors
    /// Rejects a zero lifetime and a binding lifetime above the credential
    /// lifetime.
    pub fn new(
        identifier_policy: IdentifierPolicyId,
        max_credential_lifetime_ms: u64,
        max_binding_lifetime_ms: u64,
    ) -> Result<Self, PhoneControlError> {
        Self::validate_lifetimes(max_credential_lifetime_ms, max_binding_lifetime_ms)?;
        Ok(Self {
            identifier_policy,
            max_credential_lifetime_ms,
            max_binding_lifetime_ms,
            longer_credentials_expire_by_ms: 0,
            keys: Vec::new(),
        })
    }

    /// Reject a pair of lifetimes no policy may commit to.
    ///
    /// A binding lifetime above the credential lifetime could never be
    /// reached, because a binding never outlives its credential.
    const fn validate_lifetimes(
        max_credential_lifetime_ms: u64,
        max_binding_lifetime_ms: u64,
    ) -> Result<(), PhoneControlError> {
        if max_credential_lifetime_ms == 0 {
            return Err(PhoneControlError::InvalidProviderPolicy(
                "credential lifetime must not be zero",
            ));
        }
        if max_binding_lifetime_ms == 0 {
            return Err(PhoneControlError::InvalidProviderPolicy(
                "binding lifetime must not be zero",
            ));
        }
        if max_binding_lifetime_ms > max_credential_lifetime_ms {
            return Err(PhoneControlError::InvalidProviderPolicy(
                "binding lifetime exceeds the credential lifetime",
            ));
        }
        Ok(())
    }

    /// Identities of the keys, in record order, after checking each key.
    fn key_ids(&self) -> Result<Vec<PhoneControlProviderKeyIdV1>, PhoneControlError> {
        if self.keys.len() > PHONE_CONTROL_V1_MAX_PROVIDER_KEYS {
            return Err(PhoneControlError::ProviderKeyCapacity {
                limit: PHONE_CONTROL_V1_MAX_PROVIDER_KEYS,
            });
        }
        self.keys
            .iter()
            .map(|key| {
                key.validate()?;
                key.id()
            })
            .collect()
    }

    // TODO(R.4): State validates the policy when it is registered, changed and
    // restored; no State path holds a provider policy yet.
    /// Reject a policy no namespace may commit to.
    ///
    /// This checks the shape of the record. It cannot check that the record
    /// was reached through the transitions of this type.
    ///
    /// # Errors
    /// Returns [`PhoneControlError::InvalidProviderPolicy`] for a zero or
    /// inverted lifetime, for an invalid key and for keys that are not in
    /// strictly ascending order of identity, and
    /// [`PhoneControlError::ProviderKeyCapacity`] for too many keys.
    pub fn validate(&self) -> Result<(), PhoneControlError> {
        Self::validate_lifetimes(
            self.max_credential_lifetime_ms,
            self.max_binding_lifetime_ms,
        )?;
        let ids = self.key_ids()?;
        if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(PhoneControlError::InvalidProviderPolicy(
                "provider keys are not in strictly ascending order of identity",
            ));
        }
        Ok(())
    }

    /// Commit the complete policy.
    ///
    /// # Errors
    /// Rejects an invalid policy and reports a canonical encoding failure.
    pub fn commitment(&self) -> Result<PhoneControlProviderPolicyCommitmentV1, PhoneControlError> {
        self.validate()?;
        canonical_commitment(PROVIDER_POLICY_DOMAIN, self)
            .map(PhoneControlProviderPolicyCommitmentV1)
    }

    fn position(&self, id: &PhoneControlProviderKeyIdV1) -> Result<usize, PhoneControlError> {
        self.key_ids()?
            .binary_search(id)
            .map_err(|_| PhoneControlError::UnknownProviderKey)
    }

    /// Find the key a credential names.
    ///
    /// # Errors
    /// Returns [`PhoneControlError::UnknownProviderKey`] when no key of the
    /// policy has this identity.
    pub fn key(
        &self,
        id: &PhoneControlProviderKeyIdV1,
    ) -> Result<&PhoneControlProviderKeyV1, PhoneControlError> {
        self.position(id).map(|index| &self.keys[index])
    }

    // TODO(R.4): no State transition applies the transitions below yet. The
    // owner of the identifier policy applies each through an authorized
    // instruction, State passes the consensus time of the block that carries
    // it, and State changes a registered provider policy in no other way.
    /// Change the two lifetime bounds. This is the only change of a lifetime
    /// after the policy is registered.
    ///
    /// `now_ms` is the consensus time of the changing transition. The new
    /// bounds apply to every later admission. A binding that exists keeps the
    /// expiry it was admitted with.
    ///
    /// Lowering the credential lifetime must not shorten the wait before a
    /// retired key is removed, because credentials admitted under the longer
    /// lifetime are still live. Each was admitted at or before `now_ms` and
    /// therefore expires at or before `now_ms` plus the previous lifetime.
    /// The policy keeps the latest such instant in
    /// `longer_credentials_expire_by_ms`, and no retired key is removed
    /// before it. Raising a lifetime, and any change of the binding lifetime,
    /// needs no such record.
    ///
    /// # Errors
    /// Returns [`PhoneControlError::InvalidProviderPolicy`] for a zero
    /// lifetime, for a binding lifetime above the credential lifetime and for
    /// a lowering so late that `now_ms` plus the previous credential lifetime
    /// overflows. A rejected change leaves the policy as it was.
    pub fn set_lifetimes(
        &mut self,
        max_credential_lifetime_ms: u64,
        max_binding_lifetime_ms: u64,
        now_ms: u64,
    ) -> Result<(), PhoneControlError> {
        Self::validate_lifetimes(max_credential_lifetime_ms, max_binding_lifetime_ms)?;
        if max_credential_lifetime_ms < self.max_credential_lifetime_ms {
            let expire_by_ms = now_ms.checked_add(self.max_credential_lifetime_ms).ok_or(
                PhoneControlError::InvalidProviderPolicy(
                    "lowering the credential lifetime overflows the time range",
                ),
            )?;
            self.longer_credentials_expire_by_ms =
                self.longer_credentials_expire_by_ms.max(expire_by_ms);
        }
        self.max_credential_lifetime_ms = max_credential_lifetime_ms;
        self.max_binding_lifetime_ms = max_binding_lifetime_ms;
        Ok(())
    }

    /// Register a provider key.
    ///
    /// `now_ms` is the consensus time of the registering transition. A key is
    /// trusted from its registration on, so `active_from_ms` is not earlier.
    ///
    /// # Errors
    /// Rejects an unsupported algorithm, an activation before `now_ms`, an
    /// identity that is already registered in any state and a full policy.
    pub fn register_key(
        &mut self,
        public_key: PublicKey,
        active_from_ms: u64,
        now_ms: u64,
    ) -> Result<PhoneControlProviderKeyIdV1, PhoneControlError> {
        let key = PhoneControlProviderKeyV1 {
            public_key,
            active_from_ms,
            state: PhoneControlProviderKeyStateV1::Active,
        };
        let id = key.id()?;
        if active_from_ms < now_ms {
            return Err(PhoneControlError::InvalidProviderKeyTransition(
                "a key cannot become active before it is registered",
            ));
        }
        let index = match self.key_ids()?.binary_search(&id) {
            Ok(_) => return Err(PhoneControlError::DuplicateProviderKey),
            Err(index) => index,
        };
        // TODO(R.4): a revoked key keeps its slot for ever, so a namespace whose
        // every slot is revoked registers no further key and admits no new
        // claim. This contract has no way back. R.4 decides the recovery
        // policy; a replacement of the provider policy must not trust a
        // revoked identity again without saying so.
        if self.keys.len() == PHONE_CONTROL_V1_MAX_PROVIDER_KEYS {
            return Err(PhoneControlError::ProviderKeyCapacity {
                limit: PHONE_CONTROL_V1_MAX_PROVIDER_KEYS,
            });
        }
        self.keys.insert(index, key);
        Ok(id)
    }

    /// Retire a key: it issues nothing from `retired_from_ms` on.
    ///
    /// `now_ms` is the consensus time of the retiring transition. A retirement
    /// is never backdated: `retired_from_ms` is not earlier than `now_ms`, and
    /// not earlier than the activation of the key. A retired key may only
    /// retire earlier, and again not earlier than `now_ms`, so a retirement
    /// whose instant has passed is final.
    ///
    /// The rule keeps the removal bound of [`Self::remove_retired_key`] sound.
    /// Every credential admitted before the transition was issued at or
    /// before `now_ms`, and every later one before `retired_from_ms`, so none
    /// was issued after the recorded instant. A key that may have signed
    /// without the provider's consent in the past is not retired into the
    /// past. It is revoked ([`Self::revoke_key`]).
    ///
    /// # Errors
    /// Rejects an unknown key, a revoked key, a retirement before activation,
    /// a retirement before `now_ms` and a retirement that is not earlier than
    /// the recorded one.
    pub fn retire_key(
        &mut self,
        id: &PhoneControlProviderKeyIdV1,
        retired_from_ms: u64,
        now_ms: u64,
    ) -> Result<(), PhoneControlError> {
        let index = self.position(id)?;
        let key = &mut self.keys[index];
        let recorded = match key.state {
            PhoneControlProviderKeyStateV1::Revoked { .. } => {
                return Err(PhoneControlError::InvalidProviderKeyTransition(
                    "revocation is terminal",
                ));
            }
            PhoneControlProviderKeyStateV1::Active => None,
            PhoneControlProviderKeyStateV1::Retired { retired_from_ms } => Some(retired_from_ms),
        };
        if retired_from_ms < key.active_from_ms {
            return Err(PhoneControlError::InvalidProviderKeyTransition(
                "a key cannot retire before it becomes active",
            ));
        }
        if retired_from_ms < now_ms {
            return Err(PhoneControlError::InvalidProviderKeyTransition(
                "a retirement is never backdated",
            ));
        }
        if recorded.is_some_and(|recorded| retired_from_ms >= recorded) {
            return Err(PhoneControlError::InvalidProviderKeyTransition(
                "a retired key may only retire earlier",
            ));
        }
        key.state = PhoneControlProviderKeyStateV1::Retired { retired_from_ms };
        Ok(())
    }

    /// Revoke a key: no credential under it is admissible any more.
    ///
    /// An active or retired key is revoked with any cutoff, also one in the
    /// past: the cutoff states from which ledger time admissions under the
    /// key are not trusted, and it evicts the bindings admitted from then on.
    /// A revoked key may only move its cutoff earlier. The record keeps its
    /// slot for ever, so the identity is never registered again.
    ///
    /// # Errors
    /// Rejects an unknown key and a cutoff that is not earlier than the
    /// recorded one.
    pub fn revoke_key(
        &mut self,
        id: &PhoneControlProviderKeyIdV1,
        compromised_from_ms: u64,
    ) -> Result<(), PhoneControlError> {
        let index = self.position(id)?;
        let key = &mut self.keys[index];
        if let PhoneControlProviderKeyStateV1::Revoked {
            compromised_from_ms: recorded,
        } = key.state
            && compromised_from_ms >= recorded
        {
            return Err(PhoneControlError::InvalidProviderKeyTransition(
                "a revoked key may only move its cutoff earlier",
            ));
        }
        key.state = PhoneControlProviderKeyStateV1::Revoked {
            compromised_from_ms,
        };
        Ok(())
    }

    /// Remove a retired key once nothing can depend on it.
    ///
    /// The record frees its slot from the later of two instants on:
    /// `retired_from_ms + max_credential_lifetime_ms` and
    /// `longer_credentials_expire_by_ms`. Every credential admitted under the
    /// key was issued at or before `retired_from_ms`
    /// ([`Self::retire_key`]) and lives at most the credential lifetime it was
    /// admitted under, which is the current one or one whose credentials
    /// [`Self::set_lifetimes`] recorded. The expiry is exclusive, so at that
    /// instant every such credential has expired, and so has every binding,
    /// because no binding outlives its credential. A revoked key is never
    /// removed.
    ///
    /// # Errors
    /// Rejects an unknown key, a key that is not retired and a removal before
    /// that instant.
    pub fn remove_retired_key(
        &mut self,
        id: &PhoneControlProviderKeyIdV1,
        now_ms: u64,
    ) -> Result<(), PhoneControlError> {
        let index = self.position(id)?;
        let PhoneControlProviderKeyStateV1::Retired { retired_from_ms } = self.keys[index].state
        else {
            return Err(PhoneControlError::InvalidProviderKeyTransition(
                "only a retired key is removed",
            ));
        };
        let removable = retired_from_ms
            .checked_add(self.max_credential_lifetime_ms)
            .is_some_and(|removable_from_ms| {
                now_ms >= removable_from_ms.max(self.longer_credentials_expire_by_ms)
            });
        if !removable {
            return Err(PhoneControlError::InvalidProviderKeyTransition(
                "a credential of the retired key may still be live",
            ));
        }
        self.keys.remove(index);
        Ok(())
    }
}

/// Identity of one challenge: the commitment to its complete record.
///
/// It is the nonce of the credential that answers the challenge, and the
/// value State consumes once per network.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::phone_control::PhoneControlChallengeIdV1")]
pub struct PhoneControlChallengeIdV1(Hash);

impl PhoneControlChallengeIdV1 {
    /// Borrow the marked Iroha Blake2b digest.
    #[must_use]
    pub const fn as_hash(&self) -> &Hash {
        &self.0
    }
}

/// One fresh control challenge, as the client and the provider agreed it.
///
/// The client fixes what the credential will be bound to and contributes
/// `client_nonce`. The provider contributes `provider_nonce` and the expiry
/// before it sends the SMS or carrier challenge to the number. The record
/// carries no phone number and no one-time code.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::phone_control::PhoneControlChallengeV1")]
pub struct PhoneControlChallengeV1 {
    /// Provider key that will sign the credential.
    pub provider: PhoneControlProviderKeyIdV1,
    /// Exact genesis-derived deployment identity.
    pub network: NetworkId,
    /// Identifier namespace the claim is made in.
    pub identifier_policy: IdentifierPolicyId,
    /// Commitment to the complete authoritative RAM-LFE policy.
    pub policy: RamLfePolicyCommitmentV1,
    /// Account the number will be bound to.
    pub beneficiary: AccountId,
    /// Hiding commitment to the canonical E.164 number.
    pub number: PhoneNumberCommitmentV1,
    /// Fresh client randomness: the provider cannot reuse an earlier record.
    pub client_nonce: [u8; 32],
    /// Fresh provider randomness: the client cannot predict the identity of
    /// the challenge before the provider opens it.
    pub provider_nonce: [u8; 32],
    /// Expiry of the credential that answers this challenge, in milliseconds
    /// since the Unix epoch. It is fixed when the challenge opens.
    pub expires_at_ms: u64,
}

impl PhoneControlChallengeV1 {
    /// Return the identity of this challenge.
    ///
    /// # Errors
    /// Reports a canonical encoding failure.
    pub fn id(&self) -> Result<PhoneControlChallengeIdV1, PhoneControlError> {
        canonical_commitment(CHALLENGE_DOMAIN, self).map(PhoneControlChallengeIdV1)
    }
}

/// Provider statement that one account controlled one committed number.
///
/// The provider signs [`Self::signing_message`]. The statement is evidence of
/// control at `issued_at_ms` and nothing else: canonical format, uniqueness
/// and a well-formed commitment do not establish control, and the credential
/// does not establish what a ciphertext encrypts.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::phone_control::PhoneControlCredentialV1")]
pub struct PhoneControlCredentialV1 {
    /// Provider key that signs this credential.
    pub provider: PhoneControlProviderKeyIdV1,
    /// Exact genesis-derived deployment identity.
    pub network: NetworkId,
    /// Identifier namespace the claim is made in.
    pub identifier_policy: IdentifierPolicyId,
    /// Commitment to the complete authoritative RAM-LFE policy.
    pub policy: RamLfePolicyCommitmentV1,
    /// Account that showed control and receives the binding.
    pub beneficiary: AccountId,
    /// Challenge this credential answers. State consumes it once per network.
    pub challenge: PhoneControlChallengeIdV1,
    /// Hiding commitment to the canonical E.164 number.
    pub number: PhoneNumberCommitmentV1,
    /// Instant the provider confirmed control, in milliseconds since the Unix
    /// epoch.
    pub issued_at_ms: u64,
    /// Exclusive expiry in milliseconds since the Unix epoch. It equals the
    /// expiry of the challenge.
    pub expires_at_ms: u64,
}

impl PhoneControlCredentialV1 {
    /// Build the credential that answers a challenge the claimant passed.
    ///
    /// The provider calls this after the SMS or carrier challenge succeeded
    /// for the number whose commitment it recomputed.
    ///
    /// # Errors
    /// Reports a canonical encoding failure.
    pub fn answering(
        challenge: &PhoneControlChallengeV1,
        issued_at_ms: u64,
    ) -> Result<Self, PhoneControlError> {
        Ok(Self {
            provider: challenge.provider,
            network: challenge.network,
            identifier_policy: challenge.identifier_policy.clone(),
            policy: challenge.policy,
            beneficiary: challenge.beneficiary.clone(),
            challenge: challenge.id()?,
            number: challenge.number,
            issued_at_ms,
            expires_at_ms: challenge.expires_at_ms,
        })
    }

    /// Return the exact bytes the provider signs: the credential domain
    /// followed by the canonical Norito frame of this record.
    ///
    /// # Errors
    /// Reports a canonical encoding failure.
    pub fn signing_message(&self) -> Result<Vec<u8>, PhoneControlError> {
        let frame = canonical_frame(self)?;
        let mut message = Vec::with_capacity(CREDENTIAL_DOMAIN.len() + frame.len());
        message.extend_from_slice(CREDENTIAL_DOMAIN);
        message.extend_from_slice(&frame);
        Ok(message)
    }

    /// Sign the credential with the provider key it names.
    ///
    /// # Errors
    /// Rejects a key pair other than the one the credential names, an
    /// unsupported key algorithm and a signing failure.
    pub fn sign(
        self,
        provider: &KeyPair,
    ) -> Result<PhoneControlSignedCredentialV1, PhoneControlError> {
        if PhoneControlProviderKeyIdV1::commit(provider.public_key())? != self.provider {
            return Err(PhoneControlError::ContextMismatch("provider key"));
        }
        let signature =
            phone_control_provider_sign(provider.private_key(), &self.signing_message()?)?;
        Ok(PhoneControlSignedCredentialV1 {
            credential: self,
            signature,
        })
    }

    /// Check that this credential answers exactly the presented challenge.
    ///
    /// The identity of the challenge commits its complete record, and the
    /// credential repeats every field they share. The expiry is part of the
    /// record, so a challenge identity has one expiry for ever: after State
    /// pruned a consumed challenge at that expiry, no credential that names it
    /// is admissible.
    ///
    /// # Errors
    /// Returns [`PhoneControlError::ChallengeMismatch`] naming the first field
    /// that differs.
    pub fn verify_challenge(
        &self,
        challenge: &PhoneControlChallengeV1,
    ) -> Result<(), PhoneControlError> {
        let mismatch = if self.challenge != challenge.id()? {
            Some("challenge identity")
        } else if self.provider != challenge.provider {
            Some("provider key")
        } else if self.network != challenge.network {
            Some("network")
        } else if self.identifier_policy != challenge.identifier_policy {
            Some("identifier policy")
        } else if self.policy != challenge.policy {
            Some("policy")
        } else if self.beneficiary != challenge.beneficiary {
            Some("beneficiary")
        } else if self.number != challenge.number {
            Some("number commitment")
        } else if self.expires_at_ms != challenge.expires_at_ms {
            Some("expiry")
        } else {
            None
        };
        mismatch.map_or(Ok(()), |field| {
            Err(PhoneControlError::ChallengeMismatch(field))
        })
    }

    /// Check the shape of the validity interval against the committed policy.
    fn verify_lifetime(&self, max_credential_lifetime_ms: u64) -> Result<(), PhoneControlError> {
        match self.expires_at_ms.checked_sub(self.issued_at_ms) {
            None | Some(0) => Err(PhoneControlError::EmptyValidity),
            Some(lifetime_ms) if lifetime_ms > max_credential_lifetime_ms => {
                Err(PhoneControlError::LifetimeExceeded {
                    limit_ms: max_credential_lifetime_ms,
                })
            }
            Some(_) => Ok(()),
        }
    }
}

/// A credential with the provider signature over it.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::phone_control::PhoneControlSignedCredentialV1")]
pub struct PhoneControlSignedCredentialV1 {
    /// Statement the provider signed.
    pub credential: PhoneControlCredentialV1,
    /// Provider signature over [`PhoneControlCredentialV1::signing_message`].
    pub signature: Signature,
}

/// Control evidence one phone claim carries: the challenge record and the
/// signed credential that answers it.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::phone_control::PhoneControlEvidenceV1")]
pub struct PhoneControlEvidenceV1 {
    /// Complete record of the challenge the credential answers.
    pub challenge: PhoneControlChallengeV1,
    /// Credential and provider signature.
    pub credential: PhoneControlSignedCredentialV1,
}

/// Authoritative values a validator compares control evidence with.
///
/// The network is the validator's own. State resolves the namespace of the
/// claim and the complete RAM-LFE policy registered for it. The beneficiary is
/// the account the claim binds. A claimant supplies none of them through the
/// evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhoneControlContextV1 {
    /// Exact genesis-derived deployment identity.
    pub network: NetworkId,
    /// Identifier namespace of the claim.
    pub identifier_policy: IdentifierPolicyId,
    /// Commitment to the complete authoritative RAM-LFE policy.
    pub policy: RamLfePolicyCommitmentV1,
    /// Account the claim binds.
    pub beneficiary: AccountId,
}

impl PhoneControlContextV1 {
    /// Check that a receipt belongs to the same claim as the control evidence.
    ///
    /// `program_id` is the program State resolves for the namespace. The
    /// receipt must name that program, the same network, complete policy and
    /// beneficiary, and the identifier-claim replay scope.
    ///
    /// # Errors
    /// Returns [`PhoneControlError::ContextMismatch`] naming the first value
    /// that differs.
    pub fn verify_receipt(
        &self,
        receipt: &RamLfeReceiptV1,
        program_id: &RamLfeProgramId,
    ) -> Result<(), PhoneControlError> {
        let mismatch = if receipt.network != self.network {
            Some("receipt network")
        } else if receipt.policy != self.policy {
            Some("receipt policy")
        } else if &receipt.program_id != program_id {
            Some("receipt program")
        } else if receipt.beneficiary != self.beneficiary {
            Some("receipt beneficiary")
        } else if receipt.replay.domain != RamLfeReplayDomainV1::IdentifierClaim {
            Some("receipt replay scope")
        } else {
            None
        };
        mismatch.map_or(Ok(()), |field| {
            Err(PhoneControlError::ContextMismatch(field))
        })
    }
}

impl PhoneControlEvidenceV1 {
    // TODO(R.4): no claim transition calls this yet. `ClaimIdentifier` applies
    // it together with the private relation of R.2; neither replaces the other.
    /// Verify control evidence for one claim.
    ///
    /// `provider_policy` and `context` come from committed State. `now_ms` is
    /// the consensus time of the block that admits the claim, never a node's
    /// clock. The credential is admissible while
    /// `issued_at_ms <= now_ms < expires_at_ms`, and only while the binding it
    /// supports would still be live: `now_ms < issued_at_ms +
    /// max_binding_lifetime_ms`.
    ///
    /// Success establishes that a registered, unrevoked provider key signed
    /// exactly this credential for this network, namespace, policy and
    /// beneficiary, that the credential answers the presented challenge and
    /// that it is inside its validity interval. It does not establish that the
    /// challenge is unused: the caller consumes
    /// [`PhoneControlAdmissionV1::challenge`] in the same transition
    /// ([`PhoneControlAdmissionV1::consume_challenge`]). It does not establish
    /// what any ciphertext encrypts.
    ///
    /// # Errors
    /// Returns the first failed check: an invalid provider policy, a value
    /// bound to another context, a challenge mismatch, a malformed or too
    /// long validity interval, an unknown,
    /// inactive, retired or revoked key, a time outside the interval, a
    /// binding that would already be over, or a signature that does not
    /// verify.
    pub fn verify(
        &self,
        provider_policy: &PhoneControlProviderPolicyV1,
        context: &PhoneControlContextV1,
        now_ms: u64,
    ) -> Result<PhoneControlAdmissionV1, PhoneControlError> {
        provider_policy.validate()?;
        let credential = &self.credential.credential;
        let mismatch = if provider_policy.identifier_policy != context.identifier_policy {
            Some("provider policy namespace")
        } else if credential.network != context.network {
            Some("network")
        } else if credential.identifier_policy != context.identifier_policy {
            Some("identifier policy")
        } else if credential.policy != context.policy {
            Some("policy")
        } else if credential.beneficiary != context.beneficiary {
            Some("beneficiary")
        } else {
            None
        };
        if let Some(field) = mismatch {
            return Err(PhoneControlError::ContextMismatch(field));
        }
        credential.verify_challenge(&self.challenge)?;
        credential.verify_lifetime(provider_policy.max_credential_lifetime_ms)?;
        let key = provider_policy.key(&credential.provider)?;
        key.verify_issuance(credential.issued_at_ms)?;
        if now_ms < credential.issued_at_ms {
            return Err(PhoneControlError::NotYetValid);
        }
        if now_ms >= credential.expires_at_ms {
            return Err(PhoneControlError::Expired);
        }
        // A binding never outlives its credential. An issue time so late that
        // the committed binding lifetime overflows leaves the credential
        // expiry as the bound.
        let binding_expires_at_ms = credential
            .issued_at_ms
            .checked_add(provider_policy.max_binding_lifetime_ms)
            .map_or(credential.expires_at_ms, |bound_ms| {
                bound_ms.min(credential.expires_at_ms)
            });
        if now_ms >= binding_expires_at_ms {
            return Err(PhoneControlError::BindingExpired);
        }
        phone_control_provider_verify(
            &key.public_key,
            &credential.signing_message()?,
            &self.credential.signature,
        )?;
        Ok(PhoneControlAdmissionV1 {
            network: credential.network,
            challenge: credential.challenge,
            provider: credential.provider,
            number: credential.number,
            admitted_at_ms: now_ms,
            credential_expires_at_ms: credential.expires_at_ms,
            binding_expires_at_ms,
        })
    }
}

/// Facts established by [`PhoneControlEvidenceV1::verify`].
///
/// Only verification builds this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhoneControlAdmissionV1 {
    network: NetworkId,
    challenge: PhoneControlChallengeIdV1,
    provider: PhoneControlProviderKeyIdV1,
    number: PhoneNumberCommitmentV1,
    admitted_at_ms: u64,
    credential_expires_at_ms: u64,
    binding_expires_at_ms: u64,
}

impl PhoneControlAdmissionV1 {
    /// Network the challenge is consumed on.
    #[must_use]
    pub const fn network(&self) -> &NetworkId {
        &self.network
    }

    /// Challenge the credential answers. It is consumed once per network.
    #[must_use]
    pub const fn challenge(&self) -> &PhoneControlChallengeIdV1 {
        &self.challenge
    }

    /// Provider key that signed. State keeps it with the binding, with
    /// [`Self::admitted_at_ms`], so revocation can evict the binding.
    #[must_use]
    pub const fn provider(&self) -> &PhoneControlProviderKeyIdV1 {
        &self.provider
    }

    /// Ledger time of this admission: the `now_ms` the evidence was verified
    /// at. A renewal replaces the stored key and time with those of the new
    /// evidence.
    #[must_use]
    pub const fn admitted_at_ms(&self) -> u64 {
        self.admitted_at_ms
    }

    // TODO(R.2): the private relation binds this commitment to the encrypted
    // canonical input of the receipt and to the keyed nullifier. Until it does,
    // a verified credential says nothing about the ciphertext of a claim.
    /// Number commitment the private relation takes as a public input.
    #[must_use]
    pub const fn number(&self) -> &PhoneNumberCommitmentV1 {
        &self.number
    }

    /// Exclusive expiry of the credential.
    #[must_use]
    pub const fn credential_expires_at_ms(&self) -> u64 {
        self.credential_expires_at_ms
    }

    /// Bound the credential and the provider policy put on the binding: the
    /// earlier of the credential expiry and the issue time plus the committed
    /// binding lifetime. It is strictly after [`Self::admitted_at_ms`].
    #[must_use]
    pub const fn binding_expires_at_ms(&self) -> u64 {
        self.binding_expires_at_ms
    }

    // TODO(R.4): the claim lifecycle passes the receipt, opening, key and policy
    // bounds it enforces and stores the result as the expiry of the binding,
    // for a first claim and for a renewal alike.
    /// Return the expiry of the binding: the earliest applicable bound.
    ///
    /// `other_bounds` are the expiries of everything else the binding rests
    /// on: the receipt, the opening, the keys and the policy. A bound that
    /// does not exist is left out. The result is never later than
    /// [`Self::binding_expires_at_ms`]. A renewal takes the result as it is,
    /// also when it is earlier than the expiry it replaces.
    ///
    /// # Errors
    /// Returns [`PhoneControlError::BindingExpired`] when the earliest bound
    /// is not strictly after the admission time: such a binding would never
    /// be live.
    pub fn earliest_expiry_ms(&self, other_bounds: &[u64]) -> Result<u64, PhoneControlError> {
        let earliest_ms = other_bounds
            .iter()
            .copied()
            .fold(self.binding_expires_at_ms, u64::min);
        if earliest_ms <= self.admitted_at_ms {
            return Err(PhoneControlError::BindingExpired);
        }
        Ok(earliest_ms)
    }

    // TODO(R.4): State keeps the consumed challenges of each network and applies
    // this rule in the transition that admits the claim.
    /// Consume the challenge of this admission.
    ///
    /// `recorded` is the entry State holds for
    /// (`network`, `challenge`), if any. The result is the expiry to record
    /// with the challenge, in the same atomic transition that admits the
    /// claim. A rejected transaction consumes nothing.
    ///
    /// # Errors
    /// Returns [`PhoneControlError::ChallengeReplayed`] when State already
    /// holds the challenge.
    pub const fn consume_challenge(&self, recorded: Option<u64>) -> Result<u64, PhoneControlError> {
        match recorded {
            Some(_) => Err(PhoneControlError::ChallengeReplayed),
            None => Ok(self.credential_expires_at_ms),
        }
    }
}

/// Return whether State may forget a consumed challenge.
///
/// `recorded_expires_at_ms` is the value
/// [`PhoneControlAdmissionV1::consume_challenge`] returned. From that instant
/// on every credential that names the challenge is expired, because the
/// expiry is part of the challenge identity, so the entry is no longer needed
/// to reject a replay.
#[must_use]
pub const fn phone_control_challenge_prunable(recorded_expires_at_ms: u64, now_ms: u64) -> bool {
    now_ms >= recorded_expires_at_ms
}

/// Prelude exports for provider-backed phone-control consumers.
pub mod prelude {
    pub use super::{
        PhoneControlAdmissionV1, PhoneControlChallengeIdV1, PhoneControlChallengeV1,
        PhoneControlContextV1, PhoneControlCredentialV1, PhoneControlEvidenceV1,
        PhoneControlProviderKeyStateV1, PhoneControlProviderKeyV1,
        PhoneControlProviderPolicyCommitmentV1, PhoneControlProviderPolicyV1,
        PhoneControlSignedCredentialV1,
    };
}
