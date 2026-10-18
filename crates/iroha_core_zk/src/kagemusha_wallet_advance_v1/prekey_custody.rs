//! Provider-owned immutable pre-E1 records, under the same protected exclusive root.

use super::{
    KagemushaWalletFsV1, KagemushaWalletPlatformV1, KagemushaWalletProviderErrorV1,
    advance::KagemushaWalletAdvanceCapsuleV1,
    completion::KagemushaWalletCompletionFrameV1,
    layout::{
        KagemushaWalletCustodyDirV1, KagemushaWalletEntryNameV1,
        kagemusha_wallet_require_published_v1,
    },
    platform::{
        KagemushaWalletNotPublishedV1, KagemushaWalletPublishOutcomeV1, KagemushaWalletReadV1,
        KagemushaWalletUnavailableV1,
    },
    provider::KagemushaWalletProviderV1,
};

/// Fixed journal roles. Their bytes are recovery DATA, never reconstructed live authority.
/// Client, Accepted, Slot, Cancelled and Expired are create-new and immutable. `Phase` is the attempt's one
/// mandatory replace-only, monotone enrollment phase (`enrollment_phase.rs`): created before
/// the Slot selection and atomically replaced before each effect it witnesses; never removed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PreKeyRecordV1 {
    Client,
    Accepted,
    Slot,
    Phase,
    /// Terminal pre-permit cancellation bound to the exact retained Client digest.
    Cancelled,
    /// Terminal E1 expiry proof bound to exact Client/Resume dispatch/Accepted originals.
    Expired,
}
impl PreKeyRecordV1 {
    fn name(
        self,
        id: &[u8; 32],
    ) -> Result<KagemushaWalletEntryNameV1, KagemushaWalletProviderErrorV1> {
        if *id == [0; 32] {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "pre-key request identity",
            });
        }
        let role = self.role();
        let hex = hex::encode(id);
        KagemushaWalletEntryNameV1::new(&format!("prekey-{hex}-{role}.norito")).ok_or(
            KagemushaWalletProviderErrorV1::Invalid {
                field: "pre-key record name",
            },
        )
    }
}
impl PreKeyRecordV1 {
    pub(super) const fn role(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Accepted => "accepted",
            Self::Slot => "slot",
            Self::Phase => "phase",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}
/// Retained pre-key Slot selection (`PreKeyRecordV1::Slot`), published by the enrollment owner
/// after the attempt's phase binding. Recovery cross-checks its slot against that binding.
#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_enrollment_v1::PreKeySlotV1")]
pub(crate) struct PreKeySlotSelectionV1 {
    /// Exactly 1.
    pub(crate) version: u16,
    /// Client nonce of the original Fresh dispatch.
    pub(crate) client_nonce: [u8; 32],
    /// Digest of the exact accepted permit original.
    pub(crate) permit_digest: [u8; 32],
    /// Selected slot.
    pub(crate) slot: [u8; 32],
    /// [`super::platform::KagemushaWalletKeyGenerationPolicyV1`] tag.
    pub(crate) generation_policy: u8,
}
/// A create-new publication or adoption; only an actual Published result is fresh.
pub(crate) enum PreKeyPublicationV1 {
    Published,
    Existing(Vec<u8>),
}
const MAX: usize = 16_384;
impl<F, P, C, R> KagemushaWalletProviderV1<F, P, C, R>
where
    F: KagemushaWalletFsV1,
    P: KagemushaWalletPlatformV1,
    C: KagemushaWalletAdvanceCapsuleV1,
    R: KagemushaWalletCompletionFrameV1,
{
    pub(crate) fn prekey_read(
        &self,
        id: &[u8; 32],
        role: PreKeyRecordV1,
    ) -> Result<Option<Vec<u8>>, KagemushaWalletProviderErrorV1> {
        self.require_storage()?;
        let result =
            match self
                .store
                .read(&KagemushaWalletCustodyDirV1::root(), &role.name(id)?, MAX)
            {
                KagemushaWalletReadV1::Present(bytes) => Ok(Some(bytes)),
                KagemushaWalletReadV1::Absent => Ok(None),
                KagemushaWalletReadV1::Oversized => {
                    Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                        object: "pre-key journal",
                    })
                }
                KagemushaWalletReadV1::Unavailable(reason) => {
                    Err(KagemushaWalletProviderErrorV1::Unavailable(reason))
                }
            };
        self.require_storage().and(result)
    }
    /// Durably adopt the visible records `roles` of `id`, each republished on a fresh inode
    /// once per process: a record left visible by an uncertain write or a lost writeback
    /// authorizes nothing until this succeeds.
    ///
    /// # Errors
    /// `Unavailable`/`Uncertain` when storage or the republication gives no durable answer
    /// (also when a record vanished since it was read).
    pub(crate) fn prekey_adopt(
        &self,
        id: &[u8; 32],
        roles: &[PreKeyRecordV1],
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        let dir = KagemushaWalletCustodyDirV1::root();
        for role in roles {
            let bytes =
                self.prekey_read(id, *role)?
                    .ok_or(KagemushaWalletProviderErrorV1::Unavailable(
                        KagemushaWalletUnavailableV1::Busy,
                    ))?;
            self.require_storage()?;
            let adopted = self.adopt_exact(&dir, &role.name(id)?, &bytes);
            self.require_storage().and(adopted)?;
        }
        Ok(())
    }
    /// Atomically replace the exact current bytes `expected` of a replace-only record with
    /// `bytes` (fresh inode, parent synced); nothing follows an uncertain replacement.
    ///
    /// # Errors
    /// `Uncertain` when the replacement may be visible but is not known durable; `Unavailable`
    /// for unavailable storage or when the record no longer holds exactly `expected`; the other
    /// publication errors.
    pub(crate) fn prekey_replace(
        &mut self,
        id: &[u8; 32],
        role: PreKeyRecordV1,
        expected: &[u8],
        bytes: &[u8],
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        self.require_storage()?;
        if bytes.is_empty() || bytes.len() > MAX {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "pre-key journal bound",
            });
        }
        let dir = KagemushaWalletCustodyDirV1::root();
        let name = role.name(id)?;
        let result = match self.store.replace_exact(&dir, &name, expected, bytes) {
            KagemushaWalletPublishOutcomeV1::NotPublished(
                KagemushaWalletNotPublishedV1::ContentMismatch
                | KagemushaWalletNotPublishedV1::DestinationAbsent,
            ) => Err(KagemushaWalletProviderErrorV1::Unavailable(
                KagemushaWalletUnavailableV1::Busy,
            )),
            outcome => kagemusha_wallet_require_published_v1(outcome).map(|()| {
                self.note_durable(&dir, &name, bytes);
            }),
        };
        self.require_storage().and(result)
    }
    pub(crate) fn prekey_retain(
        &mut self,
        id: &[u8; 32],
        role: PreKeyRecordV1,
        bytes: &[u8],
    ) -> Result<PreKeyPublicationV1, KagemushaWalletProviderErrorV1> {
        self.require_storage()?;
        if bytes.is_empty() || bytes.len() > MAX {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "pre-key journal bound",
            });
        }
        let result = (|| {
            let dir = KagemushaWalletCustodyDirV1::root();
            let name = role.name(id)?;
            match self.store.write_new(&dir, &name, bytes) {
                KagemushaWalletPublishOutcomeV1::Published => {
                    self.note_durable(&dir, &name, bytes);
                    Ok(PreKeyPublicationV1::Published)
                }
                KagemushaWalletPublishOutcomeV1::NotPublished(
                    KagemushaWalletNotPublishedV1::DestinationExists,
                ) => {
                    let original = self.prekey_read(id, role)?.ok_or(
                        KagemushaWalletProviderErrorV1::Unavailable(
                            KagemushaWalletUnavailableV1::Busy,
                        ),
                    )?;
                    kagemusha_wallet_require_published_v1(
                        self.store.rewrite_same(&dir, &name, &original),
                    )?;
                    self.note_durable(&dir, &name, &original);
                    Ok(PreKeyPublicationV1::Existing(original))
                }
                outcome => {
                    kagemusha_wallet_require_published_v1(outcome)?;
                    unreachable!("Published handled")
                }
            }
        })();
        self.require_storage().and(result)
    }
}
