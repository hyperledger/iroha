//! The locally installed signed blacklist: wallet custody only.
//!
//! Owner decision 2026-10-17: a list is never committed in wallet state, proved or carried in
//! a peer message. Install authenticates the complete signed list natively and selects its
//! exact original in the protected manifest, replacing a held list only for a higher
//! `list_version`. Installing changes no head, receipt, fold or lineage. With a list held, the
//! payer refuses to pay a listed receiver and the receiver refuses to request or accept money
//! from a listed payer; without one nothing is refused.

use super::*;
use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1 as object_digest;

/// Manifest selection of the installed list and its exact archived original.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::LocalBlacklistV1")]
pub(in crate::kagemusha_wallet_state_v1) struct LocalBlacklistV1 {
    version: u16,
    list_version: u64,
    digest: [u8; 32],
    original: [u8; 32],
    original_bytes: u32,
}

impl LocalBlacklistV1 {
    /// Read the selected list back. Install authenticated these exact bytes and the protected
    /// manifest names them by archive digest, so this decode does not recompute the signed
    /// entries root: enforcement stays fast for a full list.
    pub(in crate::kagemusha_wallet_state_v1) fn read(
        &self,
        store: &mut dyn ObjectWorkspace,
        scheme_id: &[u8; 32],
    ) -> Result<KagemushaWalletBlacklistV1, Error> {
        let length = usize::try_from(self.original_bytes)
            .map_err(|_| Error::WitnessLost("local blacklist length"))?;
        if self.version != 1
            || self.list_version == 0
            || self.digest == [0; 32]
            || length == 0
            || length > KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1
        {
            return Err(Error::WitnessLost("local blacklist selection"));
        }
        let original = store.read_staged_object(&self.original, length)?;
        if original.len() != length || object_digest(&original) != self.original {
            return Err(Error::WitnessLost("local blacklist exact original"));
        }
        let list: KagemushaWalletBlacklistV1 = archive::decode(&original)?;
        if list.body.scheme_id != *scheme_id
            || list.body.list_version != self.list_version
            || list.blacklist_digest() != self.digest
        {
            return Err(Error::WitnessLost("local blacklist original binding"));
        }
        Ok(list)
    }
}

// Authenticate a complete list natively: certificate set under the scheme, the list's
// RegulatoryPolicy signer and signature, scheme, entry order, count and entries root.
fn authenticate(
    scheme: &KagemushaWalletSchemeV1,
    original: &[u8],
    certificates: &[u8],
) -> Result<KagemushaWalletBlacklistV1, Error> {
    if original.is_empty()
        || original.len() > KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1
        || certificates.is_empty()
        || certificates.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
    {
        return Err(Error::Invalid("blacklist original size"));
    }
    // Caller input: a malformed set is invalid input, never lost custody.
    let set: KagemushaWalletCertificateSetV1 = norito::core::classify_decode_attempt(|| {
        norito::decode_canonical_with_limits(
            certificates,
            norito::canonical_decode_limits(certificates.len()),
        )
    })
    .map_err(|error| decode_attempt_error(error, Error::Invalid("blacklist certificates")))?;
    valid(set.verify(scheme))?;
    let list = read_model_original(
        || KagemushaWalletBlacklistV1::decode_canonical(original, &scheme.scheme_id()),
        Error::Invalid("G1 validation"),
    )?;
    let signer = valid(set.certificate(
        &list.body.signer_certificate,
        KagemushaWalletSignerRoleV1::RegulatoryPolicy,
    ))?;
    valid(list.verify(scheme, signer))?;
    Ok(list)
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    /// Authenticate a signed blacklist and install it in local custody.
    ///
    /// Reinstalling the held list is idempotent and republishes its exact original, which
    /// repairs a lost archive copy. Nothing is sent to a peer or proved, and no wallet
    /// operation, receipt or fold results. The completion carries the 32-byte object digest of
    /// the held list.
    ///
    /// # Errors
    /// No released head, an unauthenticated list or certificate set, a `list_version` that does
    /// not increase, too little free storage to keep one operation possible after the install
    /// (`NotEnoughStorage`), or unavailable storage. An uncertain publication is reconciled by
    /// installing the same list again. A failed removal of the replaced original is reported
    /// after the new selection is published; that unreferenced copy then stays in custody.
    pub fn install_blacklist(
        &mut self,
        original: &[u8],
        certificates: &[u8],
    ) -> Result<Completion, Error> {
        let (scheme, _) = self.proofs.ledger_scope()?;
        if scheme.scheme_id() != self.scheme_id {
            return Err(Error::WitnessLost("blacklist scheme"));
        }
        let installed = authenticate(&scheme, original, certificates)?;
        let digest = installed.blacklist_digest();
        let (root, mut manifest) = self.sync_manifest()?;
        if manifest.indexed.is_none() {
            return Err(Error::NoHead);
        }
        // The protected manifest authenticates the held selection; its original is not read.
        let reinstall = match &manifest.blacklist {
            Some(held) if held.digest == digest => true,
            Some(held) if installed.body.list_version <= held.list_version => {
                return Err(Error::Invalid("blacklist list_version"));
            }
            _ => false,
        };
        if !reinstall {
            self.require_blacklist_capacity(original.len())?;
        }
        let address = self
            .archive
            .write_object(original, KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1)?;
        if address != object_digest(original) {
            return Err(Error::WitnessLost("local blacklist publication"));
        }
        let entry = LocalBlacklistV1 {
            version: 1,
            list_version: installed.body.list_version,
            digest,
            original: address,
            original_bytes: u32::try_from(original.len())
                .map_err(|_| Error::Invalid("blacklist original size"))?,
        };
        if entry.read(&mut self.archive, &self.scheme_id)? != installed {
            return Err(Error::WitnessLost("local blacklist readback"));
        }
        if reinstall {
            if manifest.blacklist.as_ref() != Some(&entry) {
                return Err(Error::WitnessLost("local blacklist selection"));
            }
            return Ok(Completion::Complete(digest.to_vec()));
        }
        let previous = manifest.blacklist.replace(entry);
        self.publish_manifest(root, &manifest)?;
        // The published manifest no longer selects the replaced original, and no other record
        // holds a list frame.
        if let Some(held) = previous {
            self.archive.remove(ArchiveKey::Object(held.original))?;
        }
        Ok(Completion::Complete(digest.to_vec()))
    }

    /// The list selected by the current manifest, if any; reads local custody only.
    pub(in crate::kagemusha_wallet_state_v1) fn local_blacklist(
        &mut self,
    ) -> Result<Option<KagemushaWalletBlacklistV1>, Error> {
        let (_, manifest) = self.manifest()?;
        manifest
            .blacklist
            .as_ref()
            .map(|list| list.read(&mut self.archive, &self.scheme_id))
            .transpose()
    }
}

#[cfg(test)]
#[path = "blacklists/tests.rs"]
mod tests;
