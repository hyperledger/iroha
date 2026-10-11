//! The σ verifying-key allowlist of a scheme and its `verifying_key_set_digest` (§§3.2, 3.3,
//! 8; owner answers Q6 and Q11, A5 of the second set and B6 of the third set, 2026-10-05).
//!
//! Statements and Ω carry one scheme-level relation identity. Each consumer selects σ's
//! verifying key from this allowlist by the operation tag; for Send also by the
//! enabled-controls mask (`Ω.enabled_controls`), and for Receive also by the decision its Request
//! recorded: the blacklist entry exactly when `receiver_blacklist_version ≠ 0` (the `σ_recv` that
//! proves the payer's non-membership in the recorded list), whatever the receiver's current
//! controls, so verifying a Receive package takes its Request. Λ uses the same allowlist. G1 defines the allowlist, with one entry per
//! selector and its exact σ length, plus the Ω transport verifying key and its exact proof
//! length. Its digest `H("verifying-key-set", transcript)` is the `verifying_key_set_digest` that
//! the relation identity and the signed artifact manifest bind. The σ and Ω byte caps are these
//! exact lengths (owner answer Q6): under R9 the Ω length plus the largest `σ_send` length fits
//! the Payment budget [`KAGEMUSHA_WALLET_PAYMENT_PROOF_BUDGET_V1`], the `σ_recv` length fits
//! [`KAGEMUSHA_WALLET_CREDITED_RECEIVE_PROOF_BUDGET_V1`], and the Ω length fits the
//! Credited bound with the fixed 32-sibling opening
//! ([`KAGEMUSHA_WALLET_LINEAGE_PROOF_CAP_V1`]). Until the artifacts freeze, structural
//! validation of the wire objects enforces only the frame bounds.

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{
    KAGEMUSHA_WALLET_CREDITED_RECEIVE_PROOF_BUDGET_V1, KAGEMUSHA_WALLET_LINEAGE_PROOF_CAP_V1,
    KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1, KAGEMUSHA_WALLET_PAYMENT_PROOF_BUDGET_V1, WalletResult,
    WalletVersionsV1, decode_frame_v1,
    digest::{KagemushaWalletDigestRoleV1 as Role, WalletTranscriptV1, kagemusha_wallet_digest_v1},
    encode_frame_v1,
    identity::{
        KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1, KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1,
        KagemushaWalletArtifactManifestBodyV1,
    },
    invalid_v1,
    messages::KagemushaWalletRequestBodyV1,
    overflow_v1, require_nonzero_v1, require_version_v1,
    state::{
        KagemushaWalletLineageV1, KagemushaWalletOperationKindV1, KagemushaWalletPackageV1,
        KagemushaWalletStepProofV1,
    },
};

#[cfg(test)]
#[path = "verifying_keys_tests.rs"]
pub(super) mod verifying_keys_tests;

/// Exact transcript bytes of one allowlist entry:
/// `tag kind || LE32 enabled_controls || verifying_key_digest || LE32 proof_bytes`.
pub const KAGEMUSHA_WALLET_VERIFYING_KEY_ENTRY_TRANSCRIPT_BYTES_V1: usize = 1 + 4 + 32 + 4;
/// Maximum σ entries: one per operation with the empty mask (8), one per nonzero Send
/// enabled-controls mask (7), and the Receive entry for a Request-recorded blacklist decision
/// (1).
pub const KAGEMUSHA_WALLET_VERIFYING_KEY_ENTRIES_MAX_V1: usize = 8 + 7 + 1;
/// Maximum standalone canonical frame of one verifying-key allowlist.
pub const KAGEMUSHA_WALLET_VERIFYING_KEY_ALLOWLIST_MAX_BYTES_V1: usize = 2_048;

fn selector_mask_is_valid(kind: KagemushaWalletOperationKindV1, enabled_controls: u32) -> bool {
    match kind {
        KagemushaWalletOperationKindV1::Send => {
            enabled_controls & !KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1 == 0
        }
        KagemushaWalletOperationKindV1::Receive => {
            enabled_controls & !KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1 == 0
        }
        _ => enabled_controls == 0,
    }
}

/// One σ verifying key of the allowlist and its selector (§3.2).
///
/// Every operation has an entry with the empty mask; Send also has one entry per nonzero
/// enabled-controls mask the scheme supports, and Receive one entry with the blacklist bit
/// exactly when some Send mask has it (owner answer A5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletVerifyingKeyEntryV1"
)]
pub struct KagemushaWalletVerifyingKeyEntryV1 {
    /// Operation tag of the step relation.
    pub kind: KagemushaWalletOperationKindV1,
    /// Enabled-controls mask of a Send relation; for Receive the blacklist bit (a Request-recorded
    /// blacklist decision) or zero; zero for every other operation.
    pub enabled_controls: u32,
    /// Digest of the frozen verifying key.
    pub verifying_key_digest: [u8; 32],
    /// Exact σ length in bytes (PIPA-v1 rejects every other length).
    pub proof_bytes: u32,
}

impl KagemushaWalletVerifyingKeyEntryV1 {
    /// Selector `(operation tag, mask)` that orders the allowlist.
    #[must_use]
    pub const fn selector(&self) -> (u8, u32) {
        (self.kind.tag(), self.enabled_controls)
    }

    fn write(&self, transcript: WalletTranscriptV1) -> WalletTranscriptV1 {
        transcript
            .u8(self.kind.tag())
            .u32(self.enabled_controls)
            .digest(&self.verifying_key_digest)
            .u32(self.proof_bytes)
    }

    fn validate(&self) -> WalletResult<()> {
        require_nonzero_v1(
            "verifying_keys.verifying_key_digest",
            &self.verifying_key_digest,
        )?;
        if self.proof_bytes == 0 {
            return Err(invalid_v1("verifying_keys.proof_bytes"));
        }
        if selector_mask_is_valid(self.kind, self.enabled_controls) {
            Ok(())
        } else {
            Err(invalid_v1("verifying_keys.enabled_controls"))
        }
    }
}

/// The σ verifying-key allowlist of one scheme and the Ω transport key (§3.2, owner answer
/// Q11).
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletVerifyingKeyAllowlistV1"
)]
pub struct KagemushaWalletVerifyingKeyAllowlistV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`](super::KAGEMUSHA_WALLET_VERSION_V1).
    pub version: u16,
    /// σ entries strictly ascending by `(operation tag, mask)`.
    pub steps: Vec<KagemushaWalletVerifyingKeyEntryV1>,
    /// Digest of the frozen Ω transport verifying key.
    pub lineage_verifying_key_digest: [u8; 32],
    /// Exact Ω transport-proof length in bytes.
    pub lineage_proof_bytes: u32,
}

impl KagemushaWalletVerifyingKeyAllowlistV1 {
    /// Validate the allowlist.
    ///
    /// # Errors
    ///
    /// Rejects another version, more than [`KAGEMUSHA_WALLET_VERIFYING_KEY_ENTRIES_MAX_V1`]
    /// entries, entries not strictly ascending by selector, a missing operation, a mask other
    /// than the blacklist bit on Receive, a nonzero mask outside Send and Receive, an undefined
    /// control bit, a Receive blacklist entry present without a Send mask carrying the
    /// blacklist bit or missing with one, zero digests or lengths, an Ω length plus the largest
    /// `σ_send` length above the Payment budget (R9), a `σ_recv` length above its complete
    /// Credited envelope budget, an Ω length above the Credited cap, and a σ longer than a
    /// message.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("verifying_keys.version", self.version)?;
        if self.steps.len() > KAGEMUSHA_WALLET_VERIFYING_KEY_ENTRIES_MAX_V1 {
            return Err(invalid_v1("verifying_keys.steps"));
        }
        let mut previous: Option<(u8, u32)> = None;
        for entry in &self.steps {
            entry.validate()?;
            if previous.is_some_and(|previous| previous >= entry.selector()) {
                return Err(invalid_v1("verifying_keys.order"));
            }
            previous = Some(entry.selector());
            let proof_bytes = usize::try_from(entry.proof_bytes)
                .map_err(|_| overflow_v1("verifying_keys.proof_bytes"))?;
            if proof_bytes > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
                return Err(invalid_v1("verifying_keys.proof_bytes"));
            }
            if entry.kind == KagemushaWalletOperationKindV1::Receive
                && proof_bytes > KAGEMUSHA_WALLET_CREDITED_RECEIVE_PROOF_BUDGET_V1
            {
                return Err(invalid_v1("verifying_keys.receive_proof_bytes"));
            }
        }
        for kind in KagemushaWalletOperationKindV1::ALL {
            if !self
                .steps
                .iter()
                .any(|entry| entry.selector() == (kind.tag(), 0))
            {
                return Err(invalid_v1("verifying_keys.missing"));
            }
        }
        let send_blacklist = self.steps.iter().any(|entry| {
            entry.kind == KagemushaWalletOperationKindV1::Send
                && entry.enabled_controls & KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1 != 0
        });
        let receive_blacklist = self.steps.iter().any(|entry| {
            entry.selector()
                == (
                    KagemushaWalletOperationKindV1::Receive.tag(),
                    KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1,
                )
        });
        if send_blacklist != receive_blacklist {
            return Err(invalid_v1("verifying_keys.receive_blacklist"));
        }
        require_nonzero_v1(
            "verifying_keys.lineage_verifying_key_digest",
            &self.lineage_verifying_key_digest,
        )?;
        let lineage_cap = u64::try_from(KAGEMUSHA_WALLET_LINEAGE_PROOF_CAP_V1)
            .map_err(|_| overflow_v1("verifying_keys.lineage_proof_bytes"))?;
        if self.lineage_proof_bytes == 0 || u64::from(self.lineage_proof_bytes) > lineage_cap {
            return Err(invalid_v1("verifying_keys.lineage_proof_bytes"));
        }
        let largest_send = self
            .steps
            .iter()
            .filter(|entry| entry.kind == KagemushaWalletOperationKindV1::Send)
            .map(|entry| u64::from(entry.proof_bytes))
            .max()
            .unwrap_or(0);
        let joint = largest_send
            .checked_add(u64::from(self.lineage_proof_bytes))
            .ok_or_else(|| overflow_v1("verifying_keys.budget"))?;
        let budget = u64::try_from(KAGEMUSHA_WALLET_PAYMENT_PROOF_BUDGET_V1)
            .map_err(|_| overflow_v1("verifying_keys.budget"))?;
        if joint > budget {
            return Err(invalid_v1("verifying_keys.budget"));
        }
        Ok(())
    }

    /// Exact `verifying-key-set` transcript: `LE16 version || LE32 count || entries (41 bytes
    /// each) || lineage_verifying_key_digest || LE32 lineage_proof_bytes`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid allowlist.
    pub fn transcript(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        let count =
            u32::try_from(self.steps.len()).map_err(|_| overflow_v1("verifying_keys.steps"))?;
        let capacity = 2
            + 4
            + 32
            + 4
            + self.steps.len() * KAGEMUSHA_WALLET_VERIFYING_KEY_ENTRY_TRANSCRIPT_BYTES_V1;
        let mut transcript = WalletTranscriptV1::with_capacity(capacity)
            .u16(self.version)
            .u32(count);
        for entry in &self.steps {
            transcript = entry.write(transcript);
        }
        Ok(transcript
            .digest(&self.lineage_verifying_key_digest)
            .u32(self.lineage_proof_bytes)
            .finish())
    }

    /// `verifying_key_set_digest = H("verifying-key-set", transcript)`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid allowlist.
    pub fn verifying_key_set_digest(&self) -> WalletResult<[u8; 32]> {
        Ok(kagemusha_wallet_digest_v1(
            Role::VerifyingKeySet,
            &self.transcript()?,
        ))
    }

    /// The σ entry of selector `(kind, enabled_controls)`: Send selects by its mask, Receive by
    /// the blacklist bit of its Request's recorded decision, and every other operation with the
    /// empty mask.
    ///
    /// # Errors
    ///
    /// Rejects an invalid allowlist, a mask outside the selector rule of `kind`, and a
    /// selector without an entry.
    pub fn entry(
        &self,
        kind: KagemushaWalletOperationKindV1,
        enabled_controls: u32,
    ) -> WalletResult<&KagemushaWalletVerifyingKeyEntryV1> {
        self.validate()?;
        if !selector_mask_is_valid(kind, enabled_controls) {
            return Err(invalid_v1("verifying_keys.selector"));
        }
        self.steps
            .iter()
            .find(|entry| entry.selector() == (kind.tag(), enabled_controls))
            .ok_or_else(|| invalid_v1("verifying_keys.selector"))
    }

    /// Require σ to have the exact length of its selector's entry and return the entry's
    /// verifying-key digest.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::entry`] rejects, an invalid σ and another length.
    pub fn check_step_proof(
        &self,
        kind: KagemushaWalletOperationKindV1,
        enabled_controls: u32,
        step_proof: &KagemushaWalletStepProofV1,
    ) -> WalletResult<[u8; 32]> {
        step_proof.validate()?;
        let entry = self.entry(kind, enabled_controls)?;
        if u32::try_from(step_proof.bytes.len()).ok() != Some(entry.proof_bytes) {
            return Err(invalid_v1("step_proof.length"));
        }
        Ok(entry.verifying_key_digest)
    }

    /// Require the Ω transport proof to have the exact allowlisted length.
    ///
    /// # Errors
    ///
    /// Rejects an invalid allowlist or Ω and another length.
    pub fn check_lineage(&self, lineage: &KagemushaWalletLineageV1) -> WalletResult<()> {
        self.validate()?;
        lineage.validate()?;
        if u32::try_from(lineage.proof.len()).ok() == Some(self.lineage_proof_bytes) {
            Ok(())
        } else {
            Err(invalid_v1("lineage.proof_length"))
        }
    }

    /// Check a package's proof lengths: σ against the entry its verifying-key selector picks
    /// (operation tag; for Send the mask, which the consumer checks equate with
    /// `Ω.enabled_controls`; for Receive the blacklist bit exactly when `request` records a
    /// nonzero receiver blacklist version) and a carried Ω(pred) against the transport length.
    /// `request` is the package's Request body, required for a Receive package and ignored
    /// otherwise. Returns the selected verifying-key digest.
    ///
    /// # Errors
    ///
    /// Rejects an invalid package, what
    /// [`KagemushaWalletPackageV1::verifying_key_selector`] rejects (a Receive package without
    /// its Request included), and what [`Self::check_step_proof`] and [`Self::check_lineage`]
    /// reject.
    pub fn check_package(
        &self,
        package: &KagemushaWalletPackageV1,
        request: Option<&KagemushaWalletRequestBodyV1>,
    ) -> WalletResult<[u8; 32]> {
        package.validate()?;
        let (kind, enabled_controls) = package.verifying_key_selector(request)?;
        let digest = self.check_step_proof(kind, enabled_controls, &package.step_proof)?;
        if let Some(lineage) = package.lineage.lineage() {
            self.check_lineage(lineage)?;
        }
        Ok(digest)
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid allowlist or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_VERIFYING_KEY_ALLOWLIST_MAX_BYTES_V1)
    }

    /// Decode one canonical allowlist frame and require the digest `manifest` binds.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, an invalid
    /// allowlist, and a digest other than the manifest's `verifying_key_set_digest`.
    pub fn decode_canonical(
        bytes: &[u8],
        manifest: &KagemushaWalletArtifactManifestBodyV1,
    ) -> WalletResult<Self> {
        let allowlist: Self =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_VERIFYING_KEY_ALLOWLIST_MAX_BYTES_V1)?;
        allowlist.require_versions()?;
        allowlist.require_manifest(manifest)?;
        Ok(allowlist)
    }

    /// Require this allowlist to be the one `manifest` binds by `verifying_key_set_digest`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid allowlist or manifest body and another digest.
    pub fn require_manifest(
        &self,
        manifest: &KagemushaWalletArtifactManifestBodyV1,
    ) -> WalletResult<()> {
        manifest.validate()?;
        if self.verifying_key_set_digest()? == manifest.verifying_key_set_digest {
            Ok(())
        } else {
            Err(invalid_v1("artifact_manifest.verifying_key_set_digest"))
        }
    }
}

impl WalletVersionsV1 for KagemushaWalletVerifyingKeyAllowlistV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("verifying_keys.version", self.version)
    }
}
