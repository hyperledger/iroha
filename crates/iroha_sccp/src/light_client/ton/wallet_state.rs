//! Read-only authenticated retirement of an original standard wallet v5r1 sequence.

use super::*;

/// Native account proof collected from an untrusted TON liteserver.
#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct TonAccountStateProofV1 {
    /// Masterchain finality anchored in the original native light client.
    pub masterchain: TonMasterchainAnchorV1,
    /// Exact shard block registered for the wallet at the anchor.
    pub shard: TonShardLinkV1,
    /// Bounded one/two-root liteserver `ShardState` proof.
    pub state_proof: Vec<u8>,
    /// Canonical single-root Account state.
    pub account_state: Vec<u8>,
}

/// A wallet sequence authenticated by native TON finality and exact account/code identity.
#[derive(Clone, Copy, Debug, norito::derive::JsonSerialize)]
pub struct VerifiedTonWalletStateV1 {
    account: [u8; 32],
    wallet_id: u32,
    seqno: u32,
    masterchain: TonBlockIdExtV1,
}
impl VerifiedTonWalletStateV1 {
    /// Authenticated sequence in the immutable standard wallet code's persistent data.
    #[must_use]
    pub const fn seqno(&self) -> u32 {
        self.seqno
    }
}

/// Verify an exact basechain v5r1 wallet under the selected original native light client.
/// No getter response or local VM execution participates in this decision.
///
/// # Errors
/// Rejects unavailable/frozen/stale authority, malformed or oversized proofs and substitutions.
pub fn verify_wallet_state<V: SccpLcStateView + ?Sized>(
    profile: &TonChainProfileV1,
    view: &V,
    proof: &TonAccountStateProofV1,
    account: [u8; 32],
    wallet_id: u32,
    taira_now_ms: u64,
) -> Result<VerifiedTonWalletStateV1, SccpLcError> {
    let memory = LcMemory::detached();
    let (masterchain, registered) =
        account_anchor(profile, view, proof, account, taira_now_ms, &memory)?;
    let seqno = native_result(
        &memory,
        crate::ton_native::wallet_state::open_wallet_state(
            registered,
            &proof.shard.header_proof,
            &proof.state_proof,
            &proof.account_state,
            &account,
            wallet_id,
            memory.native(),
        ),
    )
    .map_err(|error| detached_error(&error))?;
    Ok(VerifiedTonWalletStateV1 {
        account,
        wallet_id,
        seqno,
        masterchain: masterchain.block_id,
    })
}

fn account_anchor<V: SccpLcStateView + ?Sized>(
    profile: &TonChainProfileV1,
    view: &V,
    proof: &TonAccountStateProofV1,
    account: [u8; 32],
    taira_now_ms: u64,
    memory: &LcMemory<'_>,
) -> Result<(TonMcHeaderV1, TonBlockIdExtV1), SccpLcError> {
    let light_client = super::super::usable_light_client(view, NETWORK)?;
    let signed = match &proof.masterchain {
        TonMasterchainAnchorV1::Signed(block) => block,
        TonMasterchainAnchorV1::BackLink(link) => &link.fresh,
    };
    let (signatures, transcript_bytes) = match &signed.signatures {
        TonBlockSignaturesV1::Ordinary(value) => (&value.signatures, 0),
        TonBlockSignaturesV1::Simplex(value) => (&value.signatures, value.candidate_data.len()),
    };
    // The native signature verifier admits at most 1024 entries. Apply that bound before
    // accounting variable-length untrusted signature buffers or opening any cell graph.
    if signatures.len() > 1024 {
        return Err(SccpLcError::TooManyItems {
            kind: "TON wallet signatures",
            count: signatures.len(),
            max: 1024,
        });
    }
    let signature_bytes = signatures
        .iter()
        .fold(transcript_bytes, |total, signature| {
            total
                .saturating_add(signature.signature.len())
                .saturating_add(64)
        });
    let anchor_bytes = match &proof.masterchain {
        TonMasterchainAnchorV1::Signed(block) => block.header_proof.len(),
        TonMasterchainAnchorV1::BackLink(link) => link
            .fresh
            .header_proof
            .len()
            .saturating_add(link.header_proof.len())
            .saturating_add(link.state_proof.len()),
    };
    let bytes = anchor_bytes
        .saturating_add(signature_bytes)
        .saturating_add(512)
        .saturating_add(proof.shard.header_proof.len())
        .saturating_add(proof.state_proof.len())
        .saturating_add(proof.account_state.len());
    super::super::check_frame_len(
        "TON wallet state",
        bytes,
        super::super::u32_bound(light_client.params.max_proof_bytes),
    )?;
    let ctx = Ctx {
        profile,
        view,
        now: taira_now_ms,
        memory,
    };
    let (masterchain, registered) =
        open_anchor(&ctx, &proof.masterchain, account).map_err(|error| detached_error(&error))?;
    if registered != proof.shard.block_id {
        return Err(TonNativeSourceError::ShardNotFinalized.into());
    }
    Ok((masterchain, registered))
}

pub use crate::ton_native::minter_state::{TonMinterStateV1, TonRecoveryStateV1};

/// Authenticate the locked minter's state directly from native TON account proofs.
///
/// # Errors
/// Refuses invalid native finality, substituted accounts/code, and malformed storage.
pub fn verify_minter_state<V: SccpLcStateView + ?Sized>(
    profile: &TonChainProfileV1,
    view: &V,
    proof: &TonAccountStateProofV1,
    account: [u8; 32],
    taira_now_ms: u64,
) -> Result<TonMinterStateV1, SccpLcError> {
    let memory = LcMemory::detached();
    let (_, registered) = account_anchor(profile, view, proof, account, taira_now_ms, &memory)?;
    let account_hash = native_result(
        &memory,
        crate::ton_native::wallet_state::authenticated_account_hash(
            registered,
            &proof.shard.header_proof,
            &proof.state_proof,
            &account,
            memory.native(),
        ),
    )
    .map_err(|error| detached_error(&error))?;
    native_result(
        &memory,
        crate::ton_native::minter_state::parse_minter_state(
            &proof.account_state,
            &account_hash,
            &account,
            memory.native(),
        ),
    )
    .map_err(|error| detached_error(&error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::light_client::ton::tests::{T0, installed, profiles};
    use crate::test_support::ton::SyntheticTonChainV1;

    #[test]
    fn wallet_state_authenticates_code_address_sequence_and_masterchain_anchor() {
        let chain = SyntheticTonChainV1::new([71; 32]);
        let (memory, now) = installed(&chain);
        let wallet = [9; 32];
        let wallet_id = 0x7fff_ff11;
        let proof = chain.wallet_state_proof(
            wallet,
            wallet_id,
            8,
            crate::ton_native::wallet_state::CODE_HASH,
            T0,
        );
        let verify = |proof: &TonAccountStateProofV1, account, wallet_id| {
            verify_wallet_state(&profiles().ton, &memory, proof, account, wallet_id, now)
        };
        assert_eq!(verify(&proof, wallet, wallet_id).unwrap().seqno(), 8);
        assert!(
            matches!(
                verify_wallet_state(
                    &profiles().ton,
                    &memory,
                    &proof,
                    wallet,
                    wallet_id,
                    u64::from(T0 + 65_536 + 32_768) * 1_000,
                ),
                Err(SccpLcError::StaleSigningSet { set_id: 100, .. })
            ),
            "an old original snapshot cannot keep a newly served wallet state fresh"
        );
        assert!(verify(&proof, [8; 32], wallet_id).is_err());
        assert!(verify(&proof, wallet, wallet_id + 1).is_err());
        let mut substituted = proof.clone();
        substituted.account_state = chain
            .wallet_state_proof(
                wallet,
                wallet_id,
                9,
                crate::ton_native::wallet_state::CODE_HASH,
                T0,
            )
            .account_state;
        assert!(
            verify(&substituted, wallet, wallet_id).is_err(),
            "unproven higher sequence"
        );
        let wrong_code = chain.wallet_state_proof(wallet, wallet_id, 9, [0xff; 32], T0);
        assert!(
            verify(&wrong_code, wallet, wallet_id).is_err(),
            "even finalized substitute code cannot retire a v5r1 envelope"
        );
        let mut wrong_anchor = proof.clone();
        if let TonMasterchainAnchorV1::Signed(block) = &mut wrong_anchor.masterchain {
            block.block_id.root_hash[0] ^= 1;
        }
        assert!(verify(&wrong_anchor, wallet, wallet_id).is_err());
        let mut wrong_shard = proof.clone();
        wrong_shard.shard.block_id.seqno += 1;
        assert!(verify(&wrong_shard, wallet, wallet_id).is_err());
        let mut oversized_signatures = proof.clone();
        if let TonMasterchainAnchorV1::Signed(block) = &mut oversized_signatures.masterchain
            && let TonBlockSignaturesV1::Ordinary(signatures) = &mut block.signatures
        {
            signatures.signatures[0].signature.resize(256 * 1024 + 1, 0);
        }
        assert!(verify(&oversized_signatures, wallet, wallet_id).is_err());
        let mut oversized = proof.clone();
        oversized.state_proof = vec![0; 256 * 1024 + 1];
        assert!(verify(&oversized, wallet, wallet_id).is_err());
    }
}
