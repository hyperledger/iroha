//! Collection of bounded, untrusted TON account proofs for native wallet and minter verification.

use super::*;
use iroha_sccp::light_client::ton::wallet_state::TonAccountStateProofV1;

impl TonBuilder {
    /// Collect an account proof at one exact masterchain cut. The native verifier must accept
    /// it before a journal action may use the account's wallet sequence or minter state.
    ///
    /// # Errors
    /// Fails for unavailable anchors or malformed source answers.
    pub fn account_state_proof(
        &self,
        account: [u8; 32],
        taira: &dyn TairaLightClientView,
        now_ms: u64,
    ) -> Result<TonAccountStateProofV1, BuildError> {
        let light_client = taira.light_client()?;
        let sets = taira.sets()?;
        let last = self
            .lite
            .get_masterchain_info()
            .map_err(|error| lite(&error))?
            .last;
        let state = self
            .lite
            .get_account_state(
                last,
                AccountId {
                    workchain: 0,
                    address: account,
                },
            )
            .map_err(|error| lite(&error))?;
        if state.id != last {
            return Err(BuildError::Inconsistent(
                "account proof changed masterchain cut".into(),
            ));
        }
        let masterchain = masterchain_anchor(
            self,
            &self.profile,
            block_id(&last),
            self.header(last)?,
            light_client.head.latest_set_id,
            &sets,
            now_ms,
        )?;
        Ok(TonAccountStateProofV1 {
            masterchain,
            shard: TonShardLinkV1 {
                block_id: block_id(&state.shardblk),
                header_proof: self.header(state.shardblk)?,
            },
            state_proof: state.proof,
            account_state: canonical(&state.state, "account state")?,
        })
    }
}
