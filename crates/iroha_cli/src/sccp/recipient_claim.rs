//! Recipient-owned claim bundles, verified over one original light-client observation.

use super::*;
use iroha_data_model::{
    account::{Account, AccountAddress, AccountId},
    isi::{
        Register,
        sccp::{AdvanceSccpLightClientV1, SubmitSccpInboundMessageV1},
    },
};
use iroha_sccp::{light_client::proof::SccpNormalizedEventV1, v1::payload::SccpTransferPayloadV1};
use iroha_sccp_rpc::builders::{VerifiedBuildError, build_verified};

/// One finite recipient transaction, including locally verified prerequisite advances.
pub(super) struct Evidence {
    pub advances: Vec<AdvanceSccpLightClientV1>,
    pub source: SourceEvidenceV1,
}

/// Select the nearest checkpoint across replay-learned and retained original state.
struct View<'a> {
    original: &'a dyn TairaLightClientView,
    replay: &'a LightClientReplayV1,
    checkpoints: std::cell::RefCell<Vec<SccpLcCheckpointV1>>,
}
impl TairaLightClientView for View<'_> {
    fn light_client(&self) -> std::result::Result<SccpLightClientV1, BuildError> {
        self.replay.light_client()
    }
    fn sets(&self) -> std::result::Result<Vec<SccpLcConsensusSetV1>, BuildError> {
        self.replay.sets()
    }
    fn checkpoint_covering(
        &self,
        height: u64,
    ) -> std::result::Result<Option<SccpLcCheckpointV1>, BuildError> {
        let retained = self.original.checkpoint_covering(height)?;
        if let Some(checkpoint) = retained {
            self.checkpoints.borrow_mut().push(checkpoint);
        }
        Ok(self
            .replay
            .checkpoint_covering(height)?
            .into_iter()
            .chain(retained)
            .min_by_key(|checkpoint| checkpoint.data.source_height))
    }
}

pub(super) fn prove_claim(
    profiles: iroha_sccp::light_client::profile::SccpChainProfilesV1,
    client: &BlockingClient,
    network: SccpNetworkV1,
    builder: &dyn SourceChainBuilder,
    event: &SourceEventRefV1,
    payload: &[u8],
    max_advances: u16,
) -> Result<Evidence> {
    let original = ToriiLightClient::read(client, network, profiles)?;
    build(
        &original,
        original.replay(),
        builder,
        event,
        payload,
        max_advances,
        wall_clock_ms(),
    )
}

fn build(
    original: &dyn TairaLightClientView,
    mut replay: LightClientReplayV1,
    builder: &dyn SourceChainBuilder,
    event: &SourceEventRefV1,
    payload: &[u8],
    max_advances: u16,
    now: u64,
) -> Result<Evidence> {
    let network = replay.network();
    eyre::ensure!(
        builder.network() == network,
        "source builder differs from the original light-client network"
    );
    let mut advances = Vec::new();
    loop {
        let view = View {
            original,
            replay: &replay,
            checkpoints: std::cell::RefCell::new(Vec::new()),
        };
        let proof = build_verified(
            builder.source_attempts(),
            || builder.evidence(event, &view, now),
            |evidence| {
                let mut check = replay.clone();
                check.record_checkpoints(&view.checkpoints.borrow());
                let verified = check.verify_evidence(evidence, now)?;
                require_event_payload(&verified.event, payload).map_err(|_| {
                    iroha_sccp::light_client::SccpLcError::MalformedFrame("claim payload")
                })
            },
            || builder.rotate_endpoints(),
        );
        match proof {
            Ok(source) => {
                eyre::ensure!(
                    max_advances == 0
                        || advances.len() + source.backfills.len() <= usize::from(max_advances),
                    "claim prerequisites exceed --max-advances; use separate keeper advances first"
                );
                return Ok(Evidence { advances, source });
            }
            Err(VerifiedBuildError::Build(BuildError::Unavailable(_)))
                if advances.len() < usize::from(max_advances) => {}
            Err(error) => return Err(error.into()),
        }
        let current = replay.light_client()?;
        let advance = build_verified(
            builder.source_attempts(),
            || {
                builder.advance(
                    current.head.latest_set_id,
                    AdvanceBudgetV1::for_params(&current.params, usize::MAX),
                )
            },
            |advance| replay.clone().advance(advance, now).map(|_| ()),
            || builder.rotate_endpoints(),
        )?;
        replay.advance(&advance, now)?;
        eyre::ensure!(
            replay.light_client()?.state_hash != current.state_hash,
            "source advance makes no progress; wait for source finality or separate keeper catch-up"
        );
        advances.push(AdvanceSccpLightClientV1 {
            network,
            expected_state_hash: Some(current.state_hash),
            advance,
        });
    }
}

pub(super) fn require_recipient(authority: &AccountId, payload: &[u8], fee: u128) -> Result<()> {
    let payload = SccpTransferPayloadV1::decode(payload)?;
    eyre::ensure!(
        authority.try_signatory().is_some(),
        "a multisig recipient cannot self-claim"
    );
    eyre::ensure!(
        AccountAddress::matches_account_id_bytes(authority, &payload.recipient.bytes),
        "--self-claim requires the configured authority to be the burned payload recipient"
    );
    eyre::ensure!(
        payload.amount > fee,
        "claim amount does not exceed the self-claim fee"
    );
    Ok(())
}

pub(super) fn instructions(
    authority: &AccountId,
    register: bool,
    network: SccpNetworkV1,
    revision: u32,
    payload: Vec<u8>,
    evidence: Evidence,
) -> Result<Vec<InstructionBox>> {
    let mut instructions = Vec::new();
    if register {
        instructions.push(Register::account(Account::new(authority.clone())).into());
    }
    for advance in evidence.advances {
        eyre::ensure!(
            advance.network == network && advance.expected_state_hash.is_some(),
            "claim catch-up advance lacks its original network and state expectation"
        );
        instructions.push(advance.into());
    }
    instructions.extend(evidence.source.backfills.into_iter().map(|advance| {
        AdvanceSccpLightClientV1 {
            network,
            expected_state_hash: None,
            advance,
        }
        .into()
    }));
    instructions.push(
        SubmitSccpInboundMessageV1 {
            network,
            revision,
            payload,
            proof: evidence.source.proof,
        }
        .into(),
    );
    Ok(instructions)
}

/// Bind independently discovered bytes to the event authenticated by the native verifier.
pub(super) fn require_event_payload(event: &SccpNormalizedEventV1, payload: &[u8]) -> Result<()> {
    eyre::ensure!(
        matches!(event, SccpNormalizedEventV1::TransferToTaira { payload_hash, .. }
        if *payload_hash == iroha_sccp::v1::hashes::payload_hash(payload)),
        "verified source event differs from the discovered burn payload"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
