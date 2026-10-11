//! Original certified source rows retained across paid staking observations.

use super::*;
use iroha_model_base::chain::ChainId;
use std::sync::Mutex;

enum HistoryState {
    Fresh,
    Ready(NativeFinalityJournal),
    Failed,
}

/// Retain physical proof frames, reauthenticating the complete history on every read.
/// A failed acquisition is terminal and cannot silently refill from another source.
/// TODO: fund HTTP/DTO graphs and retained metadata/decoder scratch independently.
/// The existing native source limits do not establish complete pool custody.
pub(super) struct RetainedHistory {
    chain_id: ChainId,
    network_id: NetworkId,
    signed_genesis_hash: iroha::crypto::HashOf<iroha::data_model::block::BlockHeader>,
    state: Mutex<HistoryState>,
}

impl RetainedHistory {
    /// Bind the independent signed genesis and immutable chain before any query.
    pub(super) fn new(
        chain_id: ChainId,
        network_id: NetworkId,
        signed_genesis_hash: iroha::crypto::HashOf<iroha::data_model::block::BlockHeader>,
    ) -> Result<Self> {
        ensure!(
            network_id.into_genesis_hash() == signed_genesis_hash,
            "network differs from independent signed genesis"
        );
        Ok(Self {
            chain_id,
            network_id,
            signed_genesis_hash,
            state: Mutex::new(HistoryState::Fresh),
        })
    }

    /// Read through the original client context within the caller's unchanged deadline.
    pub(super) fn read_until(
        &self,
        client: &Client,
        end: u64,
        deadline: Instant,
    ) -> Result<Vec<CertifiedBlock>> {
        let source = client.client().with_request_deadline(deadline);
        self.read_from_proofs(
            client.client().chain(),
            *client.client().network_id(),
            end,
            deadline,
            interval_finality_fetch(&source, end),
        )
    }

    fn read_from_proofs(
        &self,
        chain_id: &ChainId,
        network_id: NetworkId,
        end: u64,
        deadline: Instant,
        fetch: impl FnMut(
            NonZeroU64,
        )
            -> Result<iroha::data_model::sumeragi_finality::SumeragiFinalityProof>,
    ) -> Result<Vec<CertifiedBlock>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| eyre!("original staking history lock poisoned"))?;
        let original = std::mem::replace(&mut *state, HistoryState::Failed);
        ensure!(
            !matches!(original, HistoryState::Failed),
            "original staking history acquisition already failed"
        );
        ensure!(
            chain_id == &self.chain_id && network_id == self.network_id,
            "staking history source differs from its original chain and network"
        );
        ensure!(
            Instant::now() < deadline,
            "committee proof retrieval deadline elapsed"
        );
        let (journal, blocks) = match original {
            HistoryState::Fresh => finality_chain_from_proofs(
                &self.chain_id,
                self.network_id,
                self.signed_genesis_hash,
                end,
                deadline,
                fetch,
            )?,
            HistoryState::Ready(journal) => extend_finality_chain_from_proofs(
                &self.chain_id,
                self.network_id,
                self.signed_genesis_hash,
                journal,
                end,
                deadline,
                fetch,
            )?,
            HistoryState::Failed => unreachable!("terminal state refused above"),
        };
        *state = HistoryState::Ready(journal);
        Ok(blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core::{
        state::{StateReadOnly as _, World},
        sumeragi::{
            finality::build_proof,
            test_chain::{CertifiedTestChain, TestChainConfig},
        },
    };

    fn fixture() -> Result<(
        CertifiedTestChain,
        Vec<iroha::data_model::sumeragi_finality::SumeragiFinalityProof>,
    )> {
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 50_000))
            .map_err(|error| eyre!("native retained history fixture startup failed: {error:?}"))?;
        // Real clock-account Log transactions, not empty block production.
        for at in 50_001..=50_004 {
            chain.commit_at(at, Vec::new());
        }
        let proofs = (1..=5)
            .map(|height| build_proof(&chain.state().view(), height))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((chain, proofs))
    }

    #[test]
    fn staking_interval_source_moves_each_genuine_row_and_keeps_the_existing_full_verifier()
    -> Result<()> {
        let (chain, proofs) = fixture()?;
        let chain_id = chain.state().view().chain_id().clone();
        let mut requests = Vec::new();
        let mut fetch = interval_finality_fetch_with(5, |from, to| {
            requests.push((from.get(), to.get()));
            Ok(proofs[usize::try_from(from.get() - 1)?..usize::try_from(to.get())?].to_vec())
        });
        let (_, blocks) = finality_chain_from_proofs(
            &chain_id,
            chain.network_id(),
            chain.genesis().hash(),
            5,
            Instant::now() + WAIT,
            &mut fetch,
        )?;
        drop(fetch);
        assert_eq!(
            requests,
            vec![(1, 5)],
            "genuine interval acquisition must not issue per-height requests"
        );
        assert_eq!(
            blocks
                .iter()
                .map(|block| block.height())
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        assert_eq!(
            blocks.last().unwrap().block_hash(),
            chain.committed(5).block_hash()
        );
        let mut requests = 0;
        let mut fetch = interval_finality_fetch_with(5, |_, _| {
            requests += 1;
            Err(eyre!("original interval transport refused"))
        });
        assert!(fetch(NonZeroU64::new(1).unwrap()).is_err());
        drop(fetch);
        assert_eq!(
            requests, 1,
            "original interval failure cannot be retried through a single-proof fallback"
        );
        Ok(())
    }

    #[test]
    fn staking_history_http_read_refuses_changed_context_and_expired_deadline_before_query()
    -> Result<()> {
        let network_id = NetworkId::from_genesis_hash(
            iroha::crypto::HashOf::from_untyped_unchecked(Hash::new(b"original staking context")),
        );
        let chain_id = ChainId::from("original-staking-context");
        for case in 0..3 {
            let history =
                RetainedHistory::new(chain_id.clone(), network_id, network_id.into_genesis_hash())?;
            let config = iroha::config::Config {
                chain: if case == 0 {
                    "another-chain".into()
                } else {
                    chain_id.clone()
                },
                network_id: if case == 1 {
                    NetworkId::from_genesis_hash(iroha::crypto::HashOf::from_untyped_unchecked(
                        Hash::new(b"another staking network"),
                    ))
                } else {
                    network_id
                },
                key_pair: iroha_test_samples::ALICE_KEYPAIR.clone(),
                account: ALICE_ID.clone(),
                account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
                torii_api_url: "http://committee-history.invalid/".parse()?,
                torii_request_timeout: iroha::config::DEFAULT_TORII_REQUEST_TIMEOUT,
                basic_auth: None,
                api_token: None,
                transaction_add_nonce: false,
                transaction_ttl: Duration::from_secs(5),
                transaction_status_timeout: Duration::from_secs(10),
                sorafs_alias_cache: iroha::config::AliasCache::default().into_policy(),
                sorafs_anonymity_policy: iroha_service_model::soranet::AnonymityPolicy::default(),
                sorafs_rollout_phase: iroha_service_model::soranet::RolloutPhase::default(),
            };
            let client = Client::new(config)?;
            let error = history
                .read_until(
                    &client,
                    2,
                    if case == 2 {
                        Instant::now()
                    } else {
                        Instant::now() + WAIT
                    },
                )
                .expect_err("invalid original context must refuse without HTTP");
            assert!(
                error.to_string().contains(if case == 2 {
                    "deadline elapsed"
                } else {
                    "original chain and network"
                }),
                "{error}"
            );
            assert!(matches!(
                *history.state.lock().unwrap(),
                HistoryState::Failed
            ));
        }
        Ok(())
    }

    #[test]
    fn staking_history_retains_original_frames_and_queries_only_successors() -> Result<()> {
        let (chain, proofs) = fixture()?;
        let chain_id = chain.state().view().chain_id().clone();
        let history =
            RetainedHistory::new(chain_id.clone(), chain.network_id(), chain.genesis().hash())?;
        let deadline = Instant::now() + WAIT;
        let mut requested = Vec::new();
        let mut original = Vec::new();
        for end in [2, 2, 3, 3, 5, 5] {
            let blocks = history.read_from_proofs(
                &chain_id,
                chain.network_id(),
                end,
                deadline,
                |height| {
                    requested.push(height.get());
                    Ok(proofs[usize::try_from(height.get() - 1)?].clone())
                },
            )?;
            let (_, fresh) = finality_chain_from_proofs(
                &chain_id,
                chain.network_id(),
                chain.genesis().hash(),
                end,
                deadline,
                |height| Ok(proofs[usize::try_from(height.get() - 1)?].clone()),
            )?;
            assert_eq!(
                blocks
                    .iter()
                    .map(|b| (b.height(), b.block_hash()))
                    .collect::<Vec<_>>(),
                fresh
                    .iter()
                    .map(|b| (b.height(), b.block_hash()))
                    .collect::<Vec<_>>()
            );
            let state = history.state.lock().unwrap();
            let HistoryState::Ready(journal) = &*state else {
                panic!("successful history must retain its original source");
            };
            for (artifact, (pointer, capacity, bytes)) in journal.blocks.iter().zip(&original) {
                assert_eq!(artifact.block_wire.as_ptr(), *pointer);
                assert_eq!(artifact.block_wire.capacity(), *capacity);
                assert_eq!(&artifact.block_wire, bytes);
            }
            let retained_count = original.len();
            original.extend(journal.blocks.iter().skip(retained_count).map(|artifact| {
                (
                    artifact.block_wire.as_ptr(),
                    artifact.block_wire.capacity(),
                    artifact.block_wire.clone(),
                )
            }));
        }
        assert_eq!(
            requested,
            [1, 2, 3, 4, 5],
            "staking observations must not reacquire any original prefix row"
        );
        Ok(())
    }

    #[test]
    fn staking_history_reauthenticates_same_tip_and_keeps_failure_terminal() -> Result<()> {
        let (chain, proofs) = fixture()?;
        let chain_id = chain.state().view().chain_id().clone();
        let history =
            RetainedHistory::new(chain_id.clone(), chain.network_id(), chain.genesis().hash())?;
        let deadline = Instant::now() + WAIT;
        history.read_from_proofs(&chain_id, chain.network_id(), 2, deadline, |height| {
            Ok(proofs[usize::try_from(height.get() - 1)?].clone())
        })?;
        {
            let mut state = history.state.lock().unwrap();
            let HistoryState::Ready(journal) = &mut *state else {
                panic!("original journal missing");
            };
            journal.blocks[0].block_wire[0] ^= 1;
        }
        assert!(
            history
                .read_from_proofs(&chain_id, chain.network_id(), 2, deadline, |_| panic!(
                    "same-tip observation must not issue a query"
                ))
                .is_err(),
            "a retained frame cannot bypass complete native authentication"
        );
        let error = history
            .read_from_proofs(
                &chain_id,
                chain.network_id(),
                5,
                Instant::now() + WAIT,
                |_| panic!("failed original source cannot be reacquired"),
            )
            .expect_err("failure is terminal");
        assert!(error.to_string().contains("already failed"));
        Ok(())
    }

    #[test]
    fn staking_history_refuses_missing_wrong_regressing_expired_and_substituted_sources()
    -> Result<()> {
        let (chain, proofs) = fixture()?;
        let chain_id = chain.state().view().chain_id().clone();
        let foreign_genesis =
            iroha::crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign staking history"));
        assert!(
            RetainedHistory::new(chain_id.clone(), chain.network_id(), foreign_genesis).is_err()
        );
        for case in 0..6 {
            let history =
                RetainedHistory::new(chain_id.clone(), chain.network_id(), chain.genesis().hash())?;
            let deadline = Instant::now() + WAIT;
            history.read_from_proofs(&chain_id, chain.network_id(), 3, deadline, |height| {
                Ok(proofs[usize::try_from(height.get() - 1)?].clone())
            })?;
            let selected_chain = if case == 4 {
                ChainId::from("foreign-staking-chain")
            } else {
                chain_id.clone()
            };
            let selected_network = if case == 5 {
                NetworkId::from_genesis_hash(foreign_genesis)
            } else {
                chain.network_id()
            };
            let mut requested = Vec::new();
            let result = history.read_from_proofs(
                &selected_chain,
                selected_network,
                if case == 2 { 2 } else { 4 },
                if case == 3 { Instant::now() } else { deadline },
                |height| {
                    requested.push(height.get());
                    match case {
                        0 => Err(eyre!("original successor unavailable")),
                        1 => Ok(proofs[2].clone()),
                        _ => panic!("invalid source must refuse before querying"),
                    }
                },
            );
            assert!(result.is_err(), "invalid source case {case} must fail");
            assert_eq!(requested, if case < 2 { vec![4] } else { Vec::new() });
            assert!(
                history
                    .read_from_proofs(
                        &chain_id,
                        chain.network_id(),
                        4,
                        Instant::now() + WAIT,
                        |_| panic!("failed source must not restart")
                    )
                    .unwrap_err()
                    .to_string()
                    .contains("already failed")
            );
        }
        Ok(())
    }
}
