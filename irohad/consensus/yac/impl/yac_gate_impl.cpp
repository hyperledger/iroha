/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/yac_gate_impl.hpp"

#include <boost/range/adaptor/transformed.hpp>
#include "common/visitor.hpp"
#include "consensus/yac/cluster_order.hpp"
#include "consensus/yac/outcome_messages.hpp"
#include "consensus/yac/storage/yac_common.hpp"
#include "consensus/yac/yac_hash_provider.hpp"
#include "consensus/yac/yac_peer_orderer.hpp"
#include "cryptography/public_key.hpp"
#include "interfaces/common_objects/signature.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "logger/logger.hpp"
#include "simulator/block_creator.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      YacGateImpl::YacGateImpl(
          std::shared_ptr<HashGate> hash_gate,
          std::shared_ptr<YacPeerOrderer> orderer,
          std::shared_ptr<YacHashProvider> hash_provider,
          std::shared_ptr<simulator::BlockCreator> block_creator,
          std::shared_ptr<consensus::ConsensusResultCache>
              consensus_result_cache,
          logger::LoggerPtr log)
          : log_(std::move(log)),
            current_hash_(),
            published_events_(hash_gate->onOutcome()
                                  .flat_map([this](auto message) {
                                    return visit_in_place(
                                        message,
                                        [this](const CommitMessage &msg) {
                                          return this->handleCommit(msg);
                                        },
                                        [this](const RejectMessage &msg) {
                                          return this->handleReject(msg);
                                        });
                                  })
                                  .publish()
                                  .ref_count()),
            orderer_(std::move(orderer)),
            hash_provider_(std::move(hash_provider)),
            block_creator_(std::move(block_creator)),
            consensus_result_cache_(std::move(consensus_result_cache)),
            hash_gate_(std::move(hash_gate)) {
        block_creator_->onBlock().subscribe([this](const auto &event) {
          current_ledger_state_ = event.ledger_state;
          this->vote(event);
        });
      }

      void YacGateImpl::vote(const simulator::BlockCreatorEvent &event) {
        if (current_hash_.vote_round >= event.round) {
          log_->info(
              "Current round {} is greater than or equal to vote round {}, "
              "skipped",
              current_hash_.vote_round,
              event.round);
          return;
        }

        current_hash_ = hash_provider_->makeHash(event);

        if (not event.round_data) {
          current_block_ = boost::none;
          // previous block is committed to block storage, it is safe to clear
          // the cache
          // TODO 2019-03-15 andrei: IR-405 Subscribe BlockLoaderService to
          // BlockCreator::onBlock
          consensus_result_cache_->release();
          log_->debug("Agreed on nothing to commit");
        } else {
          current_block_ = event.round_data->block;
          // insert the block we voted for to the consensus cache
          consensus_result_cache_->insert(event.round_data->block);
          log_->info("vote for (proposal: {}, block: {})",
                     current_hash_.vote_hashes.proposal_hash,
                     current_hash_.vote_hashes.block_hash);
        }

        auto order = orderer_->getOrdering(current_hash_,
                                           *event.ledger_state->ledger_peers);
        if (not order) {
          log_->error("ordering doesn't provide peers => pass round");
          return;
        }

        hash_gate_->vote(current_hash_, *order);
      }

      rxcpp::observable<YacGateImpl::GateObject> YacGateImpl::onOutcome() {
        return published_events_;
      }

      void YacGateImpl::copySignatures(const CommitMessage &commit) {
        for (const auto &vote : commit.votes) {
          auto sig = vote.hash.block_signature;
          current_block_.value()->addSignature(sig->signedData(),
                                               sig->publicKey());
        }
      }

      rxcpp::observable<YacGateImpl::GateObject> YacGateImpl::handleCommit(
          const CommitMessage &msg) {
        const auto hash = getHash(msg.votes).value();
        if (hash.vote_round < current_hash_.vote_round) {
          log_->info(
              "Current round {} is greater than commit round {}, skipped",
              current_hash_.vote_round,
              hash.vote_round);
          return rxcpp::observable<>::empty<GateObject>();
        }

        if (hash == current_hash_ and current_block_) {
          // if node has voted for the committed block
          // append signatures of other nodes
          this->copySignatures(msg);
          auto &block = current_block_.value();
          log_->info("consensus: commit top block: height {}, hash {}",
                     block->height(),
                     block->hash().hex());
          return rxcpp::observable<>::just<GateObject>(PairValid(
              current_hash_.vote_round, current_ledger_state_, block));
        }

        auto public_keys = boost::copy_range<
            shared_model::interface::types::PublicKeyCollectionType>(
            msg.votes | boost::adaptors::transformed([](auto &vote) {
              return vote.signature->publicKey();
            }));

        if (hash.vote_hashes.proposal_hash.empty()) {
          // if consensus agreed on nothing for commit
          log_->info("Consensus skipped round, voted for nothing");
          current_block_ = boost::none;
          return rxcpp::observable<>::just<GateObject>(AgreementOnNone(
              hash.vote_round, current_ledger_state_, std::move(public_keys)));
        }

        log_->info("Voted for another block, waiting for sync");
        current_block_ = boost::none;
        auto model_hash = hash_provider_->toModelHash(hash);
        return rxcpp::observable<>::just<GateObject>(
            VoteOther(hash.vote_round,
                      current_ledger_state_,
                      std::move(public_keys),
                      std::move(model_hash)));
      }

      rxcpp::observable<YacGateImpl::GateObject> YacGateImpl::handleReject(
          const RejectMessage &msg) {
        const auto hash = getHash(msg.votes).value();
        auto public_keys = boost::copy_range<
            shared_model::interface::types::PublicKeyCollectionType>(
            msg.votes | boost::adaptors::transformed([](auto &vote) {
              return vote.signature->publicKey();
            }));
        if (hash.vote_round < current_hash_.vote_round) {
          log_->info(
              "Current round {} is greater than reject round {}, skipped",
              current_hash_.vote_round,
              hash.vote_round);
          return rxcpp::observable<>::empty<GateObject>();
        }

        auto has_same_proposals =
            std::all_of(std::next(msg.votes.begin()),
                        msg.votes.end(),
                        [first = msg.votes.begin()](const auto &current) {
                          return first->hash.vote_hashes.proposal_hash
                              == current.hash.vote_hashes.proposal_hash;
                        });
        if (not has_same_proposals) {
          log_->info("Proposal reject since all hashes are different");
          return rxcpp::observable<>::just<GateObject>(ProposalReject(
              hash.vote_round, current_ledger_state_, std::move(public_keys)));
        }
        log_->info("Block reject since proposal hashes match");
        return rxcpp::observable<>::just<GateObject>(BlockReject(
            hash.vote_round, current_ledger_state_, std::move(public_keys)));
      }
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
