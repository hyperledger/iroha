/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validation/impl/chain_validator_impl.hpp"

#include "ametsuchi/mutable_storage.hpp"
#include "ametsuchi/peer_query.hpp"
#include "consensus/yac/supermajority_checker.hpp"
#include "cryptography/public_key.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "logger/logger.hpp"
#include "validation/utils.hpp"

namespace iroha {
  namespace validation {
    ChainValidatorImpl::ChainValidatorImpl(
        std::shared_ptr<consensus::yac::SupermajorityChecker>
            supermajority_checker,
        logger::LoggerPtr log)
        : supermajority_checker_(supermajority_checker),
          log_(std::move(log)) {}

    bool ChainValidatorImpl::validateAndApply(
        rxcpp::observable<std::shared_ptr<shared_model::interface::Block>>
            blocks,
        ametsuchi::MutableStorage &storage) const {
      log_->info("validate chain...");

      return storage.apply(
          blocks,
          [this](auto block, auto &queries, const auto &top_hash) {
            return this->validateBlock(block, queries, top_hash);
          });
    }

    bool ChainValidatorImpl::validatePreviousHash(
        const shared_model::interface::Block &block,
        const shared_model::interface::types::HashType &top_hash) const {
      auto same_prev_hash = block.prevHash() == top_hash;

      if (not same_prev_hash) {
        log_->info(
            "Previous hash {} of block does not match top block hash {} "
            "in storage",
            block.prevHash().hex(),
            top_hash.hex());
      }

      return same_prev_hash;
    }

    bool ChainValidatorImpl::validatePeerSupermajority(
        const shared_model::interface::Block &block,
        const std::vector<std::shared_ptr<shared_model::interface::Peer>>
            &peers) const {
      const auto &signatures = block.signatures();
      auto has_supermajority = supermajority_checker_->hasSupermajority(
                                   boost::size(signatures), peers.size())
          and peersSubset(signatures, peers);

      if (not has_supermajority) {
        log_->info(
            "Block does not contain signatures of supermajority of "
            "peers. Block signatures public keys: [{}], ledger peers "
            "public keys: [{}]",
            std::accumulate(std::next(std::begin(signatures)),
                            std::end(signatures),
                            signatures.front().publicKey().hex(),
                            [](auto acc, auto &sig) {
                              return acc + ", " + sig.publicKey().hex();
                            }),
            std::accumulate(std::next(std::begin(peers)),
                            std::end(peers),
                            peers.front()->pubkey().hex(),
                            [](auto acc, auto &peer) {
                              return acc + ", " + peer->pubkey().hex();
                            }));
      }

      return has_supermajority;
    }

    bool ChainValidatorImpl::validateBlock(
        std::shared_ptr<const shared_model::interface::Block> block,
        ametsuchi::PeerQuery &queries,
        const shared_model::interface::types::HashType &top_hash) const {
      log_->info("validate block: height {}, hash {}",
                 block->height(),
                 block->hash().hex());

      auto peers = queries.getLedgerPeers();
      if (not peers) {
        log_->info("Cannot retrieve peers from storage");
        return false;
      }

      return validatePreviousHash(*block, top_hash)
          and validatePeerSupermajority(*block, *peers);
    }

  }  // namespace validation
}  // namespace iroha
