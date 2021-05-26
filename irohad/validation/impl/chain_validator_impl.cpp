/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validation/impl/chain_validator_impl.hpp"

#include <boost/algorithm/string/join.hpp>
#include "ametsuchi/ledger_state.hpp"
#include "ametsuchi/mutable_storage.hpp"
#include "consensus/yac/supermajority_checker.hpp"
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
        : supermajority_checker_(supermajority_checker), log_(std::move(log)) {}

    bool ChainValidatorImpl::validateAndApply(
        std::shared_ptr<const shared_model::interface::Block> block,
        ametsuchi::MutableStorage &storage) const {
      log_->info("validate block...");

      return storage.applyIf(block,
                             [this](auto block, const auto &ledger_state) {
                               return this->validateBlock(block, ledger_state);
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

    bool ChainValidatorImpl::validateHeight(
        const shared_model::interface::Block &block,
        const shared_model::interface::types::HeightType &top_height) const {
      const bool valid_height = block.height() == top_height + 1;

      if (not valid_height) {
        log_->info(
            "Block height {} is does not consequently follow the top block "
            "height {}.",
            block.height(),
            top_height);
      }

      return valid_height;
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
            boost::algorithm::join(
                signatures | boost::adaptors::transformed([](const auto &s) {
                  return s.publicKey();
                }),
                ", "),
            boost::algorithm::join(
                peers | boost::adaptors::transformed([](const auto &p) {
                  return p->pubkey();
                }),
                ", "));
      }

      return has_supermajority;
    }

    bool ChainValidatorImpl::validateBlock(
        std::shared_ptr<const shared_model::interface::Block> block,
        const iroha::LedgerState &ledger_state) const {
      log_->debug("validate block: height {}, hash {}",
                  block->height(),
                  block->hash().hex());

      return validatePreviousHash(*block, ledger_state.top_block_info.top_hash)
          and validateHeight(*block, ledger_state.top_block_info.height)
          and validatePeerSupermajority(*block, ledger_state.ledger_peers);
    }

  }  // namespace validation
}  // namespace iroha
