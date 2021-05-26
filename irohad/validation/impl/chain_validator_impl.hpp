/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CHAIN_VALIDATOR_IMPL_HPP
#define IROHA_CHAIN_VALIDATOR_IMPL_HPP

#include "validation/chain_validator.hpp"

#include <memory>

#include "interfaces/common_objects/types.hpp"
#include "logger/logger_fwd.hpp"

namespace shared_model {
  namespace interface {
    class Peer;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {

  namespace consensus {
    namespace yac {
      class SupermajorityChecker;
    }  // namespace yac
  }    // namespace consensus

  struct LedgerState;

  namespace validation {
    class ChainValidatorImpl : public ChainValidator {
     public:
      ChainValidatorImpl(std::shared_ptr<consensus::yac::SupermajorityChecker>
                             supermajority_checker,
                         logger::LoggerPtr log);

      bool validateAndApply(
          std::shared_ptr<const shared_model::interface::Block> block,
          ametsuchi::MutableStorage &storage) const override;

     private:
      /// Verifies whether previous hash of block matches top_hash
      bool validatePreviousHash(
          const shared_model::interface::Block &block,
          const shared_model::interface::types::HashType &top_hash) const;

      /// Verifies whether block height directly follows top height
      bool validateHeight(
          const shared_model::interface::Block &block,
          const shared_model::interface::types::HeightType &top_height) const;

      /// Verifies whether the block is signed by supermajority of peers
      bool validatePeerSupermajority(
          const shared_model::interface::Block &block,
          const std::vector<std::shared_ptr<shared_model::interface::Peer>>
              &peers) const;

      /**
       * Verifies previous hash and whether the block is signed by supermajority
       * of ledger peers
       */
      bool validateBlock(
          std::shared_ptr<const shared_model::interface::Block> block,
          const iroha::LedgerState &ledger_state) const;

      /**
       * Provide functions to check supermajority
       */
      std::shared_ptr<consensus::yac::SupermajorityChecker>
          supermajority_checker_;

      logger::LoggerPtr log_;
    };
  }  // namespace validation
}  // namespace iroha

#endif  // IROHA_CHAIN_VALIDATOR_IMPL_HPP
