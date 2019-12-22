/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_BLOCK_FACTORY_HPP
#define IROHA_PROTO_BLOCK_FACTORY_HPP

#include "interfaces/iroha_internal/unsafe_block_factory.hpp"

#include "backend/protobuf/transaction.hpp"
#include "block.pb.h"
#include "common/result.hpp"
#include "validators/abstract_validator.hpp"

namespace shared_model {
  namespace proto {
    /**
     * ProtoBlockFactory is used to create proto::Block objects
     */
    class ProtoBlockFactory : public interface::UnsafeBlockFactory {
     public:
      ProtoBlockFactory(
          std::unique_ptr<shared_model::validation::AbstractValidator<
              shared_model::interface::Block>> interface_validator,
          std::unique_ptr<shared_model::validation::AbstractValidator<
              iroha::protocol::Block>> proto_validator);

      std::unique_ptr<interface::Block> unsafeCreateBlock(
          interface::types::HeightType height,
          const interface::types::HashType &prev_hash,
          interface::types::TimestampType created_time,
          const interface::types::TransactionsCollectionType &txs,
          const interface::types::HashCollectionType &rejected_hashes) override;

      /**
       * Create block variant
       *
       * @param block - proto block from which block variant is created
       * @return Pointer to block.
       *         Error if block is invalid
       */
      iroha::expected::Result<std::unique_ptr<interface::Block>, std::string>
      createBlock(iroha::protocol::Block block);

     private:
      std::unique_ptr<shared_model::validation::AbstractValidator<
          shared_model::interface::Block>>
          interface_validator_;
      std::unique_ptr<
          shared_model::validation::AbstractValidator<iroha::protocol::Block>>
          proto_validator_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_BLOCK_FACTORY_HPP
