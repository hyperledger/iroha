/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_TEMPLATE_BLOCK_BUILDER_HPP
#define IROHA_PROTO_TEMPLATE_BLOCK_BUILDER_HPP

#include "backend/protobuf/block.hpp"
#include "backend/protobuf/transaction.hpp"
#include "block.pb.h"

#include "interfaces/base/signable.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "interfaces/transaction.hpp"
#include "module/shared_model/builders/protobuf/unsigned_proto.hpp"

namespace shared_model {
  namespace proto {

    /**
     * Template block builder for creating new types of block builders by
     * means of replacing template parameters
     * @tparam BT -- build type of built object returned by build method
     */
    template <typename BT = UnsignedWrapper<Block>>
    class [[deprecated]] TemplateBlockBuilder {
     private:
      using NextBuilder = TemplateBlockBuilder<BT>;

      iroha::protocol::Block_v1 block_;

      /**
       * Make transformation on copied content
       * @tparam Transformation - callable type for changing the copy
       * @param t - transform function for proto object
       * @return new builder with updated state
       */
      template <typename Transformation>
      auto transform(Transformation t) const {
        NextBuilder copy = *this;
        t(copy.block_);
        return copy;
      }

     public:
      // we do such default initialization only because it is deprecated and
      // used only in tests
      TemplateBlockBuilder() = default;

      TemplateBlockBuilder(const TemplateBlockBuilder<BT> &o)
          : block_(o.block_) {}

      template <class T>
      auto transactions(const T &transactions) const {
        return transform([&](auto &block) {
          for (const auto &tx : transactions) {
            new (block.mutable_payload()->add_transactions())
                iroha::protocol::Transaction(tx.getTransport());
          }
        });
      }

      template <class T>
      auto rejectedTransactions(const T &rejected_transactions_hashes) const {
        return transform([&](auto &block) {
          for (const auto &hash : rejected_transactions_hashes) {
            auto *next_hash =
                block.mutable_payload()->add_rejected_transactions_hashes();
            (*next_hash) = hash.hex();
          }
        });
      }

      auto height(interface::types::HeightType height) const {
        return transform(
            [&](auto &block) { block.mutable_payload()->set_height(height); });
      }

      auto prevHash(crypto::Hash hash) const {
        return transform([&](auto &block) {
          block.mutable_payload()->set_prev_block_hash(hash.hex());
        });
      }

      auto createdTime(interface::types::TimestampType time) const {
        return transform([&](auto &block) {
          block.mutable_payload()->set_created_time(time);
        });
      }

      BT build() {
        auto tx_number = block_.payload().transactions().size();
        block_.mutable_payload()->set_tx_number(tx_number);

        auto result = Block(iroha::protocol::Block_v1(block_));

        return BT(std::move(result));
      }
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_TEMPLATE_BLOCK_BUILDER_HPP
