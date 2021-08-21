/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_TEMPLATE_BLOCK_BUILDER_HPP
#define IROHA_PROTO_TEMPLATE_BLOCK_BUILDER_HPP

#include "backend/protobuf/block.hpp"
#include "backend/protobuf/transaction.hpp"
#include "block.pb.h"

#include "builders/protobuf/unsigned_proto.hpp"
#include "interfaces/base/signable.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "interfaces/transaction.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "validators/default_validator.hpp"

namespace shared_model {
  namespace proto {

    /**
     * Template block builder for creating new types of block builders by
     * means of replacing template parameters
     * @tparam S -- field counter for checking that all required fields are set
     * @tparam SV -- stateless validator called when build method is invoked
     * @tparam BT -- build type of built object returned by build method
     */
    template <int S = 0,
              typename SV = validation::DefaultUnsignedBlockValidator,
              typename BT = UnsignedWrapper<Block>>
    class /*[[deprecated]]*/ TemplateBlockBuilder {
     private:
      template <int, typename, typename>
      friend class TemplateBlockBuilder;

      enum Fields {
        Transactions,
        Height,
        PrevHash,
        CreatedTime,
        LAST_REQUIRED = CreatedTime,
        RejectedTransactions,
        TOTAL
      };

      template <int s>
      using NextBuilder = TemplateBlockBuilder<S | (1 << s), SV, BT>;

      iroha::protocol::Block_v1 block_;
      SV stateless_validator_;

      template <int Sp, typename SVp, typename BTp>
      TemplateBlockBuilder(const TemplateBlockBuilder<Sp, SVp, BTp> &o)
          : block_(o.block_), stateless_validator_(o.stateless_validator_) {}

      /**
       * Make transformation on copied content
       * @tparam Transformation - callable type for changing the copy
       * @param t - transform function for proto object
       * @return new builder with updated state
       */
      template <int Fields, typename Transformation>
      auto transform(Transformation t) const {
        NextBuilder<Fields> copy = *this;
        t(copy.block_);
        return copy;
      }

      TemplateBlockBuilder(const SV &validator)
          : stateless_validator_(validator){};

     public:
      // we do such default initialization only because it is deprecated and
      // used only in tests
      TemplateBlockBuilder()
          : TemplateBlockBuilder(SV(iroha::test::kTestsValidatorsConfig)) {}

      template <class T>
      auto transactions(const T &transactions) const {
        return transform<Transactions>([&](auto &block) {
          for (const auto &tx : transactions) {
            new (block.mutable_payload()->add_transactions())
                iroha::protocol::Transaction(tx.getTransport());
          }
        });
      }

      template <class T>
      auto rejectedTransactions(const T &rejected_transactions_hashes) const {
        return transform<RejectedTransactions>([&](auto &block) {
          for (const auto &hash : rejected_transactions_hashes) {
            auto *next_hash =
                block.mutable_payload()->add_rejected_transactions_hashes();
            (*next_hash) = hash.hex();
          }
        });
      }

      auto height(interface::types::HeightType height) const {
        return transform<Height>(
            [&](auto &block) { block.mutable_payload()->set_height(height); });
      }

      auto prevHash(crypto::Hash hash) const {
        return transform<PrevHash>([&](auto &block) {
          block.mutable_payload()->set_prev_block_hash(hash.hex());
        });
      }

      auto createdTime(interface::types::TimestampType time) const {
        return transform<CreatedTime>([&](auto &block) {
          block.mutable_payload()->set_created_time(time);
        });
      }

      BT build() {
        static_assert(((~S) & ((2 << LAST_REQUIRED) - 1)) == 0,
                      "Required fields are not set");

        auto tx_number = block_.payload().transactions().size();
        block_.mutable_payload()->set_tx_number(tx_number);

        auto result = Block(iroha::protocol::Block_v1(block_));
        if (auto error = stateless_validator_.validate(result)) {
          throw std::invalid_argument(error->toString());
        }
        return BT(std::move(result));
      }

      static const int total = Fields::TOTAL;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_TEMPLATE_BLOCK_BUILDER_HPP
