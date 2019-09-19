/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_TEMPLATE_BLOCK_BUILDER_HPP
#define IROHA_PROTO_TEMPLATE_BLOCK_BUILDER_HPP

#include <memory>

#include "backend/protobuf/block.hpp"
#include "backend/protobuf/transaction.hpp"

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
      std::unique_ptr<iroha::protocol::Block_v1> block_;

      /**
       * Make transformation on copied content
       * @tparam Transformation - callable type for changing the copy
       * @param t - transform function for proto object
       * @return new builder with updated state
       */
      template <typename Transformation>
      TemplateBlockBuilder<BT> transform(Transformation t) const;

     public:
      // we do such default initialization only because it is deprecated and
      // used only in tests
      TemplateBlockBuilder();

      TemplateBlockBuilder(const TemplateBlockBuilder<BT> &o);

      TemplateBlockBuilder<BT> transactions(
          const std::vector<shared_model::proto::Transaction> &transactions)
          const;

      TemplateBlockBuilder<BT> rejectedTransactions(
          const std::vector<shared_model::crypto::Hash>
              &rejected_transactions_hashes) const;

      TemplateBlockBuilder<BT> height(interface::types::HeightType height)
          const;

      TemplateBlockBuilder<BT> prevHash(crypto::Hash hash) const;

      TemplateBlockBuilder<BT> createdTime(interface::types::TimestampType time)
          const;

      BT build();

      ~TemplateBlockBuilder();
    };

    extern template class TemplateBlockBuilder<Block>;
    extern template class TemplateBlockBuilder<UnsignedWrapper<Block>>;
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_TEMPLATE_BLOCK_BUILDER_HPP
