/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_BLOCKS_QUERY_BUILDER_TEMPLATE_HPP
#define IROHA_PROTO_BLOCKS_QUERY_BUILDER_TEMPLATE_HPP

#include <memory>

#include "backend/protobuf/queries/proto_blocks_query.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/queries/blocks_query.hpp"
#include "module/shared_model/builders/protobuf/unsigned_proto.hpp"

namespace shared_model {
  namespace proto {

    /**
     * Template blocks query builder for creating new types of builders by
     * means of replacing template parameters
     * @tparam BT -- build type of built object returned by build method
     */
    template <typename BT = UnsignedWrapper<BlocksQuery>>
    class [[deprecated]] TemplateBlocksQueryBuilder {
     private:
      /**
       * Make transformation on copied content
       * @tparam Transformation - callable type for changing the copy
       * @param t - transform function for proto object
       * @return new builder with updated state
       */
      template <typename Transformation>
      TemplateBlocksQueryBuilder<BT> transform(Transformation t) const;

     public:
      // we do such default initialization only because it is deprecated and
      // used only in tests
      TemplateBlocksQueryBuilder();

      TemplateBlocksQueryBuilder(const TemplateBlocksQueryBuilder<BT> &o);

      TemplateBlocksQueryBuilder<BT> createdTime(
          interface::types::TimestampType created_time) const;

      TemplateBlocksQueryBuilder<BT> creatorAccountId(
          const interface::types::AccountIdType &creator_account_id) const;

      TemplateBlocksQueryBuilder<BT> queryCounter(
          interface::types::CounterType query_counter) const;

      BT build() const;

      ~TemplateBlocksQueryBuilder();

     private:
      std::unique_ptr<iroha::protocol::BlocksQuery> query_;
    };

    extern template class TemplateBlocksQueryBuilder<BlocksQuery>;
    extern template class TemplateBlocksQueryBuilder<
        UnsignedWrapper<BlocksQuery>>;
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_BLOCKS_QUERY_BUILDER_TEMPLATE_HPP
