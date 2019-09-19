/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_BLOCKS_QUERY_BUILDER_TEMPLATE_HPP
#define IROHA_PROTO_BLOCKS_QUERY_BUILDER_TEMPLATE_HPP

#include "backend/protobuf/queries/proto_blocks_query.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/queries/blocks_query.hpp"
#include "module/shared_model/builders/protobuf/unsigned_proto.hpp"
#include "queries.pb.h"

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
      using NextBuilder = TemplateBlocksQueryBuilder<BT>;

      using ProtoBlocksQuery = iroha::protocol::BlocksQuery;

      /**
       * Make transformation on copied content
       * @tparam Transformation - callable type for changing the copy
       * @param t - transform function for proto object
       * @return new builder with updated state
       */
      template <typename Transformation>
      auto transform(Transformation t) const {
        NextBuilder copy = *this;
        t(copy.query_);
        return copy;
      }

     public:
      // we do such default initialization only because it is deprecated and
      // used only in tests
      TemplateBlocksQueryBuilder() = default;

      TemplateBlocksQueryBuilder(const TemplateBlocksQueryBuilder<BT> &o)
          : query_(o.query_) {}

      auto createdTime(interface::types::TimestampType created_time) const {
        return transform([&](auto &qry) {
          auto *meta = qry.mutable_meta();
          meta->set_created_time(created_time);
        });
      }

      auto creatorAccountId(
          const interface::types::AccountIdType &creator_account_id) const {
        return transform([&](auto &qry) {
          auto *meta = qry.mutable_meta();
          meta->set_creator_account_id(creator_account_id);
        });
      }

      auto queryCounter(interface::types::CounterType query_counter) const {
        return transform([&](auto &qry) {
          auto *meta = qry.mutable_meta();
          meta->set_query_counter(query_counter);
        });
      }

      auto build() const {
        auto result = BlocksQuery(iroha::protocol::BlocksQuery(query_));

        return BT(std::move(result));
      }

     private:
      ProtoBlocksQuery query_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_BLOCKS_QUERY_BUILDER_TEMPLATE_HPP
