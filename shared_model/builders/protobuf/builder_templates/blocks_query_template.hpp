/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_BLOCKS_QUERY_BUILDER_TEMPLATE_HPP
#define IROHA_PROTO_BLOCKS_QUERY_BUILDER_TEMPLATE_HPP

#include "backend/protobuf/queries/proto_blocks_query.hpp"
#include "builders/protobuf/unsigned_proto.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/queries/blocks_query.hpp"
#include "interfaces/transaction.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "queries.pb.h"
#include "validators/default_validator.hpp"

namespace shared_model {
  namespace proto {

    /**
     * Template blocks query builder for creating new types of builders by
     * means of replacing template parameters
     * @tparam S -- field counter for checking that all required fields are
     * set
     * @tparam SV -- stateless validator called when build method is invoked
     * @tparam BT -- build type of built object returned by build method
     */
    template <int S = 0,
              typename SV = validation::DefaultUnsignedBlocksQueryValidator,
              typename BT = UnsignedWrapper<BlocksQuery>>
    class /*[[deprecated]]*/ TemplateBlocksQueryBuilder {
     private:
      template <int, typename, typename>
      friend class TemplateBlocksQueryBuilder;

      enum RequiredFields {
        CreatedTime,
        CreatorAccountId,
        QueryCounter,
        TOTAL
      };

      template <int s>
      using NextBuilder = TemplateBlocksQueryBuilder<S | (1 << s), SV, BT>;

      using ProtoBlocksQuery = iroha::protocol::BlocksQuery;

      template <int Sp>
      TemplateBlocksQueryBuilder(
          const TemplateBlocksQueryBuilder<Sp, SV, BT> &o)
          : query_(o.query_), stateless_validator_(o.stateless_validator_) {}

      /**
       * Make transformation on copied content
       * @tparam Transformation - callable type for changing the copy
       * @param t - transform function for proto object
       * @return new builder with updated state
       */
      template <int Fields, typename Transformation>
      auto transform(Transformation t) const {
        NextBuilder<Fields> copy = *this;
        t(copy.query_);
        return copy;
      }

      TemplateBlocksQueryBuilder(const SV &validator)
          : stateless_validator_(validator) {}

     public:
      // we do such default initialization only because it is deprecated and
      // used only in tests
      TemplateBlocksQueryBuilder()
          : TemplateBlocksQueryBuilder(
                SV(iroha::test::kTestsValidatorsConfig)) {}

      auto createdTime(interface::types::TimestampType created_time) const {
        return transform<CreatedTime>([&](auto &qry) {
          auto *meta = qry.mutable_meta();
          meta->set_created_time(created_time);
        });
      }

      auto creatorAccountId(
          const interface::types::AccountIdType &creator_account_id) const {
        return transform<CreatorAccountId>([&](auto &qry) {
          auto *meta = qry.mutable_meta();
          meta->set_creator_account_id(creator_account_id);
        });
      }

      auto queryCounter(interface::types::CounterType query_counter) const {
        return transform<QueryCounter>([&](auto &qry) {
          auto *meta = qry.mutable_meta();
          meta->set_query_counter(query_counter);
        });
      }

      auto build() const {
        static_assert(S == (1 << TOTAL) - 1, "Required fields are not set");
        auto result = BlocksQuery(iroha::protocol::BlocksQuery(query_));
        if (auto error = stateless_validator_.validate(result)) {
          throw std::invalid_argument(error->toString());
        }
        return BT(std::move(result));
      }

      static const int total = RequiredFields::TOTAL;

     private:
      ProtoBlocksQuery query_;
      SV stateless_validator_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_BLOCKS_QUERY_BUILDER_TEMPLATE_HPP
