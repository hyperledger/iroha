/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_QUERY_BUILDER_TEMPLATE_HPP
#define IROHA_PROTO_QUERY_BUILDER_TEMPLATE_HPP

#include <google/protobuf/util/time_util.h>

#include <boost/range/algorithm/for_each.hpp>
#include <optional>
#include <string_view>

#include "backend/plain/account_detail_record_id.hpp"
#include "backend/protobuf/queries/proto_query.hpp"
#include "builders/protobuf/unsigned_proto.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/queries/ordering.hpp"
#include "interfaces/transaction.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "queries.pb.h"
#include "validators/default_validator.hpp"

namespace shared_model {
  namespace proto {

    /**
     * Template query builder for creating new types of query builders by
     * means of replacing template parameters
     * @tparam S -- field counter for checking that all required fields are
     * set
     * @tparam SV -- stateless validator called when build method is invoked
     * @tparam BT -- build type of built object returned by build method
     */
    template <int S = 0,
              typename SV = validation::DefaultUnsignedQueryValidator,
              typename BT = UnsignedWrapper<Query>>
    class /*[[deprecated]]*/ TemplateQueryBuilder {
     private:
      template <int, typename, typename>
      friend class TemplateQueryBuilder;

      enum RequiredFields {
        CreatedTime,
        CreatorAccountId,
        QueryField,
        QueryCounter,
        TOTAL
      };

      template <int s>
      using NextBuilder = TemplateQueryBuilder<S | (1 << s), SV, BT>;

      using ProtoQuery = iroha::protocol::Query;

      template <int Sp>
      TemplateQueryBuilder(const TemplateQueryBuilder<Sp, SV, BT> &o)
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

      /**
       * Make query field transformation on copied object
       * @tparam Transformation - callable type for changing query
       * @param t - transform function for proto query
       * @return new builder with set query
       */
      template <typename Transformation>
      auto queryField(Transformation t) const {
        NextBuilder<QueryField> copy = *this;
        t(copy.query_.mutable_payload());
        return copy;
      }

      /// Set tx pagination meta
      template <typename PageMetaPayload>
      static auto setTxPaginationMeta(
          PageMetaPayload * page_meta_payload,
          interface::types::TransactionsNumberType page_size,
          const std::optional<interface::types::HashType> &first_hash =
              std::nullopt,
          const interface::Ordering *ordering = nullptr,
          const std::optional<interface::types::TimestampType> &first_tx_time =
              std::nullopt,
          const std::optional<interface::types::TimestampType> &last_tx_time =
              std::nullopt,
          const std::optional<interface::types::HeightType> &first_tx_height =
              std::nullopt,
          const std::optional<interface::types::HeightType> &last_tx_height =
              std::nullopt) {
        auto from_interface_2_proto_field =
            [](interface::Ordering::Field value) {
              switch (value) {
                case interface::Ordering::Field::kCreatedTime:
                  return iroha::protocol::Field::kCreatedTime;

                case interface::Ordering::Field::kPosition:
                  return iroha::protocol::Field::kPosition;

                default:
                  BOOST_ASSERT_MSG(false, "Unexpected Field value!");
                  return iroha::protocol::Field::kCreatedTime; //FIXME -Wreturn-type
              }
            };

        auto from_interface_2_proto_direction =
            [](interface::Ordering::Direction value) {
              switch (value) {
                case interface::Ordering::Direction::kAscending:
                  return iroha::protocol::Direction::kAscending;

                case interface::Ordering::Direction::kDescending:
                  return iroha::protocol::Direction::kDescending;

                default: {
                  BOOST_ASSERT_MSG(false, "Unexpected Direction value!");
                  return iroha::protocol::Direction::kAscending;  // suppress -Wreturn-type=error
                }
              }
            };

        page_meta_payload->set_page_size(page_size);
        if (first_hash) {
          page_meta_payload->set_first_tx_hash(first_hash->hex());
        }
        if (first_tx_time) {
          auto timestamp_begin = new google::protobuf::Timestamp{
              google::protobuf::util::TimeUtil::MillisecondsToTimestamp(
                  first_tx_time.value())};
          page_meta_payload->set_allocated_first_tx_time(timestamp_begin);
        }
        if (last_tx_time) {
          auto timestamp_end = new google::protobuf::Timestamp{
              google::protobuf::util::TimeUtil::MillisecondsToTimestamp(
                  last_tx_time.value())};
          page_meta_payload->set_allocated_last_tx_time(timestamp_end);
        }
        if (first_tx_height) {
          page_meta_payload->set_first_tx_height(first_tx_height.value());
        }
        if (last_tx_height) {
          page_meta_payload->set_last_tx_height(last_tx_height.value());
        }
        if (ordering) {
          interface::Ordering::OrderingEntry const *ptr = nullptr;
          size_t count = 0;
          (*ordering).get(ptr, count);

          for (size_t ix = 0; ix < count; ++ix) {
            interface::Ordering::OrderingEntry const &entry = ptr[ix];

            auto sequence =
                page_meta_payload->mutable_ordering()->add_sequence();
            sequence->set_field(from_interface_2_proto_field(entry.field));
            sequence->set_direction(
                from_interface_2_proto_direction(entry.direction));
          }
        }
      }

      TemplateQueryBuilder(const SV &validator)
          : stateless_validator_(validator) {}

     public:
      // we do such default initialization only because it is deprecated and
      // used only in tests
      TemplateQueryBuilder()
          : TemplateQueryBuilder(SV(iroha::test::kTestsValidatorsConfig)) {}

      auto createdTime(interface::types::TimestampType created_time) const {
        return transform<CreatedTime>([&](auto &qry) {
          qry.mutable_payload()->mutable_meta()->set_created_time(created_time);
        });
      }

      auto creatorAccountId(
          const interface::types::AccountIdType &creator_account_id) const {
        return transform<CreatorAccountId>([&](auto &qry) {
          qry.mutable_payload()->mutable_meta()->set_creator_account_id(
              creator_account_id);
        });
      }

      auto queryCounter(interface::types::CounterType query_counter) const {
        return transform<QueryCounter>([&](auto &qry) {
          qry.mutable_payload()->mutable_meta()->set_query_counter(
              query_counter);
        });
      }

      auto getAccount(const interface::types::AccountIdType &account_id) const {
        return queryField([&](auto proto_query) {
          auto query = proto_query->mutable_get_account();
          query->set_account_id(account_id);
        });
      }

      auto getSignatories(const interface::types::AccountIdType &account_id)
          const {
        return queryField([&](auto proto_query) {
          auto query = proto_query->mutable_get_signatories();
          query->set_account_id(account_id);
        });
      }

      auto getAccountTransactions(
          const interface::types::AccountIdType &account_id,
          interface::types::TransactionsNumberType page_size,
          const std::optional<interface::types::HashType> &first_hash =
              std::nullopt,
          const interface::Ordering *ordering = nullptr,
          const std::optional<interface::types::TimestampType> &first_tx_time =
              std::nullopt,
          const std::optional<interface::types::TimestampType> &last_tx_time =
              std::nullopt,
          const std::optional<interface::types::HeightType> &first_tx_height =
              std::nullopt,
          const std::optional<interface::types::HeightType> &last_tx_height =
              std::nullopt) const {
        return queryField([&](auto proto_query) {
          auto query = proto_query->mutable_get_account_transactions();
          query->set_account_id(account_id);
          setTxPaginationMeta(query->mutable_pagination_meta(),
                              page_size,
                              first_hash,
                              ordering,
                              first_tx_time,
                              last_tx_time,
                              first_tx_height,
                              last_tx_height);
        });
      }

      auto getAccountAssetTransactions(
          const interface::types::AccountIdType &account_id,
          const interface::types::AssetIdType &asset_id,
          interface::types::TransactionsNumberType page_size,
          const std::optional<interface::types::HashType> &first_hash =
              std::nullopt,
          const interface::Ordering *ordering = nullptr,
          const std::optional<interface::types::TimestampType> &first_tx_time =
              std::nullopt,
          const std::optional<interface::types::TimestampType> &last_tx_time =
              std::nullopt,
          const std::optional<interface::types::HeightType> &first_tx_height =
              std::nullopt,
          const std::optional<interface::types::HeightType> &last_tx_height =
              std::nullopt) const {
        return queryField([&](auto proto_query) {
          auto query = proto_query->mutable_get_account_asset_transactions();
          query->set_account_id(account_id);
          query->set_asset_id(asset_id);
          setTxPaginationMeta(query->mutable_pagination_meta(),
                              page_size,
                              first_hash,
                              ordering,
                              first_tx_time,
                              last_tx_time,
                              first_tx_height,
                              last_tx_height);
        });
      }

      auto getAccountAssets(
          const interface::types::AccountIdType &account_id,
          size_t page_size,
          std::optional<shared_model::interface::types::AssetIdType>
              first_asset_id) const {
        return queryField([&](auto proto_query) {
          auto query = proto_query->mutable_get_account_assets();
          query->set_account_id(account_id);
          auto pagination_meta = query->mutable_pagination_meta();
          pagination_meta->set_page_size(page_size);
          if (first_asset_id) {
            pagination_meta->set_first_asset_id(*first_asset_id);
          }
        });
      }

      auto getAccountDetail(
          size_t page_size,
          const interface::types::AccountIdType &account_id = "",
          const interface::types::AccountDetailKeyType &key = "",
          const interface::types::AccountIdType &writer = "",
          const std::optional<plain::AccountDetailRecordId> &first_record_id =
              std::nullopt) {
        return queryField([&](auto proto_query) {
          auto query = proto_query->mutable_get_account_detail();
          if (not account_id.empty()) {
            query->set_account_id(account_id);
          }
          if (not key.empty()) {
            query->set_key(key);
          }
          if (not writer.empty()) {
            query->set_writer(writer);
          }
          auto pagination_meta = query->mutable_pagination_meta();
          pagination_meta->set_page_size(page_size);
          if (first_record_id) {
            auto proto_first_record_id =
                pagination_meta->mutable_first_record_id();
            proto_first_record_id->set_writer(first_record_id->writer());
            proto_first_record_id->set_key(first_record_id->key());
          }
        });
      }

      auto getBlock(interface::types::HeightType height) const {
        return queryField([&](auto proto_query) {
          auto query = proto_query->mutable_get_block();
          query->set_height(height);
        });
      }

      auto getEngineReceipts(std::string_view tx_hash) {
        return queryField([&](auto proto_query) {
          auto query = proto_query->mutable_get_engine_receipts();
          query->set_tx_hash(tx_hash.data(), tx_hash.size());
        });
      }

      auto getRoles() const {
        return queryField(
            [&](auto proto_query) { proto_query->mutable_get_roles(); });
      }

      auto getAssetInfo(const interface::types::AssetIdType &asset_id) const {
        return queryField([&](auto proto_query) {
          auto query = proto_query->mutable_get_asset_info();
          query->set_asset_id(asset_id);
        });
      }

      auto getRolePermissions(const interface::types::RoleIdType &role_id)
          const {
        return queryField([&](auto proto_query) {
          auto query = proto_query->mutable_get_role_permissions();
          query->set_role_id(role_id);
        });
      }

      template <typename Collection>
      auto getTransactions(const Collection &hashes) const {
        return queryField([&](auto proto_query) {
          auto query = proto_query->mutable_get_transactions();
          boost::for_each(hashes, [&query](const auto &hash) {
            query->add_tx_hashes(hash.hex());
          });
        });
      }

      auto getTransactions(
          std::initializer_list<interface::types::HashType> hashes) const {
        return getTransactions(hashes);
      }

      template <typename... Hash>
      auto getTransactions(const Hash &... hashes) const {
        return getTransactions({hashes...});
      }

      auto getPendingTransactions() const {
        return queryField([&](auto proto_query) {
          proto_query->mutable_get_pending_transactions();
        });
      }

      auto getPendingTransactions(
          interface::types::TransactionsNumberType page_size,
          const std::optional<interface::types::HashType> &first_hash =
              std::nullopt,
          const std::optional<interface::types::TimestampType> &first_tx_time =
              std::nullopt,
          const std::optional<interface::types::TimestampType> &last_tx_time =
              std::nullopt) const {
        return queryField([&](auto proto_query) {
          auto query = proto_query->mutable_get_pending_transactions();
          setTxPaginationMeta(
              query->mutable_pagination_meta(), page_size, first_hash, nullptr, first_tx_time, last_tx_time);
        });
      }

      auto getPeers() const {
        return queryField(
            [&](auto proto_query) { proto_query->mutable_get_peers(); });
      }

      auto build() const {
        static_assert(S == (1 << TOTAL) - 1, "Required fields are not set");
        if (not query_.has_payload()) {
          throw std::invalid_argument("Query missing payload");
        }
        if (query_.payload().query_case()
            == iroha::protocol::Query_Payload::QueryCase::QUERY_NOT_SET) {
          throw std::invalid_argument("Missing concrete query");
        }
        auto result = Query(iroha::protocol::Query(query_));
        if (auto error = stateless_validator_.validate(result)) {
          throw std::invalid_argument(error->toString());
        }
        return BT(std::move(result));
      }

      static const int total = RequiredFields::TOTAL;

     private:
      ProtoQuery query_;
      SV stateless_validator_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_QUERY_BUILDER_TEMPLATE_HPP
