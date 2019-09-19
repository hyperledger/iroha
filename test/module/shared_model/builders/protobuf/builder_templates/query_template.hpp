/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_QUERY_BUILDER_TEMPLATE_HPP
#define IROHA_PROTO_QUERY_BUILDER_TEMPLATE_HPP

#include <boost/optional.hpp>
#include <boost/range/algorithm/for_each.hpp>

#include "backend/plain/account_detail_record_id.hpp"
#include "backend/protobuf/queries/proto_query.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/transaction.hpp"
#include "module/shared_model/builders/protobuf/unsigned_proto.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {

    /**
     * Template query builder for creating new types of query builders by
     * means of replacing template parameters
     * @tparam BT -- build type of built object returned by build method
     */
    template <typename BT = UnsignedWrapper<Query>>
    class [[deprecated]] TemplateQueryBuilder {
     private:
      using NextBuilder = TemplateQueryBuilder<BT>;

      using ProtoQuery = iroha::protocol::Query;

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

      /**
       * Make query field transformation on copied object
       * @tparam Transformation - callable type for changing query
       * @param t - transform function for proto query
       * @return new builder with set query
       */
      template <typename Transformation>
      auto queryField(Transformation t) const {
        NextBuilder copy = *this;
        t(copy.query_.mutable_payload());
        return copy;
      }

      /// Set tx pagination meta
      template <typename PageMetaPayload>
      static auto setTxPaginationMeta(
          PageMetaPayload * page_meta_payload,
          interface::types::TransactionsNumberType page_size,
          const boost::optional<interface::types::HashType> &first_hash =
              boost::none) {
        page_meta_payload->set_page_size(page_size);
        if (first_hash) {
          page_meta_payload->set_first_tx_hash(first_hash->hex());
        }
      }

     public:
      // we do such default initialization only because it is deprecated and
      // used only in tests
      TemplateQueryBuilder() = default;

      TemplateQueryBuilder(const TemplateQueryBuilder<BT> &o)
          : query_(o.query_) {}

      auto createdTime(interface::types::TimestampType created_time) const {
        return transform([&](auto &qry) {
          qry.mutable_payload()->mutable_meta()->set_created_time(created_time);
        });
      }

      auto creatorAccountId(
          const interface::types::AccountIdType &creator_account_id) const {
        return transform([&](auto &qry) {
          qry.mutable_payload()->mutable_meta()->set_creator_account_id(
              creator_account_id);
        });
      }

      auto queryCounter(interface::types::CounterType query_counter) const {
        return transform([&](auto &qry) {
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
          const boost::optional<interface::types::HashType> &first_hash =
              boost::none) const {
        return queryField([&](auto proto_query) {
          auto query = proto_query->mutable_get_account_transactions();
          query->set_account_id(account_id);
          setTxPaginationMeta(
              query->mutable_pagination_meta(), page_size, first_hash);
        });
      }

      auto getAccountAssetTransactions(
          const interface::types::AccountIdType &account_id,
          const interface::types::AssetIdType &asset_id,
          interface::types::TransactionsNumberType page_size,
          const boost::optional<interface::types::HashType> &first_hash =
              boost::none) const {
        return queryField([&](auto proto_query) {
          auto query = proto_query->mutable_get_account_asset_transactions();
          query->set_account_id(account_id);
          query->set_asset_id(asset_id);
          setTxPaginationMeta(
              query->mutable_pagination_meta(), page_size, first_hash);
        });
      }

      auto getAccountAssets(
          const interface::types::AccountIdType &account_id,
          size_t page_size,
          boost::optional<shared_model::interface::types::AssetIdType>
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
          const boost::optional<plain::AccountDetailRecordId> &first_record_id =
              boost::none) {
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
          const boost::optional<interface::types::HashType> &first_hash =
              boost::none) const {
        return queryField([&](auto proto_query) {
          auto query = proto_query->mutable_get_pending_transactions();
          setTxPaginationMeta(
              query->mutable_pagination_meta(), page_size, first_hash);
        });
      }

      auto getPeers() const {
        return queryField(
            [&](auto proto_query) { proto_query->mutable_get_peers(); });
      }

      auto build() const {
        if (not query_.has_payload()) {
          throw std::invalid_argument("Query missing payload");
        }
        if (query_.payload().query_case()
            == iroha::protocol::Query_Payload::QueryCase::QUERY_NOT_SET) {
          throw std::invalid_argument("Missing concrete query");
        }
        auto result = Query(iroha::protocol::Query(query_));

        return BT(std::move(result));
      }

     private:
      ProtoQuery query_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_QUERY_BUILDER_TEMPLATE_HPP
