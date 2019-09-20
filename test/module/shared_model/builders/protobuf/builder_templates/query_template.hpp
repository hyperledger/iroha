/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_QUERY_BUILDER_TEMPLATE_HPP
#define IROHA_PROTO_QUERY_BUILDER_TEMPLATE_HPP

#include <memory>

#include <boost/optional.hpp>
#include "backend/plain/account_detail_record_id.hpp"
#include "backend/protobuf/queries/proto_query.hpp"
#include "interfaces/common_objects/types.hpp"
#include "module/shared_model/builders/protobuf/unsigned_proto.hpp"

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
      /**
       * Make transformation on copied content
       * @tparam Transformation - callable type for changing the copy
       * @param t - transform function for proto object
       * @return new builder with updated state
       */
      template <typename Transformation>
      TemplateQueryBuilder<BT> transform(Transformation t) const;

      /**
       * Make query field transformation on copied object
       * @tparam Transformation - callable type for changing query
       * @param t - transform function for proto query
       * @return new builder with set query
       */
      template <typename Transformation>
      TemplateQueryBuilder<BT> queryField(Transformation t) const;

     public:
      // we do such default initialization only because it is deprecated and
      // used only in tests
      TemplateQueryBuilder();

      TemplateQueryBuilder(const TemplateQueryBuilder<BT> &o);

      TemplateQueryBuilder<BT> createdTime(
          interface::types::TimestampType created_time) const;

      TemplateQueryBuilder<BT> creatorAccountId(
          const interface::types::AccountIdType &creator_account_id) const;

      TemplateQueryBuilder<BT> queryCounter(
          interface::types::CounterType query_counter) const;

      TemplateQueryBuilder<BT> getAccount(
          const interface::types::AccountIdType &account_id) const;

      TemplateQueryBuilder<BT> getSignatories(
          const interface::types::AccountIdType &account_id) const;

      TemplateQueryBuilder<BT> getAccountTransactions(
          const interface::types::AccountIdType &account_id,
          interface::types::TransactionsNumberType page_size,
          const boost::optional<interface::types::HashType> &first_hash =
              boost::none) const;

      TemplateQueryBuilder<BT> getAccountAssetTransactions(
          const interface::types::AccountIdType &account_id,
          const interface::types::AssetIdType &asset_id,
          interface::types::TransactionsNumberType page_size,
          const boost::optional<interface::types::HashType> &first_hash =
              boost::none) const;

      TemplateQueryBuilder<BT> getAccountAssets(
          const interface::types::AccountIdType &account_id,
          size_t page_size,
          boost::optional<shared_model::interface::types::AssetIdType>
              first_asset_id) const;

      TemplateQueryBuilder<BT> getAccountDetail(
          size_t page_size,
          const interface::types::AccountIdType &account_id = "",
          const interface::types::AccountDetailKeyType &key = "",
          const interface::types::AccountIdType &writer = "",
          const boost::optional<plain::AccountDetailRecordId> &first_record_id =
              boost::none);

      TemplateQueryBuilder<BT> getBlock(interface::types::HeightType height)
          const;

      TemplateQueryBuilder<BT> getRoles() const;

      TemplateQueryBuilder<BT> getAssetInfo(
          const interface::types::AssetIdType &asset_id) const;

      TemplateQueryBuilder<BT> getRolePermissions(
          const interface::types::RoleIdType &role_id) const;

      TemplateQueryBuilder<BT> getTransactions(
          const std::vector<shared_model::crypto::Hash> &hashes) const;

      TemplateQueryBuilder<BT> getPendingTransactions() const;

      TemplateQueryBuilder<BT> getPendingTransactions(
          interface::types::TransactionsNumberType page_size,
          const boost::optional<interface::types::HashType> &first_hash =
              boost::none) const;

      TemplateQueryBuilder<BT> getPeers() const;

      BT build() const;

      ~TemplateQueryBuilder();

     private:
      std::unique_ptr<iroha::protocol::Query> query_;
    };

    extern template class TemplateQueryBuilder<Query>;
    extern template class TemplateQueryBuilder<UnsignedWrapper<Query>>;
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_QUERY_BUILDER_TEMPLATE_HPP
