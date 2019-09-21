/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/shared_model/builders/protobuf/builder_templates/query_template.hpp"

#include <boost/range/algorithm/for_each.hpp>
#include "queries.pb.h"

using namespace shared_model;
using namespace shared_model::proto;

namespace {
  /// Set tx pagination meta
  template <typename PageMetaPayload>
  void setTxPaginationMeta(PageMetaPayload *page_meta_payload,
                           interface::types::TransactionsNumberType page_size,
                           const boost::optional<interface::types::HashType>
                               &first_hash = boost::none) {
    page_meta_payload->set_page_size(page_size);
    if (first_hash) {
      page_meta_payload->set_first_tx_hash(first_hash->hex());
    }
  }
}  // namespace

template <typename BT>
template <typename Transformation>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::transform(
    Transformation t) const {
  TemplateQueryBuilder<BT> copy = *this;
  t(*copy.query_);
  return copy;
}

template <typename BT>
template <typename Transformation>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::queryField(
    Transformation t) const {
  TemplateQueryBuilder<BT> copy = *this;
  t(copy.query_->mutable_payload());
  return copy;
}

template <typename BT>
TemplateQueryBuilder<BT>::TemplateQueryBuilder()
    : query_{std::make_unique<iroha::protocol::Query>()} {};

template <typename BT>
TemplateQueryBuilder<BT>::TemplateQueryBuilder(
    const TemplateQueryBuilder<BT> &o)
    : query_{std::make_unique<iroha::protocol::Query>(*o.query_)} {}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::createdTime(
    interface::types::TimestampType created_time) const {
  return transform([&](auto &qry) {
    qry.mutable_payload()->mutable_meta()->set_created_time(created_time);
  });
}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::creatorAccountId(
    const interface::types::AccountIdType &creator_account_id) const {
  return transform([&](auto &qry) {
    qry.mutable_payload()->mutable_meta()->set_creator_account_id(
        creator_account_id);
  });
}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::queryCounter(
    interface::types::CounterType query_counter) const {
  return transform([&](auto &qry) {
    qry.mutable_payload()->mutable_meta()->set_query_counter(query_counter);
  });
}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::getAccount(
    const interface::types::AccountIdType &account_id) const {
  return queryField([&](auto proto_query) {
    auto query = proto_query->mutable_get_account();
    query->set_account_id(account_id);
  });
}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::getSignatories(
    const interface::types::AccountIdType &account_id) const {
  return queryField([&](auto proto_query) {
    auto query = proto_query->mutable_get_signatories();
    query->set_account_id(account_id);
  });
}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::getAccountTransactions(
    const interface::types::AccountIdType &account_id,
    interface::types::TransactionsNumberType page_size,
    const boost::optional<interface::types::HashType> &first_hash) const {
  return queryField([&](auto proto_query) {
    auto query = proto_query->mutable_get_account_transactions();
    query->set_account_id(account_id);
    setTxPaginationMeta(
        query->mutable_pagination_meta(), page_size, first_hash);
  });
}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::getAccountAssetTransactions(
    const interface::types::AccountIdType &account_id,
    const interface::types::AssetIdType &asset_id,
    interface::types::TransactionsNumberType page_size,
    const boost::optional<interface::types::HashType> &first_hash) const {
  return queryField([&](auto proto_query) {
    auto query = proto_query->mutable_get_account_asset_transactions();
    query->set_account_id(account_id);
    query->set_asset_id(asset_id);
    setTxPaginationMeta(
        query->mutable_pagination_meta(), page_size, first_hash);
  });
}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::getAccountAssets(
    const interface::types::AccountIdType &account_id,
    size_t page_size,
    boost::optional<shared_model::interface::types::AssetIdType> first_asset_id)
    const {
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

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::getAccountDetail(
    size_t page_size,
    const interface::types::AccountIdType &account_id,
    const interface::types::AccountDetailKeyType &key,
    const interface::types::AccountIdType &writer,
    const boost::optional<plain::AccountDetailRecordId> &first_record_id) {
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
      auto proto_first_record_id = pagination_meta->mutable_first_record_id();
      proto_first_record_id->set_writer(first_record_id->writer());
      proto_first_record_id->set_key(first_record_id->key());
    }
  });
}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::getBlock(
    interface::types::HeightType height) const {
  return queryField([&](auto proto_query) {
    auto query = proto_query->mutable_get_block();
    query->set_height(height);
  });
}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::getRoles() const {
  return queryField(
      [&](auto proto_query) { proto_query->mutable_get_roles(); });
}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::getAssetInfo(
    const interface::types::AssetIdType &asset_id) const {
  return queryField([&](auto proto_query) {
    auto query = proto_query->mutable_get_asset_info();
    query->set_asset_id(asset_id);
  });
}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::getRolePermissions(
    const interface::types::RoleIdType &role_id) const {
  return queryField([&](auto proto_query) {
    auto query = proto_query->mutable_get_role_permissions();
    query->set_role_id(role_id);
  });
}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::getTransactions(
    const std::vector<shared_model::crypto::Hash> &hashes) const {
  return queryField([&](auto proto_query) {
    auto query = proto_query->mutable_get_transactions();
    boost::for_each(hashes, [&query](const auto &hash) {
      query->add_tx_hashes(hash.hex());
    });
  });
}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::getPendingTransactions()
    const {
  return queryField([&](auto proto_query) {
    proto_query->mutable_get_pending_transactions();
  });
}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::getPendingTransactions(
    interface::types::TransactionsNumberType page_size,
    const boost::optional<interface::types::HashType> &first_hash) const {
  return queryField([&](auto proto_query) {
    auto query = proto_query->mutable_get_pending_transactions();
    setTxPaginationMeta(
        query->mutable_pagination_meta(), page_size, first_hash);
  });
}

template <typename BT>
TemplateQueryBuilder<BT> TemplateQueryBuilder<BT>::getPeers() const {
  return queryField(
      [&](auto proto_query) { proto_query->mutable_get_peers(); });
}

template <typename BT>
BT TemplateQueryBuilder<BT>::build() const {
  if (not query_->has_payload()) {
    throw std::invalid_argument("Query missing payload");
  }
  if (query_->payload().query_case()
      == iroha::protocol::Query_Payload::QueryCase::QUERY_NOT_SET) {
    throw std::invalid_argument("Missing concrete query");
  }
  auto result = Query(iroha::protocol::Query(*query_));

  return BT(std::move(result));
}

template <typename BT>
TemplateQueryBuilder<BT>::~TemplateQueryBuilder() = default;

template class shared_model::proto::TemplateQueryBuilder<Query>;
template class shared_model::proto::TemplateQueryBuilder<
    UnsignedWrapper<Query>>;
