/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/shared_model/builders/protobuf/builder_templates/blocks_query_template.hpp"

#include "queries.pb.h"

using namespace shared_model;
using namespace shared_model::proto;

template <typename BT>
template <typename Transformation>
TemplateBlocksQueryBuilder<BT> TemplateBlocksQueryBuilder<BT>::transform(
    Transformation t) const {
  TemplateBlocksQueryBuilder<BT> copy = *this;
  t(*copy.query_);
  return copy;
}

template <typename BT>
TemplateBlocksQueryBuilder<BT>::TemplateBlocksQueryBuilder()
    : query_{std::make_unique<iroha::protocol::BlocksQuery>()} {}

template <typename BT>
TemplateBlocksQueryBuilder<BT>::TemplateBlocksQueryBuilder(
    const TemplateBlocksQueryBuilder<BT> &o)
    : query_{std::make_unique<iroha::protocol::BlocksQuery>(*o.query_)} {}

template <typename BT>
TemplateBlocksQueryBuilder<BT> TemplateBlocksQueryBuilder<BT>::createdTime(
    interface::types::TimestampType created_time) const {
  return transform([&](auto &qry) {
    auto *meta = qry.mutable_meta();
    meta->set_created_time(created_time);
  });
}

template <typename BT>
TemplateBlocksQueryBuilder<BT> TemplateBlocksQueryBuilder<BT>::creatorAccountId(
    const interface::types::AccountIdType &creator_account_id) const {
  return transform([&](auto &qry) {
    auto *meta = qry.mutable_meta();
    meta->set_creator_account_id(creator_account_id);
  });
}

template <typename BT>
TemplateBlocksQueryBuilder<BT> TemplateBlocksQueryBuilder<BT>::queryCounter(
    interface::types::CounterType query_counter) const {
  return transform([&](auto &qry) {
    auto *meta = qry.mutable_meta();
    meta->set_query_counter(query_counter);
  });
}

template <typename BT>
BT TemplateBlocksQueryBuilder<BT>::build() const {
  auto result = BlocksQuery(iroha::protocol::BlocksQuery(*query_));

  return BT(std::move(result));
}

template <typename BT>
TemplateBlocksQueryBuilder<BT>::~TemplateBlocksQueryBuilder() = default;

template class shared_model::proto::TemplateBlocksQueryBuilder<BlocksQuery>;
template class shared_model::proto::TemplateBlocksQueryBuilder<
    UnsignedWrapper<BlocksQuery>>;
