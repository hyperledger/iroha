/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/shared_model/builders/protobuf/builder_templates/block_template.hpp"

#include "block.pb.h"

using namespace shared_model;
using namespace shared_model::proto;

template <typename BT>
template <typename Transformation>
TemplateBlockBuilder<BT> TemplateBlockBuilder<BT>::transform(
    Transformation t) const {
  TemplateBlockBuilder<BT> copy = *this;
  t(*copy.block_);
  return copy;
}

template <typename BT>
TemplateBlockBuilder<BT>::TemplateBlockBuilder()
    : block_{std::make_unique<iroha::protocol::Block_v1>()} {}

template <typename BT>
TemplateBlockBuilder<BT>::TemplateBlockBuilder(
    const TemplateBlockBuilder<BT> &o)
    : block_{std::make_unique<iroha::protocol::Block_v1>(*o.block_)} {}

template <typename BT>
TemplateBlockBuilder<BT> TemplateBlockBuilder<BT>::transactions(
    const std::vector<shared_model::proto::Transaction> &transactions) const {
  return transform([&](auto &block) {
    for (const auto &tx : transactions) {
      new (block.mutable_payload()->add_transactions())
          iroha::protocol::Transaction(tx.getTransport());
    }
  });
}

template <typename BT>
TemplateBlockBuilder<BT> TemplateBlockBuilder<BT>::rejectedTransactions(
    const std::vector<shared_model::crypto::Hash> &rejected_transactions_hashes)
    const {
  return transform([&](auto &block) {
    for (const auto &hash : rejected_transactions_hashes) {
      auto *next_hash =
          block.mutable_payload()->add_rejected_transactions_hashes();
      (*next_hash) = hash.hex();
    }
  });
}

template <typename BT>
TemplateBlockBuilder<BT> TemplateBlockBuilder<BT>::height(
    interface::types::HeightType height) const {
  return transform(
      [&](auto &block) { block.mutable_payload()->set_height(height); });
}

template <typename BT>
TemplateBlockBuilder<BT> TemplateBlockBuilder<BT>::prevHash(
    crypto::Hash hash) const {
  return transform([&](auto &block) {
    block.mutable_payload()->set_prev_block_hash(hash.hex());
  });
}

template <typename BT>
TemplateBlockBuilder<BT> TemplateBlockBuilder<BT>::createdTime(
    interface::types::TimestampType time) const {
  return transform(
      [&](auto &block) { block.mutable_payload()->set_created_time(time); });
}

template <typename BT>
BT TemplateBlockBuilder<BT>::build() {
  auto tx_number = block_->payload().transactions().size();
  block_->mutable_payload()->set_tx_number(tx_number);

  auto result = Block(iroha::protocol::Block_v1(*block_));

  return BT(std::move(result));
}

template <typename BT>
TemplateBlockBuilder<BT>::~TemplateBlockBuilder() = default;

template class shared_model::proto::TemplateBlockBuilder<Block>;
template class shared_model::proto::TemplateBlockBuilder<
    UnsignedWrapper<Block>>;
