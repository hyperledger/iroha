/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_tx_pagination_meta.hpp"

#include "cryptography/hash.hpp"

namespace types = shared_model::interface::types;

using namespace shared_model::proto;

TxPaginationMeta::TxPaginationMeta(const TransportType &query)
    : TrivialProto(query) {}

TxPaginationMeta::TxPaginationMeta(TransportType &&query)
    : TrivialProto(std::move(query)) {}

TxPaginationMeta::TxPaginationMeta(const TxPaginationMeta &o)
    : TxPaginationMeta(*o.proto_) {}

TxPaginationMeta::TxPaginationMeta(TxPaginationMeta &&o) noexcept
    : TrivialProto(std::move(*o.proto_)) {}

types::TransactionsNumberType TxPaginationMeta::pageSize() const {
  return proto_->page_size();
}

boost::optional<types::HashType> TxPaginationMeta::firstTxHash() const {
  if (proto_->opt_first_tx_hash_case()
      == TransportType::OptFirstTxHashCase::OPT_FIRST_TX_HASH_NOT_SET) {
    return boost::none;
  }
  return types::HashType::fromHexString(proto_->first_tx_hash());
}
