/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_tx_pagination_meta.hpp"

#include <google/protobuf/util/time_util.h>

#include <optional>

#include "cryptography/hash.hpp"
namespace types = shared_model::interface::types;

using namespace shared_model::proto;

TxPaginationMeta::TxPaginationMeta(iroha::protocol::TxPaginationMeta &meta)
    : meta_{meta}, ordering_(meta.ordering()) {
  /// default values
  ordering_.append(interface::Ordering::Field::kPosition,
                   interface::Ordering::Direction::kAscending);
}

types::TransactionsNumberType TxPaginationMeta::pageSize() const {
  return meta_.page_size();
}

std::optional<types::HashType> TxPaginationMeta::firstTxHash() const {
  if (meta_.opt_first_tx_hash_case()
      == iroha::protocol::TxPaginationMeta::OptFirstTxHashCase::
          OPT_FIRST_TX_HASH_NOT_SET) {
    return std::nullopt;
  }
  return types::HashType::fromHexString(meta_.first_tx_hash());
}
shared_model::interface::Ordering const &TxPaginationMeta::ordering() const {
  return ordering_;
}
// first_tx_time
std::optional<types::TimestampType> TxPaginationMeta::firstTxTime() const {
  if (meta_.opt_first_tx_time_case()
      == iroha::protocol::TxPaginationMeta::OptFirstTxTimeCase::
          OPT_FIRST_TX_TIME_NOT_SET) {
    return std::nullopt;
  }
  return google::protobuf::util::TimeUtil::TimestampToMilliseconds(
      meta_.first_tx_time());
}
// last_tx_time
std::optional<types::TimestampType> TxPaginationMeta::lastTxTime() const {
  if (meta_.opt_last_tx_time_case()
      == iroha::protocol::TxPaginationMeta::OptLastTxTimeCase::
          OPT_LAST_TX_TIME_NOT_SET) {
    return std::nullopt;
  }
  return google::protobuf::util::TimeUtil::TimestampToMilliseconds(
      meta_.last_tx_time());
}
// first tx height
std::optional<types::HeightType> TxPaginationMeta::firstTxHeight() const {
  if (meta_.opt_first_tx_height_case()
      == iroha::protocol::TxPaginationMeta::OptFirstTxHeightCase::
          OPT_FIRST_TX_HEIGHT_NOT_SET) {
    return std::nullopt;
  }
  return types::HeightType(meta_.first_tx_height());
}
// last tx height
std::optional<types::HeightType> TxPaginationMeta::lastTxHeight() const {
  if (meta_.opt_last_tx_height_case()
      == iroha::protocol::TxPaginationMeta::OptLastTxHeightCase::
          OPT_LAST_TX_HEIGHT_NOT_SET) {
    return std::nullopt;
  }
  return types::HeightType(meta_.last_tx_height());
}
