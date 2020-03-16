/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_tx_pagination_meta.hpp"

#include <optional>
#include "cryptography/hash.hpp"

namespace types = shared_model::interface::types;

using namespace shared_model::proto;

TxPaginationMeta::TxPaginationMeta(iroha::protocol::TxPaginationMeta &meta)
    : meta_{meta} {}

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
