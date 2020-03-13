/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_tx_pagination_meta.hpp"

#include "common/result.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/hash.hpp"
#include "queries.pb.h"

namespace types = shared_model::interface::types;

using namespace shared_model::proto;

iroha::expected::Result<std::unique_ptr<TxPaginationMeta>, std::string>
TxPaginationMeta::create(const iroha::protocol::TxPaginationMeta &meta) {
  if (meta.opt_first_tx_hash_case()
      == iroha::protocol::TxPaginationMeta::OptFirstTxHashCase::kFirstTxHash) {
    return shared_model::crypto::Blob::fromHexString(meta.first_tx_hash()) |
        [&](auto &&blob) {
          return std::make_unique<TxPaginationMeta>(
              meta, shared_model::crypto::Hash{std::move(blob)});
        };
  }
  return std::make_unique<TxPaginationMeta>(meta, std::nullopt);
}

TxPaginationMeta::TxPaginationMeta(
    const iroha::protocol::TxPaginationMeta &meta,
    std::optional<types::HashType> first_tx_hash)
    : meta_{meta}, first_tx_hash_(std::move(first_tx_hash)) {}

types::TransactionsNumberType TxPaginationMeta::pageSize() const {
  return meta_.page_size();
}

const std::optional<types::HashType> &TxPaginationMeta::firstTxHash() const {
  return first_tx_hash_;
}
