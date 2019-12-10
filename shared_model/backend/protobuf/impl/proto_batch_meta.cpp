/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/batch_meta.hpp"

#include <boost/range/adaptor/transformed.hpp>
#include "common/result.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/hash.hpp"

using namespace shared_model::proto;

namespace {
  using ProtoBatchType =
      iroha::protocol::Transaction_Payload_BatchMeta_BatchType;
  using IfaceBatchType = shared_model::interface::types::BatchType;

  const std::unordered_map<ProtoBatchType, IfaceBatchType>
      kProtoToIrohaBatchTypes{
          {ProtoBatchType::Transaction_Payload_BatchMeta_BatchType_ATOMIC,
           IfaceBatchType::ATOMIC},
          {ProtoBatchType::Transaction_Payload_BatchMeta_BatchType_ORDERED,
           IfaceBatchType::ORDERED}};
}  // namespace

iroha::expected::Result<std::unique_ptr<BatchMeta>, std::string>
BatchMeta::create(
    iroha::protocol::Transaction::Payload::BatchMeta &batch_meta) {
  const auto batch_type_it = kProtoToIrohaBatchTypes.find(batch_meta.type());
  if (batch_type_it != kProtoToIrohaBatchTypes.end()) {
    auto type = batch_type_it->second;
    ReducedHashesType reduced_hashes;
    for (const auto &hash : batch_meta.reduced_hashes()) {
      using namespace iroha::expected;
      auto blob_result = shared_model::crypto::Blob::fromHexString(hash);
      if (auto e = resultToOptionalError(blob_result)) {
        return e.value();
      }
      reduced_hashes.emplace_back(
          resultToOptionalValue(std::move(blob_result)).value());
    }
    return std::make_unique<BatchMeta>(type, std::move(reduced_hashes));
  } else {
    return "Unknown batch type.";
  }
}

BatchMeta::BatchMeta(IfaceBatchType type, ReducedHashesType reduced_hashes)
    : type_(type), reduced_hashes_(std::move(reduced_hashes)) {}

IfaceBatchType BatchMeta::type() const {
  return type_;
}

const BatchMeta::ReducedHashesType &BatchMeta::reducedHashes() const {
  return reduced_hashes_;
}
