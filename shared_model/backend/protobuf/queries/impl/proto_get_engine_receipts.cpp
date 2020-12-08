/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_engine_receipts.hpp"

#include "cryptography/hash.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryType>
    GetEngineReceipts::GetEngineReceipts(QueryType &&query)
        : TrivialProto(std::forward<QueryType>(query)),
          get_engine_response_{proto_->payload().get_engine_receipts()} {}

    template GetEngineReceipts::GetEngineReceipts(
        GetEngineReceipts::TransportType &);
    template GetEngineReceipts::GetEngineReceipts(
        const GetEngineReceipts::TransportType &);
    template GetEngineReceipts::GetEngineReceipts(
        GetEngineReceipts::TransportType &&);

    GetEngineReceipts::GetEngineReceipts(const GetEngineReceipts &o)
        : GetEngineReceipts(o.proto_) {}

    GetEngineReceipts::GetEngineReceipts(GetEngineReceipts &&o) noexcept
        : GetEngineReceipts(std::move(o.proto_)) {}

    const std::string &GetEngineReceipts::txHash() const {
      return get_engine_response_.tx_hash();
    }

  }  // namespace proto
}  // namespace shared_model
