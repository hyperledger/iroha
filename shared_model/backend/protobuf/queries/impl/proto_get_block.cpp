/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_block.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryType>
    GetBlock::GetBlock(QueryType &&query)
        : CopyableProto(std::forward<QueryType>(query)),
          get_block_{proto_->payload().get_block()} {}

    template GetBlock::GetBlock(GetBlock::TransportType &);
    template GetBlock::GetBlock(const GetBlock::TransportType &);
    template GetBlock::GetBlock(GetBlock::TransportType &&);

    GetBlock::GetBlock(const GetBlock &o) : GetBlock(o.proto_) {}

    GetBlock::GetBlock(GetBlock &&o) noexcept : GetBlock(std::move(o.proto_)) {}

    interface::types::HeightType GetBlock::height() const {
      return get_block_.height();
    }

  }  // namespace proto
}  // namespace shared_model
