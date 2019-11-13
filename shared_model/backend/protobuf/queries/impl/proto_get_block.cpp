/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_block.hpp"

namespace shared_model {
  namespace proto {

    GetBlock::GetBlock(iroha::protocol::Query &query)
        : get_block_{query.payload().get_block()} {}

    interface::types::HeightType GetBlock::height() const {
      return get_block_.height();
    }

  }  // namespace proto
}  // namespace shared_model
