/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_BLOCK_HPP
#define IROHA_PROTO_GET_BLOCK_HPP

#include "interfaces/queries/get_block.hpp"

#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetBlock final : public interface::GetBlock {
     public:
      explicit GetBlock(iroha::protocol::Query &query);

      interface::types::HeightType height() const override;

     private:
      // ------------------------------| fields |-------------------------------
      const iroha::protocol::GetBlock &get_block_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_BLOCK_HPP
