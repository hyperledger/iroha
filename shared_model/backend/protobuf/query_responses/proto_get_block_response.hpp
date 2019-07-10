/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_GET_BLOCK_RESPONSE_HPP
#define IROHA_SHARED_MODEL_GET_BLOCK_RESPONSE_HPP

#include "interfaces/query_responses/block_response.hpp"

#include "backend/protobuf/block.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class GetBlockResponse final : public interface::BlockResponse {
     public:
      explicit GetBlockResponse(iroha::protocol::QueryResponse &query_response);

      const interface::Block &block() const override;

     private:
      const iroha::protocol::BlockResponse &block_response_;

      Block block_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_GET_BLOCK_RESPONSE_HPP
