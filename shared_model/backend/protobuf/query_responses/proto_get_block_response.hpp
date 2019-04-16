/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_GET_BLOCK_RESPONSE_HPP
#define IROHA_SHARED_MODEL_GET_BLOCK_RESPONSE_HPP

#include "backend/protobuf/block.hpp"
#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/query_responses/block_response.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class GetBlockResponse final
        : public CopyableProto<interface::BlockResponse,
                               iroha::protocol::QueryResponse,
                               GetBlockResponse> {
     public:
      template <typename QueryResponseType>
      explicit GetBlockResponse(QueryResponseType &&queryResponse);

      GetBlockResponse(const GetBlockResponse &o);

      GetBlockResponse(GetBlockResponse &&o);

      const interface::Block &block() const override;

     private:
      const iroha::protocol::BlockResponse &block_response_;

      const Block block_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_GET_BLOCK_RESPONSE_HPP
