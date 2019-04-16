/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_BLOCK_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_BLOCK_RESPONSE_HPP

#include "backend/protobuf/block.hpp"
#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/query_responses/block_response.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class BlockResponse final
        : public CopyableProto<interface::BlockResponse,
                               iroha::protocol::BlockQueryResponse,
                               BlockResponse> {
     public:
      template <typename QueryResponseType>
      explicit BlockResponse(QueryResponseType &&queryResponse);

      BlockResponse(const BlockResponse &o);

      BlockResponse(BlockResponse &&o) noexcept;

      const Block &block() const override;

     private:
      const iroha::protocol::BlockResponse &block_response_;

      const Block block_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_BLOCK_RESPONSE_HPP
