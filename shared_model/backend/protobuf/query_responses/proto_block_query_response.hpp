/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_BLOCK_QUERY_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_BLOCK_QUERY_RESPONSE_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "backend/protobuf/query_responses/proto_block_error_response.hpp"
#include "backend/protobuf/query_responses/proto_block_response.hpp"
#include "interfaces/queries/query.hpp"
#include "interfaces/query_responses/block_query_response.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class BlockQueryResponse final
        : public CopyableProto<interface::BlockQueryResponse,
                               iroha::protocol::BlockQueryResponse,
                               BlockQueryResponse> {
     private:
      /// type of proto variant
      using ProtoQueryResponseVariantType =
          boost::variant<BlockResponse, BlockErrorResponse>;

     public:
      template <typename QueryResponseType>
      explicit BlockQueryResponse(QueryResponseType &&queryResponse);

      BlockQueryResponse(const BlockQueryResponse &o);

      BlockQueryResponse(BlockQueryResponse &&o) noexcept;

      const QueryResponseVariantType &get() const override;

     private:
      const ProtoQueryResponseVariantType variant_;
      const QueryResponseVariantType ivariant_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_BLOCK_QUERY_RESPONSE_HPP
