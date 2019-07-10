/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_BLOCK_QUERY_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_BLOCK_QUERY_RESPONSE_HPP

#include "interfaces/query_responses/block_query_response.hpp"

#include "backend/protobuf/query_responses/proto_block_error_response.hpp"
#include "backend/protobuf/query_responses/proto_block_response.hpp"
#include "interfaces/queries/query.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class BlockQueryResponse final : public interface::BlockQueryResponse {
     private:
      /// type of proto variant
      using ProtoQueryResponseVariantType =
          boost::variant<BlockResponse, BlockErrorResponse>;

     public:
      using TransportType = iroha::protocol::BlockQueryResponse;

      explicit BlockQueryResponse(TransportType &&block_query_response);

      const QueryResponseVariantType &get() const override;

      const TransportType &getTransport() const;

     private:
      iroha::protocol::BlockQueryResponse proto_;
      const ProtoQueryResponseVariantType variant_;
      const QueryResponseVariantType ivariant_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_BLOCK_QUERY_RESPONSE_HPP
