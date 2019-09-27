/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_BLOCK_QUERY_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_BLOCK_QUERY_RESPONSE_HPP

#include "interfaces/query_responses/block_query_response.hpp"

#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class BlockQueryResponse final : public interface::BlockQueryResponse {
     public:
      using TransportType = iroha::protocol::BlockQueryResponse;

      explicit BlockQueryResponse(TransportType &&block_query_response);

      ~BlockQueryResponse() override;

      const QueryResponseVariantType &get() const override;

      const TransportType &getTransport() const;

     private:
      struct Impl;
      std::unique_ptr<Impl> impl_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_BLOCK_QUERY_RESPONSE_HPP
