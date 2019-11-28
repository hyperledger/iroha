/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_QUERY_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_QUERY_RESPONSE_HPP

#include "interfaces/query_responses/query_response.hpp"

#include "common/result_fwd.hpp"

namespace iroha {
  namespace protocol {
    class QueryResponse;
  }
}  // namespace iroha

namespace shared_model {
  namespace proto {
    class QueryResponse final : public interface::QueryResponse {
     public:
      using TransportType = iroha::protocol::QueryResponse;

      static iroha::expected::Result<std::unique_ptr<QueryResponse>,
                                     std::string>
      create(TransportType queryResponse);

      ~QueryResponse() override;

      const QueryResponseVariantType &get() const override;

      const interface::types::HashType &queryHash() const override;

      const TransportType &getTransport() const;

     private:
      struct Impl;
      explicit QueryResponse(std::unique_ptr<Impl> impl);
      std::unique_ptr<Impl> impl_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_QUERY_RESPONSE_HPP
