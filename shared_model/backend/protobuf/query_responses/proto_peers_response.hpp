/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_PEERS_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_PEERS_RESPONSE_HPP

#include "interfaces/query_responses/peers_response.hpp"

#include "common/result_fwd.hpp"

namespace iroha {
  namespace protocol {
    class QueryResponse;
  }
}  // namespace iroha

namespace shared_model {
  namespace proto {
    class PeersResponse final : public interface::PeersResponse {
     public:
      static iroha::expected::Result<std::unique_ptr<PeersResponse>,
                                     std::string>
      create(iroha::protocol::QueryResponse &query_response);

      explicit PeersResponse(
          std::vector<std::unique_ptr<shared_model::interface::Peer>> peers);

      ~PeersResponse() override;

      interface::PeersForwardCollectionType peers() const override;

     private:
      std::vector<std::unique_ptr<shared_model::interface::Peer>> peers_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_PEERS_RESPONSE_HPP
