/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_peers_response.hpp"

#include <boost/range/adaptor/indirected.hpp>
#include "backend/protobuf/common_objects/peer.hpp"
#include "common/result.hpp"
#include "cryptography/blob.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    iroha::expected::Result<std::unique_ptr<PeersResponse>, std::string>
    PeersResponse::create(iroha::protocol::QueryResponse &query_response) {
      using namespace iroha::expected;

      std::vector<std::unique_ptr<shared_model::interface::Peer>> peers;
      for (auto &proto :
           *query_response.mutable_peers_response()->mutable_peers()) {
        if (auto e = resultToOptionalError(
                Peer::create(proto) |
                    [&peers](auto &&peer) -> Result<void, std::string> {
                  peers.emplace_back(std::move(peer));
                  return {};
                })) {
          return e.value();
        }
      }

      return std::make_unique<PeersResponse>(std::move(peers));
    }

    PeersResponse::PeersResponse(
        std::vector<std::unique_ptr<shared_model::interface::Peer>> peers)
        : peers_{std::move(peers)} {}

    PeersResponse::~PeersResponse() = default;

    interface::PeersForwardCollectionType PeersResponse::peers() const {
      return peers_ | boost::adaptors::indirected;
    }

  }  // namespace proto
}  // namespace shared_model
