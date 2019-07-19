/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/query_client.hpp"

#include <grpc++/channel.h>
#include <grpc++/grpc++.h>
#include "network/impl/grpc_channel_builder.hpp"

namespace torii_utils {

  using iroha::protocol::Query;
  using iroha::protocol::QueryResponse;

  QuerySyncClient::QuerySyncClient(const std::string &ip, size_t port)
      : ip_(ip),
        port_(port),
        stub_(iroha::network::createClient<iroha::protocol::QueryService_v1>(
            ip + ":" + std::to_string(port))) {}

  QuerySyncClient::QuerySyncClient(const QuerySyncClient &rhs)
      : QuerySyncClient(rhs.ip_, rhs.port_) {}

  QuerySyncClient &QuerySyncClient::operator=(QuerySyncClient rhs) {
    swap(*this, rhs);
    return *this;
  }

  QuerySyncClient::QuerySyncClient(QuerySyncClient &&rhs) noexcept {
    swap(*this, rhs);
  }

  QuerySyncClient &QuerySyncClient::operator=(QuerySyncClient &&rhs) noexcept {
    swap(*this, rhs);
    return *this;
  }

  /**
   * requests query to a torii server and returns response (blocking, sync)
   * @param query
   * @param response
   * @return grpc::Status
   */
  grpc::Status QuerySyncClient::Find(const iroha::protocol::Query &query,
                                     QueryResponse &response) const {
    grpc::ClientContext context;
    return stub_->Find(&context, query, &response);
  }

  std::vector<iroha::protocol::BlockQueryResponse>
  QuerySyncClient::FetchCommits(
      const iroha::protocol::BlocksQuery &blocks_query) const {
    grpc::ClientContext context;
    auto reader = stub_->FetchCommits(&context, blocks_query);
    std::vector<iroha::protocol::BlockQueryResponse> responses;
    iroha::protocol::BlockQueryResponse resp;
    while (reader->Read(&resp)) {
      responses.push_back(resp);
    }
    reader->Finish();
    return responses;
  }

  void QuerySyncClient::swap(QuerySyncClient &lhs, QuerySyncClient &rhs) {
    using std::swap;
    swap(lhs.ip_, rhs.ip_);
    swap(lhs.port_, rhs.port_);
    swap(lhs.stub_, rhs.stub_);
  }

}  // namespace torii_utils
