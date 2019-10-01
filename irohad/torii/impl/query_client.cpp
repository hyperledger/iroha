/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/query_client.hpp"

#include <grpc++/channel.h>
#include <grpc++/grpc++.h>

namespace torii_utils {

  using iroha::protocol::Query;
  using iroha::protocol::QueryResponse;

  QuerySyncClient::QuerySyncClient(std::shared_ptr<Service::StubInterface> stub)
      : stub_(std::move(stub)) {}

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

}  // namespace torii_utils
