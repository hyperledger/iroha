/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TORII_UTILS_QUERY_CLIENT_HPP
#define TORII_UTILS_QUERY_CLIENT_HPP

#include <endpoint.grpc.pb.h>
#include <endpoint.pb.h>
#include <memory>
#include <thread>

namespace torii_utils {

  /**
   * CommandSyncClient
   */
  class QuerySyncClient {
   public:
    using Service = iroha::protocol::QueryService_v1;

    QuerySyncClient(std::shared_ptr<Service::StubInterface> stub);

    /**
     * requests query to a torii server and returns response (blocking, sync)
     * @param query - contains Query what clients request.
     * @param response - QueryResponse that contains what clients want to get.
     * @return grpc::Status
     */
    grpc::Status Find(const iroha::protocol::Query &query,
                      iroha::protocol::QueryResponse &response) const;

    std::vector<iroha::protocol::BlockQueryResponse> FetchCommits(
        const iroha::protocol::BlocksQuery &blocks_query) const;

   private:
    void swap(QuerySyncClient &lhs, QuerySyncClient &rhs);

    std::shared_ptr<Service::StubInterface> stub_;
  };

  /**
   * QueryAsyncClient

  // Implement here if we need this.

  class QueryAsyncClient {
  };
   */

}  // namespace torii_utils

#endif  // TORII_UTILS_QUERY_CLIENT_HPP
