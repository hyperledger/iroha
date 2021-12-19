/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TORII_QUERY_SERVICE_HPP
#define TORII_QUERY_SERVICE_HPP

#include <unordered_map>
#include "endpoint.grpc.pb.h"
#include "endpoint.pb.h"
#include "qry_responses.pb.h"

#include "backend/protobuf/queries/proto_blocks_query.hpp"
#include "backend/protobuf/queries/proto_query.hpp"
#include "builders/protobuf/transport_builder.hpp"
#include "cache/cache.hpp"
#include "logger/logger_fwd.hpp"
#include "main/iroha_status.hpp"
#include "main/subscription.hpp"
#include "torii/processor/query_processor.hpp"

namespace shared_model::interface {
  template <typename Interface, typename Transport>
  class AbstractTransportFactory;
}  // namespace shared_model::interface

namespace iroha::torii {
  /**
   * Actual implementation of async QueryService.
   * ToriiServiceHandler::(SomeMethod)Handler calls a corresponding method in
   * this class.
   */
  class QueryService : public iroha::protocol::QueryService_v1::Service {
   public:
    using QueryFactoryType = shared_model::interface::AbstractTransportFactory<
        shared_model::interface::Query,
        iroha::protocol::Query>;
    using BlocksQueryFactoryType =
        shared_model::interface::AbstractTransportFactory<
            shared_model::interface::BlocksQuery,
            iroha::protocol::BlocksQuery>;

    QueryService(
        std::shared_ptr<iroha::torii::QueryProcessor> query_processor,
        std::shared_ptr<QueryFactoryType> query_factory,
        std::shared_ptr<BlocksQueryFactoryType> blocks_query_factory,
        logger::LoggerPtr log,
        std::shared_ptr<iroha::BaseSubscriber<
            iroha::utils::ReadWriteObject<iroha::IrohaStoredStatus, std::mutex>,
            iroha::IrohaStatus>> iroha_status_subscription);

    QueryService(const QueryService &) = delete;
    QueryService &operator=(const QueryService &) = delete;

    /**
     * actual implementation of async Find in QueryService
     * @param request - Query
     * @param response - QueryResponse
     */
    void Find(iroha::protocol::Query const &request,
              iroha::protocol::QueryResponse &response);

    grpc::Status Find(grpc::ServerContext *context,
                      const iroha::protocol::Query *request,
                      iroha::protocol::QueryResponse *response) override;

    grpc::Status FetchCommits(
        grpc::ServerContext *context,
        const iroha::protocol::BlocksQuery *request,
        grpc::ServerWriter<::iroha::protocol::BlockQueryResponse> *writer)
        override;

    grpc::Status Healthcheck(
        grpc::ServerContext *context,
        const google::protobuf::Empty *request,
        iroha::protocol::HealthcheckData *response) override;

   private:
    std::shared_ptr<iroha::torii::QueryProcessor> query_processor_;
    std::shared_ptr<QueryFactoryType> query_factory_;
    std::shared_ptr<BlocksQueryFactoryType> blocks_query_factory_;

    // TODO 18.02.2019 lebdron: IR-336 Replace cache
    iroha::cache::Cache<shared_model::crypto::Hash,
                        int,
                        shared_model::crypto::Hash::Hasher>
        cache_;

    logger::LoggerPtr log_;
    std::shared_ptr<iroha::BaseSubscriber<
        iroha::utils::ReadWriteObject<iroha::IrohaStoredStatus, std::mutex>,
        iroha::IrohaStatus>>
        iroha_status_subscription_;
  };
}  // namespace iroha::torii

#endif  // TORII_QUERY_SERVICE_HPP
