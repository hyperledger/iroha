/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_OS_TRANSPORT_CLIENT_GRPC_HPP
#define IROHA_ON_DEMAND_OS_TRANSPORT_CLIENT_GRPC_HPP

#include "ordering/on_demand_os_transport.hpp"

#include "common/result.hpp"
#include "interfaces/iroha_internal/abstract_transport_factory.hpp"
#include "logger/logger_fwd.hpp"
#include "network/impl/async_grpc_client.hpp"
#include "ordering.grpc.pb.h"

namespace iroha {
  namespace network {
    template <typename Service>
    class ClientFactory;
  }
  namespace ordering {
    namespace transport {

      /**
       * gRPC client for on demand ordering service
       */
      class OnDemandOsClientGrpc : public OdOsNotification {
       public:
        using TransportFactoryType =
            shared_model::interface::AbstractTransportFactory<
                shared_model::interface::Proposal,
                iroha::protocol::Proposal>;
        using TimepointType = std::chrono::system_clock::time_point;
        using TimeoutType = std::chrono::milliseconds;

        /**
         * Constructor is left public because testing required passing a mock
         * stub interface
         */
        OnDemandOsClientGrpc(
            std::shared_ptr<proto::OnDemandOrdering::StubInterface> stub,
            std::shared_ptr<network::AsyncGrpcClient<google::protobuf::Empty>>
                async_call,
            std::shared_ptr<TransportFactoryType> proposal_factory,
            std::function<TimepointType()> time_provider,
            std::chrono::milliseconds proposal_request_timeout,
            logger::LoggerPtr log);

        void onBatches(CollectionType batches) override;

        // TODO return expected::Result<boost::optional<std::shared_ptr<>>, std::string>
        boost::optional<std::shared_ptr<const ProposalType>> onRequestProposal(
            consensus::Round round) override;

       private:
        logger::LoggerPtr log_;
        std::shared_ptr<proto::OnDemandOrdering::StubInterface> stub_;
        std::shared_ptr<network::AsyncGrpcClient<google::protobuf::Empty>>
            async_call_;
        std::shared_ptr<TransportFactoryType> proposal_factory_;
        std::function<TimepointType()> time_provider_;
        std::chrono::milliseconds proposal_request_timeout_;
      };

      class OnDemandOsClientGrpcFactory : public OdOsNotificationFactory {
       public:
        using Service = proto::OnDemandOrdering;
        using ClientFactory = iroha::network::ClientFactory<Service>;

        using TransportFactoryType = OnDemandOsClientGrpc::TransportFactoryType;
        OnDemandOsClientGrpcFactory(
            std::shared_ptr<network::AsyncGrpcClient<google::protobuf::Empty>>
                async_call,
            std::shared_ptr<TransportFactoryType> proposal_factory,
            std::function<OnDemandOsClientGrpc::TimepointType()> time_provider,
            OnDemandOsClientGrpc::TimeoutType proposal_request_timeout,
            logger::LoggerPtr client_log,
            std::unique_ptr<ClientFactory> client_factory);

        iroha::expected::Result<std::unique_ptr<OdOsNotification>, std::string>
        create(const shared_model::interface::Peer &to) override;

       private:
        std::shared_ptr<network::AsyncGrpcClient<google::protobuf::Empty>>
            async_call_;
        std::shared_ptr<TransportFactoryType> proposal_factory_;
        std::function<OnDemandOsClientGrpc::TimepointType()> time_provider_;
        std::chrono::milliseconds proposal_request_timeout_;
        logger::LoggerPtr client_log_;
        std::unique_ptr<ClientFactory> client_factory_;
      };

    }  // namespace transport
  }    // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_OS_TRANSPORT_CLIENT_GRPC_HPP
