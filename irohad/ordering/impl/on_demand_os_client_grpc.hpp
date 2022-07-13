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
#include "main/subscription.hpp"
#include "ordering.grpc.pb.h"
#include "ordering/impl/on_demand_common.hpp"
#include "subscription/dispatcher.hpp"

namespace iroha {
  namespace network {
    template <typename Service>
    class ClientFactory;
  }
  namespace ordering {
    class ExecutorKeeper;

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
        using DynamicEventType = uint64_t;

        /**
         * Constructor is left public because testing required passing a mock
         * stub interface
         */
        OnDemandOsClientGrpc(
            std::shared_ptr<proto::OnDemandOrdering::StubInterface> stub,
            std::shared_ptr<TransportFactoryType> proposal_factory,
            std::function<TimepointType()> time_provider,
            std::chrono::milliseconds proposal_request_timeout,
            logger::LoggerPtr log,
            std::shared_ptr<ExecutorKeeper> os_execution_keepers,
            std::string peer_name);

        ~OnDemandOsClientGrpc() override;

        void onBatches(CollectionType batches) override;
        void onBatchesToWholeNetwork(CollectionType batches) override;

        void onRequestProposal(consensus::Round round,
                               PackedProposalData ref_proposal) override;

        std::chrono::milliseconds getRequestDelay() const override;

       private:
        logger::LoggerPtr log_;
        std::shared_ptr<proto::OnDemandOrdering::StubInterface> stub_;
        std::shared_ptr<TransportFactoryType> proposal_factory_;
        std::function<TimepointType()> time_provider_;
        std::chrono::milliseconds proposal_request_timeout_;
        std::weak_ptr<grpc::ClientContext> context_;
        std::shared_ptr<ExecutorKeeper> os_execution_keepers_;
        std::string peer_name_;
      };

      class OnDemandOsClientGrpcFactory : public OdOsNotificationFactory {
       public:
        using Service = proto::OnDemandOrdering;
        using ClientFactory = iroha::network::ClientFactory<Service>;

        using TransportFactoryType = OnDemandOsClientGrpc::TransportFactoryType;
        OnDemandOsClientGrpcFactory(
            std::shared_ptr<TransportFactoryType> proposal_factory,
            std::function<OnDemandOsClientGrpc::TimepointType()> time_provider,
            OnDemandOsClientGrpc::TimeoutType proposal_request_timeout,
            logger::LoggerPtr client_log,
            std::unique_ptr<ClientFactory> client_factory,
            std::shared_ptr<ExecutorKeeper> os_execution_keepers);

        iroha::expected::Result<std::unique_ptr<OdOsNotification>, std::string>
        create(const shared_model::interface::Peer &to) override;

        std::chrono::milliseconds getRequestDelay() const override;

       private:
        std::shared_ptr<TransportFactoryType> proposal_factory_;
        std::function<OnDemandOsClientGrpc::TimepointType()> time_provider_;
        std::chrono::milliseconds proposal_request_timeout_;
        logger::LoggerPtr client_log_;
        std::unique_ptr<ClientFactory> client_factory_;
        std::shared_ptr<ExecutorKeeper> os_execution_keepers_;
      };

    }  // namespace transport
  }    // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_OS_TRANSPORT_CLIENT_GRPC_HPP
