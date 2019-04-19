/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_OS_TRANSPORT_SERVER_GRPC_HPP
#define IROHA_ON_DEMAND_OS_TRANSPORT_SERVER_GRPC_HPP

#include "ordering/on_demand_os_transport.hpp"

#include <boost/optional.hpp>
#include "interfaces/iroha_internal/abstract_transport_factory.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser.hpp"
#include "logger/logger_fwd.hpp"
#include "ordering.grpc.pb.h"
#include "ordering/ordering_service_proposal_creation_strategy.hpp"
#include "validators/field_validator.hpp"

namespace iroha {
  namespace ordering {
    namespace transport {

      /**
       * gRPC server for on demand ordering service
       */
      class OnDemandOsServerGrpc : public proto::OnDemandOrdering::Service {
       public:
        using TransportFactoryType =
            shared_model::interface::AbstractTransportFactory<
                shared_model::interface::Transaction,
                iroha::protocol::Transaction>;

        OnDemandOsServerGrpc(
            std::shared_ptr<OdOsNotification> ordering_service,
            std::shared_ptr<TransportFactoryType> transaction_factory,
            std::shared_ptr<shared_model::interface::TransactionBatchParser>
                batch_parser,
            std::shared_ptr<shared_model::interface::TransactionBatchFactory>
                transaction_batch_factory,
            std::shared_ptr<shared_model::validation::FieldValidator>
                field_validator,
            std::shared_ptr<ProposalCreationStrategy>
                proposal_creation_strategy,
            logger::LoggerPtr log);

        grpc::Status SendBatches(::grpc::ServerContext *context,
                                 const proto::BatchesRequest *request,
                                 ::google::protobuf::Empty *response) override;

        grpc::Status RequestProposal(
            ::grpc::ServerContext *context,
            const proto::ProposalRequest *request,
            proto::ProposalResponse *response) override;

       private:
        boost::optional<shared_model::crypto::PublicKey> fetchPeer(
            const std::string &pub_key) const;

        /**
         * Flat map transport transactions to shared model
         */
        shared_model::interface::types::SharedTxsCollectionType
        deserializeTransactions(const proto::BatchesRequest *request);

        std::shared_ptr<OdOsNotification> ordering_service_;

        std::shared_ptr<TransportFactoryType> transaction_factory_;
        std::shared_ptr<shared_model::interface::TransactionBatchParser>
            batch_parser_;
        std::shared_ptr<shared_model::interface::TransactionBatchFactory>
            batch_factory_;
        std::shared_ptr<shared_model::validation::FieldValidator>
            field_validator_;
        std::shared_ptr<ProposalCreationStrategy> proposal_creation_strategy_;

        logger::LoggerPtr log_;
      };

    }  // namespace transport
  }    // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_OS_TRANSPORT_SERVER_GRPC_HPP
