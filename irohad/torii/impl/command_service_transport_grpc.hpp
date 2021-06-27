/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TORII_COMMAND_SERVICE_TRANSPORT_GRPC_HPP
#define TORII_COMMAND_SERVICE_TRANSPORT_GRPC_HPP

#include "torii/command_service.hpp"

#include "endpoint.grpc.pb.h"
#include "endpoint.pb.h"
#include "interfaces/common_objects/transaction_sequence_common.hpp"
#include "interfaces/iroha_internal/abstract_transport_factory.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha::torii {
  class StatusBus;
}

namespace shared_model::interface {
  class TxStatusFactory;
  class TransactionBatchParser;
  class TransactionBatchFactory;
}  // namespace shared_model::interface

namespace iroha::torii {
  class CommandServiceTransportGrpc
      : public iroha::protocol::CommandService_v1::Service {
   public:
    using TransportFactoryType =
        shared_model::interface::AbstractTransportFactory<
            shared_model::interface::Transaction,
            iroha::protocol::Transaction>;

    struct ConsensusGateEvent {};

    /**
     * Creates a new instance of CommandServiceTransportGrpc
     * @param command_service - to delegate logic work
     * @param status_bus is a common notifier for tx statuses
     * @param status_factory - factory of statuses
     * @param transaction_factory - factory of transactions
     * @param batch_parser - parses of batches
     * @param transaction_batch_factory - factory of batchesof transactions
     * @param maximum_rounds_without_update - defines how long tx status
     * stream is kept alive when no new tx statuses appear
     * @param log to print progress
     */
    CommandServiceTransportGrpc(
        std::shared_ptr<CommandService> command_service,
        std::shared_ptr<iroha::torii::StatusBus> status_bus,
        std::shared_ptr<shared_model::interface::TxStatusFactory>
            status_factory,
        std::shared_ptr<TransportFactoryType> transaction_factory,
        std::shared_ptr<shared_model::interface::TransactionBatchParser>
            batch_parser,
        std::shared_ptr<shared_model::interface::TransactionBatchFactory>
            transaction_batch_factory,
        int maximum_rounds_without_update,
        logger::LoggerPtr log);

    /**
     * Torii call via grpc
     * @param context - call context (see grpc docs for details)
     * @param request - transaction received
     * @param response - no actual response (grpc stub for empty answer)
     * @return status
     */
    grpc::Status Torii(grpc::ServerContext *context,
                       const iroha::protocol::Transaction *request,
                       google::protobuf::Empty *response) override;

    /**
     * Torii call for transactions list via grpc
     * @param context - call context (see grpc docs for details)
     * @param request - list of transactions received
     * @param response - no actual response (grpc stub for empty answer)
     * @return status
     */
    grpc::Status ListTorii(grpc::ServerContext *context,
                           const iroha::protocol::TxList *request,
                           google::protobuf::Empty *response) override;

    /**
     * Status call via grpc
     * @param context - call context
     * @param request - TxStatusRequest object which identifies transaction
     * uniquely
     * @param response - ToriiResponse which contains a current state of
     * requested transaction
     * @return status
     */
    grpc::Status Status(grpc::ServerContext *context,
                        const iroha::protocol::TxStatusRequest *request,
                        iroha::protocol::ToriiResponse *response) override;

    /**
     * StatusStream call via grpc
     * @param context - call context
     * @param request - TxStatusRequest object which identifies transaction
     * uniquely
     * @param response_writer - grpc::ServerWriter which can repeatedly send
     * transaction statuses back to the client
     * @return status
     */
    grpc::Status StatusStream(grpc::ServerContext *context,
                              const iroha::protocol::TxStatusRequest *request,
                              grpc::ServerWriter<iroha::protocol::ToriiResponse>
                                  *response_writer) override;

   private:
    std::shared_ptr<CommandService> command_service_;
    std::shared_ptr<iroha::torii::StatusBus> status_bus_;
    std::shared_ptr<shared_model::interface::TxStatusFactory> status_factory_;
    std::shared_ptr<TransportFactoryType> transaction_factory_;
    std::shared_ptr<shared_model::interface::TransactionBatchParser>
        batch_parser_;
    std::shared_ptr<shared_model::interface::TransactionBatchFactory>
        batch_factory_;
    logger::LoggerPtr log_;

    const int maximum_rounds_without_update_;
  };
}  // namespace iroha::torii

#endif  // TORII_COMMAND_SERVICE_TRANSPORT_GRPC_HPP
