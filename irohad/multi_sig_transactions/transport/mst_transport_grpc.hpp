/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_TRANSPORT_GRPC_HPP
#define IROHA_MST_TRANSPORT_GRPC_HPP

#include "mst.grpc.pb.h"
#include "network/mst_transport.hpp"

#include "interfaces/common_objects/common_objects_factory.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/iroha_internal/abstract_transport_factory.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser.hpp"
#include "logger/logger_fwd.hpp"
#include "multi_sig_transactions/mst_types.hpp"
#include "network/impl/async_grpc_client.hpp"

namespace iroha {

  namespace ametsuchi {
    class TxPresenceCache;
  }

  namespace network {
    class MstTransportGrpc : public MstTransport,
                             public transport::MstTransportGrpc::Service {
     public:
      using SenderFactory = std::function<
          std::unique_ptr<transport::MstTransportGrpc::StubInterface>(
              const shared_model::interface::Peer &)>;
      using TransportFactoryType =
          shared_model::interface::AbstractTransportFactory<
              shared_model::interface::Transaction,
              iroha::protocol::Transaction>;

      MstTransportGrpc(
          std::shared_ptr<network::AsyncGrpcClient<google::protobuf::Empty>>
              async_call,
          std::shared_ptr<TransportFactoryType> transaction_factory,
          std::shared_ptr<shared_model::interface::TransactionBatchParser>
              batch_parser,
          std::shared_ptr<shared_model::interface::TransactionBatchFactory>
              transaction_batch_factory,
          std::shared_ptr<iroha::ametsuchi::TxPresenceCache> tx_presence_cache,
          std::shared_ptr<Completer> mst_completer,
          shared_model::interface::types::PublicKeyHexStringView my_key,
          logger::LoggerPtr mst_state_logger,
          logger::LoggerPtr log,
          boost::optional<SenderFactory> = boost::none);

      /**
       * Server part of grpc SendState method call
       * @param context - server context with information about call
       * @param request - received new MstState object
       * @param response - buffer for response data, not used
       * @return grpc::Status (always OK)
       */
      grpc::Status SendState(
          ::grpc::ServerContext *context,
          const ::iroha::network::transport::MstState *request,
          ::google::protobuf::Empty *response) override;

      void subscribe(
          std::shared_ptr<MstTransportNotification> notification) override;

      rxcpp::observable<bool> sendState(
          std::shared_ptr<shared_model::interface::Peer const> to,
          MstState const &providing_state) override;

     private:
      std::weak_ptr<MstTransportNotification> subscriber_;
      std::shared_ptr<network::AsyncGrpcClient<google::protobuf::Empty>>
          async_call_;
      std::shared_ptr<TransportFactoryType> transaction_factory_;
      std::shared_ptr<shared_model::interface::TransactionBatchParser>
          batch_parser_;
      std::shared_ptr<shared_model::interface::TransactionBatchFactory>
          batch_factory_;
      std::shared_ptr<iroha::ametsuchi::TxPresenceCache> tx_presence_cache_;
      /// source peer key for MST propogation messages
      std::shared_ptr<Completer> mst_completer_;
      std::string const my_key_;

      logger::LoggerPtr mst_state_logger_;  ///< Logger for created MstState
                                            ///< objects.
      logger::LoggerPtr log_;               ///< Logger for local use.

      boost::optional<SenderFactory> sender_factory_;
    };

    void sendStateAsync(
        shared_model::interface::Peer const &to,
        MstState const &state,
        shared_model::interface::types::PublicKeyHexStringView sender_key,
        AsyncGrpcClient<google::protobuf::Empty> &async_call,
        std::function<void(grpc::Status &, google::protobuf::Empty &)>
            on_response = {});

  }  // namespace network
}  // namespace iroha

#endif  // IROHA_MST_TRANSPORT_GRPC_HPP
