/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/impl/command_service_transport_grpc.hpp"

#include "backend/protobuf/deserialize_repeated_transactions.hpp"
#include "backend/protobuf/transaction_responses/proto_tx_response.hpp"
#include "backend/protobuf/util.hpp"
#include "cryptography/hash_providers/sha3_256.hpp"
#include "interfaces/iroha_internal/parse_and_create_batches.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser.hpp"
#include "interfaces/iroha_internal/tx_status_factory.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger.hpp"
#include "main/subscription.hpp"
#include "subscription/scheduler_impl.hpp"
#include "torii/impl/final_status_value.hpp"
#include "torii/status_bus.hpp"

using iroha::torii::CommandServiceTransportGrpc;

CommandServiceTransportGrpc::CommandServiceTransportGrpc(
    std::shared_ptr<CommandService> command_service,
    std::shared_ptr<iroha::torii::StatusBus> status_bus,
    std::shared_ptr<shared_model::interface::TxStatusFactory> status_factory,
    std::shared_ptr<TransportFactoryType> transaction_factory,
    std::shared_ptr<shared_model::interface::TransactionBatchParser>
        batch_parser,
    std::shared_ptr<shared_model::interface::TransactionBatchFactory>
        transaction_batch_factory,
    int maximum_rounds_without_update,
    logger::LoggerPtr log)
    : command_service_(std::move(command_service)),
      status_bus_(std::move(status_bus)),
      status_factory_(std::move(status_factory)),
      transaction_factory_(std::move(transaction_factory)),
      batch_parser_(std::move(batch_parser)),
      batch_factory_(std::move(transaction_batch_factory)),
      log_(std::move(log)),
      maximum_rounds_without_update_(maximum_rounds_without_update) {}

grpc::Status CommandServiceTransportGrpc::Torii(
    grpc::ServerContext *context,
    const iroha::protocol::Transaction *request,
    google::protobuf::Empty *response) {
  iroha::protocol::TxList single_tx_list;
  *single_tx_list.add_transactions() = *request;
  return ListTorii(context, &single_tx_list, response);
}

grpc::Status CommandServiceTransportGrpc::ListTorii(
    grpc::ServerContext *context,
    const iroha::protocol::TxList *request,
    google::protobuf::Empty *response) {
  auto publish_stateless_fail = [&](auto &&message) {
    using HashProvider = shared_model::crypto::Sha3_256;

    log_->warn("{}", message);
    for (const auto &tx : request->transactions()) {
      status_bus_->publish(status_factory_->makeStatelessFail(
          HashProvider::makeHash(shared_model::proto::makeBlob(tx.payload())),
          shared_model::interface::TxStatusFactory::TransactionError{
              message, 0, 0}));
    }
    return grpc::Status::OK;
  };

  auto transactions = shared_model::proto::deserializeTransactions(
      *transaction_factory_, request->transactions());
  if (auto e = expected::resultToOptionalError(transactions)) {
    return publish_stateless_fail(fmt::format(
        "Transaction deserialization failed: hash {}, {}", e->hash, e->error));
  }

  auto batches = shared_model::interface::parseAndCreateBatches(
      *batch_parser_, *batch_factory_, std::move(transactions).assumeValue());
  if (auto e = expected::resultToOptionalError(batches)) {
    return publish_stateless_fail(
        fmt::format("Batch deserialization failed: {}", *e));
  }

  for (auto &batch : std::move(batches).assumeValue()) {
    this->command_service_->handleTransactionBatch(std::move(batch));
  }

  return grpc::Status::OK;
}

grpc::Status CommandServiceTransportGrpc::Status(
    grpc::ServerContext *context,
    const iroha::protocol::TxStatusRequest *request,
    iroha::protocol::ToriiResponse *response) {
  *response =
      std::static_pointer_cast<shared_model::proto::TransactionResponse>(
          command_service_->getStatus(
              shared_model::crypto::Hash::fromHexString(request->tx_hash())))
          ->getTransport();
  return grpc::Status::OK;
}

grpc::Status CommandServiceTransportGrpc::StatusStream(
    grpc::ServerContext *context,
    const iroha::protocol::TxStatusRequest *request,
    grpc::ServerWriter<iroha::protocol::ToriiResponse> *response_writer) {
  auto is_final_status = [](auto response) {
    return iroha::visit_in_place(
        response->get(),
        [&](const auto &resp)
            -> std::enable_if_t<FinalStatusValue<decltype(resp)>, bool> {
          return true;
        },
        [](const auto &resp)
            -> std::enable_if_t<not FinalStatusValue<decltype(resp)>, bool> {
          return false;
        });
  };

  auto hash = shared_model::crypto::Hash::fromHexString(request->tx_hash());

  std::string client_id =
      fmt::format("Peer: '{}', {}", context->peer(), hash.toString());

  auto initial_response =
      std::static_pointer_cast<shared_model::proto::TransactionResponse>(
          command_service_->getStatus(hash));
  if (not response_writer->Write(initial_response->getTransport())) {
    log_->error("write to stream has failed to client {}", client_id);
    return grpc::Status::OK;
  }

  iroha::protocol::TxStatus last_tx_status =
      initial_response->getTransport().tx_status();
  auto rounds_counter{0};

  auto scheduler = std::make_shared<iroha::subscription::SchedulerBase>();
  auto tid = iroha::getSubscription()->dispatcher()->bind(scheduler);

  // complete the observable if client is disconnected or too many
  // rounds have passed without tx status change

  auto responses_subscription = SubscriberCreator<
      bool,
      std::shared_ptr<shared_model::interface::TransactionResponse>>::
      template create<EventTypes::kOnTransactionResponse>(
          static_cast<iroha::SubscriptionEngineHandlers>(*tid),
          [&](auto, auto response) {
            if (response->transactionHash() != hash) {
              return;
            }

            const auto &proto_response =
                std::static_pointer_cast<
                    shared_model::proto::TransactionResponse>(response)
                    ->getTransport();

            if (context->IsCancelled()) {
              log_->debug("client unsubscribed, {}", client_id);
              scheduler->dispose();
              return;
            }

            // increment round counter when the same status arrived
            // again.
            auto status = proto_response.tx_status();
            auto status_is_same = status == last_tx_status;
            if (status_is_same) {
              ++rounds_counter;
              if (rounds_counter >= maximum_rounds_without_update_) {
                // we stop the stream when round counter is greater than
                // allowed.
                scheduler->dispose();
                return;
              }
              // omit the received status, but do not stop the stream
              return;
            }
            rounds_counter = 0;
            last_tx_status = status;

            // write a new status to the stream
            if (not response_writer->Write(proto_response)) {
              log_->error("write to stream has failed to client {}", client_id);
              scheduler->dispose();
              return;
            }
            log_->debug("status written, {}", client_id);

            if (is_final_status(response)) {
              scheduler->dispose();
            }
          });

  auto sync_events_subscription =
      SubscriberCreator<bool, ConsensusGateEvent>::template create<
          EventTypes::kOnConsensusGateEvent>(
          static_cast<iroha::SubscriptionEngineHandlers>(*tid),
          [&, last_compared_status = last_tx_status](auto, auto) mutable {
            auto status_is_same = last_compared_status == last_tx_status;
            last_compared_status = last_tx_status;
            if (status_is_same) {
              ++rounds_counter;
              if (rounds_counter >= maximum_rounds_without_update_) {
                // we stop the stream when round counter is greater than
                // allowed.
                scheduler->dispose();
                return;
              }
            }
          });

  if (not is_final_status(initial_response)) {
    scheduler->process();
  }

  getSubscription()->dispatcher()->unbind(*tid);

  log_->debug("stream done, {}", client_id);
  log_->debug("status stream done, {}", client_id);

  return grpc::Status::OK;
}
