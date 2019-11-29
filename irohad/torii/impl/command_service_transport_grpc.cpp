/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common/default_constructible_unary_fn.hpp"  // non-copyable value workaround

#include "torii/impl/command_service_transport_grpc.hpp"

#include <atomic>
#include <condition_variable>
#include <iterator>

#include <boost/algorithm/string/join.hpp>
#include <boost/format.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <rxcpp/operators/rx-start_with.hpp>
#include <rxcpp/operators/rx-take_while.hpp>
#include "backend/protobuf/deserialize_repeated_transactions.hpp"
#include "backend/protobuf/transaction_responses/proto_tx_response.hpp"
#include "backend/protobuf/util.hpp"
#include "common/combine_latest_until_first_completed.hpp"
#include "common/run_loop_handler.hpp"
#include "cryptography/hash_providers/sha3_256.hpp"
#include "interfaces/iroha_internal/parse_and_create_batches.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser.hpp"
#include "interfaces/iroha_internal/tx_status_factory.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger.hpp"
#include "torii/status_bus.hpp"

namespace iroha {
  namespace torii {

    CommandServiceTransportGrpc::CommandServiceTransportGrpc(
        std::shared_ptr<CommandService> command_service,
        std::shared_ptr<iroha::torii::StatusBus> status_bus,
        std::shared_ptr<shared_model::interface::TxStatusFactory>
            status_factory,
        std::shared_ptr<TransportFactoryType> transaction_factory,
        std::shared_ptr<shared_model::interface::TransactionBatchParser>
            batch_parser,
        std::shared_ptr<shared_model::interface::TransactionBatchFactory>
            transaction_batch_factory,
        rxcpp::observable<ConsensusGateEvent> consensus_gate_objects,
        int maximum_rounds_without_update,
        logger::LoggerPtr log)
        : command_service_(std::move(command_service)),
          status_bus_(std::move(status_bus)),
          status_factory_(std::move(status_factory)),
          transaction_factory_(std::move(transaction_factory)),
          batch_parser_(std::move(batch_parser)),
          batch_factory_(std::move(transaction_batch_factory)),
          log_(std::move(log)),
          consensus_gate_objects_(std::move(consensus_gate_objects)),
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
              HashProvider::makeHash(
                  shared_model::proto::makeBlob(tx.payload())),
              shared_model::interface::TxStatusFactory::TransactionError{
                  message, 0, 0}));
        }
        return grpc::Status::OK;
      };

      auto transactions = shared_model::proto::deserializeTransactions(
          *transaction_factory_, request->transactions());
      if (auto e = expected::resultToOptionalError(transactions)) {
        return publish_stateless_fail(
            fmt::format("Transaction deserialization failed: hash {}, {}",
                        e->hash,
                        e->error));
      }

      auto batches = shared_model::interface::parseAndCreateBatches(
          *batch_parser_,
          *batch_factory_,
          expected::resultToValue(std::move(transactions)));
      if (auto e = expected::resultToOptionalError(batches)) {
        return publish_stateless_fail(
            fmt::format("Batch deserialization failed: {}", *e));
      }

      for (auto &batch : expected::resultToValue(std::move(batches))) {
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
                  shared_model::crypto::Hash::fromHexString(
                      request->tx_hash())))
              ->getTransport();
      return grpc::Status::OK;
    }

    grpc::Status CommandServiceTransportGrpc::StatusStream(
        grpc::ServerContext *context,
        const iroha::protocol::TxStatusRequest *request,
        grpc::ServerWriter<iroha::protocol::ToriiResponse> *response_writer) {
      rxcpp::schedulers::run_loop rl;

      auto current_thread = rxcpp::synchronize_in_one_worker(
          rxcpp::schedulers::make_run_loop(rl));

      rxcpp::composite_subscription subscription;

      auto hash = shared_model::crypto::Hash::fromHexString(request->tx_hash());

      auto client_id_format = boost::format("Peer: '%s', %s");
      std::string client_id =
          (client_id_format % context->peer() % hash.toString()).str();
      auto status_bus = command_service_->getStatusStream(hash);
      auto consensus_gate_observable =
          consensus_gate_objects_
              // a dummy start_with lets us don't wait for the consensus event
              // on further combine_latest
              .start_with(ConsensusGateEvent{});

      boost::optional<iroha::protocol::TxStatus> last_tx_status;
      auto rounds_counter{0};
      makeCombineLatestUntilFirstCompleted(
          status_bus,
          current_thread,
          [](auto status, auto) { return status; },
          consensus_gate_observable)
          // complete the observable if client is disconnected or too many
          // rounds have passed without tx status change
          .take_while([=, &rounds_counter, &last_tx_status](
                          const auto &response) {
            const auto &proto_response =
                std::static_pointer_cast<
                    shared_model::proto::TransactionResponse>(response)
                    ->getTransport();

            if (context->IsCancelled()) {
              log_->debug("client unsubscribed, {}", client_id);
              return false;
            }

            // increment round counter when the same status arrived again.
            auto status = proto_response.tx_status();
            auto status_is_same =
                last_tx_status and (status == *last_tx_status);
            if (status_is_same) {
              ++rounds_counter;
              if (rounds_counter >= maximum_rounds_without_update_) {
                // we stop the stream when round counter is greater than
                // allowed.
                return false;
              }
              // omit the received status, but do not stop the stream
              return true;
            }
            rounds_counter = 0;
            last_tx_status = status;

            // write a new status to the stream
            if (not response_writer->Write(proto_response)) {
              log_->error("write to stream has failed to client {}", client_id);
              return false;
            }
            log_->debug("status written, {}", client_id);
            return true;
          })
          .subscribe(subscription,
                     [](const auto &) {},
                     [&](std::exception_ptr ep) {
                       log_->error("something bad happened, client_id {}",
                                   client_id);
                     },
                     [&] { log_->debug("stream done, {}", client_id); });

      // run loop while subscription is active or there are pending events in
      // the queue
      iroha::schedulers::handleEvents(subscription, rl);

      log_->debug("status stream done, {}", client_id);
      return grpc::Status::OK;
    }
  }  // namespace torii
}  // namespace iroha
