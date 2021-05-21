/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_os_server_grpc.hpp"

#include "backend/protobuf/deserialize_repeated_transactions.hpp"
#include "backend/protobuf/proposal.hpp"
#include "interfaces/iroha_internal/parse_and_create_batches.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "logger/logger.hpp"
#include "main/subscription.hpp"
#include "ordering/on_demand_ordering_service.hpp"
#include "subscription/scheduler_impl.hpp"

using namespace iroha::ordering;
using namespace iroha::ordering::transport;

OnDemandOsServerGrpc::OnDemandOsServerGrpc(
    std::shared_ptr<OnDemandOrderingService> ordering_service,
    std::shared_ptr<TransportFactoryType> transaction_factory,
    std::shared_ptr<shared_model::interface::TransactionBatchParser>
        batch_parser,
    std::shared_ptr<shared_model::interface::TransactionBatchFactory>
        transaction_batch_factory,
    logger::LoggerPtr log,
    std::chrono::milliseconds delay)
    : ordering_service_(ordering_service),
      transaction_factory_(std::move(transaction_factory)),
      batch_parser_(std::move(batch_parser)),
      batch_factory_(std::move(transaction_batch_factory)),
      log_(std::move(log)),
      delay_(delay) {}

grpc::Status OnDemandOsServerGrpc::SendBatches(
    ::grpc::ServerContext *context,
    const proto::BatchesRequest *request,
    ::google::protobuf::Empty *response) {
  auto transactions = shared_model::proto::deserializeTransactions(
      *transaction_factory_, request->transactions());
  if (auto e = expected::resultToOptionalError(transactions)) {
    log_->warn(
        "Transaction deserialization failed: hash {}, {}", e->hash, e->error);
    return ::grpc::Status::OK;
  }

  auto batches = shared_model::interface::parseAndCreateBatches(
      *batch_parser_, *batch_factory_, std::move(transactions).assumeValue());
  if (auto e = expected::resultToOptionalError(batches)) {
    log_->warn("Batch deserialization failed: {}", *e);
    return ::grpc::Status::OK;
  }

  ordering_service_->onBatches(std::move(batches).assumeValue());

  return ::grpc::Status::OK;
}

grpc::Status OnDemandOsServerGrpc::RequestProposal(
    ::grpc::ServerContext *context,
    const proto::ProposalRequest *request,
    proto::ProposalResponse *response) {
  consensus::Round round{request->round().block_round(),
                         request->round().reject_round()};
  log_->info("Received RequestProposal for {} from {}", round, context->peer());
  if (not ordering_service_->hasProposal(round)
      and ordering_service_->isEmptyBatchesCache()) {
    auto scheduler = std::make_shared<subscription::SchedulerBase>();
    auto tid = getSubscription()->dispatcher()->bind(scheduler);

    auto batches_subscription = SubscriberCreator<
        bool,
        std::shared_ptr<shared_model::interface::TransactionBatch>>::
        template create<EventTypes::kOnNewBatchInCache>(
            static_cast<iroha::SubscriptionEngineHandlers>(*tid),
            [scheduler(utils::make_weak(scheduler))](auto, auto) {
              if (auto maybe_scheduler = scheduler.lock()) {
                maybe_scheduler->dispose();
              }
            });
    scheduler->addDelayed(delay_, [scheduler(utils::make_weak(scheduler))] {
      if (auto maybe_scheduler = scheduler.lock()) {
        maybe_scheduler->dispose();
      }
    });

    scheduler->process();

    getSubscription()->dispatcher()->unbind(*tid);
  }

  if (auto maybe_proposal = ordering_service_->onRequestProposal(round)) {
    *response->mutable_proposal() =
        static_cast<const shared_model::proto::Proposal *>(
            maybe_proposal->get())
            ->getTransport();
  }
  return ::grpc::Status::OK;
}
