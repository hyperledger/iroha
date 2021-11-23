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

  log_->info("Received SendBatches with {} from {}",
             *batches.assumeValue().front(),
             context->peer());

  ordering_service_->onBatches(std::move(batches).assumeValue());

  return ::grpc::Status::OK;
}

grpc::Status OnDemandOsServerGrpc::RequestProposal(
    ::grpc::ServerContext *context,
    const proto::ProposalRequest *request,
    proto::ProposalResponse *response) {
  consensus::Round round{request->round().block_round(),
                         request->round().reject_round()};
  log_->info("Received RequestProposal for {} with hash {} from {}",
             round,
             request->own_proposal_hash(),
             context->peer());
  // Wait for proposal_or_hash created or for number of transactions for
  // proposal_or_hash
  if (not ordering_service_->hasProposal(round)
      and not ordering_service_->hasEnoughBatchesInCache()) {
    auto scheduler = std::make_shared<subscription::SchedulerBase>();
    auto tid = getSubscription()->dispatcher()->bind(scheduler);
    auto batches_subscription = SubscriberCreator<
        bool,
        std::shared_ptr<shared_model::interface::TransactionBatch>>::
        template create<EventTypes::kOnTxsEnoughForProposal>(
            static_cast<iroha::SubscriptionEngineHandlers>(*tid),
            [&scheduler](auto, auto) { scheduler->dispose(); });
    auto proposals_subscription =
        SubscriberCreator<bool, consensus::Round>::template create<
            EventTypes::kOnPackProposal>(
            static_cast<iroha::SubscriptionEngineHandlers>(*tid),
            [round, &scheduler](auto, auto packed_round) {
              if (round == packed_round)
                scheduler->dispose();
            });
    scheduler->addDelayed(delay_, [&scheduler] { scheduler->dispose(); });
    scheduler->process();
    getSubscription()->dispatcher()->unbind(*tid);
  }

  auto [opt_proposal, hash] = ordering_service_->onRequestProposal(round);
  if (opt_proposal) {
    //    assert((*opt_proposal)->transactions().size() > 0);
    //    assert(hash.size() && "empty hash for valid proposal");
    if (hash == shared_model::crypto::Hash(request->own_proposal_hash())) {
      fmt::print("SAME HASH {}", request->own_proposal_hash());
      *response->mutable_same_proposal_hash() = request->own_proposal_hash();
    } else
      *response->mutable_proposal() =
          static_cast<const shared_model::proto::Proposal *>(
              opt_proposal->get())
              ->getTransport();
  }
  log_->debug(
      "Responding for {} {}: our proposal {}",
      round,
      request->own_proposal_hash(),
      response->optional_proposal_case() == response->kProposal
          ? fmt::format("has DIFFERENT hash {}, sending full proposal", hash)
          : response->optional_proposal_case() == response->kSameProposalHash
          ? "has SAME hash, sending only hash"
          : "is EMPTY");
  return ::grpc::Status::OK;
}
