/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_os_server_grpc.hpp"

#include "backend/protobuf/deserialize_repeated_transactions.hpp"
#include "backend/protobuf/proposal.hpp"
#include "backend/protobuf/transaction.hpp"
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
  log_->info("Received RequestProposal for {} from {}", round, context->peer());
  auto maybe_proposal = ordering_service_->waitForLocalProposal(round, delay_);
  if (maybe_proposal.has_value()) {
    for (auto const &src_proposal : maybe_proposal.value()) {
      auto const &[sptr_proposal, bf_local] = src_proposal;
      auto proposal = response->add_proposal();

#if USE_BLOOM_FILTER
      response->set_bloom_filter(bf_local.load().data(),
                                 bf_local.load().size());
      proposal->set_proposal_hash(sptr_proposal->hash().blob().data(),
                                  sptr_proposal->hash().blob().size());
#endif  // USE_BLOOM_FILTER

      log_->debug("OS proposal: {}\nproposal: {}",
                  sptr_proposal->hash(),
                  *sptr_proposal);

      auto const &proto_proposal =
          static_cast<const shared_model::proto::Proposal *>(
              sptr_proposal.get())
              ->getTransport();
#if USE_BLOOM_FILTER
      if (!request->has_bloom_filter()
          || request->bloom_filter().size() != BloomFilter256::kBytesCount) {
#endif  // USE_BLOOM_FILTER
        log_->debug("Response with full {} txs proposal.",
                    sptr_proposal->transactions().size());
        *proposal = proto_proposal;
#if USE_BLOOM_FILTER
      } else {
        response->mutable_proposal()->set_created_time(
            proto_proposal.created_time());
        response->mutable_proposal()->set_height(proto_proposal.height());

        BloomFilter256 bf_remote;
        bf_remote.store(std::string_view(request->bloom_filter()));

        assert((size_t)proto_proposal.transactions().size()
               == sptr_proposal->transactions().size());
        for (size_t ix = 0; ix < sptr_proposal->transactions().size(); ++ix) {
          assert(sptr_proposal->transactions()[ix].getBatchHash());
          if (!bf_remote.test(sptr_proposal->transactions()[(int)ix]
                                  .getBatchHash()
                                  .value())) {
            auto *tx_dst =
                response->mutable_proposal()->mutable_transactions()->Add();
            *tx_dst = proto_proposal.transactions()[(int)ix];
          }
        }
      }
#endif  // USE_BLOOM_FILTER
    }
  }
  return ::grpc::Status::OK;
}
