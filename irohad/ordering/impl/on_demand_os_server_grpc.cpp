/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common/default_constructible_unary_fn.hpp"  // non-copyable value workaround

#include "ordering/impl/on_demand_os_server_grpc.hpp"

#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include "backend/protobuf/proposal.hpp"
#include "common/bind.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "logger/logger.hpp"

using namespace iroha::ordering;
using namespace iroha::ordering::transport;

OnDemandOsServerGrpc::OnDemandOsServerGrpc(
    std::shared_ptr<OdOsNotification> ordering_service,
    std::shared_ptr<TransportFactoryType> transaction_factory,
    std::shared_ptr<shared_model::interface::TransactionBatchParser>
        batch_parser,
    std::shared_ptr<shared_model::interface::TransactionBatchFactory>
        transaction_batch_factory,
    logger::LoggerPtr log)
    : ordering_service_(ordering_service),
      transaction_factory_(std::move(transaction_factory)),
      batch_parser_(std::move(batch_parser)),
      batch_factory_(std::move(transaction_batch_factory)),
      log_(std::move(log)) {}

shared_model::interface::types::SharedTxsCollectionType
OnDemandOsServerGrpc::deserializeTransactions(
    const proto::BatchesRequest *request) {
  return boost::copy_range<
      shared_model::interface::types::SharedTxsCollectionType>(
      request->transactions()
      | boost::adaptors::transformed(
            [&](const auto &tx) { return transaction_factory_->build(tx); })
      | boost::adaptors::filtered([&](const auto &result) {
          return result.match(
              [](const auto &) { return true; },
              [&](const auto &error) {
                log_->info("Transaction deserialization failed: hash {}, {}",
                           error.error.hash,
                           error.error.error);
                return false;
              });
        })
      | boost::adaptors::transformed([](auto result) {
          return std::move(
                     boost::get<iroha::expected::ValueOf<decltype(result)>>(
                         result))
              .value;
        }));
}

grpc::Status OnDemandOsServerGrpc::SendBatches(
    ::grpc::ServerContext *context,
    const proto::BatchesRequest *request,
    ::google::protobuf::Empty *response) {
  auto transactions = deserializeTransactions(request);

  auto batch_candidates = batch_parser_->parseBatches(std::move(transactions));

  auto batches = std::accumulate(
      std::begin(batch_candidates),
      std::end(batch_candidates),
      OdOsNotification::CollectionType{},
      [this](auto &acc, const auto &cand) {
        batch_factory_->createTransactionBatch(cand).match(
            [&](auto &&value) { acc.push_back(std::move(value).value); },
            [&](const auto &error) {
              log_->warn("Batch deserialization failed: {}", error.error);
            });
        return acc;
      });

  ordering_service_->onBatches(std::move(batches));

  return ::grpc::Status::OK;
}

grpc::Status OnDemandOsServerGrpc::RequestProposal(
    ::grpc::ServerContext *context,
    const proto::ProposalRequest *request,
    proto::ProposalResponse *response) {
  ordering_service_->onRequestProposal(
      {request->round().block_round(), request->round().reject_round()})
      | [&](auto &&proposal) {
          *response->mutable_proposal() =
              static_cast<const shared_model::proto::Proposal *>(proposal.get())
                  ->getTransport();
        };
  return ::grpc::Status::OK;
}
