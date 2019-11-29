/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common/default_constructible_unary_fn.hpp"  // non-copyable value workaround

#include "ordering/impl/on_demand_os_server_grpc.hpp"

#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include "backend/protobuf/deserialize_repeated_transactions.hpp"
#include "backend/protobuf/proposal.hpp"
#include "common/bind.hpp"
#include "interfaces/iroha_internal/parse_and_create_batches.hpp"
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
      *batch_parser_,
      *batch_factory_,
      expected::resultToValue(std::move(transactions)));
  if (auto e = expected::resultToOptionalError(batches)) {
    log_->warn("Batch deserialization failed: {}", *e);
    return ::grpc::Status::OK;
  }

  ordering_service_->onBatches(expected::resultToValue(std::move(batches)));

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
