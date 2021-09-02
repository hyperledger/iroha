/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_os_client_grpc.hpp"

#include "backend/protobuf/proposal.hpp"
#include "backend/protobuf/transaction.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "logger/logger.hpp"
#include "main/subscription.hpp"
#include "network/impl/client_factory.hpp"

using iroha::ordering::transport::OnDemandOsClientGrpc;
using iroha::ordering::transport::OnDemandOsClientGrpcFactory;

OnDemandOsClientGrpc::OnDemandOsClientGrpc(
    std::shared_ptr<proto::OnDemandOrdering::StubInterface> stub,
    std::shared_ptr<TransportFactoryType> proposal_factory,
    std::function<TimepointType()> time_provider,
    std::chrono::milliseconds proposal_request_timeout,
    logger::LoggerPtr log,
    std::function<void(ProposalEvent)> callback)
    : log_(std::move(log)),
      stub_(std::move(stub)),
      proposal_factory_(std::move(proposal_factory)),
      time_provider_(std::move(time_provider)),
      proposal_request_timeout_(proposal_request_timeout),
      callback_(std::move(callback)) {}

void OnDemandOsClientGrpc::onBatches(CollectionType batches) {
  proto::BatchesRequest request;
  for (auto &batch : batches) {
    for (auto &transaction : batch->transactions()) {
      *request.add_transactions() = std::move(
          static_cast<shared_model::proto::Transaction *>(transaction.get())
              ->getTransport());
    }
  }

  getSubscription()->dispatcher()->add(
      getSubscription()->dispatcher()->kExecuteInPool,
      [time_provider(time_provider_),
       request(std::move(request)),
       stub(utils::make_weak(stub_)),
       log(utils::make_weak(log_))] {
        auto maybe_stub = stub.lock();
        auto maybe_log = log.lock();
        if (not(maybe_stub and maybe_log)) {
          return;
        }
        grpc::ClientContext context;
        context.set_wait_for_ready(true);
        context.set_deadline(time_provider() + std::chrono::seconds(5));
        google::protobuf::Empty response;
        maybe_log->info("Sending batches");
        auto status = maybe_stub->SendBatches(&context, request, &response);
        if (not status.ok()) {
          maybe_log->warn(
              "RPC failed: {} {}", context.peer(), status.error_message());
        } else {
          maybe_log->info("RPC succeeded: {}", context.peer());
        }
      });
}

void OnDemandOsClientGrpc::onRequestProposal(consensus::Round round) {
  // Cancel an unfinished request
  if (auto maybe_context = context_.lock()) {
    maybe_context->TryCancel();
  }

  auto context = std::make_shared<grpc::ClientContext>();
  context_ = context;
  proto::ProposalRequest request;
  request.mutable_round()->set_block_round(round.block_round);
  request.mutable_round()->set_reject_round(round.reject_round);
  getSubscription()->dispatcher()->add(
      getSubscription()->dispatcher()->kExecuteInPool,
      [round,
       time_provider(time_provider_),
       proposal_request_timeout(proposal_request_timeout_),
       context(std::move(context)),
       request(std::move(request)),
       stub(utils::make_weak(stub_)),
       log(utils::make_weak(log_)),
       proposal_factory(utils::make_weak(proposal_factory_)),
       callback(callback_)] {
        auto maybe_stub = stub.lock();
        auto maybe_log = log.lock();
        auto maybe_proposal_factory = proposal_factory.lock();
        if (not(maybe_stub and maybe_log and maybe_proposal_factory)) {
          return;
        }
        context->set_deadline(time_provider() + proposal_request_timeout);
        proto::ProposalResponse response;
        maybe_log->info("Requesting proposal");
        auto status =
            maybe_stub->RequestProposal(context.get(), request, &response);
        if (not status.ok()) {
          maybe_log->warn(
              "RPC failed: {} {}", context->peer(), status.error_message());
          callback({std::nullopt, round});
          return;
        } else {
          maybe_log->info("RPC succeeded: {}", context->peer());
        }
        if (not response.has_proposal()) {
          callback({std::nullopt, round});
          return;
        }
        auto maybe_proposal =
            maybe_proposal_factory->build(response.proposal());
        if (expected::hasError(maybe_proposal)) {
          maybe_log->info("{}", maybe_proposal.assumeError().error);
          callback({std::nullopt, round});
        }
        callback({std::move(maybe_proposal).assumeValue(), round});
      });
}

OnDemandOsClientGrpcFactory::OnDemandOsClientGrpcFactory(
    std::shared_ptr<TransportFactoryType> proposal_factory,
    std::function<OnDemandOsClientGrpc::TimepointType()> time_provider,
    OnDemandOsClientGrpc::TimeoutType proposal_request_timeout,
    logger::LoggerPtr client_log,
    std::unique_ptr<ClientFactory> client_factory,
    std::function<void(ProposalEvent)> callback)
    : proposal_factory_(std::move(proposal_factory)),
      time_provider_(time_provider),
      proposal_request_timeout_(proposal_request_timeout),
      client_log_(std::move(client_log)),
      client_factory_(std::move(client_factory)),
      callback_(callback) {}

iroha::expected::Result<
    std::unique_ptr<iroha::ordering::transport::OdOsNotification>,
    std::string>
OnDemandOsClientGrpcFactory::create(const shared_model::interface::Peer &to) {
  return client_factory_->createClient(to) |
             [&](auto &&client) -> std::unique_ptr<OdOsNotification> {
    return std::make_unique<OnDemandOsClientGrpc>(std::move(client),
                                                  proposal_factory_,
                                                  time_provider_,
                                                  proposal_request_timeout_,
                                                  client_log_,
                                                  callback_);
  };
}
