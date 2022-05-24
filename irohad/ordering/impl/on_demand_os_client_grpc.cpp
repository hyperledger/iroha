/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_os_client_grpc.hpp"

#include "backend/protobuf/proposal.hpp"
#include "backend/protobuf/transaction.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "logger/logger.hpp"
#include "main/subscription.hpp"
#include "network/impl/client_factory.hpp"
#include "ordering/impl/os_executor_keepers.hpp"
#include "subscription/thread_handler.hpp"

using iroha::ordering::transport::OnDemandOsClientGrpc;
using iroha::ordering::transport::OnDemandOsClientGrpcFactory;

namespace {
  bool sendBatches(
      std::string peer_name,
      std::weak_ptr<iroha::ordering::ExecutorKeeper> os_execution_keepers,
      iroha::ordering::proto::BatchesRequest request,
      std::function<OnDemandOsClientGrpc::TimepointType()> time_provider,
      std::weak_ptr<iroha::ordering::proto::OnDemandOrdering::StubInterface>
          wstub,
      std::weak_ptr<logger::Logger> wlog) {
    auto maybe_stub = wstub.lock();
    auto maybe_log = wlog.lock();
    if (not(maybe_stub and maybe_log)) {
      if (maybe_log)
        maybe_log->info("No stub. Send batches skipped.");
      return true;
    }

    grpc::ClientContext context;
    context.set_wait_for_ready(false);
    context.set_deadline(time_provider() + std::chrono::seconds(5));
    google::protobuf::Empty response;
    maybe_log->info("Sending batches");
    auto status = maybe_stub->SendBatches(&context, request, &response);
    iroha::getSubscription()->notify(iroha::EventTypes::kSendBatchComplete,
                                     uint64_t(request.transactions().size()));

    if (not status.ok()) {
      maybe_log->warn(
          "RPC failed: {} {}", context.peer(), status.error_message());
      /// TODO(iceseer): uncomment if we need resend. Maybe add repeat counter.
      /*if (auto ek = os_execution_keepers.lock()) {
        ek->executeFor(
            peer_name,
            [peer_name, request(std::move(request)), os_execution_keepers,
                time_provider(time_provider),
                wstub,
                wlog]() mutable {
              sendBatches(std::move(peer_name), os_execution_keepers,
      std::move(request), time_provider, wstub, wlog);
            });
      }*/
      return false;
    }

    maybe_log->info("RPC succeeded(SendBatches): {}", context.peer());
    return true;
  }
}  // namespace

OnDemandOsClientGrpc::OnDemandOsClientGrpc(
    std::shared_ptr<proto::OnDemandOrdering::StubInterface> stub,
    std::shared_ptr<TransportFactoryType> proposal_factory,
    std::function<TimepointType()> time_provider,
    std::chrono::milliseconds proposal_request_timeout,
    logger::LoggerPtr log,
    std::shared_ptr<ExecutorKeeper> os_execution_keepers,
    std::string peer_name)
    : log_(std::move(log)),
      stub_(std::move(stub)),
      proposal_factory_(std::move(proposal_factory)),
      time_provider_(std::move(time_provider)),
      proposal_request_timeout_(proposal_request_timeout),
      os_execution_keepers_(std::move(os_execution_keepers)),
      peer_name_(std::move(peer_name)) {
  assert(os_execution_keepers_);
}

OnDemandOsClientGrpc::~OnDemandOsClientGrpc() {
  if (auto sh_ctx = context_.lock())
    sh_ctx->TryCancel();
}

void OnDemandOsClientGrpc::onBatchesToWholeNetwork(CollectionType batches) {
  // This code should not be called.
  assert(false);
}

void OnDemandOsClientGrpc::onBatches(CollectionType batches) {
  std::shared_ptr<proto::BatchesRequest> request;
  for (auto &batch : batches) {
    if (!request)
      request = std::make_shared<proto::BatchesRequest>();

    for (auto &transaction : batch->transactions()) {
      *(*request).add_transactions() = std::move(
          static_cast<shared_model::proto::Transaction *>(transaction.get())
              ->getTransport());
    }

    if (request->ByteSizeLong() >= 2ull * 1024 * 1024) {
      log_->debug("execute for called");
      os_execution_keepers_->executeFor(
          peer_name_,
          [peer_name(peer_name_),
           request(std::move(*request)),
           wos_execution_keepers(utils::make_weak(os_execution_keepers_)),
           time_provider(time_provider_),
           stub(utils::make_weak(stub_)),
           log(utils::make_weak(log_))]() mutable {
            sendBatches(std::move(peer_name),
                        wos_execution_keepers,
                        std::move(request),
                        time_provider,
                        stub,
                        log);
          });
      request.reset();
    }
  }

  if (request) {
    log_->debug("execute for called");
    os_execution_keepers_->executeFor(
        peer_name_,
        [peer_name(peer_name_),
         request(std::move(*request)),
         wos_execution_keepers(utils::make_weak(os_execution_keepers_)),
         time_provider(time_provider_),
         stub(utils::make_weak(stub_)),
         log(utils::make_weak(log_))]() mutable {
          sendBatches(std::move(peer_name),
                      wos_execution_keepers,
                      std::move(request),
                      time_provider,
                      stub,
                      log);
        });
  }
}

std::chrono::milliseconds OnDemandOsClientGrpc::getRequestDelay() const {
  return proposal_request_timeout_;
}

void OnDemandOsClientGrpc::onRequestProposal(
    consensus::Round round,
    std::optional<
        std::pair<std::shared_ptr<shared_model::interface::Proposal const>,
                  BloomFilter256>> ref_proposal) {
  // Cancel an unfinished request
  if (auto maybe_context = context_.lock()) {
    maybe_context->TryCancel();
  }

  auto context = std::make_shared<grpc::ClientContext>();
  context_ = context;
  proto::ProposalRequest request;
  request.mutable_round()->set_block_round(round.block_round);
  request.mutable_round()->set_reject_round(round.reject_round);

#if USE_BLOOM_FILTER
  if (ref_proposal.has_value())
    request.set_bloom_filter(
        std::string(ref_proposal.value().second.load().data(),
                    ref_proposal.value().second.load().size()));
#endif  // USE_BLOOM_FILTER

  getSubscription()->dispatcher()->add(
      getSubscription()->dispatcher()->kExecuteInPool,
      [round,
       ref_proposal{std::move(ref_proposal)},
       time_provider(time_provider_),
       proposal_request_timeout(proposal_request_timeout_),
       context(std::move(context)),
       request(std::move(request)),
       stub(utils::make_weak(stub_)),
       log(utils::make_weak(log_)),
       proposal_factory(utils::make_weak(proposal_factory_))] {
        auto maybe_stub = stub.lock();
        auto maybe_log = log.lock();
        auto maybe_proposal_factory = proposal_factory.lock();
        if (not(maybe_stub and maybe_log and maybe_proposal_factory)) {
          return;
        }

        /// make request
        context->set_deadline(time_provider() + proposal_request_timeout);
        proto::ProposalResponse response;
        maybe_log->info("Requesting proposal");
        auto status =
            maybe_stub->RequestProposal(context.get(), request, &response);
        if (not status.ok()) {
          maybe_log->warn(
              "RPC failed: {} {}", context->peer(), status.error_message());
          iroha::getSubscription()->notify(
              iroha::EventTypes::kOnProposalResponse,
              ProposalEvent{std::nullopt, round});
          return;
        } else {
          maybe_log->info("RPC succeeded(RequestingProposal): {}",
                          context->peer());
        }

        if (!response.has_proposal_hash()) {
          maybe_log->info("Remote node {} has no proposal.", context->peer());
          iroha::getSubscription()->notify(
              iroha::EventTypes::kOnProposalResponse,
              ProposalEvent{std::nullopt, round});
          return;
        }

        /// parse request
        std::shared_ptr<shared_model::interface::Proposal const>
            remote_proposal;
        if (auto proposal_result =
                maybe_proposal_factory->build(response.proposal());
            expected::hasError(proposal_result)) {
          maybe_log->warn("{}", proposal_result.assumeError().error);
          iroha::getSubscription()->notify(
              iroha::EventTypes::kOnProposalResponse,
              ProposalEvent{std::nullopt, round});
          return;
        } else
          remote_proposal = std::move(proposal_result).assumeValue();

      /// merge if has local proposal or process directly if not
#if USE_BLOOM_FILTER
        if (ref_proposal.has_value()) {
          std::shared_ptr<shared_model::interface::Proposal const>
              local_proposal;
          local_proposal = ref_proposal.value().first;

          iroha::getSubscription()->notify(
              iroha::EventTypes::kRemoteProposalDiff,
              RemoteProposalDownloadedEvent{
                  local_proposal,
                  remote_proposal,
                  response.bloom_filter(),
                  response.proposal_hash(),
                  round,
                  remote_proposal ? remote_proposal->createdTime() : 0ull});
        } else
#endif  // USE_BLOOM_FILTER
            if (!remote_proposal->transactions().empty())
          iroha::getSubscription()->notify(
              iroha::EventTypes::kOnProposalResponse,
              ProposalEvent{std::move(remote_proposal), round});
        else {
          maybe_log->info("Transactions sequence in proposal is empty");
          iroha::getSubscription()->notify(
              iroha::EventTypes::kOnProposalResponse,
              ProposalEvent{std::nullopt, round});
        }
      });
}

OnDemandOsClientGrpcFactory::OnDemandOsClientGrpcFactory(
    std::shared_ptr<TransportFactoryType> proposal_factory,
    std::function<OnDemandOsClientGrpc::TimepointType()> time_provider,
    OnDemandOsClientGrpc::TimeoutType proposal_request_timeout,
    logger::LoggerPtr client_log,
    std::unique_ptr<ClientFactory> client_factory,
    std::shared_ptr<ExecutorKeeper> os_execution_keepers)
    : proposal_factory_(std::move(proposal_factory)),
      time_provider_(time_provider),
      proposal_request_timeout_(proposal_request_timeout),
      client_log_(std::move(client_log)),
      client_factory_(std::move(client_factory)),
      os_execution_keepers_(std::move(os_execution_keepers)) {
  assert(os_execution_keepers_);
}

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
                                                  os_execution_keepers_,
                                                  to.pubkey());
  };
}

std::chrono::milliseconds OnDemandOsClientGrpcFactory::getRequestDelay() const {
  return proposal_request_timeout_;
}
