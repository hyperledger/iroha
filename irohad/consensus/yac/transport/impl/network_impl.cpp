/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/transport/impl/network_impl.hpp"

#include <grpc++/grpc++.h>
#include <memory>

#include <fmt/core.h>
#include "consensus/yac/storage/yac_common.hpp"
#include "consensus/yac/transport/yac_pb_converters.hpp"
#include "consensus/yac/vote_message.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "logger/logger.hpp"
#include "main/subscription.hpp"
#include "network/impl/client_factory.hpp"
#include "yac.pb.h"

using iroha::consensus::yac::NetworkImpl;

// ----------| Public API |----------
NetworkImpl::NetworkImpl(std::unique_ptr<ClientFactory> client_factory,
                         logger::LoggerPtr log)
    : client_factory_(std::move(client_factory)), log_(std::move(log)) {}

void NetworkImpl::stop() {
  std::lock_guard<std::mutex> stop_lock(stop_mutex_);
  stop_requested_ = true;
}

void NetworkImpl::sendState(const shared_model::interface::Peer &to,
                            const std::vector<VoteMessage> &state) {
  std::lock_guard<std::mutex> stop_lock(stop_mutex_);
  if (stop_requested_) {
    log_->warn("Not sending state to {} because stop was requested.", to);
    return;
  }

  proto::State request;
  for (const auto &vote : state) {
    auto pb_vote = request.add_votes();
    *pb_vote = PbConverters::serializeVote(vote);
  }

  auto maybe_client = client_factory_->createClient(to);
  if (expected::hasError(maybe_client)) {
    log_->error(
        "Could not send state to {}: {}", to, maybe_client.assumeError());
    return;
  }
  std::shared_ptr<decltype(maybe_client)::ValueInnerType::element_type> client =
      std::move(maybe_client).assumeValue();

  log_->debug("Propagating votes for {}, size={} to {}",
              state.front().hash.vote_round,
              state.size(),
              to);
  getSubscription()->dispatcher()->add(
      getSubscription()->dispatcher()->kExecuteInPool,
      [request(std::move(request)),
       client(std::move(client)),
       log(utils::make_weak(log_)),
       log_sending_msg(fmt::format("Send votes bundle[size={}] for {} to {}",
                                   state.size(),
                                   state.front().hash.vote_round,
                                   to))] {
        auto maybe_log = log.lock();
        if (not maybe_log) {
          return;
        }
        grpc::ClientContext context;
        context.set_wait_for_ready(true);
        context.set_deadline(std::chrono::system_clock::now()
                             + std::chrono::seconds(5));
        google::protobuf::Empty response;
        maybe_log->info(log_sending_msg);
        auto status = client->SendState(&context, request, &response);
        if (not status.ok()) {
          maybe_log->warn(
              "RPC failed: {} {}", context.peer(), status.error_message());
          return;
        } else {
          maybe_log->info("RPC succeeded: {}", context.peer());
        }
      });
}
