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

  auto stream_writer = stubs_.exclusiveAccess(
      [&](auto &stubs) -> std::shared_ptr<::grpc::ClientWriterInterface<
                           ::iroha::consensus::yac::proto::State>> {
        auto const it = stubs.find(to.pubkey());
        if (it == stubs.end() || std::get<0>(it->second) != to.address()) {
          if (it != stubs.end()) {
            // clear all
            std::get<3>(it->second)->WritesDone();
            stubs.erase(to.pubkey());
          }

          auto maybe_client = client_factory_->createClient(to);
          if (expected::hasError(maybe_client)) {
            log_->error("Could not send state to {}: {}",
                        to,
                        maybe_client.assumeError());
            return nullptr;
          }

          std::unique_ptr<proto::Yac::StubInterface> client =
              std::move(maybe_client).assumeValue();

          auto context = std::make_unique<grpc::ClientContext>();
          context->set_wait_for_ready(true);
          context->set_deadline(std::chrono::system_clock::now()
                                + std::chrono::seconds(5));

          auto response = std::make_unique<::google::protobuf::Empty>();
          std::shared_ptr<::grpc::ClientWriterInterface<
              ::iroha::consensus::yac::proto::State>>
              writer = client->SendState(context.get(), response.get());

          stubs[to.pubkey()] = std::make_tuple(std::string{to.address()},
                                               std::move(client),
                                               std::move(context),
                                               writer,
                                               std::move(response));
          return writer;
        }

        return std::get<3>(it->second);
      });

  if (!stream_writer)
    return;

  log_->debug("Propagating votes for {}, size={} to {}",
              state.front().hash.vote_round,
              state.size(),
              to);
  getSubscription()->dispatcher()->add(
      getSubscription()->dispatcher()->kExecuteInPool,
      [wptr{weak_from_this()},
       peer{to.pubkey()},
       request(std::move(request)),
       wstream_writer(utils::make_weak(stream_writer)),
       log(utils::make_weak(log_)),
       log_sending_msg(fmt::format("Send votes bundle[size={}] for {} to {}",
                                   state.size(),
                                   state.front().hash.vote_round,
                                   to))] {
        auto self = wptr.lock();
        auto maybe_log = log.lock();
        auto stream_writer = wstream_writer.lock();

        if (!self || !maybe_log || !stream_writer) {
          return;
        }

        maybe_log->info(log_sending_msg);
        if (!stream_writer->Write(request)) {
          maybe_log->warn("RPC failed: {}", peer);
          self->stubs_.exclusiveAccess([&](auto &stubs) { stubs.erase(peer); });
          return;
        }
        maybe_log->info("RPC succeeded: {}", peer);
      });
}
