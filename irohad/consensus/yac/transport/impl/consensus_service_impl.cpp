/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/transport/impl/consensus_service_impl.hpp"

#include "consensus/yac/transport/yac_pb_converters.hpp"

using iroha::consensus::yac::ServiceImpl;

ServiceImpl::ServiceImpl(logger::LoggerPtr log,
                         std::function<void(std::vector<VoteMessage>)> callback)
    : callback_(std::move(callback)), log_(std::move(log)) {}

grpc::Status ServiceImpl::SendState(
    ::grpc::ServerContext *context,
    const ::iroha::consensus::yac::proto::State *request,
    ::google::protobuf::Empty *response) {
  std::vector<VoteMessage> state;
  for (const auto &pb_vote : request->votes()) {
    if (auto vote = PbConverters::deserializeVote(pb_vote, log_)) {
      state.push_back(*vote);
    }
  }
  if (state.empty()) {
    log_->info("Received an empty votes collection");
    return grpc::Status::CANCELLED;
  }
  if (not sameKeys(state)) {
    log_->info("Votes are statelessly invalid: proposal rounds are different");
    return grpc::Status::CANCELLED;
  }

  log_->info("Received votes[size={}] from {}", state.size(), context->peer());

  callback_(std::move(state));
  return grpc::Status::OK;
}
