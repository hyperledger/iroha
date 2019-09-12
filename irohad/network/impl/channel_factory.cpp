/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/channel_factory.hpp"

#include <limits>

#include <boost/algorithm/string/join.hpp>
#include <boost/format.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include "common/bind.hpp"
#include "interfaces/common_objects/peer.hpp"

using namespace iroha::network;
using namespace std::literals::chrono_literals;

using iroha::operator|;

std::string makeJsonString(const std::string &val) {
  return std::string{"\""} + val + "\"";
}

std::unique_ptr<GrpcChannelParams> iroha::network::getDefaultChannelParams() {
  static const auto retry_policy = [] {
    GrpcChannelParams::RetryPolicy retry_policy;
    retry_policy.max_attempts = 5u;
    retry_policy.initial_backoff = 5s;
    retry_policy.max_backoff = 120s;
    retry_policy.backoff_multiplier = 1.6f;
    retry_policy.retryable_status_codes = {
        "UNKNOWN", "DEADLINE_EXCEEDED", "ABORTED", "INTERNAL", "UNAVAILABLE"};
    return retry_policy;
  }();
  auto params = std::make_unique<GrpcChannelParams>();
  params->max_request_message_bytes = std::numeric_limits<int>::max();
  params->max_response_message_bytes = std::numeric_limits<int>::max();
  params->retry_policy = retry_policy;
  return params;
}

grpc::ChannelArguments iroha::network::makeChannelArguments(
    const std::set<std::string> &services, const GrpcChannelParams &params) {
  std::string retry_policy =
      params.retry_policy | [](const auto &retry_policy) {
        auto formatted = boost::format(R"(
            "retryPolicy": {
              "maxAttempts": %d,
              "initialBackoff": "%ds",
              "maxBackoff": "%ds",
              "backoffMultiplier": %f,
              "retryableStatusCodes": [
                %s
              ]
            },)")
            % retry_policy.max_attempts % retry_policy.initial_backoff.count()
            % retry_policy.max_backoff.count() % retry_policy.backoff_multiplier
            % boost::algorithm::join(
                             retry_policy.retryable_status_codes
                                 | boost::adaptors::transformed(makeJsonString),
                             ", ");
        return formatted.str();
      };
  static const auto make_service_id = [](const std::string &service_full_name) {
    return (boost::format(R"(
              { "service": "%s" }
        )") % service_full_name)
        .str();
  };
  std::string service_config =
      (boost::format(R"(
        {
          "methodConfig": [ {
            "name": [
              %s
            ],
            %s
            "maxRequestMessageBytes": %d,
            "maxResponseMessageBytes": %d
          } ]
        })")
       % boost::algorithm::join(
             services | boost::adaptors::transformed(make_service_id), ",\n")
       % retry_policy % params.max_request_message_bytes
       % params.max_response_message_bytes)
          .str();

  std::cerr << std::endl << service_config << std::endl;  // DEBUG REMOVE
  grpc::ChannelArguments args;
  args.SetServiceConfigJSON(service_config);
  return args;
}

std::shared_ptr<grpc::Channel> iroha::network::createInsecureChannel(
    const shared_model::interface::types::AddressType &address,
    const std::string &service_full_name,
    const GrpcChannelParams &params) {
  return grpc::CreateCustomChannel(
      address,
      grpc::InsecureChannelCredentials(),
      makeChannelArguments({service_full_name}, params));
}

class ChannelFactory::ChannelArgumentsProvider {
 public:
  ChannelArgumentsProvider(std::shared_ptr<const GrpcChannelParams> params)
      : params_(std::move(params)) {}

  const grpc::ChannelArguments &get(const std::string &service_full_name) {
    if (service_names_.count(service_full_name) == 0) {
      service_names_.emplace(service_full_name);
      args_ = makeChannelArguments(service_names_, *params_);
    }
    return args_;
  }

 private:
  std::shared_ptr<const GrpcChannelParams> params_;
  std::set<std::string> service_names_;
  grpc::ChannelArguments args_;
};

ChannelFactory::ChannelFactory(std::shared_ptr<const GrpcChannelParams> params)
    : args_(std::make_unique<ChannelArgumentsProvider>(std::move(params))) {}

ChannelFactory::~ChannelFactory() = default;

std::shared_ptr<grpc::Channel> ChannelFactory::getChannel(
    const std::string &service_full_name,
    const shared_model::interface::Peer &peer) {
  return grpc::CreateCustomChannel(peer.address(),
                                   getChannelCredentials(peer),
                                   args_->get(service_full_name));
}

std::shared_ptr<grpc::ChannelCredentials> ChannelFactory::getChannelCredentials(
    const shared_model::interface::Peer &) const {
  return grpc::InsecureChannelCredentials();
}
