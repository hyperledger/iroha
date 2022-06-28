/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "network/impl/channel_factory.hpp"

#include <limits>

#include <fmt/core.h>
#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/transformed.hpp>

#include "common/bind.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "network/channel_constants.hpp"

using namespace iroha::expected;
using namespace iroha::network;

using iroha::operator|;

std::string makeJsonString(const std::string &val) {
  return fmt::format("\"{}\"", val);
}

grpc::ChannelArguments iroha::network::detail::makeInterPeerChannelArguments(
    const std::set<std::string> &services, const GrpcChannelParams &params) {
  return detail::makeChannelArguments(services, params);
}

grpc::ChannelArguments iroha::network::detail::makeChannelArguments(
    const std::set<std::string> &services, const GrpcChannelParams &params) {
  std::string retry_policy =
      params.retry_policy | [](const auto &retry_policy) {
        return fmt::format(
            R"(
            "retryPolicy": {{
              "maxAttempts": {},
              "initialBackoff": "{}s",
              "maxBackoff": "{}s",
              "backoffMultiplier": {},
              "retryableStatusCodes": [
                {}
              ]
            }},)",
            retry_policy.max_attempts,
            retry_policy.initial_backoff.count(),
            retry_policy.max_backoff.count(),
            retry_policy.backoff_multiplier,
            boost::algorithm::join(
                retry_policy.retryable_status_codes
                    | boost::adaptors::transformed(makeJsonString),
                ", "));
      };
  static const auto make_service_id = [](const std::string &service_full_name) {
    return fmt::format(R"(
              {{ "service": "{}" }}
        )",
                       service_full_name);
  };
  std::string service_config = fmt::format(
      R"(
        {{
          "methodConfig": [ {{
            "name": [
              {}
            ],
            {}
            "maxRequestMessageBytes": {},
            "maxResponseMessageBytes": {}
          }} ]
        }})",
      boost::algorithm::join(
          services | boost::adaptors::transformed(make_service_id), ",\n"),
      retry_policy,
      params.max_request_message_bytes,
      params.max_response_message_bytes);

  grpc::ChannelArguments args;
  args.SetServiceConfigJSON(service_config);
  return args;
}

std::shared_ptr<grpc::Channel> iroha::network::createInsecureChannel(
    const shared_model::interface::types::AddressType &address,
    const std::string &service_full_name,
    std::optional<std::reference_wrapper<GrpcChannelParams const>>
        maybe_params) {
  if (not maybe_params)
    return grpc::CreateChannel(address, grpc::InsecureChannelCredentials());

  return grpc::CreateCustomChannel(address,
                                   grpc::InsecureChannelCredentials(),
                                   detail::makeInterPeerChannelArguments(
                                       {service_full_name}, *maybe_params));
}

class ChannelFactory::ChannelArgumentsProvider {
 public:
  ChannelArgumentsProvider(
      std::optional<std::shared_ptr<const GrpcChannelParams>> maybe_params)
      : maybe_params_(std::move(maybe_params)) {}

  const grpc::ChannelArguments &get(const std::string &service_full_name) {
    if (maybe_params_ and service_names_.count(service_full_name) == 0) {
      service_names_.emplace(service_full_name);
      args_ = detail::makeInterPeerChannelArguments(service_names_,
                                                    *maybe_params_.value());
    }

    args_.SetMaxSendMessageSize(kMaxMessageSize);
    args_.SetMaxReceiveMessageSize(kMaxMessageSize);
    return args_;
  }

 private:
  std::optional<std::shared_ptr<const GrpcChannelParams>> maybe_params_;
  std::set<std::string> service_names_;
  grpc::ChannelArguments args_;
};

ChannelFactory::ChannelFactory(
    std::optional<std::shared_ptr<const GrpcChannelParams>> maybe_params)
    : args_(
          std::make_unique<ChannelArgumentsProvider>(std::move(maybe_params))) {
}

ChannelFactory::~ChannelFactory() = default;

Result<std::shared_ptr<grpc::Channel>, std::string> ChannelFactory::getChannel(
    const std::string &service_full_name,
    const shared_model::interface::Peer &peer) {
  return getChannelCredentials(peer) | [&](auto &&credentials) {
    return grpc::CreateCustomChannel(
        peer.address(), std::move(credentials), args_->get(service_full_name));
  };
}

Result<std::shared_ptr<grpc::ChannelCredentials>, std::string>
ChannelFactory::getChannelCredentials(
    const shared_model::interface::Peer &) const {
  return grpc::InsecureChannelCredentials();
}
