/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_SERVICE_IMPL_HPP
#define IROHA_YAC_SERVICE_IMPL_HPP

#include "yac.grpc.pb.h"

#include <memory>

#include "consensus/yac/vote_message.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha::consensus::yac {
  /**
   * Class which provides implementation of server-side transport for
   * consensus based on grpc
   */
  class ServiceImpl : public proto::Yac::Service {
   public:
    using Service = proto::Yac;

    ServiceImpl(logger::LoggerPtr log,
                std::function<void(std::vector<VoteMessage>)> callback);

    /**
     * Receive votes from another peer;
     * Naming is confusing, because this is rpc call that
     * perform on another machine;
     */
    grpc::Status SendState(::grpc::ServerContext *context,
                           const ::iroha::consensus::yac::proto::State *request,
                           ::google::protobuf::Empty *response) override;

   private:
    std::function<void(std::vector<VoteMessage>)> callback_;

    logger::LoggerPtr log_;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_SERVICE_IMPL_HPP
