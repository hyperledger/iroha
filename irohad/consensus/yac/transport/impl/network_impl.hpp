/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_NETWORK_IMPL_HPP
#define IROHA_NETWORK_IMPL_HPP

#include "consensus/yac/transport/yac_network_interface.hpp"  // for YacNetwork
#include "yac.grpc.pb.h"

#include <memory>
#include <mutex>

#include "consensus/yac/vote_message.hpp"
#include "logger/logger_fwd.hpp"
#include "network/impl/async_grpc_client.hpp"
#include "network/impl/client_factory.hpp"

namespace iroha::consensus::yac {
  /**
   * Class which provides implementation of client-side transport for
   * consensus based on grpc
   */
  class NetworkImpl : public YacNetwork {
   public:
    using Service = proto::Yac;
    using ClientFactory = iroha::network::ClientFactory<Service>;

    NetworkImpl(
        std::shared_ptr<network::AsyncGrpcClient<google::protobuf::Empty>>
            async_call,
        std::unique_ptr<
            iroha::network::ClientFactory<::iroha::consensus::yac::proto::Yac>>
            client_factory,
        logger::LoggerPtr log);

    void sendState(const shared_model::interface::Peer &to,
                   const std::vector<VoteMessage> &state) override;

    void stop() override;

   private:
    std::function<void(std::vector<VoteMessage>)> callback_;

    /**
     * Rpc call to provide an ability to perform call grpc endpoints
     */
    std::shared_ptr<network::AsyncGrpcClient<google::protobuf::Empty>>
        async_call_;

    /**
     * Yac stub creator
     */
    std::unique_ptr<ClientFactory> client_factory_;

    std::mutex stop_mutex_;
    bool stop_requested_{false};

    logger::LoggerPtr log_;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_NETWORK_IMPL_HPP
