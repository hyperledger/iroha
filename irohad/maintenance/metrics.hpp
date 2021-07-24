/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MAINTENANCE_METRICS_HPP
#define IROHA_MAINTENANCE_METRICS_HPP

#include <prometheus/exposer.h>
#include <prometheus/registry.h>

#include <memory>
#include <optional>
#include <string>
#include <thread>

#include "ametsuchi/storage.hpp"
#include "ametsuchi/wsv_query.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "logger/logger_fwd.hpp"
#include "main/subscription.hpp"
#include "network/ordering_gate_common.hpp"

class Metrics : public std::enable_shared_from_this<Metrics> {
  using OnProposalSubscription = iroha::BaseSubscriber<
      bool,
      iroha::network::OrderingEvent>;  // FixMe subscribtion ≠ subscriber
  using BlockPtr = std::shared_ptr<const shared_model::interface::Block>;
  using BlockSubscriber = iroha::BaseSubscriber<bool, BlockPtr>;

  std::string listen_addr_port_;
  std::shared_ptr<prometheus::Exposer> exposer_;
  std::shared_ptr<prometheus::Registry> registry_;
  std::shared_ptr<iroha::ametsuchi::Storage> storage_;
  std::shared_ptr<BlockSubscriber> block_subscriber_;
  std::shared_ptr<OnProposalSubscription> on_proposal_subscription_;
  logger::LoggerPtr logger_;

  Metrics(std::string const &listen_addr,
          std::shared_ptr<iroha::ametsuchi::Storage> storage,
          logger::LoggerPtr const &logger);

 public:
  std::string const &getListenAddress() const {
    return listen_addr_port_;
  }

  template <class... Ts>
  static std::shared_ptr<Metrics> create(Ts &&... args) {
    struct Resolver : Metrics {
      Resolver(Ts &&... args) : Metrics(std::forward<Ts>(args)...) {}
    };
    return std::make_shared<Resolver>(std::forward<Ts>(args)...);
  }
};

#endif  // IROHA_MAINTENANCE_METRICS_HPP
