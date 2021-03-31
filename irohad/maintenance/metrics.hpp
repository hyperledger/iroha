/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MAINTENANCE_METRICS_HPP
#define IROHA_MAINTENANCE_METRICS_HPP

#include <string>
#include <memory>
#include <optional>
#include <thread>
#include <prometheus/registry.h>
#include <prometheus/exposer.h>
#include <prometheus/gateway.h>
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "main/subscription.hpp"
#include "network/ordering_gate_common.hpp"
#include "ametsuchi/wsv_query.hpp"
#include "ametsuchi/storage.hpp"
#include "logger/logger_fwd.hpp"
//#include "boost/asiofwd.hpp"

//namespace boost { namespace asio { class io_context; }}

struct io_worker;

class Metrics : public std::enable_shared_from_this<Metrics> {
  using OnProposalSubscription = iroha::BaseSubscriber<
      bool,iroha::network::OrderingEvent>;  //FixMe subscribtion ≠ subscriber
  using BlockPtr = std::shared_ptr<const shared_model::interface::Block>;
  using BlockSubscriber = iroha::BaseSubscriber<bool,BlockPtr>;

  std::string listen_addr_port_;
  std::string push_addr_;
  std::string push_port_;
  std::shared_ptr<prometheus::Exposer> exposer_;
  std::shared_ptr<prometheus::Registry> registry_;
  std::shared_ptr<prometheus::Gateway> gateway_;
  std::shared_ptr<iroha::ametsuchi::Storage> storage_;
//  std::shared_ptr<iroha::ametsuchi::WsvQuery> wsv_;
  std::shared_ptr<BlockSubscriber> block_subscriber_;
  std::shared_ptr<OnProposalSubscription> on_proposal_subscription_;
  logger::LoggerPtr logger_;
  std::shared_ptr<io_worker> io_worker_;  // want to use unique_ptr but it does not allow incomplete types.
  std::shared_ptr<std::function<void(void)>> handler_gateway_push_wrapper_;

 public:
  Metrics(
      std::string const& listen_addr,
      std::string const& metrics_push_addr,
      std::shared_ptr<iroha::ametsuchi::Storage> storage,
      logger::LoggerPtr const& logger
  );
  std::string const& getListenAddress()const{ return listen_addr_port_; }
  bool valid()const;
};

#endif //IROHA_MAINTENANCE_METRICS_HPP
