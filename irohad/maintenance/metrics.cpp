/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "maintenance/metrics.hpp"

#include <prometheus/counter.h>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>

#include <memory>
#include <regex>

#include "CivetServer.h"  // for CivetCallbacks
#include "interfaces/commands/add_peer.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/commands/create_domain.hpp"
#include "interfaces/commands/remove_peer.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger.hpp"
#include "main/subscription.hpp"

using namespace iroha;
using namespace prometheus;

Metrics::Metrics(std::string const &listen_addr,
                 std::shared_ptr<iroha::ametsuchi::Storage> storage,
                 logger::LoggerPtr const &logger)
    : storage_(storage), logger_(logger) {
  static const std::regex full_matcher(
      "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-"
      "9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]):[0-9]+$");
  static const std::regex port_matcher("^:?([0-9]{1,5})$");
  if (std::regex_match(listen_addr, full_matcher)) {
    listen_addr_port_ = listen_addr;
  } else if (std::regex_match(listen_addr, port_matcher)) {
    listen_addr_port_ = "127.0.0.1";
    if (listen_addr[0] != ':')
      listen_addr_port_ += ":";
    listen_addr_port_ += listen_addr;
  } else {
    throw std::runtime_error("Metrics does not accept listen address '"
                             + listen_addr + "'");
  }

  // @note it's the users responsibility to keep the object alive
  registry_ = std::make_shared<Registry>();

  CivetCallbacks cvcbs;
  auto civet_no_log = [](const struct mg_connection *conn,
                         const char *message) { return 1; };
  cvcbs.log_message = civet_no_log;
  cvcbs.log_access = civet_no_log;

  // create an http server running on addr:port
  exposer_ = std::make_shared<Exposer>(listen_addr_port_,
                                       /*num_threads*/ 2,
                                       &cvcbs);

  // ask the exposer_ to scrape the registry_ on incoming HTTP requests
  exposer_->RegisterCollectable(registry_, "/metrics");

  auto &block_height_gauge = BuildGauge()
                                 .Name("blocks_height")
                                 .Help("Total number of blocks in chain")
                                 .Register(*registry_);
  auto &block_height = block_height_gauge.Add({});
  block_height.Set(storage_->getBlockQuery()->getTopBlockHeight());

  auto &peers_number_gauge =
      BuildGauge()
          .Name("peers_number")
          .Help("Total number peers to send transactions and request proposals")
          .Register(*registry_);
  auto &number_of_peers = peers_number_gauge.Add({});
  number_of_peers.Set(storage_->getWsvQuery()->getPeers()->size());

  auto &domains_number_gauge = BuildGauge()
                                   .Name("number_of_domains")
                                   .Help("Total number of domains in WSV")
                                   .Register(*registry_);
  auto &domains_number = domains_number_gauge.Add({});
  domains_number.Set(storage_->getWsvQuery()->countDomains().assumeValue());

  auto &total_number_of_transactions_gauge =
      BuildGauge()
          .Name("total_number_of_transactions")
          .Help("Total number of transactions in blockchain")
          .Register(*registry_);
  auto &total_number_of_transactions =
      total_number_of_transactions_gauge.Add({});
  total_number_of_transactions.Set(
      storage_->getWsvQuery()->countTransactions().assumeValue());

  auto &number_of_signatures_in_last_block_gauge =
      BuildGauge()
          .Name("number_of_signatures_in_last_block")
          .Help("Number of signatures in last block")
          .Register(*registry_);
  auto &number_of_signatures_in_last_block =
      number_of_signatures_in_last_block_gauge.Add({});
  auto ptopblock =
      storage_->getBlockQuery()
          ->getBlock(storage_->getBlockQuery()->getTopBlockHeight())
          .assumeValue();
  number_of_signatures_in_last_block.Set(boost::size(ptopblock->signatures()));

  block_subscriber_ =
      SubscriberCreator<bool, BlockPtr>::template create<EventTypes::kOnBlock>(
          SubscriptionEngineHandlers::kMetrics,
          [&, wregistry = std::weak_ptr<Registry>(registry_)](auto &,
                                                              BlockPtr pblock) {
            // Metrics values are stored inside and owned by registry,
            // capture them by reference is legal.
            std::shared_ptr<Registry> registry{wregistry};  // throw if expired
            assert(pblock);
            block_height.Set(pblock->height());
            number_of_signatures_in_last_block.Set(
                boost::size(pblock->signatures()));
            total_number_of_transactions.Increment(
                boost::size(pblock->transactions()));
            int domains_diff = 0, peers_diff = 0;
            using namespace shared_model::interface;
            for (Transaction const &trx : pblock->transactions()) {
              for (Command const &cmd : trx.commands()) {
                domains_diff += cmd.is<CreateDomain>() ? 1 : 0;
                peers_diff += cmd.is<AddPeer>() ? 1 : 0;
                peers_diff -= cmd.is<RemovePeer>() ? 1 : 0;
              }
            }
            number_of_peers.Increment(peers_diff);
            domains_number.Increment(domains_diff);
          });
}
