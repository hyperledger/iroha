/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "maintenance/metrics.hpp"
#include "main/subscription.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "logger/logger.hpp"
#include "network/ordering_gate_common.hpp"
#include "interfaces/transaction.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/commands/create_domain.hpp"

#include <prometheus/counter.h>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#include <prometheus/gateway.h>

#include <array>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <string>
#include <future>
#include <regex>

using namespace iroha;
using namespace prometheus;

bool Metrics::valid()const{
  return registry_ and exposer_ and block_subscriber_
      and on_proposal_subscription_ and storage_;
}

Metrics::Metrics(
    std::string const& listen_addr,
    std::shared_ptr<iroha::ametsuchi::Storage> storage,
    logger::LoggerPtr const& logger
    )
:storage_(storage),logger_(logger)
{
  static const std::regex full_matcher("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]):[0-9]+$");
  static const std::regex port_matcher("^:?([0-9]{1,5})$");
  if(std::regex_match(listen_addr,full_matcher)) {
    listen_addr_port_ = listen_addr;
  } else if(std::regex_match(listen_addr,port_matcher)) {
    listen_addr_port_ = "127.0.0.1";
    if (listen_addr[0] != ':')
      listen_addr_port_ += ":";
    listen_addr_port_ += listen_addr;
  } else {
    return;
  }

  // @note it's the users responsibility to keep the object alive
  registry_ = std::make_shared<Registry>();

  // create an http server running on addr:port
  exposer_ = std::make_shared<Exposer>(listen_addr_port_);

  // ask the exposer_ to scrape the registry_ on incoming HTTP requests
  exposer_->RegisterCollectable(registry_);

  auto&block_height_gauge = BuildGauge()
                                .Name("blocks_height")
                                .Help("Total number of blocks in chain")
                                //.Labels({{"label","a_metter"}})
                                .Register(*registry_);
  auto&block_height_value = block_height_gauge.Add({});//{{"value", "some"}});
  block_height_value.Set(storage_->getBlockQuery()->getTopBlockHeight());

  auto&peers_number_gauge = BuildGauge()
      .Name("peers_number")
      .Help("Total number peers to send transactions and request proposals")
      //.Labels({{"label","a_metter"}})
      .Register(*registry_);
  auto&peers_number_value = peers_number_gauge.Add({});//{{"valueP", "any"}});

  auto&domains_number_gauge = BuildGauge()
      .Name("number_of_domains")
      .Help("Total number of domains in WSV")
      //.Labels({{"label","a_metter"}})
      .Register(*registry_);
  auto&domains_number_value = domains_number_gauge.Add({});

  auto&number_of_signatures_in_last_block_gauge = BuildGauge()
      .Name("number_of_signatures_in_last_block")
      .Help("Number of signatures in last block")
          //.Labels({{"label","a_metter"}})
      .Register(*registry_);
  auto&number_of_signatures_in_last_block = number_of_signatures_in_last_block_gauge.Add({});
  
  block_subscriber_ = std::make_shared<BlockSubscriber>(
      getSubscription()->getEngine<EventTypes,BlockPtr>());
  block_subscriber_->setCallback(
        [&] //Values are stored in registry_
        (auto, auto&receiver, auto const event, BlockPtr pblock){
          // block_height_value is captured by reference because it is stored inside registry_, which is shared_ptr
          assert(pblock);
          block_height_value.Set(pblock->height());
          ///---
          int domain_created = 0;
          unsigned signatures_num = 0;
          for(auto const& trx : pblock->transactions()){
            for(auto const& cmd : trx.commands()){
              using shared_model::interface::CreateDomain;
              domain_created += boost::get<CreateDomain>(&cmd.get()) != nullptr;  // Check if command is CreateDomain
              //todo domain_created -= boost::get<RemoveDomain>(&cmd.get()) != nullptr;
            }
            signatures_num += boost::size(trx.signatures());
          }
#if 1
          domains_number_value.Increment(domain_created);
#else  // no need to querry DB but here is a way to do
          if(domain_created){
            assert(storage_);
            assert(storage_->getWsvQuery());
            auto opt_n_domains = storage_->getWsvQuery()->getNumberOfDomains();
            if(opt_n_domains)
              domains_number_value.Set(*opt_n_domains);
            else
              logger_->warn("Cannot getNumberOfDomains() from WSV");
          }
#endif
          ///---
          number_of_signatures_in_last_block.Set(signatures_num);
        });
  block_subscriber_->subscribe<SubscriptionEngineHandlers::kMetrics>(
      0,EventTypes::kOnBlock); //FIXME: I am not sure what is ID and why 0
  
  on_proposal_subscription_ = std::make_shared<OnProposalSubscription>(
      getSubscription()->getEngine<EventTypes, network::OrderingEvent>());
  on_proposal_subscription_->setCallback(
      [&peers_number_value]
      (auto, auto, auto key, network::OrderingEvent const &oe) {
        // peers_number_value can be captured by reference because it is stored inside registry_
        assert(EventTypes::kOnProposal == key);
        peers_number_value.Set(oe.ledger_state->ledger_peers.size());
      });
  on_proposal_subscription_->subscribe<SubscriptionEngineHandlers::kMetrics>(
      0,EventTypes::kOnProposal); //FIXME: I am not sure what is ID and why 0
}
