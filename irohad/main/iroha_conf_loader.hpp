/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CONF_LOADER_HPP
#define IROHA_CONF_LOADER_HPP

#include <string>
#include <unordered_map>

#include "interfaces/common_objects/common_objects_factory.hpp"
#include "interfaces/common_objects/types.hpp"
#include "logger/logger_manager.hpp"

struct IrohadConfig {
  std::string block_store_path;
  uint16_t torii_port;
  uint16_t torii_tls_port;
  std::string torii_tls_keypair;
  uint16_t internal_port;
  std::string pg_opt;
  uint32_t max_proposal_size;
  uint32_t proposal_delay;
  uint32_t vote_delay;
  bool mst_support;
  boost::optional<uint32_t> mst_expiration_time;
  boost::optional<uint32_t> max_round_delay_ms;
  boost::optional<uint32_t> stale_stream_max_rounds;
  boost::optional<logger::LoggerManagerTreePtr> logger_manager;
  boost::optional<shared_model::interface::types::PeerList> initial_peers;
};

/**
 * parse and assert trusted peers json in `iroha.conf`
 * @param conf_path is a path to iroha's config
 * @return a parsed equivalent of that file
 */
IrohadConfig parse_iroha_config(
    const std::string &conf_path,
    std::shared_ptr<shared_model::interface::CommonObjectsFactory>
        common_objects_factory);

#endif  // IROHA_CONF_LOADER_HPP
