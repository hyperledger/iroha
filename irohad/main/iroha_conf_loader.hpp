/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CONF_LOADER_HPP
#define IROHA_CONF_LOADER_HPP

#include <string>
#include <unordered_map>

#include "common/result_fwd.hpp"
#include "interfaces/common_objects/common_objects_factory.hpp"
#include "interfaces/common_objects/types.hpp"
#include "logger/logger_manager.hpp"
#include "torii/tls_params.hpp"

struct IrohadConfig {
  struct DbConfig {
    std::string host;
    uint16_t port;
    std::string user;
    std::string password;
    std::string working_dbname;
    std::string maintenance_dbname;
  };

  struct InterPeerTls {
    struct RootCert {
      std::string path;
    };
    struct FromWsv {};
    struct None {};
    using PeerCertProvider = boost::variant<RootCert, FromWsv, None>;

    boost::optional<std::string> my_tls_creds_path;
    PeerCertProvider peer_certificates;
  };

  // TODO: block_store_path is now optional, change docs IR-576
  // luckychess 29.06.2019
  boost::optional<std::string> block_store_path;
  uint16_t torii_port;
  boost::optional<iroha::torii::TlsParams> torii_tls_params;
  boost::optional<InterPeerTls> inter_peer_tls;
  uint16_t internal_port;
  boost::optional<std::string>
      pg_opt;  // TODO 2019.06.26 mboldyrev IR-556 remove
  boost::optional<DbConfig>
      database_config;  // TODO 2019.06.26 mboldyrev IR-556 make required
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
iroha::expected::Result<IrohadConfig, std::string> parse_iroha_config(
    const std::string &conf_path,
    std::shared_ptr<shared_model::interface::CommonObjectsFactory>
        common_objects_factory);

#endif  // IROHA_CONF_LOADER_HPP
