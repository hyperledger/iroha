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
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager.hpp"
#include "multihash/type.hpp"
#include "torii/tls_params.hpp"

static const std::string kDbTypeRocksdb = "rocksdb";
static const std::string kDbTypePostgres = "postgres";

struct IrohadConfig {
  struct DbConfig {
    std::string type;
    std::string path;
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

  struct UtilityService {
    std::string ip;
    uint16_t port;
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
  uint32_t vote_delay;
  [[deprecated]] bool mst_support;
  bool syncing_mode;
  boost::optional<uint32_t> mst_expiration_time;
  boost::optional<uint32_t> max_round_delay_ms;
  boost::optional<uint32_t> proposal_creation_timeout;
  boost::optional<uint32_t> healthcheck_port;
  boost::optional<uint32_t> max_proposal_pack;
  boost::optional<uint32_t> stale_stream_max_rounds;
  boost::optional<logger::LoggerManagerTreePtr> logger_manager;
  std::optional<shared_model::interface::types::PeerList> initial_peers;
  boost::optional<UtilityService> utility_service;
  std::optional<uint32_t> max_past_created_hours;
  // getters
  uint32_t getMaxpProposalPack() const;
  uint32_t getProposalDelay() const;
  uint32_t getProposalCreationTimeout() const;

  // This is a part of cryto providers feature:
  // https://github.com/MBoldyrev/iroha/tree/feature/hsm-utimaco.
  // This brings unnecessary complexity, but the aim is that this config section
  // should require no modifications from users when the feature branch is
  // merged.
  struct Crypto {
    struct Default {
      static char const *kName;
      iroha::multihash::Type type;
      std::optional<std::string> private_key;
    };

    using ProviderId = std::string;
    using ProviderList = std::unordered_map<ProviderId, Default>;

    ProviderList providers;
    ProviderId signer;
  };

  boost::optional<Crypto> crypto;

  std::string metrics_addr_port;
};

/**
 * parse and assert trusted peers json in `iroha.conf`
 * @param conf_text is the contents of iroha's config file
 * @return a parsed equivalent of that file
 */
iroha::expected::Result<IrohadConfig, std::string> parse_iroha_config(
    const std::string &conf_path,
    std::shared_ptr<shared_model::interface::CommonObjectsFactory>
        common_objects_factory,
    std::optional<logger::LoggerPtr> log);

#endif  // IROHA_CONF_LOADER_HPP
