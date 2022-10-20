/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/iroha_conf_literals.hpp"

namespace config_members {
  const char *BlockStorePath = "block_store_path";
  const char *ToriiPort = "torii_port";
  const char *ToriiTlsParams = "torii_tls_params";
  const char *InterPeerTls = "inter_peer_tls";
  const char *PeerCertProvider = "peer_certificates";
  const char *RootCert = "root_certificate";
  const char *InLengerCerts = "from_ledger";
  const char *Type = "type";
  const char *Path = "path";
  const char *InternalPort = "internal_port";
  const char *KeyPairPath = "key_pair_path";
  const char *PgOpt = "pg_opt";
  const char *DbConfig = "database";
  const char *Host = "host";
  const char *Ip = "ip";
  const char *Port = "port";
  const char *User = "user";
  const char *Password = "password";
  const char *WorkingDbName = "working database";
  const char *MaintenanceDbName = "maintenance database";
  const char *DbPath = "path";
  const char *DbType = "type";
  const char *MaxProposalSize = "max_proposal_size";
  const char *ProposalCreationTimeout = "proposal_creation_timeout";
  const char *HealthcheckPort = "healthcheck_port";
  const char *MaxProposalPack = "max_proposal_pack";
  const char *VoteDelay = "vote_delay";
  const char *MstSupport = "mst_enable";
  const char *MstExpirationTime = "mst_expiration_time";
  const char *MaxRoundsDelay = "max_rounds_delay";
  const char *StaleStreamMaxRounds = "stale_stream_max_rounds";
  const char *LogSection = "log";
  const char *LogLevel = "level";
  const char *LogPatternsSection = "patterns";
  const char *LogChildrenSection = "children";
  const std::unordered_map<std::string, logger::LogLevel> LogLevels{
      {"trace", logger::LogLevel::kTrace},
      {"debug", logger::LogLevel::kDebug},
      {"info", logger::LogLevel::kInfo},
      {"warning", logger::LogLevel::kWarn},
      {"error", logger::LogLevel::kError},
      {"critical", logger::LogLevel::kCritical}};
  const char *MaxPastCreatedHours = "max_past_created_hours";
  const char *Address = "address";
  const char *PublicKey = "public_key";
  const char *InitialPeers = "initial_peers";
  const char *TlsCertificatePath = "tls_certificate_path";
  const char *UtilityService = "utility_service";
  const char *kCrypto = "crypto";
  const char *kProviders = "providers";
  const char *kCryptoType = "crypto_type";
  const char *kSigner = "signer";
  const char *kCryptoProviderDefault = "default";
  const char *PrivateKey = "private_key";
  const char *kMetrics = "metrics";
}  // namespace config_members
