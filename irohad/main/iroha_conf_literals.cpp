/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/iroha_conf_literals.hpp"

namespace config_members {
  const char *BlockStorePath = "block_store_path";
  const char *ToriiPort = "torii_port";
  const char *InternalPort = "internal_port";
  const char *KeyPairPath = "key_pair_path";
  const char *PgOpt = "pg_opt";
  const char *MaxProposalSize = "max_proposal_size";
  const char *ProposalDelay = "proposal_delay";
  const char *VoteDelay = "vote_delay";
  const char *MstSupport = "mst_enable";
  const char *MstExpirationTime = "mst_expiration_time";
  const char *MstStateTxsLimit = "mst_state_transactions_limit";
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
}  // namespace config_members
