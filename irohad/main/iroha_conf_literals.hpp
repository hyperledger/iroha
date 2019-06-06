/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CONF_LITERALS_HPP
#define IROHA_CONF_LITERALS_HPP

#include <string>
#include <unordered_map>

#include "logger/logger.hpp"

namespace config_members {
  extern const char *BlockStorePath;
  extern const char *ToriiPort;
  extern const char *ToriiTlsPort;
  extern const char *ToriiTlsKeypair;
  extern const char *InternalPort;
  extern const char *KeyPairPath;
  extern const char *PgOpt;
  extern const char *MaxProposalSize;
  extern const char *ProposalDelay;
  extern const char *VoteDelay;
  extern const char *MstSupport;
  extern const char *MstExpirationTime;
  extern const char *MaxRoundsDelay;
  extern const char *StaleStreamMaxRounds;
  extern const char *LogSection;
  extern const char *LogLevel;
  extern const char *LogPatternsSection;
  extern const char *LogChildrenSection;
  extern const std::unordered_map<std::string, logger::LogLevel> LogLevels;
  extern const char *InitialPeers;
  extern const char *Address;
  extern const char *PublicKey;

}  // namespace config_members

#endif  // IROHA_CONF_LITERALS_HPP
