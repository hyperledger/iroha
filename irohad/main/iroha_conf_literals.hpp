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
  extern const char *ToriiTlsParams;
  extern const char *InterPeerTls;
  extern const char *PeerCertProvider;
  extern const char *RootCert;
  extern const char *InLengerCerts;
  extern const char *Type;
  extern const char *Path;
  extern const char *InternalPort;
  extern const char *KeyPairPath;
  extern const char *PgOpt;
  extern const char *DbConfig;
  extern const char *Host;
  extern const char *Ip;
  extern const char *Port;
  extern const char *User;
  extern const char *Password;
  extern const char *WorkingDbName;
  extern const char *MaintenanceDbName;
  extern const char *DbPath;
  extern const char *DbType;
  extern const char *MaxProposalSize;
  extern const char *ProposalCreationTimeout;
  extern const char *HealthcheckPort;
  extern const char *MaxProposalPack;
  extern const char *VoteDelay;
  extern const char *MstSupport;
  extern const char *MstExpirationTime;
  extern const char *MaxRoundsDelay;
  extern const char *StaleStreamMaxRounds;
  extern const char *LogSection;
  extern const char *LogLevel;
  extern const char *LogPatternsSection;
  extern const char *LogChildrenSection;
  extern const char *MaxPastCreatedHours;
  extern const std::unordered_map<std::string, logger::LogLevel> LogLevels;
  extern const char *InitialPeers;
  extern const char *Address;
  extern const char *PublicKey;
  extern const char *TlsCertificatePath;
  extern const char *UtilityService;
  extern const char *kCrypto;
  extern const char *kProviders;
  extern const char *kCryptoType;
  extern const char *kSigner;
  extern const char *kCryptoProviderDefault;
  extern const char *PrivateKey;

}  // namespace config_members

#endif  // IROHA_CONF_LITERALS_HPP
