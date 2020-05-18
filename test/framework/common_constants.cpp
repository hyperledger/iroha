/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/common_constants.hpp"

#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"

using namespace shared_model::crypto;

namespace common_constants {

  // user names
  const std::string kAdminName = "admin";
  const std::string kUser = "user";
  const std::string kSecondUser = "user2";

  // role names
  const std::string kAdminRole = "admin_role";
  const std::string kMoneyCreator = "money_creator";
  const std::string kDefaultRole = "default_role";
  const std::string kRole = "user_role";

  // asset names
  const std::string kAssetName = "coin";

  // domain names
  const std::string kDomain = "domain";
  const std::string kSecondDomain = "domain2";

  // ids
  const std::string kAdminId = kAdminName + "@" + kDomain;
  const std::string kUserId = kUser + "@" + kDomain;
  const std::string kSameDomainUserId = kSecondUser + "@" + kDomain;
  const std::string kSecondDomainUserId = kSecondUser + "@" + kSecondDomain;
  const std::string kAssetId = kAssetName + "#" + kDomain;
  const std::string kSecondDomainAssetId = kAssetName + "#" + kSecondDomain;

  // keypairs
  const Keypair kAdminKeypair = CryptoProviderEd25519Sha3::generateKeypair();
  const Keypair kUserKeypair = CryptoProviderEd25519Sha3::generateKeypair();
  const Keypair kSameDomainUserKeypair =
      CryptoProviderEd25519Sha3::generateKeypair();
  const Keypair kSecondDomainUserKeypair =
      CryptoProviderEd25519Sha3::generateKeypair();

  // misc
  const shared_model::interface::Amount kAmountPrec1Max{
      "1157920892373161954235709850086879078532"
      "6998466564056403945758400791312963993.5"};  // (2**256 - 1) / 10**1
  const shared_model::interface::Amount kAmountPrec2Max{
      "1157920892373161954235709850086879078532"
      "699846656405640394575840079131296399.35"};  // (2**256 - 1) / 10**2
}  // namespace common_constants
