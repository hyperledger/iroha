/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_KEYS_MANAGER_IMPL_HPP
#define IROHA_KEYS_MANAGER_IMPL_HPP

#include "crypto/keys_manager.hpp"

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>
#include "cryptography/keypair.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {

  class KeysManagerImpl : public KeysManager {
   public:
    /**
     * Initialize key manager for a specific account
     * @param account_id - fully qualified account id, e.g. admin@test
     * @param path_to_keypair - path to directory that contains priv and pub key
     * of an account
     * @param log to print progress
     */
    KeysManagerImpl(const std::string &account_id,
                    const boost::filesystem::path &path_to_keypair,
                    logger::LoggerPtr log);

    /**
     * Initialize key manager for a specific account
     * @param account_id - fully qualified account id, e.g. admin@test
     * @param log to print progress
     */
    KeysManagerImpl(const std::string account_id, logger::LoggerPtr log);

    bool createKeys(const boost::optional<std::string> &pass_phrase) override;

    iroha::expected::Result<shared_model::crypto::Keypair, std::string>
    loadKeys(const boost::optional<std::string> &pass_phrase) override;

    static const std::string kPublicKeyExtension;
    static const std::string kPrivateKeyExtension;

   private:
    /**
     * Stores strings, that represent public and private keys on disk
     * @param pub is a public key
     * @param priv is a private key
     * @return true, if saving was successful
     */
    bool store(std::string_view pub, std::string_view priv);

    boost::filesystem::path path_to_keypair_;
    std::string account_id_;
    logger::LoggerPtr log_;
  };
}  // namespace iroha
#endif  // IROHA_KEYS_MANAGER_IMPL_HPP
