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

    bool createKeys() override;

    bool createKeys(const std::string &pass_phrase) override;

    boost::optional<shared_model::crypto::Keypair> loadKeys() override;

    boost::optional<shared_model::crypto::Keypair> loadKeys(
        const std::string &pass_phrase) override;

    static const std::string kPublicKeyExtension;
    static const std::string kPrivateKeyExtension;

   private:
    /**
     * Check if keypair provides valid signature
     * @param keypair - keypair for validation
     * @return true, if verification of signature is successful
     */
    bool validate(const shared_model::crypto::Keypair &keypair) const;

    /**
     * Tries to read the file
     * @param path - path to the target file
     * @return file contents if reading was successful, otherwise - boost::none
     */
    boost::optional<std::string> loadFile(
        const boost::filesystem::path &path) const;

    /**
     * Stores strings, that represent public and private keys on disk
     * @param pub is a public key
     * @param priv is a private key
     * @return true, if saving was successful
     */
    bool store(const std::string &pub, const std::string &priv);

    boost::filesystem::path path_to_keypair_;
    std::string account_id_;
    logger::LoggerPtr log_;
  };
}  // namespace iroha
#endif  // IROHA_KEYS_MANAGER_IMPL_HPP
