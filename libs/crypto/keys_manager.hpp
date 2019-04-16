/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_KEYS_MANAGER_HPP
#define IROHA_KEYS_MANAGER_HPP

#include <string>

#include <boost/optional.hpp>
#include "cryptography/keypair.hpp"

namespace iroha {
  /**
   * Interface provides facilities to create and store keypair on disk.
   */
  class KeysManager {
   public:
    virtual ~KeysManager() = default;

    /**
     * Create keys of a new keypair and store them on disk
     * @return false if keys creation was failed
     */
    virtual bool createKeys() = 0;

    /**
     * Create keys of a new keypair and store it encrypted on disk
     * @param pass_phrase is used for private key encryption
     * @return false if keys creation was failed
     */
    virtual bool createKeys(const std::string &pass_phrase) = 0;

    /**
     * Load keys associated with the manager, then validate loaded keypair by
     * signing and verifying the signature of a test message
     * @return nullopt if no keypair found locally, or in case of verification
     *         failure. Otherwise - the keypair will be returned
     */
    virtual boost::optional<shared_model::crypto::Keypair> loadKeys() = 0;

    /**
     * Load encrypted keys associated with the manager, then validate loaded
     * keypair by signing and verifying the signature of a test message
     * @param pass_phrase is a password for decryption
     * @return nullopt if no keypair found locally, or in case of verification
     *         failure. Otherwise - the keypair will be returned
     */
    virtual boost::optional<shared_model::crypto::Keypair> loadKeys(
        const std::string &pass_phrase) = 0;
  };

}  // namespace iroha
#endif  // IROHA_KEYS_MANAGER_HPP
