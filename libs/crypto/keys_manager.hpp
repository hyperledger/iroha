/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_KEYS_MANAGER_HPP
#define IROHA_KEYS_MANAGER_HPP

#include <string>

#include <boost/optional.hpp>
#include "common/result_fwd.hpp"
#include "cryptography/keypair.hpp"

namespace iroha {
  /**
   * Interface provides facilities to create and store keypair on disk.
   */
  class KeysManager {
   public:
    virtual ~KeysManager() = default;

    /**
     * Create keys of a new keypair and store them on disk. If pass phrase is
     * provided, the private key is encrypted.
     * @param pass_phrase (optional) used for private key encryption
     * @return false if keys creation failed
     */
    virtual bool createKeys(
        const boost::optional<std::string> &pass_phrase) = 0;

    /**
     * Load keys associated with the manager, then validate loaded keypair by
     * signing and verifying the signature of a test message.
     * @param pass_phrase (optional) is used to decrypt the private key
     * @return error if no keypair found locally, or in case of verification
     *         failure. Otherwise - the keypair will be returned
     */
    virtual iroha::expected::Result<shared_model::crypto::Keypair, std::string>
    loadKeys(const boost::optional<std::string> &pass_phrase) = 0;
  };

}  // namespace iroha
#endif  // IROHA_KEYS_MANAGER_HPP
