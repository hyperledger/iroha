/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_HPP
#define IROHA_CRYPTO_HPP

#include <string>

#include "crypto/keypair.hpp"

namespace iroha {

  /**
   * Sign message with ed25519 crypto algorithm
   * @param msg
   * @param msgsize
   * @param pub
   * @param priv
   * @return
   */
  sig_t sign(shared_model::interface::types::ConstByteRange msg,
             const PubkeyView &pub,
             const PrivkeyView &priv);

  /**
   * Verify signature of ed25519 crypto algorithm
   * @param msg
   * @param msgsize
   * @param pub
   * @param sig
   * @return true if signature is valid, false otherwise
   */
  bool verify(shared_model::interface::types::ConstByteRange msg,
              const PubkeyView &pub,
              const SigView &sig);

  /**
   * Generate random seed reading from /dev/urandom
   */
  blob_t<32> create_seed();

  /**
   * Create new keypair
   * @param seed
   * @return
   */
  keypair_t create_keypair(blob_t<32> seed);

  /**
   * Create new keypair with a default seed (by create_seed())
   * @return
   */
  keypair_t create_keypair();

}  // namespace iroha
#endif  // IROHA_CRYPTO_HPP
