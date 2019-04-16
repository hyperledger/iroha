/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_KEYPAIR_HPP
#define IROHA_CRYPTO_KEYPAIR_HPP

#include "common/blob.hpp"

namespace iroha {

  using sig_t = blob_t<64>;  // ed25519 sig is 64 bytes length
  using pubkey_t = blob_t<32>;
  using privkey_t = blob_t<32>;

  struct keypair_t {
    keypair_t() = default;

    keypair_t(pubkey_t pubkey, privkey_t privkey)
        : pubkey(pubkey), privkey(privkey) {}

    pubkey_t pubkey;
    privkey_t privkey;
  };
}  // namespace iroha

#endif  // IROHA_CRYPTO_KEYPAIR_HPP
