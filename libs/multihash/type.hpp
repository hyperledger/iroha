/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MULTIHASH_HASH_TYPE_HPP
#define IROHA_MULTIHASH_HASH_TYPE_HPP

#include <cstdint>

namespace iroha {
  namespace multihash {
    /// https://github.com/multiformats/js-multihash/blob/master/src/constants.js
    enum Type : uint64_t {
      //
      // --- Hash types ---
      //
      sha1 = 0x11,
      sha256 = 0x12,
      sha512 = 0x13,
      blake2s128 = 0xb250,
      blake2s256 = 0xb260,

      //
      // --- public key and signature types ---
      //
      ed25519pub = 0xed,
      ed25519_sha3_256 = 0x15a16d,

    };
  }  // namespace multihash
}  // namespace iroha

#endif
