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
      kEd25519Sha2_224 = 0xed2224,
      kEd25519Sha2_256 = 0xed,
      kEd25519Sha2_384 = 0xed2384,
      kEd25519Sha2_512 = 0xed2512,
      kEd25519Sha3_224 = 0xed3224,
      kEd25519Sha3_256 = 0xed3256,
      kEd25519Sha3_384 = 0xed3384,
      kEd25519Sha3_512 = 0xed3512,
      kGost3410Sha_512 = 0xab2512,

    };
  }  // namespace multihash
}  // namespace iroha

#endif
