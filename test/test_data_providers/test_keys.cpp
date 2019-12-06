/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_data_providers/test_keys.hpp"

#include "common/byteutils.hpp"
#include "common/files.hpp"
#include "common/result.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/private_key.hpp"
#include "cryptography/public_key.hpp"

using shared_model::crypto::Blob;
using shared_model::crypto::PrivateKey;
using shared_model::crypto::PublicKey;

static_assert(NUM_TEST_KEYS == 3,
              "Wrong number of generated test credentials!");

namespace {
  std::string loadFile(const char *path) {
    return iroha::expected::resultToOptionalValue(iroha::readFile(path))
        .value();
  }

  Blob loadHexFile(const char *path) {
    return Blob{iroha::hexstringToBytestring(loadFile(path)).value()};
  }
}  // namespace

namespace iroha {
  const PrivateKey &getPeer1PrivateKey() {
    static const PrivateKey kPeer1PrivateKey{loadHexFile(PEER1_PRIVKEY)};
    return kPeer1PrivateKey;
  }

  const PublicKey &getPeer1PublicKey() {
    static const PublicKey &kPeer1PublicKey{loadHexFile(PEER1_PUBKEY)};
    return kPeer1PublicKey;
  }

  const PrivateKey &getPeer2PrivateKey() {
    static const PrivateKey kPeer2PrivateKey{loadHexFile(PEER2_PRIVKEY)};
    return kPeer2PrivateKey;
  }

  const PublicKey &getPeer2PublicKey() {
    static const PublicKey &kPeer2PublicKey{loadHexFile(PEER2_PUBKEY)};
    return kPeer2PublicKey;
  }

  const PrivateKey &getPeer3PrivateKey() {
    static const PrivateKey kPeer3PrivateKey{loadHexFile(PEER3_PRIVKEY)};
    return kPeer3PrivateKey;
  }

  const PublicKey &getPeer3PublicKey() {
    static const PublicKey &kPeer3PublicKey{loadHexFile(PEER3_PUBKEY)};
    return kPeer3PublicKey;
  }
}  // namespace iroha
