/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_KEYS_HPP
#define IROHA_TEST_KEYS_HPP

namespace shared_model {
  namespace crypto {
    class PublicKey;
    class PrivateKey;
  }  // namespace crypto
}  // namespace shared_model

namespace iroha {
  const shared_model::crypto::PrivateKey &getPeer1PrivateKey();
  const shared_model::crypto::PublicKey &getPeer1PublicKey();

  const shared_model::crypto::PrivateKey &getPeer2PrivateKey();
  const shared_model::crypto::PublicKey &getPeer2PublicKey();

  const shared_model::crypto::PrivateKey &getPeer3PrivateKey();
  const shared_model::crypto::PublicKey &getPeer3PublicKey();
}  // namespace iroha

#endif
