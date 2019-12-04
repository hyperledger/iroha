/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <vector>

#include "common/result.hpp"

namespace shared_model {
  namespace crypto {
    class PublicKey;
  }
}  // namespace shared_model

namespace iroha {

  /**
   * Extract ED25519 keys that the provided PEM certificate certifies to its
   * subject. For this, the certificate must contain a Subject Alternative Name
   * of type OtherName with OID 1.3.101.112 (ED25519 public key) and the ED25519
   * key(s) as value.
   *
   * @param cert_buf_pem - pointer to memory containing PEM certificate
   * @param cert_buf_sz - size of PEM certificate
   *
   * @return ED25519 public keys certified by this certificate.
   */
  expected::Result<std::vector<shared_model::crypto::PublicKey>, std::string>
  getIrohaPubKeysFromX509(const char *cert_buf_pem, size_t cert_buf_sz);

}  // namespace iroha
