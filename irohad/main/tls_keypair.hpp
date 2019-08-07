/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TLS_KEYPAIR_HPP
#define IROHA_TLS_KEYPAIR_HPP

#include <string>

#include <boost/optional.hpp>

class TLSKeypair {
 public:
  /**
   * Initialize a keypair with a private key and a certificate
   * @param pem_private_key - PEM-encoded private key
   * @param pem_certificate - PEM-encoded certificate
   */
  explicit TLSKeypair(const std::string &pem_private_key,
                      const std::string &pem_certificate);

  std::string pem_private_key;
  std::string pem_certificate;
};

class TLSKeypairFactory {
 public:
  /**
   * Create a TLSKeypair from two files
   * @param path - path to files in a form to which .crt and .key will be
   *               appended.
   *               @see iroha::torii::TlsParams
   * @return keypair read from this path
   */
  boost::optional<TLSKeypair> readFromFiles(const std::string &path);
};

#endif  // IROHA_TLS_KEYPAIR_HPP
