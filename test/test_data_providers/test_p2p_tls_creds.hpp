/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEST_P2P_TLS_CREDS_HPP
#define IROHA_TEST_P2P_TLS_CREDS_HPP

namespace iroha {
  namespace network {
    struct TlsCredentials;
  }
}  // namespace iroha

namespace iroha {
  const iroha::network::TlsCredentials &getPeer1TlsCreds();
  const iroha::network::TlsCredentials &getPeer2TlsCreds();
  const iroha::network::TlsCredentials &getPeer3TlsCreds();
}  // namespace iroha

#endif
