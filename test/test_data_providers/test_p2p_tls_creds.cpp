/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_data_providers/test_p2p_tls_creds.hpp"

#include "common/files.hpp"
#include "common/result.hpp"
#include "network/impl/tls_credentials.hpp"

using iroha::network::TlsCredentials;

static_assert(NUM_TEST_P2P_TLS_CREDS == 3,
              "Wrong number of generated test credentials!");

namespace {
  std::string loadFile(const char *path) {
    return iroha::readTextFile(path).assumeValue();
  }
}  // namespace

namespace iroha {
  const TlsCredentials &getPeer1TlsCreds() {
    static const TlsCredentials kPeer1TlsCreds(loadFile(PEER1_P2P_TLS_KEY),
                                               loadFile(PEER1_P2P_TLS_CERT));
    return kPeer1TlsCreds;
  }

  const TlsCredentials &getPeer2TlsCreds() {
    static const TlsCredentials kPeer2TlsCreds(loadFile(PEER2_P2P_TLS_KEY),
                                               loadFile(PEER2_P2P_TLS_CERT));
    return kPeer2TlsCreds;
  }

  const TlsCredentials &getPeer3TlsCreds() {
    static const TlsCredentials kPeer3TlsCreds(loadFile(PEER3_P2P_TLS_KEY),
                                               loadFile(PEER3_P2P_TLS_CERT));
    return kPeer3TlsCreds;
  }
}  // namespace iroha
