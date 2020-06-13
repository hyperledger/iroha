/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_HSM_UTIMACO_CONNECTION_HPP
#define IROHA_CRYPTO_HSM_UTIMACO_CONNECTION_HPP

#include <memory>
#include <mutex>

namespace cxi {
  class Cxi;
}

namespace shared_model::crypto::hsm_utimaco {

  struct Connection {
    std::unique_ptr<cxi::Cxi> cxi;
    std::mutex mutex;
  };

}  // namespace shared_model::crypto::hsm_utimaco

#endif
