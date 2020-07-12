/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_PKCS11_DATA_HPP
#define IROHA_CRYPTO_PKCS11_DATA_HPP

#include <functional>
#include <memory>

#include <botan/p11_module.h>
#include <botan/p11_session.h>
#include <botan/p11_slot.h>
#include "main/iroha_conf_loader.hpp"

namespace shared_model::crypto::pkcs11 {

  struct OperationContext {
    Botan::PKCS11::Module &module;
    Botan::PKCS11::Slot slot;
    Botan::PKCS11::Session session;
  };

  using OperationContextFactory = std::function<OperationContext()>;

}  // namespace shared_model::crypto::pkcs11

#endif
