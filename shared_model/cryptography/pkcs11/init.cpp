/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/pkcs11/init.hpp"

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>
#include <unordered_map>

#include <botan/p11.h>
#include <botan/p11_object.h>
#include <botan/p11_session.h>
#include <botan/p11_slot.h>
#include <boost/range/adaptor/map.hpp>
#include "cryptography/crypto_init/from_config.hpp"
#include "cryptography/pkcs11/algorithm_identifier.hpp"
//#include "cryptography/pkcs11/connection.hpp"
#include "cryptography/pkcs11/data.hpp"
#include "cryptography/pkcs11/formatters.hpp"
#include "cryptography/pkcs11/safe_cxi.hpp"
#include "cryptography/pkcs11/signer.hpp"
#include "cryptography/pkcs11/verifier.hpp"

using namespace shared_model::crypto;

using iroha::InitCryptoProviderException;

namespace {
  pkcs11::OperationContext makeAnonReadOnlyOperationContext(
      std::shared_ptr<Botan::PKCS11::Module> module,
      IrohadConfig::Crypto::Pkcs11 const &config) {
    Botan::PKCS11::Slot slot{*module, config.slot_id};
    return pkcs11::OperationContext{
        *module, slot, Botan::PKCS11::Session{slot, true}};
  }

  // throws InitCryptoProviderException
  std::unique_ptr<CryptoSigner> makeSigner(
      IrohadConfig::Crypto::Pkcs11::Signer const &config,
      std::shared_ptr<Botan::PKCS11::Module> module,
      pkcs11::OperationContext op_ctx) {
    if (config.password) {
      Botan::PKCS11::secure_string password;
      password.reserve(config.password->size());
      std::transform(config.password->begin(),
                     config.password->end(),
                     std::back_inserter(password),
                     [](auto c) -> decltype(*password.data()) { return c; });
      op_ctx.session.init_pin(password);
    }

    auto opt_pkcs11_key_type = pkcs11::getPkcs11KeyType(config.type);
    auto opt_emsa_name = pkcs11::getEmsaName(config.type);
    if (not opt_pkcs11_key_type or not opt_emsa_name) {
      throw InitCryptoProviderException{"Unsupported algorithm."};
    }

    Botan::PKCS11::ObjectProperties signer_key_attrs{
        Botan::PKCS11::ObjectClass::PrivateKey};
    signer_key_attrs.add_numeric(Botan::PKCS11::AttributeType::KeyType,
                                 opt_pkcs11_key_type.value());
    if (config.signer_key_attrs) {
      if (config.signer_key_attrs->label) {
        signer_key_attrs.add_string(Botan::PKCS11::AttributeType::Label,
                                    config.signer_key_attrs->label.value());
      }
      if (config.signer_key_attrs->id) {
        signer_key_attrs.add_binary(Botan::PKCS11::AttributeType::Id,
                                    config.signer_key_attrs->id.value());
      }
    }

    auto matching_keys{Botan::PKCS11::ObjectFinder{
        op_ctx.session, signer_key_attrs.attributes()}
                           .find()};
    if (matching_keys.empty()) {
      throw InitCryptoProviderException{"No matching signer key found."};
    }
    if (matching_keys.size() > 1) {
      throw InitCryptoProviderException{
          "Found more than one signing key matching given attributes."};
    }
    auto opt_signer_key = pkcs11::loadPrivateKeyOfType(
        config.type, op_ctx.session, matching_keys[0]);
    if (not opt_signer_key) {
      throw InitCryptoProviderException{"Could not load private key."};
    }

    return std::make_unique<pkcs11::Signer>(module,
                                            op_ctx,
                                            opt_signer_key.value(),
                                            opt_emsa_name.value(),
                                            config.type);
  }
}  // namespace
   // open a read-only session
   // login for private token objects access

void iroha::initCryptoProviderPkcs11(iroha::PartialCryptoInit initializer,
                                     IrohadConfig::Crypto::Pkcs11 const &config,
                                     logger::LoggerManagerTreePtr log_manager) {
  auto module = std::make_shared<Botan::PKCS11::Module>(config.library_file);

  auto make_anon_context = [module, slot_id{config.slot_id}]() {
    Botan::PKCS11::Slot slot{*module, slot_id};
    return pkcs11::OperationContext{
        *module, slot, Botan::PKCS11::Session{slot, true}};
  };

  if (initializer.init_signer) {
    if (not config.signer) {
      throw InitCryptoProviderException{"Signer configuration missing."};
    }

    initializer.init_signer.value()(makeSigner(
        config.signer.value(), std::move(module), make_anon_context()));
  }

  if (initializer.init_verifier) {
    initializer.init_verifier.value()(
        std::make_unique<pkcs11::Verifier>(std::move(make_anon_context)));
  }
}
