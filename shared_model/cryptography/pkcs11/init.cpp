/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/pkcs11/init.hpp"

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>
#include <type_traits>
#include <unordered_map>

#include <botan/exceptn.h>
#include <botan/p11.h>
#include <botan/p11_module.h>
#include <botan/p11_object.h>
#include <botan/p11_session.h>
#include <botan/p11_slot.h>
#include <botan/pk_keys.h>
#include <fmt/core.h>
#include <sys/types.h>
#include <boost/range/adaptor/map.hpp>
#include "cryptography/crypto_init/from_config.hpp"
#include "cryptography/pkcs11/algorithm_identifier.hpp"
#include "cryptography/pkcs11/data.hpp"
#include "cryptography/pkcs11/signer.hpp"
#include "cryptography/pkcs11/verifier.hpp"

using namespace shared_model::crypto;

using iroha::InitCryptoProviderException;

namespace {
  pkcs11::OperationContext makeOperationContext(
      Botan::PKCS11::Module &module,
      Botan::PKCS11::SlotId slot_id,
      std::optional<std::string> pin) {
    Botan::PKCS11::Slot slot{module, slot_id};
    pkcs11::OperationContext op_ctx{
        module, slot, Botan::PKCS11::Session{slot, true}};
    if (pin) {
      Botan::PKCS11::secure_string pkcs11_pin;
      pkcs11_pin.reserve(pin->size());
      std::transform(
          pin->begin(), pin->end(), std::back_inserter(pkcs11_pin), [](auto c) {
            return static_cast<std::decay_t<decltype(*pkcs11_pin.data())>>(c);
          });
      op_ctx.session.login(Botan::PKCS11::UserType::User, pkcs11_pin);
    }
    return op_ctx;
  }

  // throws InitCryptoProviderException
  std::unique_ptr<CryptoSigner> makeSigner(
      IrohadConfig::Crypto::Pkcs11::Signer const &config,
      std::shared_ptr<Botan::PKCS11::Module> module,
      Botan::PKCS11::SlotId slot_id) {
    pkcs11::OperationContext op_ctx{
        makeOperationContext(*module, slot_id, config.pin)};

    auto signer_key_attrs = pkcs11::getPkcs11PrivateKeyProperties(config.type);
    auto emsa_name = pkcs11::getEmsaName(config.type);
    if (not signer_key_attrs or not emsa_name) {
      throw InitCryptoProviderException{"Unsupported algorithm."};
    }

    if (config.signer_key_attrs) {
      if (config.signer_key_attrs->label) {
        signer_key_attrs->add_string(Botan::PKCS11::AttributeType::Label,
                                     config.signer_key_attrs->label.value());
      }
      if (config.signer_key_attrs->id) {
        signer_key_attrs->add_binary(Botan::PKCS11::AttributeType::Id,
                                     config.signer_key_attrs->id.value());
      }
    }

    auto matching_keys{Botan::PKCS11::ObjectFinder{
        op_ctx.session, signer_key_attrs->attributes()}
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

    return std::make_unique<pkcs11::Signer>(std::move(module),
                                            std::move(op_ctx),
                                            std::move(opt_signer_key).value(),
                                            emsa_name.value(),
                                            config.type);
  }

}  // namespace
   // open a read-only session
   // login for private token objects access

void iroha::initCryptoProviderPkcs11(iroha::PartialCryptoInit initializer,
                                     IrohadConfig::Crypto::Pkcs11 const &config,
                                     logger::LoggerManagerTreePtr log_manager) {
  try {
    auto module = std::make_shared<Botan::PKCS11::Module>(config.library_file);

    if (initializer.init_signer) {
      if (not config.signer) {
        throw InitCryptoProviderException{"Signer configuration missing."};
      }

      initializer.init_signer.value()(
          makeSigner(config.signer.value(), module, config.slot_id));
    }

    if (initializer.init_verifier) {
      auto make_op_context =
          [module, slot_id{config.slot_id}, pin{config.pin}]() {
            return makeOperationContext(*module, slot_id, pin);
          };

      initializer.init_verifier.value()(
          std::make_unique<pkcs11::Verifier>(std::move(make_op_context)));
    }
  } catch (Botan::Exception const &ex) {
    throw InitCryptoProviderException{ex.what()};
  }
}
