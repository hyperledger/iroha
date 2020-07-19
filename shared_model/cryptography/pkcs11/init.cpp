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
#include <utility>
#include "common/hexutils.hpp"
#include "common/result.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/crypto_init/from_config.hpp"
#include "cryptography/pkcs11/algorithm_identifier.hpp"
#include "cryptography/pkcs11/data.hpp"
#include "cryptography/pkcs11/signer.hpp"
#include "cryptography/pkcs11/verifier.hpp"
#include "interfaces/common_objects/byte_range.hpp"
#include "interfaces/common_objects/range_types.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "logger/logger_fwd.hpp"
#include "multihash/converters.hpp"
#include "multihash/multihash.hpp"
#include "multihash/type.hpp"

using namespace shared_model::crypto;

using iroha::InitCryptoProviderException;

namespace {
  pkcs11::OperationContext makeOperationContext(
      Botan::PKCS11::Module &module,
      Botan::PKCS11::SlotId slot_id,
      std::optional<std::string> pin) {
    auto slot = std::make_unique<Botan::PKCS11::Slot>(module, slot_id);
    auto session = std::make_unique<Botan::PKCS11::Session>(*slot, true);
    // open a read-only session
    pkcs11::OperationContext op_ctx{
        module, std::move(slot), std::move(session)};
    if (pin) {
      // login for private token objects access
      Botan::PKCS11::secure_string pkcs11_pin;
      pkcs11_pin.reserve(pin->size());
      std::transform(
          pin->begin(), pin->end(), std::back_inserter(pkcs11_pin), [](auto c) {
            return static_cast<std::decay_t<decltype(*pkcs11_pin.data())>>(c);
          });
      op_ctx.session->login(Botan::PKCS11::UserType::User, pkcs11_pin);
    }
    return op_ctx;
  }

  // throws InitCryptoProviderException
  std::unique_ptr<CryptoSigner> makeSigner(
      IrohadConfig::Crypto::Pkcs11::Signer const &config,
      std::shared_ptr<Botan::PKCS11::Module> module,
      Botan::PKCS11::SlotId slot_id,
      std::optional<std::string> default_pin) {
    /*
    return std::make_unique<pkcs11::Signer>(
        std::move(module),
        makeOperationContext(*module, slot_id, default_pin),
        nullptr,
        "emsa_name",
        config.type);
    */

    auto &signer_pin = config.pin ? config.pin : default_pin;
    pkcs11::OperationContext op_ctx{
        makeOperationContext(*module, slot_id, signer_pin)};

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
        *op_ctx.session, signer_key_attrs->attributes()}
                           .find()};
    if (matching_keys.empty()) {
      throw InitCryptoProviderException{"No matching signer key found."};
    }
    if (matching_keys.size() > 1) {
      throw InitCryptoProviderException{
          "Found more than one signing key matching given attributes."};
    }
    auto opt_signer_key = pkcs11::loadPrivateKeyOfType(
        config.type, *op_ctx.session, matching_keys[0]);
    if (not opt_signer_key) {
      throw InitCryptoProviderException{"Could not load private key."};
    }

    return std::make_unique<pkcs11::Signer>(std::move(module),
                                            std::move(op_ctx),
                                            std::move(opt_signer_key).value(),
                                            emsa_name.value(),
                                            config.type);
  }

  bool isAlgoSupported(
      pkcs11::OperationContextFactory operation_context_factory,
      std::shared_ptr<Botan::PKCS11::Module> module,
      iroha::multihash::Type multihash_type) {
    try {
      auto op_ctx = operation_context_factory();

      auto opt_emsa_name = pkcs11::getEmsaName(multihash_type);
      auto opt_keypair = pkcs11::generateKeypairOfType(op_ctx, multihash_type);
      if (not opt_emsa_name or not opt_keypair) {
        return false;
      }

      using namespace shared_model::interface::types;

      pkcs11::Signer signer{module,
                            std::move(op_ctx),
                            std::move(opt_keypair->first),
                            opt_emsa_name.value(),
                            multihash_type};

      // parse and check public_key from signer
      auto signer_multihash_pubkey =
          iroha::multihash::createFromBuffer(
              makeByteRange(
                  iroha::hexstringToBytestringResult(signer.publicKey())
                      .assumeValue()))
              .assumeValue();
      if (signer_multihash_pubkey.type != multihash_type
          or signer_multihash_pubkey.data
              != makeByteRange(opt_keypair->second->public_key_bits())) {
        return false;
      }

      pkcs11::Verifier verifier{std::move(operation_context_factory),
                                {multihash_type}};

      shared_model::crypto::Blob message{"attack at dawn"};
      auto signature_hex = signer.sign(message);
      return iroha::expected::hasValue(verifier.verify(
          multihash_type,
          SignatureByteRangeView{makeByteRange(
              iroha::hexstringToBytestringResult(signature_hex).assumeValue())},
          message.range(),
          PublicKeyByteRangeView{makeByteRange(
              iroha::hexstringToBytestringResult(signer.publicKey())
                  .assumeValue())}));

    } catch (iroha::expected::ResultException const &) {
      return false;
    } catch (iroha::InitCryptoProviderException const &) {
      return false;
    } catch (Botan::Exception const &) {
      return false;
    }
    return true;
  }

  std::unique_ptr<pkcs11::Verifier> makeVerifier(
      std::shared_ptr<Botan::PKCS11::Module> module,
      pkcs11::OperationContextFactory operation_context_factory,
      logger::LoggerPtr log) {
    std::vector<iroha::multihash::Type> all_types{
        pkcs11::getAllMultihashTypes()};
    std::vector<iroha::multihash::Type> supported_types;
    std::copy_if(all_types.begin(),
                 all_types.end(),
                 std::back_inserter(supported_types),
                 [&](iroha::multihash::Type multihash_type) {
                   bool const is_supported = isAlgoSupported(
                       operation_context_factory, module, multihash_type);
                   log->trace("Algorithm {} is {}supported",
                              multihash_type,
                              is_supported ? "" : "not ");
                   return is_supported;
                 });
    return std::make_unique<pkcs11::Verifier>(
        std::move(operation_context_factory), std::move(supported_types));
  }

}  // namespace

void iroha::initCryptoProviderPkcs11(iroha::PartialCryptoInit initializer,
                                     IrohadConfig::Crypto::Pkcs11 const &config,
                                     logger::LoggerManagerTreePtr log_manager) {
  try {
    auto module = std::make_shared<Botan::PKCS11::Module>(config.library_file);

    if (initializer.init_signer) {
      if (not config.signer) {
        throw InitCryptoProviderException{"Signer configuration missing."};
      }

      initializer.init_signer.value()(makeSigner(
          config.signer.value(), module, config.slot_id, config.pin));
    }

    if (initializer.init_verifier) {
      auto make_op_context =
          [module, slot_id{config.slot_id}, pin{config.pin}]() {
            return makeOperationContext(*module, slot_id, pin);
          };

      initializer.init_verifier.value()(
          makeVerifier(std::move(module),
                       std::move(make_op_context),
                       log_manager->getChild("VerifierInit")->getLogger()));
    }
  } catch (Botan::Exception const &ex) {
    throw InitCryptoProviderException{ex.what()};
  }
}
