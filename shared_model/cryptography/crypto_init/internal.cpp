/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/crypto_init/internal.hpp"

#include "common/result.hpp"
#include "crypto/keys_manager_impl.hpp"
#include "cryptography/crypto_init/from_config.hpp"
#include "cryptography/crypto_provider/crypto_signer.hpp"
#include "cryptography/crypto_provider/crypto_signer_internal.hpp"
#include "cryptography/crypto_provider/crypto_verifier.hpp"
#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"
#include "cryptography/ed25519_sha3_impl/verifier.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "logger/logger_manager.hpp"
#include "multihash/multihash.hpp"
#include "multihash/type.hpp"

#if defined(USE_LIBURSA)
#include "cryptography/ed25519_ursa_impl/crypto_provider.hpp"
#include "cryptography/ed25519_ursa_impl/verifier.hpp"
#define ED25519_PROVIDER CryptoProviderEd25519Ursa
#endif

using namespace shared_model::crypto;
using namespace shared_model::interface::types;

namespace {
  std::unique_ptr<shared_model::crypto::CryptoSigner> makeCryptoSignerInternal(
      std::string const &keypair_name,
      logger::LoggerManagerTreePtr log_manager) {
    using SignerOrError =
        iroha::expected::Result<std::unique_ptr<CryptoSigner>, std::string>;
    SignerOrError signer_result;
    signer_result =
        (keypair_name.empty()
             ? iroha::expected::makeError("please specify --keypair_name to "
                                          "use internal crypto signer")
             : iroha::KeysManagerImpl{keypair_name,
                                      log_manager->getChild("KeysManager")
                                          ->getLogger()}
                   .loadKeys(boost::none))
        |
        [&](auto &&keypair) {
          return iroha::hexstringToBytestringResult(keypair.publicKey()) |
                     [&keypair](auto const &public_key) -> SignerOrError {
            using DefaultSigner =
                shared_model::crypto::CryptoProviderEd25519Sha3;
            if (public_key.size() == DefaultSigner::kPublicKeyLength) {
              return std::make_unique<CryptoSignerInternal<DefaultSigner>>(
                  std::move(keypair));
            }
            return iroha::multihash::createFromBuffer(makeByteRange(public_key))
                       |
                       [&keypair](const iroha::multihash::Multihash &public_key)
                       -> SignerOrError {
              // prevent unused warnings when compiling without any additional
              // crypto engines:
              (void)keypair;

              using iroha::multihash::Type;
              switch (public_key.type) {
#if defined(ED25519_PROVIDER)
                case Type::ed25519_sha2_256:
                  return std::make_unique<
                      CryptoSignerInternal<ED25519_PROVIDER>>(
                      std::move(keypair));
#endif
                default:
                  return iroha::expected::makeError(
                      "Unknown crypto algorithm.");
              };
            };
          };
        };
    if (auto e = iroha::expected::resultToOptionalError(signer_result)) {
      throw iroha::InitCryptoProviderException{
          fmt::format("Failed to load keypair: {}", e.value())};
    }
    return std::move(signer_result).assumeValue();
  }
}  // namespace

void iroha::initCryptoProviderInternal(
    iroha::PartialCryptoInit initializer,
    IrohadConfig::Crypto::Default const &param,
    logger::LoggerManagerTreePtr log_manager) {
  if (initializer.init_signer) {
    if (not param.keypair) {
      throw InitCryptoProviderException{"Keypair not specified."};
    }
    initializer.init_signer.value()(
        makeCryptoSignerInternal(param.keypair.value(), log_manager));
  }
  if (initializer.init_verifier) {
    initializer.init_verifier.value()(
        std::make_unique<shared_model::crypto::ed25519_sha3::Verifier>());
#if defined(USE_LIBURSA)
    initializer.init_verifier.value()(
        std::make_unique<shared_model::crypto::ursa::Verifier>());
#endif
  }
}
