/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/crypto_init/from_config.hpp"

#include <memory>

#include "common/result.hpp"
#include "cryptography/crypto_init/internal.hpp"
#include "cryptography/crypto_provider/crypto_provider.hpp"
#include "cryptography/crypto_provider/crypto_signer.hpp"
#include "cryptography/crypto_provider/crypto_verifier.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "logger/logger_manager.hpp"
#include "main/iroha_conf_literals.hpp"
#include "main/iroha_conf_loader.hpp"
#include "multihash/multihash.hpp"
#include "multihash/type.hpp"

#if defined(USE_HSM_UTIMACO)
#include "cryptography/hsm_utimaco/init.hpp"
#endif

#if defined(USE_PKCS11)
#include "cryptography/pkcs11/init.hpp"
#endif

using namespace shared_model::crypto;

namespace {
  void checkCrypto(CryptoProvider const &crypto_provider) {
    Blob test_blob{"12345"};
    auto signature = crypto_provider.signer->sign(test_blob);
    if (auto e = iroha::expected::resultToOptionalError(
            crypto_provider.verifier->verify(
                shared_model::interface::types::SignedHexStringView{signature},
                test_blob,
                crypto_provider.signer->publicKey()))) {
      throw iroha::InitCryptoProviderException{
          fmt::format("Cryptography startup check failed: {}.", e.value())};
    }
  }
}  // namespace

namespace iroha {
  CryptoProvider makeCryptoProvider(IrohadConfig::Crypto const &config,
                                    std::string const &keypair_name,
                                    logger::LoggerManagerTreePtr log_manager) {
    CryptoProvider crypto_provider;
    crypto_provider.verifier = std::make_shared<CryptoVerifier>();

    struct AlgorithmInitializer {
      IrohadConfig::Crypto::ProviderVariant connection_params;
      PartialCryptoInit what_to_init;
    };

    std::unordered_map<IrohadConfig::Crypto::ProviderId, AlgorithmInitializer>
        initializers;

    const IrohadConfig::Crypto::Default kFallbackDefaultParam{keypair_name};

    auto get_provider_conf_param =
        [&config, &kFallbackDefaultParam](IrohadConfig::Crypto::ProviderId tag)
        -> IrohadConfig::Crypto::ProviderVariant const & {
      const auto conf_it = config.providers.find(tag);
      if (conf_it == config.providers.end()) {
        if (tag == config_members::kCryptoProviderDefault) {
          return kFallbackDefaultParam;
        }
        throw InitCryptoProviderException{fmt::format(
            "Crypto provider with tag '{}' requested but not defined",
            config.signer)};
      }
      return conf_it->second;
    };

    auto get_initializer =
        [&initializers, &get_provider_conf_param](
            IrohadConfig::Crypto::ProviderId tag) -> AlgorithmInitializer & {
      auto init_it = initializers.find(tag);
      if (init_it == initializers.end()) {
        init_it =
            initializers
                .emplace(tag,
                         AlgorithmInitializer{
                             get_provider_conf_param(tag),
                             PartialCryptoInit{std::nullopt, std::nullopt}})
                .first;
      }
      return init_it->second;
    };

    get_initializer(config.signer).what_to_init.init_signer =
        [&crypto_provider](auto signer) {
          crypto_provider.signer = std::move(signer);
        };
    for (auto const &verifier : config.verifiers) {
      get_initializer(verifier).what_to_init.init_verifier =
          [&crypto_provider](auto verifier) {
            crypto_provider.verifier->addSpecificVerifier(std::move(verifier));
          };
    }

    for (auto const &pair : initializers) {
      auto &initializer = pair.second;
      std::visit(
          iroha::make_visitor(
              [&](IrohadConfig::Crypto::Default const &param) {
                initCryptoProviderInternal(initializer.what_to_init,
                                           param,
                                           log_manager->getChild("Internal"));
              },
#if defined(USE_HSM_UTIMACO)
              [&](IrohadConfig::Crypto::HsmUtimaco const &param) {
                initCryptoProviderUtimaco(initializer.what_to_init,
                                          param,
                                          log_manager->getChild("Utimaco"));
              },
#endif
#if defined(USE_PKCS11)
              [&](IrohadConfig::Crypto::Pkcs11 const &param) {
                initCryptoProviderPkcs11(initializer.what_to_init,
                                         param,
                                         log_manager->getChild("Pkcs11"));
              },
#endif
              [&](auto const &param) {
                throw InitCryptoProviderException{fmt::format(
                    "Crypto provider '{}' is not configured.", param.kName)};
              }),
          initializer.connection_params);
    }

    assert(crypto_provider.signer);
    assert(crypto_provider.verifier);
    checkCrypto(crypto_provider);
    return crypto_provider;
  }
}  // namespace iroha
