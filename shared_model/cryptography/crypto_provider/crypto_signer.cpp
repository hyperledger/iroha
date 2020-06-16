/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/crypto_provider/crypto_signer.hpp"

#include "common/hexutils.hpp"
#include "common/result.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"
#include "cryptography/keypair.hpp"
#include "interfaces/common_objects/byte_range.hpp"
#include "multihash/multihash.hpp"
#include "multihash/type.hpp"

#if defined(USE_LIBURSA)
#include "cryptography/ed25519_ursa_impl/crypto_provider.hpp"
#define ED25519_PROVIDER CryptoProviderEd25519Ursa
#endif

using namespace iroha::expected;
using namespace shared_model::crypto;
using namespace shared_model::interface::types;

using DefaultSigner = CryptoProviderEd25519Sha3;
using iroha::multihash::Multihash;

std::string CryptoSigner::sign(const Blob &blob, const Keypair &keypair) {
  if (iroha::hexstringToBytestringSize(keypair.publicKey())
      == DefaultSigner::kPublicKeyLength) {
    return DefaultSigner::sign(blob, keypair);
  }

  auto signing_result =
      iroha::hexstringToBytestringResult(keypair.publicKey()) |
      [](auto const &public_key) {
        return iroha::multihash::createFromBuffer(makeByteRange(public_key));
      }
      | [&blob, &keypair](
            const Multihash &public_key) -> Result<std::string, char const *> {
    // prevent unused warnings when compiling without any additional crypto
    // engines:
    (void)blob;
    (void)keypair;

    using iroha::multihash::Type;
    switch (public_key.type) {
#if defined(ED25519_PROVIDER)
      case Type::ed25519pub:
        return ED25519_PROVIDER::sign(blob, keypair);
#endif
      default:
        return makeError("Unimplemented signature algorithm.");
    };
  };

  return std::move(signing_result)
      .match([](auto &&signature) { return std::move(signature.value); },
             [](const auto & /* error */) { return std::string{}; });
}
