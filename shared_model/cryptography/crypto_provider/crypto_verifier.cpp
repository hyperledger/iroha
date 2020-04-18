/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/crypto_provider/crypto_verifier.hpp"

#include "common/hexutils.hpp"
#include "common/result.hpp"
#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"
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

using iroha::multihash::Multihash;

using DefaultVerifier = CryptoProviderEd25519Sha3;

namespace {
  inline Result<bool, const char *> verifyMultihash(
      const ByteRange &signature,
      const Blob &source,
      const Multihash &public_key) {
    const ByteRange source_range = source.range();
    const ByteRange &pubkey_range = public_key.data;

    using iroha::multihash::Type;
    switch (public_key.type) {
#if defined(ED25519_PROVIDER)
      case Type::ed25519pub:
        return ED25519_PROVIDER::verify(signature, source_range, pubkey_range);
#endif
      default:
        return makeError("Unimplemented signature algorithm.");
    };
  }

  inline Result<bool, const char *> verifyDefaultOrMultihash(
      const SignatureByteRangeView &signature,
      const Blob &source,
      const PublicKeyByteRangeView &public_key) {
    const auto get_size = [](const auto &o) {
      return static_cast<const ByteRange &>(o).size();
    };
    if (get_size(public_key) == DefaultVerifier::kPublicKeyLength
        and get_size(signature) == DefaultVerifier::kSignatureLength) {
      return DefaultVerifier::verify(signature, source, public_key);
    }

    return iroha::multihash::createFromBuffer(public_key) |
        [&source, &signature](const Multihash &public_key) {
          return verifyMultihash(signature, source, public_key);
        };
  }
}  // namespace

Result<void, const char *> CryptoVerifier::verify(
    const SignedHexStringView &signature,
    const Blob &source,
    const PublicKeyHexStringView &public_key) {
  return iroha::hexstringToBytestringResult(signature) |
      [&source, &public_key](const auto &signature) {
        return iroha::hexstringToBytestringResult(public_key) |
            [&signature, &source](const auto &public_key) {
              return verifyDefaultOrMultihash(
                         makeStrongView<SignatureByteRangeView>(signature),
                         source,
                         makeStrongView<PublicKeyByteRangeView>(public_key))
                         | [](const auto &verification_result)
                         -> Result<void, const char *> {
                if (not verification_result) {
                  return "Bad signature.";
                }
                return Value<void>{};
              };
            };
      };
}
