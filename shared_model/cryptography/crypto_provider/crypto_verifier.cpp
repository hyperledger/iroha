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
  /**
   * Verify that given signature matches given blob using a multihash public key
   * @param signature to verify
   * @param source signed data to verify
   * @param public_key public key in multihash format
   * @return boolean verification result if verification could be performed,
   *   with true meaning that signature is OK and false otherwise, or a pointer
   *   to error description if verification could not be performed
  inline Result<bool, const char *> verifyMultihash(
      ByteRange signature, const Blob &source, const Multihash &public_key) {
    const ByteRange source_range = source.range();
    const ByteRange &pubkey_range = public_key.data;

    // prevent unused warnings when compiling without any additional crypto
    // engines:
    (void)source_range;
    (void)pubkey_range;

    using iroha::multihash::Type;
    switch (public_key.type) {
#if defined(ED25519_PROVIDER)
      case Type::ed25519_sha2_256:
        return ED25519_PROVIDER::verify(signature, source_range, pubkey_range);
#endif
      default:
        return makeError("Unimplemented signature algorithm.");
    };
  }
   */

  /**
   * Verify the given signature with specific algorithm verifier.
   * @param type the algorithm type
   * @param signature to verify
   * @param source signed data to verify
   * @param public_key public key raw bytes
   * @return boolean verification result if verification could be performed,
   *   with true meaning that signature is OK and false otherwise, or a pointer
   *   to error description if verification could not be performed
   */
  inline Result<void, std::string> verifySpecificType(
      iroha::multihash::Type type,
      SignatureByteRangeView signature,
      ByteRange source,
      PublicKeyByteRangeView public_key,
      std::map<iroha::multihash::Type,
               std::reference_wrapper<CryptoVerifierMultihash>> const
          &specific_verifiers_by_type) {
    auto it = specific_verifiers_by_type.find(type);
    if (it == specific_verifiers_by_type.end()) {
      return makeError("Unknown signature algorithm.");
    }
    return it->second.get().verify(type, signature, source, public_key);
  }

  /**
   * Verify that given signature matches given blob using a public key in either
   * multihash or default format
   * @param signature to verify
   * @param source signed data to verify
   * @param public_key public key in a yet unknown format
   * @return boolean verification result if verification could be performed,
   *   with true meaning that signature is OK and false otherwise, or a pointer
   *   to error description if verification could not be performed
   */
  inline Result<void, std::string> verifyDefaultOrMultihash(
      SignatureByteRangeView signature,
      const Blob &source,
      PublicKeyByteRangeView public_key,
      std::map<iroha::multihash::Type,
               std::reference_wrapper<CryptoVerifierMultihash>> const
          &specific_verifiers_by_type) {
    const auto get_size = [](const auto &o) {
      return static_cast<const ByteRange &>(o).size();
    };
    if (get_size(public_key) == DefaultVerifier::kPublicKeyLength
        and get_size(signature) == DefaultVerifier::kSignatureLength) {
      return verifySpecificType(iroha::multihash::Type::ed25519_sha3_256,
                                signature,
                                source.range(),
                                public_key,
                                specific_verifiers_by_type);
    }

    return iroha::multihash::createFromBuffer(public_key) |
        [&source, &signature, &specific_verifiers_by_type](
               const Multihash &public_key) {
          return verifySpecificType(public_key.type,
                                    signature,
                                    source.range(),
                                    PublicKeyByteRangeView{public_key.data},
                                    specific_verifiers_by_type);
        };
  }
}  // namespace

Result<void, std::string> CryptoVerifier::verify(
    SignedHexStringView signature,
    const Blob &source,
    PublicKeyHexStringView public_key) const {
  return iroha::hexstringToBytestringResult(signature) |
      [&source, &public_key, this](const auto &signature) {
        return iroha::hexstringToBytestringResult(public_key) |
            [&signature, &source, this](const auto &public_key) {
              return verifyDefaultOrMultihash(
                  SignatureByteRangeView{makeByteRange(signature)},
                  source,
                  PublicKeyByteRangeView{makeByteRange(public_key)},
                  specific_verifiers_by_type_);
            };
      };
}

void CryptoVerifier::addSpecificVerifier(
    std::unique_ptr<CryptoVerifierMultihash> verifier) {
  for (auto type : verifier->getSupportedTypes()) {
    specific_verifiers_by_type_.emplace(type, *verifier);
  }
  specific_verifiers_.emplace_back(std::move(verifier));
}
