/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/hsm_utimaco/verifier.hpp"

#include <fmt/format.h>
#include "common/hexutils.hpp"
#include "common/result.hpp"
#include "cryptography/hsm_utimaco/common.hpp"
#include "cryptography/hsm_utimaco/formatters.hpp"
#include "cryptography/hsm_utimaco/safe_cxi.hpp"
#include "interfaces/common_objects/byte_range.hpp"

using namespace shared_model::crypto::hsm_utimaco;
using namespace shared_model::interface::types;

namespace {

  iroha::expected::Result<cxi::ByteArray, std::string> makeCxiKeyImportBlob(
      iroha::multihash::Type type, PublicKeyByteRangeView public_key) {
    // this is precompiled blob for ed25519 public keys import,
    // other formats need different ones
    unsigned char const kEd25519ImportBase[] = {
        0x4b, 0x42, 0x00, 0x00, 0x00, 0x59, 0x42, 0x48, 0x00, 0x00, 0x00,
        0x27, 0x50, 0x4c, 0x00, 0x00, 0x00, 0x21, 0x00, 0x03, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00,
        0xff, 0x00, 0x1e, 0x00, 0x0d, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
        0x73, 0x32, 0x35, 0x35, 0x31, 0x39, 0x00, 0x4b, 0x43, 0x00, 0x00,
        0x00, 0x26, 0x50, 0x4b, 0x00, 0x00, 0x00, 0x20};
    const size_t kEcdsaEd25519ImportBaseSize =
        std::extent_v<decltype(kEd25519ImportBase)>;

    switch (type) {
      case iroha::multihash::Type::kEd25519Sha2_224:
      case iroha::multihash::Type::kEd25519Sha2_256:
      case iroha::multihash::Type::kEd25519Sha2_384:
      case iroha::multihash::Type::kEd25519Sha2_512:
      case iroha::multihash::Type::kEd25519Sha3_224:
      case iroha::multihash::Type::kEd25519Sha3_256:
      case iroha::multihash::Type::kEd25519Sha3_384:
      case iroha::multihash::Type::kEd25519Sha3_512: {
        const size_t kPublicKeySize = 32;
        ByteRange public_key_range{public_key};
        if (public_key_range.size() != kPublicKeySize) {
          return iroha::expected::makeError(fmt::format(
              "Wrong public key size: {}.", public_key_range.size()));
        }
        cxi::ByteArray import_blob{
            reinterpret_cast<char const *>(kEd25519ImportBase),
            kEcdsaEd25519ImportBaseSize};
        import_blob.append(
            reinterpret_cast<char const *>(public_key_range.data()),
            public_key_range.size());
        return import_blob;
      }
      default:
        return iroha::expected::makeError("Unsupported public key type.");
    }
  }

  iroha::expected::Result<cxi::Key, std::string> makeCxiKey(
      cxi::Cxi &cxi,
      iroha::multihash::Type type,
      PublicKeyByteRangeView public_key,
      std::string const &temporary_key_name,
      std::optional<std::string> const &temporary_key_group) {
    return makeCxiKeyImportBlob(type, public_key) | [&](auto const &import_blob)
               -> iroha::expected::Result<cxi::Key, std::string> {
      cxi::PropertyList key_descr;
      key_descr.setName(temporary_key_name.c_str());
      if (temporary_key_group) {
        key_descr.setGroup(temporary_key_group->c_str());
      }
      try {
        return cxi.key_import(CXI_KEY_FLAG_VOLATILE | CXI_KEY_FLAG_OVERWRITE,
                              CXI_KEY_BLOB_SIMPLE,
                              key_descr,
                              import_blob,
                              nullptr);
      } catch (const cxi::Exception &e) {
        return iroha::expected::makeError(
            fmt::format("Could not prepare puclic key: {}", e));
      }
    };
  }
}  // namespace

Verifier::Verifier(std::shared_ptr<Connection> connection,
                   std::string temporary_key_name,
                   std::optional<std::string> temporary_key_group)
    : connection_(std::move(connection)),
      temporary_key_name_(std::move(temporary_key_name)),
      temporary_key_group_(std::move(temporary_key_group)) {}

Verifier::~Verifier() = default;

iroha::expected::Result<void, std::string> Verifier::verify(
    iroha::multihash::Type type,
    shared_model::interface::types::SignatureByteRangeView signature,
    shared_model::interface::types::ByteRange message,
    shared_model::interface::types::PublicKeyByteRangeView public_key) const {
  using ReturnType = iroha::expected::Result<void, std::string>;

  auto cxi_algo = multihashToCxiHashAlgo(type);
  if (not cxi_algo) {
    return iroha::expected::makeError("Unsupported signature type.");
  }

  std::lock_guard<std::mutex> lock{connection_->mutex};

  cxi::Cxi &cxi = *connection_->cxi;

  return makeCxiKey(
             cxi, type, public_key, temporary_key_name_, temporary_key_group_)
             | [&cxi, cxi_algo, &message, &signature](
                   cxi::Key key) -> ReturnType {
    cxi::ByteArray cxi_message{irohaToCxiBuffer(message)};
    cxi::ByteArray cxi_signature{irohaToCxiBuffer(signature)};

    cxi::MechanismParameter mech;
    mech.set(cxi_algo.value());

    bool verification_successful = false;
    try {
      verification_successful =
          cxi.verify(CXI_FLAG_HASH_DATA | CXI_FLAG_CRYPT_FINAL,
                     key,
                     mech,
                     cxi_message,
                     &cxi_signature,
                     nullptr);
    } catch (const cxi::Exception &e) {
      return iroha::expected::makeError(
          fmt::format("Signature verification failed: {}", e));
    }

    if (verification_successful) {
      return iroha::expected::Value<void>{};
    }
    return iroha::expected::makeError("Wrong signature.");
  };
}

std::vector<iroha::multihash::Type> Verifier::getSupportedTypes() const {
  using iroha::multihash::Type;
#define ALGO_COMMA(z, i, ...) BOOST_PP_TUPLE_ELEM(2, 0, ALGOS_EL##i),
  return {BOOST_PP_REPEAT(NUM_ALGOS, ALGO_COMMA, )};
#undef ALGO_COMMA
}
