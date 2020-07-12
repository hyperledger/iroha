/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/pkcs11/signer.hpp"

#include <memory>

#include <botan/auto_rng.h>
#include <botan/emsa1.h>
#include <botan/p11_module.h>
#include <botan/pk_keys.h>
#include <botan/pubkey.h>
#include <fmt/format.h>
#include "common/hexutils.hpp"
//#include "cryptography/pkcs11/common.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/pkcs11/algorithm_identifier.hpp"
#include "cryptography/pkcs11/data.hpp"
#include "interfaces/common_objects/byte_range.hpp"
#include "multihash/multihash.hpp"

using namespace shared_model::crypto;
using namespace shared_model::crypto::pkcs11;
using namespace shared_model::interface::types;

Signer::Signer(std::shared_ptr<Botan::PKCS11::Module> module,
               OperationContext operation_context,
               std::unique_ptr<Botan::Private_Key> private_key,
               char const *emsa_name,
               iroha::multihash::Type multihash_type)
    : module_(std::move(module)),
      operation_context_(std::move(operation_context)),
      private_key_(std::move(private_key)),
      rng_(std::make_unique<Botan::AutoSeeded_RNG>()),
      signer_(
          std::make_unique<Botan::PK_Signer>(*private_key_, *rng_, emsa_name)),
      public_key_(iroha::multihash::encode<std::string>(
          multihash_type, makeByteRange(private_key_->public_key_bits()))) {
  Botan::PKCS11::Info module_info = operation_context_.module.get_info();
  Botan::PKCS11::SlotInfo slot_info = operation_context_.slot.get_slot_info();
  description_ = fmt::format(
      "PKCS11 cryptographic signer "
      "using library {} version {}.{} from {}, "
      "slot {}, "
      "algorithm {} {}, "
      "public key '{}'",
      module_info.libraryDescription,
      module_info.libraryVersion.major,
      module_info.libraryVersion.minor,
      module_info.manufacturerID,
      slot_info.slotDescription,
      emsa_name,
      private_key_->algo_name(),
      public_key_);
}

Signer::~Signer() = default;

std::string Signer::sign(const shared_model::crypto::Blob &blob) const {
  return iroha::bytestringToHexstring(
      makeByteRange(signer_->sign_message(blob.blob(), *rng_)));
}

PublicKeyHexStringView Signer::publicKey() const {
  return PublicKeyHexStringView{public_key_};
}

std::string Signer::toString() const {
  return description_;
}
