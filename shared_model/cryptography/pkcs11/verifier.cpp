/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/pkcs11/verifier.hpp"

#include <botan/emsa.h>
#include <botan/exceptn.h>
#include <botan/p11.h>
#include <botan/p11_slot.h>
#include <botan/pk_ops.h>
#include <fmt/core.h>
#include <fmt/format.h>
#include <memory>
#include <utility>
#include "common/bind.hpp"
#include "common/hexutils.hpp"
#include "common/result.hpp"
#include "cryptography/crypto_init/from_config.hpp"
#include "cryptography/pkcs11/algorithm_identifier.hpp"
#include "interfaces/common_objects/byte_range.hpp"
#include "multihash/type.hpp"

using namespace shared_model::crypto::pkcs11;
using namespace shared_model::interface::types;

using iroha::operator|;

Verifier::Verifier(OperationContextFactory operation_context_factory,
                   std::vector<iroha::multihash::Type> supported_types)
    : operation_context_factory_(std::move(operation_context_factory)),
      supported_types_(std::move(supported_types)) {
  auto operation_context = operation_context_factory_();
  Botan::PKCS11::Info module_info = operation_context.module.get_info();
  Botan::PKCS11::SlotInfo slot_info = operation_context.slot.get_slot_info();
  description_ = fmt::format(
      "PKCS11 cryptographic verifier "
      "using library {} version {}.{} from {}, "
      "slot {}",
      module_info.libraryDescription,
      module_info.libraryVersion.major,
      module_info.libraryVersion.minor,
      module_info.manufacturerID,
      slot_info.slotDescription);
}

Verifier::~Verifier() = default;

iroha::expected::Result<void, std::string> Verifier::verify(
    iroha::multihash::Type type,
    shared_model::interface::types::SignatureByteRangeView signature,
    shared_model::interface::types::ByteRange message,
    shared_model::interface::types::PublicKeyByteRangeView public_key) const {
  try {
    // the temporary public key will be destroyed with this operation_context
    auto operation_context = operation_context_factory_();

    auto opt_emsa_name = getEmsaName(type);
    auto opt_pkcs11_pubkey =
        createPublicKeyOfType(type, operation_context.session, public_key);
    assert(opt_emsa_name);
    assert(opt_pkcs11_pubkey);
    if (not opt_emsa_name or not opt_pkcs11_pubkey) {
      return iroha::expected::makeError("Unsupported algorithm.");
    }

    std::unique_ptr<Botan::PK_Ops::Verification> pkcs11_verifier =
        opt_pkcs11_pubkey.value()->create_verification_op(opt_emsa_name.value(),
                                                          {});

    ByteRange signature_raw{signature};
    if (pkcs11_verifier->is_valid_signature(
            reinterpret_cast<uint8_t const *>(signature_raw.data()),
            signature_raw.size())) {
      return iroha::expected::Value<void>{};
    }

    return iroha::expected::makeError("Wrong signature.");
  } catch (Botan::Exception const &ex) {
    return iroha::expected::makeError(
        fmt::format("Could not verify signature: {}", ex.what()));
  }
}

std::vector<iroha::multihash::Type> Verifier::getSupportedTypes() const {
  return supported_types_;
}
