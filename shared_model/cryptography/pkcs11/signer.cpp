/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/pkcs11/signer.hpp"

#include <memory>

#include <botan/auto_rng.h>
#include <botan/emsa1.h>
#include <botan/pk_keys.h>
#include <botan/pubkey.h>
#include <ed25519/ed25519/ed25519.h>
#include <fmt/format.h>
#include "common/hexutils.hpp"
//#include "cryptography/pkcs11/common.hpp"
#include "cryptography/pkcs11/data.hpp"
#include "interfaces/common_objects/byte_range.hpp"
#include "multihash/multihash.hpp"

using namespace shared_model::crypto;
using namespace shared_model::crypto::pkcs11;
using namespace shared_model::interface::types;

Signer::Signer(std::shared_ptr<Data> data,
               std::unique_ptr<Botan::Private_Key> private_key)
    : data_(std::move(data)),
      private_key_(std::move(private_key)),
      rng_(std::make_unique<Botan::AutoSeeded_RNG>()),
      signer_(std::make_unique<Botan::PK_Signer>(
          *private_key_, *rng_, Botan::EMSA1{data_->hash.get()})),
      public_key_(iroha::multihash::encode<std::string>(
          makeByteRange(private_key_->public_key_bits()))) {
  assert(multihashToCxiHashAlgo(multihash_type) == cxi_algo_);
}

Signer::~Signer() = default;

std::string Signer::sign(const shared_model::crypto::Blob &blob) const {
  std::lock_guard<std::mutex> lock{connection_.mutex};

  cxi::MechanismParameter mech;
  mech.set(cxi_algo_);

  cxi::ByteArray result =
      connection_.cxi->sign(CXI_FLAG_HASH_DATA | CXI_FLAG_CRYPT_FINAL,
                            *key_,
                            mech,
                            irohaToCxiBuffer(blob.range()),
                            nullptr);

  return iroha::bytestringToHexstring(cxiToIrohaBufferView(std::move(result)));
}

PublicKeyHexStringView Signer::publicKey() const {
  return PublicKeyHexStringView{public_key_};
}

std::string Signer::toString() const {
  return fmt::format("HSM Utimaco cryptographic signer with public key '{}'",
                     public_key_);
}
