/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/hsm_utimaco/signer.hpp"

#include <fmt/format.h>
#include "common/hexutils.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/hsm_utimaco/common.hpp"
#include "cryptography/hsm_utimaco/safe_cxi.hpp"
#include "interfaces/common_objects/byte_range.hpp"
#include "multihash/multihash.hpp"

using namespace shared_model::crypto;
using namespace shared_model::crypto::hsm_utimaco;
using namespace shared_model::interface::types;

Signer::Signer(std::shared_ptr<Connection> connection,
               std::unique_ptr<cxi::Key> key,
               iroha::multihash::Type multihash_type,
               int cxi_algo)
    : connection_(std::move(connection)),
      key_(std::move(key)),
      public_key_(iroha::multihash::encode<std::string>(
          multihash_type,
          cxiToIrohaBufferView(cxi::KeyBlob{
              connection_->cxi->key_export(
                  CXI_KEY_BLOB_SIMPLE | CXI_KEY_TYPE_PUBLIC, *key_, NULL, 0)}
                                   .getPublic()))),
      cxi_algo_(cxi_algo) {
  assert(multihashToCxiHashAlgo(multihash_type) == cxi_algo_);
}

Signer::~Signer() = default;

std::string Signer::sign(const shared_model::crypto::Blob &blob) const {
  std::lock_guard<std::mutex> lock{connection_->mutex};

  cxi::MechanismParameter mech;
  mech.set(cxi_algo_);

  cxi::ByteArray result =
      connection_->cxi->sign(CXI_FLAG_HASH_DATA | CXI_FLAG_CRYPT_FINAL,
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
