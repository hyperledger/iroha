/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/gost3410_impl/signer.hpp"

#include "crypto/hash_types.hpp"
#include "cryptography/gost3410_impl/internal/gost_impl.hpp"
#include "common/hexutils.hpp"

namespace shared_model::crypto::gost3410 {
  std::string Signer::sign(const Blob &blob, const Keypair &keypair){
    auto res = gost3410::sign(toBinaryString(blob), 
              keypair.privateKey().blob().data(),
              keypair.privateKey().blob().size());
    return iroha::bytestringToHexstring(
              interface::types::makeByteRange(res.data(), res.size()));
  } 
} // namespace shared_model::crypto::gost3410
