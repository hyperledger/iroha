/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common/byteutils.hpp"
#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"

#include <gtest/gtest.h>

using iroha::create_keypair;
using iroha::create_seed;
using iroha::sign;
using iroha::stringToBlob;
using iroha::verify;

TEST(Signature, sign_data_size) {
  auto keypair = iroha::create_keypair();

  std::string nonce =
      "c0a5cca43b8aa79eb50e3464bc839dd6fd414fae0ddf928ca23dcebf8a8b8dd0";
  auto signature = sign((const unsigned char *)nonce.c_str(),
                        nonce.size(),
                        keypair.pubkey,
                        keypair.privkey);

  ASSERT_TRUE(verify((const unsigned char *)nonce.c_str(),
                     nonce.size(),
                     keypair.pubkey,
                     signature));
}
