/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common/byteutils.hpp"
#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"

#include <gtest/gtest.h>
#include "framework/make_byte_range.hpp"

using iroha::create_keypair;
using iroha::create_seed;
using iroha::sign;
using iroha::stringToBlob;
using iroha::verify;

TEST(Signature, sign_data_size) {
  auto keypair = iroha::create_keypair();

  std::string nonce =
      "c0a5cca43b8aa79eb50e3464bc839dd6fd414fae0ddf928ca23dcebf8a8b8dd0";
  auto signature = sign(iroha::makeByteRange(nonce),
                        keypair.pubkey.getView(),
                        keypair.privkey.getView());

  ASSERT_TRUE(verify(iroha::makeByteRange(nonce),
                     keypair.pubkey.getView(),
                     signature.getView()));
}
