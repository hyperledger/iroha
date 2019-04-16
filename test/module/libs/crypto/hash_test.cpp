/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp>

#define LOOP_N (100)

using iroha::sha3_256;
using iroha::sha3_512;

// Test Data cited by https://emn178.github.io/online-tools/

TEST(Hash, sha3_256_empty_text) {
  std::string res =
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
  std::string str_("");
  std::vector<uint8_t> str(str_.begin(), str_.end());
  ASSERT_STREQ(sha3_256(str.data(), str.size()).to_hexstring().c_str(),
               res.c_str());
}

TEST(Hash, sha3_512_empty_text) {
  std::string res =
      "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123a"
      "f1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
  std::string str_("");
  std::vector<uint8_t> str(str_.begin(), str_.end());
  ASSERT_STREQ(sha3_512(str.data(), str.size()).to_hexstring().c_str(),
               res.c_str());
}

TEST(Hash, sha3_256_ASCII_text) {
  std::string res =
      "cb7c96616a2466df29a1edc2979ef5080945f92d1907c08a55b502eba063d638";
  std::string str_("Is the Order a distributed ledger?");
  std::vector<uint8_t> str(str_.begin(), str_.end());
  ASSERT_STREQ(sha3_256(str.data(), str.size()).to_hexstring().c_str(),
               res.c_str());
}

TEST(Hash, sha3_256_JP_text) {
  std::string res =
      "3cd375d2948fd4e03e83c104fb5abe47a9ce79f770fe72d1a79c9e9b1b0621f1";
  std::string str_("ご注文は分散台帳ですか？");
  std::vector<uint8_t> str(str_.begin(), str_.end());
  ASSERT_STREQ(sha3_256(str.data(), str.size()).to_hexstring().c_str(),
               res.c_str());
}

TEST(Hash, sha3_512_ASCII_text) {
  std::string res =
      "ec23f5e93bf0626496bac7de45bbde02b5d4eafd5fb597f46ed9d1b4bb5946e58d92be2e"
      "fe861305ec7a1a32b316935e17f19d169e063b2bd6e1a24b155f8e55";
  std::string str_("Is the Order a distributed ledger?");
  std::vector<uint8_t> str(str_.begin(), str_.end());
  ASSERT_STREQ(sha3_512(str.data(), str.size()).to_hexstring().c_str(),
               res.c_str());
}

TEST(Hash, sha3_512_JP_text) {
  std::string res =
      "5df6fa84a650819d59d422d289159420a8830f49e63a222fd5964f220ff6f05386e41304"
      "1897b456d1eacc79bed3acccdc816340263cfff82dd83ddd10e193da";
  std::string str_("ご注文は分散台帳ですか？");
  std::vector<uint8_t> str(str_.begin(), str_.end());
  ASSERT_STREQ(sha3_512(str.data(), str.size()).to_hexstring().c_str(),
               res.c_str());
}

TEST(Hash, sha3_256_JP_text_LOOP) {
  std::string res =
      "3cd375d2948fd4e03e83c104fb5abe47a9ce79f770fe72d1a79c9e9b1b0621f1";
  std::string str_("ご注文は分散台帳ですか？");
  std::vector<uint8_t> str(str_.begin(), str_.end());
  for (int i = 0; i < LOOP_N; i++) {
    EXPECT_STREQ(sha3_256(str.data(), str.size()).to_hexstring().c_str(),
                 res.c_str());
  }
}

TEST(Hash, sha3_512_JP_text_LOOP) {
  std::string res =
      "5df6fa84a650819d59d422d289159420a8830f49e63a222fd5964f220ff6f05386e41304"
      "1897b456d1eacc79bed3acccdc816340263cfff82dd83ddd10e193da";
  std::string str_("ご注文は分散台帳ですか？");
  std::vector<uint8_t> str(str_.begin(), str_.end());

  for (int i = 0; i < LOOP_N; i++) {
    EXPECT_STREQ(sha3_512(str.data(), str.size()).to_hexstring().c_str(),
                 res.c_str());
  }
}

TEST(Hash, sha3_256_RU_text) {
  std::string res =
      "cf5987add8080bbf2e70e45d913acc1d4fc919ff4634428a71dabb3e0777a1a7";
  std::string str_(
      "Является ли Order распределённой программой финансового учёта?");
  std::vector<uint8_t> str(str_.begin(), str_.end());
  ASSERT_STREQ(sha3_256(str.data(), str.size()).to_hexstring().c_str(),
               res.c_str());
}

TEST(Hash, sha3_512_RU_text) {
  std::string res =
      "920078690881a2fb4a2b59874ac318608534f173fa019065525f63b5efa3893269bbd20e"
      "339300760eace14edeb28415ade75118aaff810194901583e817878c";
  std::string str_(
      "Является ли Order распределённой программой финансового учёта?");
  std::vector<uint8_t> str(str_.begin(), str_.end());
  ASSERT_STREQ(sha3_512(str.data(), str.size()).to_hexstring().c_str(),
               res.c_str());
}

TEST(Hash, sha3_256_RU_text_LOOP) {
  std::string res =
      "cf5987add8080bbf2e70e45d913acc1d4fc919ff4634428a71dabb3e0777a1a7";
  std::string str_(
      "Является ли Order распределённой программой финансового учёта?");
  std::vector<uint8_t> str(str_.begin(), str_.end());
  for (int i = 0; i < LOOP_N; i++) {
    EXPECT_STREQ(sha3_256(str.data(), str.size()).to_hexstring().c_str(),
                 res.c_str());
  }
}

TEST(Hash, sha3_512_RU_text_LOOP) {
  std::string res =
      "920078690881a2fb4a2b59874ac318608534f173fa019065525f63b5efa3893269bbd20e"
      "339300760eace14edeb28415ade75118aaff810194901583e817878c";
  std::string str_(
      "Является ли Order распределённой программой финансового учёта?");
  std::vector<uint8_t> str(str_.begin(), str_.end());
  for (int i = 0; i < LOOP_N; i++) {
    EXPECT_STREQ(sha3_512(str.data(), str.size()).to_hexstring().c_str(),
                 res.c_str());
  }
}
