/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "common/byteutils.hpp"

using namespace iroha;
using namespace std::string_literals;

/**
 * @given hex string
 * @when hex string was converted to binary string
 * @then converted string match the result we are expected
 */
TEST(StringConverterTest, ConvertHexToBinary) {
  std::string hex = "ff000233551117daa110050399";
  std::string bin = "\xFF\x00\x02\x33\x55\x11\x17\xDA\xA1\x10\x05\x03\x99"s;
  ASSERT_EQ(hexstringToBytestring(hex).value(), bin);
}

/**
 * @given invalid hex string
 * @when string is converted to binary string
 * @then boost::none is returned
 */
TEST(StringConverterTest, InvalidHexToBinary) {
  std::string invalid_hex = "au";
  ASSERT_FALSE(hexstringToBytestring(invalid_hex));
}

/**
 * @given binary string
 * @when binary string was converted to hex string
 * @then converted string match the result we are expected
 */
TEST(StringConverterTest, ConvertBinaryToHex) {
  std::string bin = "\xFF\x00\x02\x33\x55\x11\x17\xDA\xA1\x10\x05\x03\x99"s;
  ASSERT_EQ(bytestringToHexstring(bin), "ff000233551117daa110050399");
}

/**
 * @given hex string of length 256 with all possible byte values
 * @when convert it to byte string and back
 * @then resulted string is the same as given one
 */
TEST(StringConverterTest, ConvertHexToBinaryAndBack) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (int i = 0; i < 256; ++i) {
    ss << std::setw(2) << i;
  }
  ASSERT_EQ(ss.str(),
            bytestringToHexstring(hexstringToBytestring(ss.str()).value()));
}
