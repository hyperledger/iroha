/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/blob.hpp"
#include <gtest/gtest.h>
#include <memory>

using namespace shared_model::crypto;
using namespace std::literals::string_literals;

class BlobMock : public ::testing::Test {
 public:
  void SetUp() override {
    blob = std::make_shared<Blob>(data);
  }
  std::shared_ptr<Blob> blob;
  std::string data = "Hello \0World"s;
};

/**
 * @given arbitrary string and known its hex representation
 * @when conversion of this string to hex is done
 * @then conversion is done right
 */
TEST_F(BlobMock, HexConversionTest) {
  ASSERT_EQ("48656c6c6f2000576f726c64", blob->hex());
}

/**
 * @given arbitrary string
 * @when making a blob from it
 * @then make sure that the blob's blob stores the same data as string
 */
TEST_F(BlobMock, BlobIsString) {
  auto bin_str = toBinaryString(*blob);
  auto binary = blob->blob();
  size_t sz = binary.size();

  ASSERT_EQ(bin_str.size(), sz);
  for (size_t i = 0; i < sz; ++i) {
    ASSERT_EQ(binary[i], bin_str[i]);
  }
}
