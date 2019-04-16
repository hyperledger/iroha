/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <iostream>
#include "common/byteutils.hpp"

using namespace iroha;
using namespace std;

TEST(ConverterTest, UsageTest) {
  cout << "----------| string => convert to blob"
          " => convert to string |----------"
       << endl;

  std::string source = "blob was here!";
  auto blob = stringToBytes(source);
  auto converted = bytesToString(blob);
  ASSERT_EQ(source, converted);
}
