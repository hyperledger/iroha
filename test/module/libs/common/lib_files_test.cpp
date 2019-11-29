/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common/files.hpp"

#include <fstream>
#include <iostream>

#include <gtest/gtest.h>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include "common/hexutils.hpp"
#include "common/result.hpp"
#include "framework/result_gtest_checkers.hpp"

namespace fs = boost::filesystem;

namespace {
  const std::string kText =
      "Ohne Sinnlichkeit würde uns kein Gegenstand gegeben,\n"
      "und ohne Verstand keiner gedacht werden.\n";

  const std::string kBlobString{
      iroha::hexstringToBytestringResult(
          "e00045003a0000239ae6d8c83a20423743e68039034b23dbc1ea5b8017ad37aa4b6c"
          "bd5af29aa0e8d1d1ce6d399e509eda7a7e193ee3e6c30b935abc493acf400000")
          .assumeValue()};

  const std::vector<uint8_t> kBlob{kBlobString.begin(), kBlobString.end()};

  const fs::path kTestDir{PATH_TEST_DIR};
  const fs::path kTextFilePath{kTestDir / "text"};
  const fs::path kBinFilePath{kTestDir / "binary"};
  const fs::path kNonexistentFilePath{kTestDir / "nonexistent"};
}  // namespace

class ReadFileTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    for (const auto &f : {kBinFilePath, kTextFilePath, kNonexistentFilePath}) {
      if (fs::exists(f)) {
        fs::remove(f);
      }
    }
    std::ofstream out(kTextFilePath.string(), std::ios::trunc);
    out << kText;
    out.close();
    out.open(kBinFilePath.string(), std::ios::binary | std::ios::trunc);
    out << kBlobString;
    out.close();
  }
};

TEST_F(ReadFileTest, TextFile) {
  auto result = iroha::readTextFile(kTextFilePath);
  IROHA_ASSERT_RESULT_VALUE(result) << "Could not read " << kTextFilePath;
  EXPECT_EQ(result.assumeValue(), kText);
}

TEST_F(ReadFileTest, BinaryFile) {
  auto result = iroha::readBinaryFile(kBinFilePath);
  IROHA_ASSERT_RESULT_VALUE(result) << "Could not read " << kBinFilePath;
  EXPECT_EQ(result.assumeValue(), kBlob);
}

TEST_F(ReadFileTest, NonexistentFile) {
  ASSERT_FALSE(fs::exists(kNonexistentFilePath));
  auto result = iroha::readBinaryFile(kNonexistentFilePath);
  IROHA_ASSERT_RESULT_ERROR(result);
}
