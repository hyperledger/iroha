/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multihash/multihash.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "framework/result_gtest_checkers.hpp"
#include "interfaces/common_objects/byte_range.hpp"
#include "multihash/type.hpp"
#include "multihash/varint.hpp"

using namespace iroha::multihash;
using namespace shared_model::interface::types;

inline ByteRange operator""_byterange(const char *c, size_t s) {
  return ByteRange{reinterpret_cast<const std::byte *>(c), s};
}

inline std::basic_string<std::byte> operator""_bytestring(const char *c,
                                                          size_t s) {
  return std::basic_string<std::byte>{reinterpret_cast<const std::byte *>(c),
                                      s};
}

static const std::initializer_list<uint64_t> kInts = {
    0, 1, 0xF0, 0xFF, 0xFFFF, 0xFFFFFF};

class VarIntTestParam : public ::testing::TestWithParam<uint64_t> {};

/**
 *   @given an integer
 *   @when encode and decode varint
 *   @then result is equal to former integer
 **/
TEST_P(VarIntTestParam, SingleIntEncDec) {
  std::basic_string<std::byte> buffer;
  encodeVarInt(GetParam(), buffer);
  uint64_t read_number = 0;
  ByteRange buffer_view = makeByteRange(buffer);
  EXPECT_TRUE(readVarInt(buffer_view, read_number));
  EXPECT_EQ(GetParam(), read_number);
}

INSTANTIATE_TEST_SUITE_P(Ints, VarIntTestParam, ::testing::ValuesIn(kInts));

/**
 *   @given a sequence of integers
 *   @when encode and decode the sequentially to varint
 *   @then result is equal to former integer
 *      @and past-the-end read fails
 **/
TEST(VarIntTest, SequentialValid) {
  std::basic_string<std::byte> buffer;
  for (auto i : kInts) {
    encodeVarInt(i, buffer);
  }
  ByteRange buffer_view = makeByteRange(buffer);
  for (auto i : kInts) {
    uint64_t read_number = 0;
    EXPECT_TRUE(readVarInt(buffer_view, read_number));
    EXPECT_EQ(i, read_number);
  }
  // past-the-end read must fail
  EXPECT_THAT(buffer_view, ::testing::IsEmpty());
  uint64_t read_number = 0;
  EXPECT_FALSE(readVarInt(buffer_view, read_number));
}

/**
 *   @given b buffer with an integer encoded to varint with last byte truncated
 *   @when decode the buffer
 *   @then decoding fails
 *      @and buffer out-param is not changed
 **/
TEST(VarIntTest, TryReadTruncatedBuffer) {
  // --- given ---
  std::basic_string<std::byte> buffer;
  encodeVarInt(123456ul, buffer);
  ByteRange buffer_view{buffer.data(), buffer.size() - 1};
  ASSERT_GE(buffer_view.size(), 0);
  ByteRange buffer_view_original = buffer_view;

  // --- when ---
  uint64_t read_number = 0;
  EXPECT_FALSE(readVarInt(buffer_view, read_number));

  // --- then ---
  EXPECT_EQ(buffer_view.data(), buffer_view_original.data());
  EXPECT_EQ(buffer_view.size(), buffer_view_original.size());
}

static const std::initializer_list<Type> kTypes = {
    Type::sha256, Type::blake2s128, Type::ed25519pub};
static const std::basic_string<std::byte> kData = "some data"_bytestring;

class MultihashTestTypeParam : public ::testing::TestWithParam<Type> {};

/**
 *   @given a buffer with a hash
 *   @when creating a multihash using the buffer
 *   @then a correct multihash object is created
 **/
TEST_P(MultihashTestTypeParam, CreateFromValidBuffer) {
  std::basic_string<std::byte> buffer;
  encodeVarIntType(GetParam(), buffer);
  encodeVarInt(kData.size(), buffer);
  buffer.append(kData);

  const auto multihash_result = createFromBuffer(buffer);
  IROHA_ASSERT_RESULT_VALUE(multihash_result);
  const iroha::multihash::Multihash &multihash = multihash_result.assumeValue();
  EXPECT_EQ(multihash.type, GetParam());
  EXPECT_EQ(multihash.data, kData);
}

INSTANTIATE_TEST_SUITE_P(Types,
                         MultihashTestTypeParam,
                         ::testing::ValuesIn(kTypes));

/**
 *   @given a buffer with invalid varint in type field
 *   @when creating a multihash using the buffer
 *   @then error is returned
 **/
TEST(MultihashTest, CreateFromBufferWithBadType) {
  const auto multihash_result =
      createFromBuffer("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"_byterange);
  IROHA_ASSERT_RESULT_ERROR(multihash_result);
  const char *error = multihash_result.assumeError();
  EXPECT_THAT(error, ::testing::HasSubstr("type"));
}

/**
 *   @given a buffer with invalid varint in length field
 *   @when creating a multihash using the buffer
 *   @then error is returned
 **/
TEST(MultihashTest, CreateFromBufferWithBadLength) {
  const auto multihash_result =
      createFromBuffer("\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff"_byterange);
  IROHA_ASSERT_RESULT_ERROR(multihash_result);
  const char *error = multihash_result.assumeError();
  EXPECT_THAT(error, ::testing::HasSubstr("length"));
}

/**
 *   @given a buffer with data length mismatch
 *   @when creating a multihash using the buffer
 *   @then error is returned
 **/
TEST(MultihashTest, CreateFromBufferWithWrongLength) {
  const auto multihash_result =
      createFromBuffer("\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff"_byterange);
  IROHA_ASSERT_RESULT_ERROR(multihash_result);
  const char *error = multihash_result.assumeError();
  EXPECT_THAT(error, ::testing::HasSubstr("actual length"));
}
