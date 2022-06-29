/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

#include "ordering/ordering_types.hpp"

using ::testing::ByMove;
using ::testing::Ref;
using ::testing::Return;
using ::testing::ReturnRefOfCopy;

struct BloomFilterTest : public ::testing::Test {
  void SetUp() override {
    filter_ = std::make_shared<iroha::ordering::BloomFilter256>();
  }
  std::shared_ptr<iroha::ordering::BloomFilter256> filter_;
};

/**
 * @given Bloom-filter
 * @when set Hash there
 * @then test of that Hash will return true
 */
TEST_F(BloomFilterTest, SimplePos) {
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "0000000000000001000000000000000000000000000000000000000000000000"));
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "0000000000000001000000000000000000000000000000000000000000000000")));
}

/**
 * @given Bloom-filter
 * @when set Hash there
 * @then test of the other Hash will return false
 */
TEST_F(BloomFilterTest, SimpleNeg) {
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "0000000001000000000000000000000000000000000000000000000000000000"));
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "0000000002000000000000000000000000000000000000000000000000000000")));
}

/**
 * @given Bloom-filter
 * @when set multiple Hashes
 * @then test of the Hashes which are not present should return false(remember
 * false-positive)
 */
TEST_F(BloomFilterTest, RandomNeg) {
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "1111111111111111111111111111111111111111111111111111111111111111"));
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "9123594865892659791270573928567890379843798672987395677893427597"));
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "1298367587946526947123063707196892848236917480679537296387464598"));
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "0000000001000000000000000000000000000000000000000000000000000000"));
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "3897425687243695369327492877329067903476059372073409674908137884"));
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "2934756983467951879084309649306870136709760987508225675248658387"));
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "0912570146507610507436597430971934675798697834672098347567983268"));
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "0000000002000000000000000000000000000000000000000000000000000000")));
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "1598367587913427657436516589643765786191095018987467296387464598")));
}

/**
 * @given Bloom-filter
 * @when set multiple Hashes there
 * @then test the ones that are present will always return true
 */
TEST_F(BloomFilterTest, RandomPos) {
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "1111111111111111111111111111111111111111111111111111111111111111"));
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "9123594865892659791270573928567890379843798672987395677893427597"));
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "1298367587946526947123063707196892848236917480679537296387464598"));
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "0000000000000001000000000000000000000000000000000000000000000000"));
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "3897425687243695369327492877329067903476059372073409674908137884"));
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "2934756983467951879084309649306870136709760987508225675248658387"));
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "0912570146507610507436597430971934675798697834672098347567983268"));
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "0000000000000001000000000000000000000000000000000000000000000000")));
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "1298367587946526947123063707196892848236917480679537296387464598")));
}

/**
 * @given Bloom-filter
 * @when set Hash there
 * @and make clean after that
 * @then test of this Hash will return false
 */
TEST_F(BloomFilterTest, ClearTest) {
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "1111111111111111111111111111111111111111111111111111111111111111"));
  filter_->clear();
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "1111111111111111111111111111111111111111111111111111111111111111")));
}

/**
 * @given Bloom-filter
 * @when set Hash1 there
 * @and make clear after that
 * @and add another Hash2 in BF
 * @then test of the Hash1 will return false and test Hash 2 will return true
 */
TEST_F(BloomFilterTest, Clear2Test) {
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "9123594865892659791270573928567890379843798672987395677893427597"));
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "9123594865892659791270573928567890379843798672987395677893427597")));
  filter_->clear();
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "9123594865892659791270573928567890379843798672987395677893427597")));
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "1298367587946526947123063707196892848236917480679537296387464598"));
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "1298367587946526947123063707196892848236917480679537296387464598")));
}

/**
 * @given Bloom-filter
 * @when call load
 * @then the result data should be the appropriate size
 */
TEST_F(BloomFilterTest, LoadTest) {
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "9123594865892659791270573928567890379843798672987395677893427597"));
  auto value = filter_->load();
  ASSERT_EQ(value.size(), iroha::ordering::BloomFilter256::kBytesCount);
}

/**
 * @given Bloom-filter
 * @when set Hash there
 * @and after that load data from the filter to string
 * @and after thar clear the filter
 * @and after that store this data in filter again
 * @then test of the Hash should return true
 */
TEST_F(BloomFilterTest, ReloadTest) {
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "1298367587946526947123063707196892848236917480679537296387464598"));
  std::string const stored(filter_->load().data(), filter_->load().size());
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "1298367587946526947123063707196892848236917480679537296387464598")));
  filter_->clear();
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "1298367587946526947123063707196892848236917480679537296387464598")));

  filter_->store(stored);
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "1298367587946526947123063707196892848236917480679537296387464598")));
}

/**
 * @given Bloom-filter
 * @when set Hash1 there
 * @and after that load data from the filter to string
 * @and after thar clear the filter
 * @and after that set another Hash2 to the filter
 * @and after that store the BF from the string to the BF
 * @then BF will be updated: Hash1 test will return true and Hash2 will be
 * overriten and return false
 */
TEST_F(BloomFilterTest, ReloadTest2) {
  filter_->set(shared_model::crypto::Hash::fromHexString(
      "9123594865892659791270573928567890379843798672987395677893427597"));
  std::string const stored(filter_->load().data(), filter_->load().size());
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "9123594865892659791270573928567890379843798672987395677893427597")));
  filter_->clear();
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "9123594865892659791270573928567890379843798672987395677893427597")));

  filter_->set(shared_model::crypto::Hash::fromHexString(
      "1298367587946526947123063707196892848236917480679537296387464598"));
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "1298367587946526947123063707196892848236917480679537296387464598")));

  filter_->store(stored);
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "9123594865892659791270573928567890379843798672987395677893427597")));
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString(
      "1298367587946526947123063707196892848236917480679537296387464598")));
}
