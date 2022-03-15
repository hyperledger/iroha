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

TEST_F(BloomFilterTest, SimplePos) {
  filter_->set(shared_model::crypto::Hash::fromHexString("0000000000000001000000000000000000000000000000000000000000000000"));
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString("0000000000000001000000000000000000000000000000000000000000000000")));
}

TEST_F(BloomFilterTest, SimpleNeg) {
  filter_->set(shared_model::crypto::Hash::fromHexString("0000000000000001000000000000000000000000000000000000000000000000"));
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString("0000000000000002000000000000000000000000000000000000000000000000")));
}

TEST_F(BloomFilterTest, RandomNeg) {
  filter_->set(shared_model::crypto::Hash::fromHexString("1111111111111111111111111111111111111111111111111111111111111111"));
  filter_->set(shared_model::crypto::Hash::fromHexString("9123594865892659791270573928567890379843798672987395677893427597"));
  filter_->set(shared_model::crypto::Hash::fromHexString("1298367587946526947123063707196892848236917480679537296387464598"));
  filter_->set(shared_model::crypto::Hash::fromHexString("0000000000000001000000000000000000000000000000000000000000000000"));
  filter_->set(shared_model::crypto::Hash::fromHexString("3897425687243695369327492877329067903476059372073409674908137884"));
  filter_->set(shared_model::crypto::Hash::fromHexString("2934756983467951879084309649306870136709760987508225675248658387"));
  filter_->set(shared_model::crypto::Hash::fromHexString("0912570146507610507436597430971934675798697834672098347567983268"));
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString("0000000000000002000000000000000000000000000000000000000000000000")));
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString("0111111111111111111111111111111111111111111111111111111111111111")));
}

TEST_F(BloomFilterTest, RandomPos) {
  filter_->set(shared_model::crypto::Hash::fromHexString("1111111111111111111111111111111111111111111111111111111111111111"));
  filter_->set(shared_model::crypto::Hash::fromHexString("9123594865892659791270573928567890379843798672987395677893427597"));
  filter_->set(shared_model::crypto::Hash::fromHexString("1298367587946526947123063707196892848236917480679537296387464598"));
  filter_->set(shared_model::crypto::Hash::fromHexString("0000000000000001000000000000000000000000000000000000000000000000"));
  filter_->set(shared_model::crypto::Hash::fromHexString("3897425687243695369327492877329067903476059372073409674908137884"));
  filter_->set(shared_model::crypto::Hash::fromHexString("2934756983467951879084309649306870136709760987508225675248658387"));
  filter_->set(shared_model::crypto::Hash::fromHexString("0912570146507610507436597430971934675798697834672098347567983268"));
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString("0000000000000001000000000000000000000000000000000000000000000000")));
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString("1298367587946526947123063707196892848236917480679537296387464598")));
}

TEST_F(BloomFilterTest, ClearTest) {
  filter_->set(shared_model::crypto::Hash::fromHexString("1111111111111111111111111111111111111111111111111111111111111111"));
  filter_->clear();
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString("1111111111111111111111111111111111111111111111111111111111111111")));
}

TEST_F(BloomFilterTest, Clear2Test) {
  filter_->set(shared_model::crypto::Hash::fromHexString("9123594865892659791270573928567890379843798672987395677893427597"));
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString("9123594865892659791270573928567890379843798672987395677893427597")));
  filter_->clear();
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString("9123594865892659791270573928567890379843798672987395677893427597")));
  filter_->set(shared_model::crypto::Hash::fromHexString("1298367587946526947123063707196892848236917480679537296387464598"));
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString("1298367587946526947123063707196892848236917480679537296387464598")));
}

TEST_F(BloomFilterTest, LoadTest) {
  filter_->set(shared_model::crypto::Hash::fromHexString("9123594865892659791270573928567890379843798672987395677893427597"));
  auto value = filter_->load();
  ASSERT_EQ(value.size(), iroha::ordering::BloomFilter256::kBytesCount);
}

TEST_F(BloomFilterTest, ReloadTest) {
  filter_->set(shared_model::crypto::Hash::fromHexString("1298367587946526947123063707196892848236917480679537296387464598"));
  std::string const stored(filter_->load().data(), filter_->load().size());
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString("1298367587946526947123063707196892848236917480679537296387464598")));
  filter_->clear();
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString("1298367587946526947123063707196892848236917480679537296387464598")));

  filter_->store(stored);
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString("1298367587946526947123063707196892848236917480679537296387464598")));
}

TEST_F(BloomFilterTest, ReloadTest2) {
  filter_->set(shared_model::crypto::Hash::fromHexString("9123594865892659791270573928567890379843798672987395677893427597"));
  std::string const stored(filter_->load().data(), filter_->load().size());
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString("9123594865892659791270573928567890379843798672987395677893427597")));
  filter_->clear();
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString("9123594865892659791270573928567890379843798672987395677893427597")));

  filter_->set(shared_model::crypto::Hash::fromHexString("1298367587946526947123063707196892848236917480679537296387464598"));
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString("1298367587946526947123063707196892848236917480679537296387464598")));

  filter_->store(stored);
  ASSERT_TRUE(filter_->test(shared_model::crypto::Hash::fromHexString("9123594865892659791270573928567890379843798672987395677893427597")));
  ASSERT_FALSE(filter_->test(shared_model::crypto::Hash::fromHexString("1298367587946526947123063707196892848236917480679537296387464598")));
}
