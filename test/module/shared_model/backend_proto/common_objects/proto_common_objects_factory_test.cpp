/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "backend/protobuf/common_objects/proto_common_objects_factory.hpp"
#include "common/hexutils.hpp"
#include "framework/crypto_literals.hpp"
#include "framework/result_fixture.hpp"
#include "framework/stateless_valid_field_helpers.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "validators/field_validator.hpp"

using namespace shared_model;
using namespace framework::expected;

using interface::types::PublicKeyHexStringView;
using interface::types::SignedHexStringView;

class ProtoFixture : public ::testing::Test {
 public:
  ProtoFixture() : factory(iroha::test::kTestsValidatorsConfig) {}

  proto::ProtoCommonObjectsFactory<validation::FieldValidator> factory;
};

class PeerTest : public ProtoFixture {
 public:
  std::string valid_address = "127.0.0.1:8080";
  interface::types::PublicKeyHexStringView valid_hex_pubkey{"600D"_hex_pubkey};
  std::string invalid_address = "127.0.0.1";

  void testValidPeerCreation(const std::string &address,
                             std::string_view pubkey,
                             const std::optional<std::string> &tls_cert) {
    factory.createPeer(address, PublicKeyHexStringView{pubkey}, tls_cert)
        .match(
            [&](const auto &v) {
              ASSERT_EQ(v.value->address(), address);
              ASSERT_EQ(v.value->pubkey(), pubkey);
              ASSERT_EQ(v.value->tlsCertificate(), tls_cert);
            },
            [](const auto &e) { FAIL() << e.error; });
  }
};

/**
 * @given valid data for peer including TLS certficate
 * @when peer is created via factory
 * @then peer is successfully initialized
 */
TEST_F(PeerTest, ValidPeerInitializationWithTlsCert) {
  testValidPeerCreation(valid_address, valid_hex_pubkey, std::string(""));
}

/**
 * @given valid data for peer without TLS certficate
 * @when peer is created via factory
 * @then peer is successfully initialized
 */
TEST_F(PeerTest, ValidPeerInitializationWithoutTlsCert) {
  testValidPeerCreation(valid_address, valid_hex_pubkey, std::nullopt);
}

/**
 * @given invalid data for peer
 * @when peer is created via factory
 * @then peer is not initialized correctly
 */
TEST_F(PeerTest, InvalidPeerInitialization) {
  auto peer = factory.createPeer(invalid_address,
                                 PublicKeyHexStringView{valid_hex_pubkey},
                                 std::string(""));

  peer.match([](const auto &v) { FAIL() << "Expected error case"; },
             [](const auto &e) { SUCCEED(); });
}

class AccountTest : public ProtoFixture {
 public:
  interface::types::AccountIdType valid_account_id = "hello@world";
  interface::types::DomainIdType valid_domain_id = "bit.connect";
  interface::types::QuorumType valid_quorum = 1;
  interface::types::JsonType valid_json = R"({"name": "json" })";

  interface::types::AccountIdType invalid_account_id = "hello123";
};

/**
 * @given valid data for account
 * @when account is created via factory
 * @then peer is successfully initialized
 */
TEST_F(AccountTest, ValidAccountInitialization) {
  auto account = factory.createAccount(
      valid_account_id, valid_domain_id, valid_quorum, valid_json);

  account.match(
      [&](const auto &v) {
        ASSERT_EQ(v.value->accountId(), valid_account_id);
        ASSERT_EQ(v.value->domainId(), valid_domain_id);
        ASSERT_EQ(v.value->quorum(), valid_quorum);
        ASSERT_EQ(v.value->jsonData(), valid_json);
      },
      [](const auto &e) { FAIL() << e.error; });
}

/**
 * @given invalid data for account
 * @when account is created via factory
 * @then account is not initialized correctly
 */
TEST_F(AccountTest, InvalidAccountInitialization) {
  auto account = factory.createAccount(
      invalid_account_id, valid_domain_id, valid_quorum, valid_json);

  account.match([](const auto &v) { FAIL() << "Expected error case"; },
                [](const auto &e) { SUCCEED(); });
}

class AccountAssetTest : public ProtoFixture {
 public:
  interface::types::AccountIdType valid_account_id = "hello@world";
  interface::types::AssetIdType valid_asset_id = "bit#connect";
  interface::Amount valid_amount = interface::Amount("10.00");

  interface::types::AccountIdType invalid_account_id = "hello123";
};

/**
 * @given valid data for account asset
 * @when account asset is created via factory
 * @then account asset is successfully initialized
 */
TEST_F(AccountAssetTest, ValidAccountAssetInitialization) {
  auto account_asset = factory.createAccountAsset(
      valid_account_id, valid_asset_id, valid_amount);

  account_asset.match(
      [&](const auto &v) {
        ASSERT_EQ(v.value->accountId(), valid_account_id);
        ASSERT_EQ(v.value->assetId(), valid_asset_id);
        ASSERT_EQ(v.value->balance(), valid_amount);
      },
      [](const auto &e) { FAIL() << e.error; });
}

/**
 * @given invalid data for account asset
 * @when account asset is created via factory
 * @then account asset is not initialized correctly
 */
TEST_F(AccountAssetTest, InvalidAccountAssetInitialization) {
  auto account_asset = factory.createAccountAsset(
      invalid_account_id, valid_asset_id, valid_amount);

  account_asset.match([](const auto &v) { FAIL() << "Expected error case"; },
                      [](const auto &e) { SUCCEED(); });
}

class AssetTest : public ProtoFixture {
 public:
  interface::types::AssetIdType valid_asset_id = "bit#connect";
  interface::types::DomainIdType valid_domain_id = "iroha.com";
  interface::types::PrecisionType valid_precision = 2;

  interface::types::AssetIdType invalid_asset_id = "bit";
};

/**
 * @given valid data for asset
 * @when asset is created via factory
 * @then asset is successfully initialized
 */
TEST_F(AssetTest, ValidAssetInitialization) {
  auto asset =
      factory.createAsset(valid_asset_id, valid_domain_id, valid_precision);

  asset.match(
      [&](const auto &v) {
        ASSERT_EQ(v.value->assetId(), valid_asset_id);
        ASSERT_EQ(v.value->domainId(), valid_domain_id);
        ASSERT_EQ(v.value->precision(), valid_precision);
      },
      [](const auto &e) { FAIL() << e.error; });
}

/**
 * @given invalid data for asset
 * @when asset is created via factory
 * @then asset is not initialized correctly
 */
TEST_F(AssetTest, InvalidAssetInitialization) {
  auto asset =
      factory.createAsset(invalid_asset_id, valid_domain_id, valid_precision);

  asset.match([](const auto &v) { FAIL() << "Expected error case"; },
              [](const auto &e) { SUCCEED(); });
}

class DomainTest : public ProtoFixture {
 public:
  interface::types::DomainIdType valid_domain_id = "iroha.com";
  interface::types::RoleIdType valid_role_id = "admin";

  interface::types::DomainIdType invalid_domain_id = "123irohacom";
};

/**
 * @given valid data for domain
 * @when domain is created via factory
 * @then domain is successfully initialized
 */
TEST_F(DomainTest, ValidDomainInitialization) {
  auto domain = factory.createDomain(valid_domain_id, valid_role_id);

  domain.match(
      [&](const auto &v) {
        ASSERT_EQ(v.value->domainId(), valid_domain_id);
        ASSERT_EQ(v.value->defaultRole(), valid_role_id);
      },
      [](const auto &e) { FAIL() << e.error; });
}

/**
 * @given invalid data for domain
 * @when domain is created via factory
 * @then domain is not initialized correctly
 */
TEST_F(DomainTest, InvalidDomainInitialization) {
  auto domain = factory.createDomain(invalid_domain_id, valid_role_id);

  domain.match([](const auto &v) { FAIL() << "Expected error case"; },
               [](const auto &e) { SUCCEED(); });
}
