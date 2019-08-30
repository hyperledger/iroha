/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "backend/protobuf/common_objects/proto_common_objects_factory.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "framework/result_fixture.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "validators/field_validator.hpp"

using namespace shared_model;
using namespace framework::expected;

class ProtoFixture : public ::testing::Test {
 public:
  ProtoFixture() : factory(iroha::test::kTestsValidatorsConfig) {}

  proto::ProtoCommonObjectsFactory<validation::FieldValidator> factory;
};

class PeerTest : public ProtoFixture {
 public:
  std::string valid_address = "127.0.0.1:8080";
  crypto::PublicKey valid_pubkey =
      crypto::DefaultCryptoAlgorithmType::generateKeypair().publicKey();
  std::string invalid_address = "127.0.0.1";
  std::string example_tls_certificate = R"(
-----BEGIN CERTIFICATE-----
MIIDpDCCAoygAwIBAgIUXwQAtk7WnMb1Rb3hQvnNLGUUjxcwDQYJKoZIhvcNAQEL
BQAwWTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDESMBAGA1UEAwwJbG9jYWxob3N0MB4X
DTE5MDgyODE1NDcyMVoXDTM5MDgyMzE1NDcyMVowWTELMAkGA1UEBhMCQVUxEzAR
BgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5
IEx0ZDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA0+8KU9ZsYIoePPwHl/e1yPBKLW/mVv6XgjP2LVJ+4lq7j0+0KNGE
0P1/W2MBA0kVIe5i2wNFo8ac22lP+s34aKSjcWWLlFEmBH7Tk17VHqetyRBmAVNO
BLs/VCZA/eg5mG5EE2hsh/jS5A6KezZ7xDxlfvmCcjJ51qo7mZ3samZkwvG1ktdQ
lYrWtX7ziTDyEP0XVYT3GfVhkN9L6d9yebCzcqlpC+E+JVSmtetussz56bGL+ycZ
wko2BkGqZLekmegf5hxyQdVt2YN+LtoCODZMqYNgprBwdeqrapq0VtvfhWBeYCRl
HemL2VR3iAdC2Q7cuAo2kbYVZXjNxTskpQIDAQABo2QwYjAdBgNVHQ4EFgQUujeO
B1gunwsQi4Ua+F8GzEGJSaowHwYDVR0jBBgwFoAUujeOB1gunwsQi4Ua+F8GzEGJ
SaowDwYDVR0TAQH/BAUwAwEB/zAPBgNVHREECDAGhwR/AAABMA0GCSqGSIb3DQEB
CwUAA4IBAQAc7i5pXtY9iFX9OIOdUFl7o1CbA4DENLD7GIF+RiuL4whoPwHxj6g5
2h287E+Vk+Mo2A/M+/Vi4guVhBbMROm72zPpnKRoQAqwRN6y/+FhZV4Zw1hf9fw6
N1PgJiOdAcYdsoZtrrWFUQ8pcvrrmJpi8e4QNC0DmePCI5hKlB94PAQg81rL1fPs
NhkvxwFwAUBCzHmisHPGDz8DNwdpu2KoMHtDIiTGa38ZxBTSw5BEnP2/5VhsI+2o
1b540Kw9rtbHux+CHbCs7Cs3XIY5BLnAf3T7MOpA+a5/rWPkiWAdVCxguxy/OLZQ
J6DR+swaKJJCJpwSShC2+YjrcPa9hdkc
-----END CERTIFICATE-----
  )";
};

/**
 * @given valid data for peer
 * @when peer is created via factory
 * @then peer is successfully initialized
 */
TEST_F(PeerTest, ValidPeerInitialization) {
  auto peer = factory.createPeer(valid_address, valid_pubkey, example_tls_certificate);

  peer.match(
      [&](const auto &v) {
        ASSERT_EQ(v.value->address(), valid_address);
        ASSERT_EQ(v.value->pubkey().hex(), valid_pubkey.hex());
      },
      [](const auto &e) { FAIL() << e.error; });
}

/**
 * @given invalid data for peer
 * @when peer is created via factory
 * @then peer is not initialized correctly
 */
TEST_F(PeerTest, InvalidPeerInitialization) {
  auto peer = factory.createPeer(invalid_address, valid_pubkey, example_tls_certificate);

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

class SignatureTest : public ProtoFixture {
 public:
  crypto::PublicKey valid_pubkey =
      crypto::DefaultCryptoAlgorithmType::generateKeypair().publicKey();
  crypto::Signed valid_data{"hello"};
  crypto::PublicKey invalid_pubkey{"1234"};
};

/**
 * @given valid data for signature
 * @when signature is created via factory
 * @then signature is successfully initialized
 */
TEST_F(SignatureTest, ValidSignatureInitialization) {
  auto signature = factory.createSignature(valid_pubkey, valid_data);

  signature.match(
      [&](const auto &v) {
        ASSERT_EQ(v.value->publicKey().hex(), valid_pubkey.hex());
        ASSERT_EQ(v.value->signedData().hex(), valid_data.hex());
      },
      [](const auto &e) { FAIL() << e.error; });
}

/**
 * @given invalid data for signature
 * @when signature is created via factory
 * @then signature is not initialized correctly
 */
TEST_F(SignatureTest, InvalidSignatureInitialization) {
  auto signature = factory.createSignature(invalid_pubkey, valid_data);

  signature.match([](const auto &v) { FAIL() << "Expected error case"; },
                  [](const auto &e) { SUCCEED(); });
}
