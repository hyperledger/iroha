/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crypto/keys_manager.hpp"

#include <cstddef>
#include <string_view>

#include <gtest/gtest.h>
#include <boost/filesystem.hpp>
#include <fstream>
#include <string>
#include "crypto/keys_manager_impl.hpp"
#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_logger.hpp"

#if defined(USE_LIBURSA)
#include "cryptography/ed25519_ursa_impl/crypto_provider.hpp"
#endif

using namespace iroha;
using namespace boost::filesystem;
using namespace std::string_literals;
using namespace shared_model::crypto;

void create_file(const path &ph, std::string_view contents) {
  std::ofstream f(ph.c_str());
  assert(f);
  if (not contents.empty()) {
    f.write(contents.data(), contents.size());
  }
  assert(f.good());
}

template <typename CurrentCryptoProviderParam>
class KeyManager : public ::testing::Test {
 public:
  void SetUp() {
    create_directory(test_dir);
  }

  void TearDown() {
    boost::filesystem::remove_all(test_dir);
  }

  const path test_dir = boost::filesystem::temp_directory_path()
      / boost::filesystem::unique_path();
  const std::string filepath =
      (test_dir / boost::filesystem::unique_path()).string();
  const path pub_key_path = filepath + KeysManagerImpl::kPublicKeyExtension;
  const path pri_key_path = filepath + KeysManagerImpl::kPrivateKeyExtension;

  Keypair keypair = CurrentCryptoProviderParam::generateKeypair();
  std::string pubkey = keypair.publicKey();
  const std::string prikey = keypair.privateKey().hex();

  const logger::LoggerPtr kKeysManagerLogger = getTestLogger("KeysManager");
  KeysManagerImpl manager = KeysManagerImpl(filepath, kKeysManagerLogger);
  const std::string passphrase = "test";
  const std::string nonexistent = (boost::filesystem::temp_directory_path()
                                   / boost::filesystem::unique_path())
                                      .string();
};

using CryptoUsageTestTypes = ::testing::Types<CryptoProviderEd25519Sha3
#if defined(USE_LIBURSA)
                                              ,
                                              CryptoProviderEd25519Ursa
#endif
                                              >;
TYPED_TEST_CASE(KeyManager, CryptoUsageTestTypes, );

TYPED_TEST(KeyManager, LoadNonExistentKeyFile) {
  IROHA_ASSERT_RESULT_ERROR(this->manager.loadKeys(boost::none));
}

TYPED_TEST(KeyManager, LoadEmptyFilesPubkey) {
  create_file(this->pub_key_path, "");
  create_file(this->pri_key_path, this->prikey);
  IROHA_ASSERT_RESULT_ERROR(this->manager.loadKeys(boost::none));
}

TYPED_TEST(KeyManager, LoadEmptyFilesPrikey) {
  create_file(this->pub_key_path, this->pubkey);
  create_file(this->pri_key_path, "");
  IROHA_ASSERT_RESULT_ERROR(this->manager.loadKeys(boost::none));
}

TYPED_TEST(KeyManager, LoadInvalidPubkey) {
  create_file(this->pub_key_path, std::string(this->pubkey.size() * 2, '1'));
  create_file(this->pri_key_path, this->prikey);
  IROHA_ASSERT_RESULT_ERROR(this->manager.loadKeys(boost::none));
}

TYPED_TEST(KeyManager, LoadInvalidPrikey) {
  create_file(this->pub_key_path, this->pubkey);
  create_file(this->pri_key_path, std::string(this->prikey.size() * 2, '1'));
  IROHA_ASSERT_RESULT_ERROR(this->manager.loadKeys(boost::none));
}

TYPED_TEST(KeyManager, LoadValid) {
  create_file(this->pub_key_path, this->pubkey);
  create_file(this->pri_key_path, this->prikey);
  IROHA_ASSERT_RESULT_VALUE(this->manager.loadKeys(boost::none));
}

TYPED_TEST(KeyManager, CreateAndLoad) {
  ASSERT_TRUE(this->manager.createKeys(boost::none));
  IROHA_ASSERT_RESULT_VALUE(this->manager.loadKeys(boost::none));
}

TYPED_TEST(KeyManager, CreateAndLoadEncrypted) {
  ASSERT_TRUE(this->manager.createKeys(this->passphrase));
  IROHA_ASSERT_RESULT_VALUE(this->manager.loadKeys(this->passphrase));
}

TYPED_TEST(KeyManager, CreateAndLoadEncryptedEmptyKey) {
  ASSERT_TRUE(this->manager.createKeys(std::string{""}));
  IROHA_ASSERT_RESULT_VALUE(this->manager.loadKeys(std::string{""}));
}

TYPED_TEST(KeyManager, CreateAndLoadEncryptedInvalidKey) {
  ASSERT_TRUE(this->manager.createKeys(this->passphrase));
  IROHA_ASSERT_RESULT_ERROR(this->manager.loadKeys(this->passphrase + "123"));
}

TYPED_TEST(KeyManager, LoadInaccessiblePubkey) {
  create_file(this->pub_key_path, this->pubkey);
  create_file(this->pri_key_path, this->prikey);
  remove(this->pub_key_path);
  IROHA_ASSERT_RESULT_ERROR(this->manager.loadKeys(boost::none));
}

TYPED_TEST(KeyManager, LoadInaccessiblePrikey) {
  create_file(this->pub_key_path, this->pubkey);
  create_file(this->pri_key_path, this->prikey);
  remove(this->pri_key_path);
  IROHA_ASSERT_RESULT_ERROR(this->manager.loadKeys(boost::none));
}

TYPED_TEST(KeyManager, CreateKeypairInNonexistentDir) {
  KeysManagerImpl manager =
      KeysManagerImpl(boost::filesystem::unique_path().string(),
                      this->nonexistent,
                      this->kKeysManagerLogger);
  ASSERT_FALSE(manager.createKeys(this->passphrase));
}
