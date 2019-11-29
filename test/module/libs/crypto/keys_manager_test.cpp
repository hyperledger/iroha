/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crypto/keys_manager.hpp"

#include <gtest/gtest.h>
#include <boost/filesystem.hpp>
#include <fstream>
#include <string>
#include "crypto/keys_manager_impl.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_logger.hpp"

using namespace iroha;
using namespace boost::filesystem;
using namespace std::string_literals;
using namespace shared_model::crypto;

class KeyManager : public ::testing::Test {
 public:
  bool create_file(const path &ph, const std::string &contents) {
    std::ofstream f(ph.c_str());
    if (not f) {
      return false;
    }
    if (not contents.empty()) {
      f.write(contents.c_str(), contents.size());
    }
    return f.good();
  }

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

  Keypair keypair = DefaultCryptoAlgorithmType::generateKeypair();
  const std::string pubkey = keypair.publicKey().hex();
  const std::string prikey = keypair.privateKey().hex();

  const logger::LoggerPtr kKeysManagerLogger = getTestLogger("KeysManager");
  KeysManagerImpl manager = KeysManagerImpl(filepath, kKeysManagerLogger);
  const std::string passphrase = "test";
  const std::string nonexistent = (boost::filesystem::temp_directory_path()
                                   / boost::filesystem::unique_path())
                                      .string();
};

TEST_F(KeyManager, LoadNonExistentKeyFile) {
  IROHA_ASSERT_RESULT_ERROR(manager.loadKeys(boost::none));
}

TEST_F(KeyManager, LoadEmptyPubkey) {
  create_file(pub_key_path, pubkey);
  create_file(pri_key_path, "");
  IROHA_ASSERT_RESULT_ERROR(manager.loadKeys(boost::none));
}

TEST_F(KeyManager, LoadEmptyFilesPrikey) {
  create_file(pub_key_path, "");
  create_file(pri_key_path, prikey);
  IROHA_ASSERT_RESULT_ERROR(manager.loadKeys(boost::none));
}

TEST_F(KeyManager, LoadInvalidPubkey) {
  create_file(pub_key_path, pubkey);
  create_file(
      pri_key_path,
      std::string(DefaultCryptoAlgorithmType::kPublicKeyLength * 2, '1'));
  IROHA_ASSERT_RESULT_ERROR(manager.loadKeys(boost::none));
}

TEST_F(KeyManager, LoadInvalidPrikey) {
  create_file(
      pub_key_path,
      std::string(DefaultCryptoAlgorithmType::kPrivateKeyLength * 2, '1'));
  create_file(pri_key_path, prikey);
  IROHA_ASSERT_RESULT_ERROR(manager.loadKeys(boost::none));
}

TEST_F(KeyManager, LoadValid) {
  create_file(pub_key_path, pubkey);
  create_file(pri_key_path, prikey);
  IROHA_ASSERT_RESULT_VALUE(manager.loadKeys(boost::none));
}

TEST_F(KeyManager, CreateAndLoad) {
  ASSERT_TRUE(manager.createKeys(boost::none));
  IROHA_ASSERT_RESULT_VALUE(manager.loadKeys(boost::none));
}

TEST_F(KeyManager, CreateAndLoadEncrypted) {
  ASSERT_TRUE(manager.createKeys(passphrase));
  IROHA_ASSERT_RESULT_VALUE(manager.loadKeys(passphrase));
}

TEST_F(KeyManager, CreateAndLoadEncryptedEmptyKey) {
  ASSERT_TRUE(manager.createKeys(std::string{""}));
  IROHA_ASSERT_RESULT_VALUE(manager.loadKeys(std::string{""}));
}

TEST_F(KeyManager, CreateAndLoadEncryptedInvalidKey) {
  ASSERT_TRUE(manager.createKeys(passphrase));
  IROHA_ASSERT_RESULT_ERROR(manager.loadKeys(passphrase + "123"));
}

TEST_F(KeyManager, LoadInaccessiblePubkey) {
  create_file(pub_key_path, pubkey);
  create_file(pri_key_path, prikey);
  remove(pub_key_path);
  IROHA_ASSERT_RESULT_ERROR(manager.loadKeys(boost::none));
}

TEST_F(KeyManager, LoadInaccessiblePrikey) {
  create_file(pub_key_path, pubkey);
  create_file(pri_key_path, prikey);
  remove(pri_key_path);
  IROHA_ASSERT_RESULT_ERROR(manager.loadKeys(boost::none));
}

TEST_F(KeyManager, CreateKeypairInNonexistentDir) {
  KeysManagerImpl manager =
      KeysManagerImpl(boost::filesystem::unique_path().string(),
                      nonexistent,
                      kKeysManagerLogger);
  ASSERT_FALSE(manager.createKeys(passphrase));
}
