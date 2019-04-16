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
#include "framework/test_logger.hpp"

#define PUBKEY_HEX_SIZE 64
#define PRIVKEY_HEX_SIZE 64

using namespace iroha;
using namespace boost::filesystem;
using namespace std::string_literals;

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
  const std::string pubkey =
      "00576e02f23c8c694c322796cb3ef494829fdf484f4b42312fb7d776fbd5123b"s;
  const std::string prikey =
      "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80"s;
  const logger::LoggerPtr kKeysManagerLogger = getTestLogger("KeysManager");
  KeysManagerImpl manager = KeysManagerImpl(filepath, kKeysManagerLogger);
  const std::string passphrase = "test";
  const std::string nonexistent = (boost::filesystem::temp_directory_path()
                                   / boost::filesystem::unique_path())
                                      .string();
};

TEST_F(KeyManager, LoadNonExistentKeyFile) {
  ASSERT_FALSE(manager.loadKeys());
}

TEST_F(KeyManager, LoadEmptyPubkey) {
  create_file(pub_key_path, pubkey);
  create_file(pri_key_path, "");
  ASSERT_FALSE(manager.loadKeys());
}

TEST_F(KeyManager, LoadEmptyFilesPrikey) {
  create_file(pub_key_path, "");
  create_file(pri_key_path, prikey);
  ASSERT_FALSE(manager.loadKeys());
}

TEST_F(KeyManager, LoadInvalidPubkey) {
  create_file(pub_key_path, pubkey);
  create_file(pri_key_path, std::string(PUBKEY_HEX_SIZE, '1'));
  ASSERT_FALSE(manager.loadKeys());
}

TEST_F(KeyManager, LoadInvalidPrikey) {
  create_file(pub_key_path, std::string(PRIVKEY_HEX_SIZE, '1'));
  create_file(pri_key_path, prikey);
  ASSERT_FALSE(manager.loadKeys());
}

TEST_F(KeyManager, LoadValid) {
  create_file(pub_key_path, pubkey);
  create_file(pri_key_path, prikey);
  ASSERT_TRUE(manager.loadKeys());
}

TEST_F(KeyManager, CreateAndLoad) {
  ASSERT_TRUE(manager.createKeys());
  ASSERT_TRUE(manager.loadKeys());
}

TEST_F(KeyManager, CreateAndLoadEncrypted) {
  ASSERT_TRUE(manager.createKeys(passphrase));
  ASSERT_TRUE(manager.loadKeys(passphrase));
}

TEST_F(KeyManager, CreateAndLoadEncryptedEmptyKey) {
  ASSERT_TRUE(manager.createKeys(""));
  ASSERT_TRUE(manager.loadKeys(""));
}

TEST_F(KeyManager, CreateAndLoadEncryptedInvalidKey) {
  ASSERT_TRUE(manager.createKeys(passphrase));
  ASSERT_FALSE(manager.loadKeys(passphrase + "123"));
}

TEST_F(KeyManager, LoadInaccessiblePubkey) {
  create_file(pub_key_path, pubkey);
  create_file(pri_key_path, prikey);
  remove(pub_key_path);
  ASSERT_FALSE(manager.loadKeys());
}

TEST_F(KeyManager, LoadInaccessiblePrikey) {
  create_file(pub_key_path, pubkey);
  create_file(pri_key_path, prikey);
  remove(pri_key_path);
  ASSERT_FALSE(manager.loadKeys());
}

TEST_F(KeyManager, CreateKeypairInNonexistentDir) {
  KeysManagerImpl manager =
      KeysManagerImpl(boost::filesystem::unique_path().string(),
                      nonexistent,
                      kKeysManagerLogger);
  ASSERT_FALSE(manager.createKeys(passphrase));
}
