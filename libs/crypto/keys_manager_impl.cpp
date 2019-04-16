/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crypto/keys_manager_impl.hpp"

#include <fstream>

#include "common/byteutils.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "logger/logger.hpp"

using namespace shared_model::crypto;

using iroha::operator|;

namespace iroha {
  /**
   * Function for the key encryption via XOR
   * @tparam is a key type
   * @param privkey is a private key
   * @param pass_phrase is a key for encryption
   * @return encrypted string
   */
  template <typename T>
  static std::string encrypt(const T &key, const std::string &pass_phrase) {
    std::string ciphertext(key.size(), '\0');
    const size_t min_pass_size = 1;
    // pass_size will always be > 0
    const auto pass_size = std::max(min_pass_size, pass_phrase.size());
    // When pass_phrase is empty it, pass_phrase[0] is "\0", so no out_of_range
    // exception is possible
    for (size_t i = 0; i < key.size(); i++) {
      ciphertext[i] = key[i] ^ pass_phrase[i % pass_size];
    }
    return ciphertext;
  }

  /**
   * Function for XOR decryption
   */
  static constexpr auto decrypt = encrypt<Blob::Bytes>;

  KeysManagerImpl::KeysManagerImpl(
      const std::string &account_id,
      const boost::filesystem::path &path_to_keypair,
      logger::LoggerPtr log)
      : path_to_keypair_(path_to_keypair),
        account_id_(account_id),
        log_(std::move(log)) {}

  /**
   * Here we use an empty string as a default value of path to file,
   * since there are usages of KeysManagerImpl with path passed as a part of
   * account_id.
   */
  KeysManagerImpl::KeysManagerImpl(const std::string account_id,
                                   logger::LoggerPtr log)
      : KeysManagerImpl(account_id, "", std::move(log)) {}

  bool KeysManagerImpl::validate(const Keypair &keypair) const {
    try {
      auto test = Blob("12345");
      auto sig = DefaultCryptoAlgorithmType::sign(test, keypair);
      if (not DefaultCryptoAlgorithmType::verify(
              sig, test, keypair.publicKey())) {
        log_->error("key validation failed");
        return false;
      }
    } catch (const BadFormatException &exception) {
      log_->error("Cannot validate keyapir: {}", exception.what());
      return false;
    }
    return true;
  }

  boost::optional<std::string> KeysManagerImpl::loadFile(
      const boost::filesystem::path &path) const {
    auto file_path = path.string();
    std::ifstream file(file_path);
    if (not file) {
      log_->error("Cannot read '" + file_path + "'");
      return {};
    }

    std::string contents;
    file >> contents;
    return contents;
  }

  boost::optional<Keypair> KeysManagerImpl::loadKeys() {
    return loadKeys("");
  }

  boost::optional<Keypair> KeysManagerImpl::loadKeys(
      const std::string &pass_phrase) {
    auto public_key =
        loadFile(path_to_keypair_ / (account_id_ + kPublicKeyExtension));
    auto private_key =
        loadFile(path_to_keypair_ / (account_id_ + kPrivateKeyExtension));

    if (not public_key or not private_key) {
      return boost::none;
    }

    Keypair keypair = Keypair(
        PublicKey(Blob::fromHexString(public_key.get())),
        PrivateKey(decrypt(Blob::fromHexString(private_key.get()).blob(),
                           pass_phrase)));

    return validate(keypair) ? boost::make_optional(keypair) : boost::none;
  }

  bool KeysManagerImpl::createKeys() {
    return createKeys("");
  }

  bool KeysManagerImpl::createKeys(const std::string &pass_phrase) {
    Keypair keypair = DefaultCryptoAlgorithmType::generateKeypair();

    auto pub = keypair.publicKey().hex();
    auto priv = bytestringToHexstring(
        encrypt(keypair.privateKey().blob(), pass_phrase));
    return store(pub, priv);
  }

  bool KeysManagerImpl::store(const std::string &pub, const std::string &priv) {
    std::ofstream pub_file(
        (path_to_keypair_ / (account_id_ + kPublicKeyExtension)).string());
    std::ofstream priv_file(
        (path_to_keypair_ / (account_id_ + kPrivateKeyExtension)).string());
    if (not pub_file or not priv_file) {
      return false;
    }

    pub_file << pub;
    priv_file << priv;
    return pub_file.good() && priv_file.good();
  }

  const std::string KeysManagerImpl::kPublicKeyExtension = ".pub";
  const std::string KeysManagerImpl::kPrivateKeyExtension = ".priv";
}  // namespace iroha
