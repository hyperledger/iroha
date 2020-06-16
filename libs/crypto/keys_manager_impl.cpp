/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crypto/keys_manager_impl.hpp"

#include <fstream>

#include <fmt/core.h>
#include "common/byteutils.hpp"
#include "common/files.hpp"
#include "common/result.hpp"
#include "cryptography/crypto_provider/crypto_signer.hpp"
#include "cryptography/crypto_provider/crypto_verifier.hpp"
#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"
#include "logger/logger.hpp"

using namespace shared_model::crypto;
using namespace shared_model::interface::types;

using iroha::operator|;

using DefaultCryptoAlgorithmType = CryptoProviderEd25519Sha3;

namespace {
  /**
   * Check that keypair is valid
   * @param keypair - keypair for validation
   * @return error if any, boost::none otherwise
   */
  iroha::expected::Result<void, const char *> validate(const Keypair &keypair) {
    auto test = Blob("12345");
    auto signature = CryptoSigner::sign(test, keypair);
    return CryptoVerifier::verify(SignedHexStringView{signature},
                                  test,
                                  PublicKeyHexStringView{keypair.publicKey()});
  }
}  // namespace

namespace iroha {
  /**
   * Function for the key (en|de)cryption via XOR
   * @tparam is a key type
   * @param privkey is a private key
   * @param pass_phrase is a key for encryption
   * @return encrypted string
   */
  template <typename T>
  static std::string xorCrypt(const T &key, const std::string &pass_phrase) {
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

  iroha::expected::Result<Keypair, std::string> KeysManagerImpl::loadKeys(
      const boost::optional<std::string> &pass_phrase) {
    auto load_from_file = [this](const auto &extension) {
      return iroha::readTextFile(
          (path_to_keypair_ / (account_id_ + extension)).string());
    };

    using ReturnType = iroha::expected::Result<Keypair, std::string>;
    return load_from_file(kPublicKeyExtension) | [&](auto &&pubkey_hex) {
      return load_from_file(kPrivateKeyExtension) | [&](auto &&privkey_hex) {
        return iroha::hexstringToBytestringResult(privkey_hex) |
                   [&](auto &&privkey_blob) -> ReturnType {
          auto &&decrypted_privkey_blob = pass_phrase
              ? xorCrypt(privkey_blob, pass_phrase.value())
              : privkey_blob;
          Keypair keypair(PublicKeyHexStringView{pubkey_hex},
                          PrivateKey{decrypted_privkey_blob});

          return validate(keypair).match(
              [&keypair](const auto &) -> ReturnType {
                return std::move(keypair);
              },
              [](const auto &error) -> ReturnType { return error.error; });
        };
      };
    };
  }

  bool KeysManagerImpl::createKeys(
      const boost::optional<std::string> &pass_phrase) {
    Keypair keypair = DefaultCryptoAlgorithmType::generateKeypair();

    auto pub = keypair.publicKey();
    auto &&priv = pass_phrase
        ? bytestringToHexstring(
              xorCrypt(keypair.privateKey().blob(), pass_phrase.value()))
        : keypair.privateKey().hex();
    return store(pub, priv);
  }

  bool KeysManagerImpl::store(std::string_view pub, std::string_view priv) {
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
