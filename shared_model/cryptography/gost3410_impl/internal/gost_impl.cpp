/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/gost3410_impl/internal/gost_impl.hpp"

#include <botan/auto_rng.h>
#include <botan/gost_3410.h>
#include <botan/pubkey.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <botan/rng.h>
#include <botan/data_src.h>

namespace shared_model::crypto::gost3410 {
  static const auto ECGName = std::string("gost_256A");
  static const auto EMSA = std::string("EMSA1(SHA-512)");

  bool verify(const uint8_t *msg, size_t msgsize,
              const uint8_t* pub_key, size_t pub_key_size,
              const uint8_t* signature, size_t signature_size) {

    auto ds = Botan::DataSource_Memory(pub_key, pub_key_size);
    auto key = Botan::X509::load_key(ds);

    auto verifier = Botan::PK_Verifier(*key, EMSA);
    verifier.update(msg, msgsize);
    auto res = verifier.check_signature(
      signature, signature_size
      );
      
    delete key;
    return res;
  }

  bool verify(std::string_view msg,
              const std::vector<uint8_t>& public_key,
              const std::vector<uint8_t>& signature) {
    return verify(reinterpret_cast<const uint8_t *>(msg.data()),
                  msg.size(),
                  public_key.data(), public_key.size(),
                  signature.data(), signature.size()
                  );
  }

  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> create_keypair() {
    auto rng = Botan::AutoSeeded_RNG();
    auto key = Botan::GOST_3410_PrivateKey(rng, Botan::EC_Group(ECGName));

    auto pvkey = Botan::PKCS8::BER_encode(key);
    return std::make_pair(
        Botan::X509::BER_encode(key),
        std::vector<uint8_t>(pvkey.begin(), pvkey.end())
      );
  }
  
  std::vector<uint8_t> sign(const uint8_t *msg, size_t msgsize,
                            const uint8_t* priv, size_t privLen){
    auto ds = Botan::DataSource_Memory(priv, privLen);
    auto key = Botan::PKCS8::load_key(ds);

    auto rng = Botan::AutoSeeded_RNG();
    auto signer = Botan::PK_Signer(*key.get(), rng, EMSA);
    signer.update(msg, msgsize);
    auto signature = signer.signature(rng);

    return signature;
  }

  std::vector<uint8_t> sign(const std::string& msg, const uint8_t* priv, size_t privLen){
    return sign(reinterpret_cast<const uint8_t*>(msg.data()), msg.size(),
                priv, privLen);
  }
}
