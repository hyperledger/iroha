/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/impl/x509_utils.hpp"

#include <cstring>
#include <string>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "cryptography/public_key.hpp"

using namespace iroha;

using shared_model::crypto::PublicKey;

namespace {
  const char kOidEd25519[] = {0x2b, 0x65, 0x70};

  int otherNameIsEd25519Key(OTHERNAME *other_name) {
    ASN1_OBJECT *obj = other_name->type_id;
    if (obj->length != sizeof(kOidEd25519)) {
      return 0;
    }
    return 0 == std::memcmp(obj->data, kOidEd25519, sizeof(kOidEd25519));
  }

  PublicKey getEd15519Key(ASN1_TYPE *a) {
    ASN1_INTEGER *key = a->value.integer;
    return PublicKey{std::string{reinterpret_cast<const char *>(key->data),
                                 static_cast<size_t>(key->length)}};
  }

  std::vector<shared_model::crypto::PublicKey> getIrohaPubKeys(X509 &cert) {
    std::vector<shared_model::crypto::PublicKey> extracted_keys;
    int idx = -1;
    int critical = 0;

    const auto get_alt_names = [&cert, &idx, &critical]() {
      auto alt_names_deleter = [](GENERAL_NAMES *ptr) {
        GENERAL_NAMES_free(ptr);
      };
      return std::unique_ptr<GENERAL_NAMES, decltype(alt_names_deleter)>{
          static_cast<GENERAL_NAMES *>(
              X509_get_ext_d2i(&cert, NID_subject_alt_name, &critical, &idx)),
          alt_names_deleter};
    };

    while (auto alt_names = get_alt_names()) {
      for (int i = 0; i < sk_GENERAL_NAME_num(alt_names.get()); i++) {
        if (not critical) {
          continue;
        }
        GENERAL_NAME *gen;
        gen = sk_GENERAL_NAME_value(alt_names.get(), i);
        if (gen->type != GEN_OTHERNAME) {
          continue;
        }
        OTHERNAME *other_name = gen->d.otherName;
        if (otherNameIsEd25519Key(other_name)) {
          extracted_keys.emplace_back(getEd15519Key(other_name->value));
        }
      }
    }

    return extracted_keys;
  }
}  // namespace

expected::Result<std::vector<shared_model::crypto::PublicKey>, std::string>
iroha::getIrohaPubKeysFromX509(const char *cert_buf_pem, size_t cert_buf_sz) {
  if (cert_buf_sz > std::numeric_limits<int>::max()) {
    return "Certificate too large.";
  }

  std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()),
                                                &BIO_free);
  BIO_write(bio.get(), cert_buf_pem, static_cast<int>(cert_buf_sz));
  std::unique_ptr<X509, decltype(&X509_free)> cert(
      PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), &X509_free);

  if (cert == nullptr) {
    return "Unable to parse x509 cert.";
  }

  return getIrohaPubKeys(*cert);
}
