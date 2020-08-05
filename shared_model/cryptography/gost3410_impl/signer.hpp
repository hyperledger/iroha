#ifndef GOST_CRYPTO_SIGNER_HPP
#define GOST_CRYPTO_SIGNER_HPP

#include "cryptography/blob.hpp"
#include "cryptography/keypair.hpp"

namespace shared_model::crypto::gost3410 {
  class Signer {
    public:
    /**
     * Signs provided blob.
     * @param blob - to sign
     * @param keypair - keypair with public and private keys
     * @return hex signature data string
     */
    static std::string sign(const Blob &blob, const Keypair &keypair);
  };
} // namespase shared_model::crypto::gost3410

#endif // GOST_CRYPTO_SIGNER_HPP
