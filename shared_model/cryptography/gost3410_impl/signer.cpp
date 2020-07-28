#include "cryptography/gost3410_impl/signer.hpp"

#include "crypto/hash_types.hpp"
#include "cryptography/gost3410_impl/internal/gost_impl.hpp"
#include <iostream>
#include <vector>

namespace shared_model {
  namespace crypto {
    std::string Signer::sign(const Blob & blob, const Keypair &keypair){
      return iroha::sign(crypto::toBinaryString(blob), 
                keypair.privateKey().blob().data(),
                keypair.privateKey().blob().size());
    }
  } // namespace crypto
} // namespace shared_model