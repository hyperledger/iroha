#include "cryptography/gost3410_impl/signer.hpp"

#include "crypto/hash_types.hpp"
#include "cryptography/gost3410_impl/internal/gost_impl.hpp"
#include <iostream>
#include <vector>

namespace shared_model::crypto::gost3410 {
  std::string Signer::sign(const Blob & blob, const Keypair &keypair){;
    return gost3410::sign(toBinaryString(blob), 
              keypair.privateKey().blob().data(),
              keypair.privateKey().blob().size());
  } 
} // namespace shared_model::crypto::gost3410
