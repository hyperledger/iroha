#include "cryptography/gost3410_impl/signer.hpp"

#include "crypto/hash_types.hpp"
#include "cryptography/gost3410_impl/internal/gost_impl.hpp"

namespace shared_model {
  namespace crypto {
    std::string Signer::sign(const Blob & blob, const Keypair &keypair){
      return iroha::pubkey_t::from_hexstring(keypair.publicKey())
          .match(
              [&](auto &&public_key) {
                return iroha::sign(crypto::toBinaryString(blob),
                                   std::move(public_key).value,
                                   iroha::privkey_t::from_raw(
                                       keypair.privateKey().blob().data()))
                    .to_hexstring();
              },
              [](const auto & /* error */) { return std::string{}; });
    }
  } // namespace crypto
} // namespace shared_model