#include "cryptography/gost3410_impl/signer.hpp"

#include "crypto/hash_types.hpp"
#include "cryptography/gost3410_impl/internal/gost_impl.hpp"
#include <iostream>
#include <vector>

namespace shared_model {
  namespace crypto {
    std::string Signer::sign(const Blob & blob, const Keypair &keypair){
      // std::cout << "Hex PubKey: " << keypair.publicKey().t << std::endl;
      // return iroha::pubkey_t::from_hexstring(keypair.publicKey())
      //     .match(
      //         [&](auto &&public_key) {
      //           return iroha::sign(crypto::toBinaryString(blob),
      //                              std::move(public_key).value,
      //                              iroha::privkey_t::from_raw(
      //                                  keypair.privateKey().blob().data()))
      //               .to_hexstring();
      //         },
      //         [](const auto & /* error */) { return std::string{}; });
      // auto tmp = iroha::sign(crypto::toBinaryString(blob),
      //                              std::move(public_key).value,
      //                              iroha::privkey_t::from_raw(
      //                                  keypair.privateKey().blob().data()))
      // std::cout << "PK: " << keypair.publicKey().t << std::endl;
      // auto pkb = std::vector<uint8_t>(keypair.privateKey().blob().begin(),
      //                   keypair.privateKey().blob().end());
      return iroha::sign(crypto::toBinaryString(blob), 
                keypair.privateKey().blob().data(),
                keypair.privateKey().blob().size());
    }
  } // namespace crypto
} // namespace shared_model