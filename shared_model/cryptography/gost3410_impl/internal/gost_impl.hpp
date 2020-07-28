#ifndef GOST_IMPL_HPP
#define GOST_IMPL_HPP

#include <string>
#include <string_view>

#include "cryptography/blob.hpp"
#include "cryptography/keypair.hpp" //TODO: move convertation to impl from internal
#include "crypto/keypair.hpp" // remove
#include "interfaces/common_objects/string_view_types.hpp"
#include <vector>

using shared_model::crypto::Keypair;

namespace iroha {
  sig_t sign(const uint8_t *msg,
              size_t msgsize,
              const pubkey_t &pub,
              const privkey_t &priv);

  sig_t sign(std::string_view msg, const pubkey_t &pub, const privkey_t &priv);

  std::vector<uint8_t> sign(const uint8_t *msg,
                    size_t msgsize,
                    const uint8_t* priv, size_t privLen);
  std::string sign(const std::string& msg, const uint8_t* priv, size_t privLen);

  bool verify(const uint8_t *msg,
              size_t msgsize,
              shared_model::interface::types::PublicKeyByteRangeView public_key,
              shared_model::interface::types::SignatureByteRangeView signature);

  bool verify(std::string_view msg,
              shared_model::interface::types::PublicKeyByteRangeView public_key,
              shared_model::interface::types::SignatureByteRangeView signature);


  blob_t<32> create_seed();

  blob_t<32> create_seed(std::string passphrase);

  Keypair create_keypair(blob_t<32> seed);

  Keypair create_keypair();

} // namespace iroha

#endif // GOST_IMPL_HPP