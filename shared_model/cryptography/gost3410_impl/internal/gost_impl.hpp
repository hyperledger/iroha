#ifndef GOST_IMPL_HPP
#define GOST_IMPL_HPP

#include <string_view>
#include <vector>
#include <utility>

namespace shared_model::crypto::gost3410 {
  std::vector<uint8_t> sign(const uint8_t *msg,
                    size_t msgsize,
                    const uint8_t* priv, size_t privLen);
  std::vector<uint8_t> sign(const std::string& msg, const uint8_t* priv, size_t privLen);
 
  bool verify(const uint8_t* msg,
              size_t msgsize,
              const uint8_t* pub_key,
              size_t pub_key_size,
              const uint8_t* signature,
              size_t signature_size);
              
  bool verify(std::string_view& msg,
              const std::vector<uint8_t>& public_key,
              const std::vector<uint8_t>& signature);

  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> create_keypair();
} // namespace shared_model::crypto::gost3410

#endif // GOST_IMPL_HPP
