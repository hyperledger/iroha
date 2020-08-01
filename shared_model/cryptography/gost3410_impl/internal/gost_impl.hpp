#ifndef GOST_IMPL_HPP
#define GOST_IMPL_HPP

#include <string_view>
#include <vector>
#include <utility>

namespace iroha {
  std::vector<uint8_t> sign(const uint8_t *msg,
                    size_t msgsize,
                    const uint8_t* priv, size_t privLen);
  std::string sign(const std::string& msg, const uint8_t* priv, size_t privLen);
 
  bool verify(const uint8_t* msg,
              size_t msgsize,
              const uint8_t* pub_key,
              size_t pub_key_size,
              const uint8_t* signature,
              size_t signature_size);
              
  bool verify(std::string_view& msg,
              const std::vector<uint8_t>& public_key,
              const std::vector<uint8_t>& signature);

  std::pair<std::string, std::vector<uint8_t>> create_keypair();

} // namespace iroha

#endif // GOST_IMPL_HPP
