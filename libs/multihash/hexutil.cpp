/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "hexutil.hpp"

#include <boost/algorithm/hex.hpp>
#include <boost/format.hpp>

namespace kagome {
  namespace common {

    std::string int_to_hex(uint64_t n, size_t fixed_width) noexcept {
      std::stringstream result;
      result.width(fixed_width);
      result.fill('0');
      result << std::hex << std::uppercase << n;
      auto str = result.str();
      if (str.length() % 2 != 0) {
        str.push_back('\0');
        for (int64_t i = str.length() - 2; i >= 0; --i) {
          str[i + 1] = str[i];
        }
        str[0] = '0';
      }
      return str;
    }

    std::string hex_upper(const std::vector<uint8_t> &bytes) noexcept {
      std::string res(bytes.size() * 2, '\x00');
      boost::algorithm::hex(bytes.begin(), bytes.end(), res.begin());
      return res;
    }

    iroha::expected::Result<std::vector<uint8_t>, std::string> unhex(
        const std::string &hex) {
      std::vector<uint8_t> blob;
      blob.reserve((hex.size() + 1) / 2);

      try {
        boost::algorithm::unhex(
            hex.begin(), hex.end(), std::back_inserter(blob));
        return blob;

      } catch (const boost::algorithm::not_enough_input &e) {
        return "Input contains odd number of characters";

      } catch (const boost::algorithm::non_hex_input &e) {
        return "Input contains non-hex characters";

      } catch (const std::exception &e) {
        return e.what();
      }
    }

  }  // namespace common
}  // namespace kagome
