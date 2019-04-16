/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <numeric>
#include <utility>

#include "common/bind.hpp"
#include "interactive/interactive_common_cli.hpp"
#include "parser/parser.hpp"

namespace iroha_cli {
  namespace interactive {

    DescriptionMap getCommonDescriptionMap() {
      return {
          // commonDescriptionMap
          {SAVE_CODE, "Save as json file"},
          {SEND_CODE, "Send to Iroha peer"}
          // commonDescriptionMap
      };
    }

    ParamsMap getCommonParamsMap(const std::string &default_ip,
                                 int default_port) {
      return {
          // commonParamsMap
          {SAVE_CODE, makeParamsDescription({"Path to save json file"})},
          {SEND_CODE,
           {ParamData({"Peer address", default_ip}),
            ParamData({"Peer port", std::to_string(default_port)})}}
          // commonParamsMap
      };
    }

    ParamsDescription makeParamsDescription(
        const std::vector<std::string> &params) {
      return std::accumulate(params.begin(),
                             params.end(),
                             ParamsDescription{},
                             [](auto &&acc, auto &el) {
                               acc.push_back(ParamData({el, {}}));
                               return std::forward<decltype(acc)>(acc);
                             });
    }

    void handleEmptyCommand() {
      std::cout << "Put not empty command" << std::endl;
    }

    void handleUnknownCommand(std::string &command) {
      std::cout << "Command not found: " << command << std::endl;
    }

    void addBackOption(MenuPoints &menu) {
      menu.push_back("0. Back (" + BACK_CODE + ")");
    }

    bool isBackOption(std::string line) {
      auto command = parser::parseFirstCommand(std::move(line));
      return command and (*command == "0" or *command == BACK_CODE);
    }

    void printCommandParameters(std::string &command,
                                const ParamsDescription &parameters) {
      std::cout << "Run " << command
                << " with following parameters: " << std::endl;
      std::for_each(parameters.begin(), parameters.end(), [](auto el) {
        std::cout << "  " << el.message << std::endl;
      });
    }

    void printMenu(const std::string &message, MenuPoints menu_points) {
      std::cout << message << std::endl;
      std::for_each(menu_points.begin(), menu_points.end(), [](auto el) {
        std::cout << el << std::endl;
      });
    }

    boost::optional<std::string> promptString(const std::string &message) {
      std::string line;
      std::cout << message << ": ";
      if (not std::getline(std::cin, line)) {
        // Input is a terminating symbol
        return boost::none;
      }
      return line;
    }

    boost::optional<std::string> promptString(const ParamData &param) {
      std::string message = param.message;
      if (not param.cache.empty()) {
        message += " (" + param.cache + ")";
      }
      return promptString(message);
    }

    void printEnd() {
      std::cout << "--------------------" << std::endl;
    }

    boost::optional<std::pair<std::string, uint16_t>> parseIrohaPeerParams(
        std::vector<std::string> params,
        const std::string &default_ip,
        int default_port) {
      const auto &address = params[0].empty() ? default_ip : params[0];
      auto port = params[1].empty() ? default_port
                                    : parser::parseValue<uint16_t>(params[1]);
      if (not params.empty() and not port) {
        std::cout << "Port has wrong format" << std::endl;
        // Continue parsing
        return boost::none;
      }
      return std::make_pair(address, *port);
    }

    boost::optional<std::vector<std::string>> parseParams(
        std::string line, std::string command_name, ParamsMap &params_map) {
      auto params_description = findInHandlerMap(command_name, params_map);
      if (not params_description) {
        // Report no params where found for this command
        std::cout << "Command params not found" << std::endl;
        // Stop parsing, something is not implemented
        return boost::none;
      }
      auto words = parser::split(std::move(line));
      if (words.size() == 1) {
        // Start interactive mode
        std::vector<std::string> params;
        std::for_each(params_description.value().begin(),
                      params_description.value().end(),
                      [&params](auto &param) {
                        using namespace iroha;
                        promptString(param) | [&](auto &&val) {
                          if (not val.empty()) {
                            // Update input cache
                            param.cache = val;
                            params.push_back(val);
                          } else if (not param.cache.empty()) {
                            // Input cache is not empty, use cached value
                            params.push_back(param.cache);
                          }
                        };
                      });
        if (params.size() != params_description.value().size()) {
          // Wrong params passed
          return boost::none;
        }
        return params;
      } else if (words.size() != params_description.value().size() + 1) {
        // Not enough parameters passed
        printCommandParameters(command_name, params_description.value());
        return boost::none;
      } else {
        // Remove command name, return parameters
        words.erase(words.begin());
        return words;
      }
    }

    size_t addMenuPoint(std::vector<std::string> &menu_points,
                        const std::string &description,
                        const std::string &command_short_name) {
      menu_points.push_back(std::to_string(menu_points.size() + 1) + ". "
                            + description + " (" + command_short_name + ")");
      return menu_points.size();
    }
  }  // namespace interactive
}  // namespace iroha_cli
