/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CLI_INTERACTIVE_COMMON_CLI_HPP
#define IROHA_CLI_INTERACTIVE_COMMON_CLI_HPP

#include <algorithm>
#include <ciso646>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/optional.hpp>

namespace parser {
  boost::optional<std::string> parseFirstCommand(std::string line);
}

namespace iroha_cli {
  namespace interactive {

    /**
     * Parsing menu context, used to identify the context of parsing
     */
    enum MenuContext {
      /**
       * Main menu context, used to print all commands/queries
       */
      MAIN,
      /**
       * Result menu, used for send, save tx/query
       */
      RESULT
    };

    /**
     * Data structure for parameter data
     */
    struct ParamData {
      /**
       * Message to display when prompting for user input
       */
      std::string message;

      /**
       * Cached user input for the parameter or the default value
       */
      std::string cache;
    };

    // Description of parameters
    using ParamsDescription = std::vector<ParamData>;
    // map for command - command description relationship
    using DescriptionMap = std::unordered_map<std::string, std::string>;
    // Points in a menu
    using MenuPoints = std::vector<std::string>;
    // map for command - ParamsDescription relationship
    using ParamsMap = std::unordered_map<std::string, ParamsDescription>;

    // ------ Common commands short name ---------
    const std::string SAVE_CODE = "save";
    const std::string SEND_CODE = "send";
    const std::string BACK_CODE = "b";

    /**
     * Return mapping of Command_name to Command description
     * @return DesciptionMap for common commands
     */
    DescriptionMap getCommonDescriptionMap();

    /**
     * Return mapping of Command_name to parameters descriptions
     * @param default_ip - default hostname or IP to be used when connecting to
     * irohad
     * @param default_port - default port to be used when connecting to irohad
     * @return ParamsMap with parameters of common commands
     */
    ParamsMap getCommonParamsMap(const std::string &default_ip,
                                 int default_port);

    /**
     * Creates parameters descriptions with empty default/cache values
     * @param params - parameters as a vector of prompt messages
     * @return ParamsDescription with parameter data
     */
    ParamsDescription makeParamsDescription(
        const std::vector<std::string> &params);

    /**
     * Handle error with empty command
     */
    void handleEmptyCommand();

    /**
     * Handle error of unknown command
     * @param command - name of unknown command
     */
    void handleUnknownCommand(std::string &command);

    /**
     * Add back option to menu
     * @param menu - menu to add the back option
     */
    void addBackOption(MenuPoints &menu);

    /**
     * Is line contains "Go Back" option
     * @param line to parse
     * @return true if line has command "go back"
     */
    bool isBackOption(std::string line);

    /**
     * Print end of session symbol
     */
    void printEnd();

    /**
     * Print help for cli command.
     * @param command - name of the cli command
     * @param parameters needed to run the command
     */
    void printCommandParameters(std::string &command,
                                const ParamsDescription &parameters);

    /**
     * Pretty Print of menu
     * @param message - message to print before menu
     * @param menu_points - elements of the menu
     */
    void printMenu(const std::string &message, MenuPoints menu_points);

    /**
     * Get string input from user
     * @param message Message to ask user
     * @return nullopt if termintaing symbol, else user's input
     */
    boost::optional<std::string> promptString(const std::string &message);

    /**
     * Construct a prompt and get a string input from user
     * @param param Parameter to collect the input for
     * @return nullopt if termintaing symbol, else user's input
     */
    boost::optional<std::string> promptString(const ParamData &param);

    /**
     * Parse parameters in interactive and shortcuted mode.
     * Function run interactive mode if in line only the command name is passed.
     * Function will parse all needed parameters from line if the line with
     * commands is passed, it will print help if there are not enough parameters
     * in line.
     * @param line - cli line to parse
     * @param command_name - command name to print
     * @param notes - parameters needed to run the command
     * @return vector with needed parameters
     */
    boost::optional<std::vector<std::string>> parseParams(
        std::string line, std::string command_name, ParamsMap &params_map);

    /**
     * Add menu point to vector menu
     * @param menu_points to add new point
     * @param description of the command to add
     * @param command_short_name command short name
     */
    size_t addMenuPoint(std::vector<std::string> &menu_points,
                        const std::string &description,
                        const std::string &command_short_name);

    /**
     * Get next numerical index in the map.
     * Used to build menu
     * @tparam K - key type in map
     * @tparam V - value type in map
     * @param parsers_map - map to process
     * @return index for the next menu point
     */
    template <typename K, typename V>
    std::size_t getNextIndex(std::unordered_map<K, V> parsers_map) {
      return parsers_map.size() == 0 ? 1 : parsers_map.size();
    }

    /**
     * Find in unordered map with error reporting.
     * Will print unkown command if key not found.
     * @tparam K key type
     * @tparam V value type
     * @param command_name - key to find in the map
     * @param params_map - map
     * @return nullopt if key not found, value if found
     */
    template <typename K, typename V>
    boost::optional<V &> findInHandlerMap(
        K command_name, std::unordered_map<K, V> &params_map) {
      auto it = params_map.find(command_name);
      if (it == params_map.end()) {
        // Command not found, report error
        handleUnknownCommand(command_name);
        return boost::none;
      }
      return it->second;
    }

    /**
     * Parse parameters related to Iroha Peer
     * @param params in format: vector of strings
     * @return pair if ip and port if formed right, nullopt otherwise
     */
    boost::optional<std::pair<std::string, uint16_t>> parseIrohaPeerParams(
        std::vector<std::string> params,
        const std::string &default_ip,
        int default_port);

    /**
     * Handle parsing routine:
     *  - find appropriate parser function for the command
     *  - get input from user for the command
     *  - trigger specific parser
     * @tparam T - expected return type of a parsing function
     * @tparam V - type of the parser function in parsers_map
     * @tparam C - class type of class_pointer
     * @param class_pointer - class pointer that holds parser functions
     * @param line - line to parse
     * @param parsers_map - map holding parser functions
     * @param params_map - map holding descriptions for command parameters
     * @return T if parsing successful, nullopt otherwise
     */
    template <typename T, typename V, typename C>
    boost::optional<T> handleParse(
        C class_pointer,
        std::string &line,
        std::unordered_map<std::string, V> &parsers_map,
        ParamsMap &params_map) {
      auto raw_command = parser::parseFirstCommand(line);
      if (not raw_command) {
        handleEmptyCommand();
        return boost::none;
      }
      auto command_name = raw_command.value();
      auto parser = findInHandlerMap(command_name, parsers_map);
      if (not parser) {
        std::cout << "Parser for command not found" << std::endl;
        return boost::none;
      }
      auto params = parseParams(line, command_name, params_map);
      if (not params) {
        std::cout << "Parse params returned no value" << std::endl;
        return boost::none;
      }
      return (class_pointer->*parser.value())(params.value());
    }

    /**
     * Add new  cli command to menu points and menu handlers (parsers)
     * @tparam V type of parser functions in parsers_map
     * @param menu_points - menu to which points will be added
     * @param parsers_map - map holding specific parser functions
     * @param command_name - short command name
     * @param command_description - description for the command
     * @param parser - specific parser for current command
     */
    template <typename V>
    void addCliCommand(MenuPoints &menu_points,
                       std::unordered_map<std::string, V> &parsers_map,
                       const std::string &command_name,
                       const std::string &command_description,
                       V parser) {
      // Add menu point and get the index in menu of current command
      auto index = std::to_string(
          addMenuPoint(menu_points, command_description, command_name));
      // Add parser for this command
      parsers_map[index] = parser;
      parsers_map[command_name] = parser;
    }

    /**
     * Form menu points from given parameters and bind index of the command with
     * their parser and parameters
     * @tparam V - type of specific  parser functions in parsers_map
     * @param parsers_map - map holding specific parser functions
     * @param paramsMap - map holding descriptions for command parameters
     * @param descriptionMap - map holding description of a command
     * @return Formed menu points
     */
    template <typename V>
    MenuPoints formMenu(std::unordered_map<std::string, V> &parsers_map,
                        ParamsMap &paramsMap,
                        const DescriptionMap descriptionMap) {
      // Add menu point and get the index in menu of current command
      MenuPoints menu_points;
      std::for_each(descriptionMap.begin(),
                    descriptionMap.end(),
                    [&parsers_map, &menu_points, &paramsMap](auto val) {
                      auto command_name = val.first;
                      auto command_description = val.second;

                      auto index = std::to_string(addMenuPoint(
                          menu_points, command_description, command_name));
                      parsers_map[index] = parsers_map.at(command_name);
                      ;
                      paramsMap[index] = paramsMap.at(command_name);
                    });
      return menu_points;
    }

  }  // namespace interactive
}  // namespace iroha_cli

#endif  // IROHA_CLI_INTERACTIVE_COMMON_CLI_HPP
