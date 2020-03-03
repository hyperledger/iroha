# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.14.0)

project(shared_model C CXX)

set(IROHA_SCHEMA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/schema")
set(SM_SCHEMA_DIR "${IROHA_SCHEMA_DIR}")
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../libs
    ${CMAKE_CURRENT_SOURCE_DIR}
)

if (NOT IROHA_ROOT_PROJECT)
  set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
  if (NOT MSVC)
    set(CMAKE_CXX_FLAGS "-std=c++17 -Wall -fdiagnostics-color=always")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -Wno-error=deprecated-declarations")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -Wextra -Wno-unused-parameter -Wno-deprecated-declarations -O0")
  endif ()

  if(CMAKE_GENERATOR MATCHES "Make")
    set(MAKE "$(MAKE)")
  else()
    set(MAKE make)
  endif()

  option(TESTING "Build tests" ON)

  set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Modules)

  include(FeatureSummary)
  include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/functions.cmake)
  include(cmake/dependencies.cmake)
  set(SCHEMA_OUT_DIR ${CMAKE_BINARY_DIR}/schema)

  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../libs/generator generator)
endif ()

add_subdirectory(backend)
add_subdirectory(builders)
add_subdirectory(converters)
add_subdirectory(cryptography)
add_subdirectory(interfaces)
add_subdirectory(utils)
add_subdirectory(validators)
add_subdirectory(schema)

if (NOT IROHA_ROOT_PROJECT)
  if (TESTING)
    enable_testing()
    add_subdirectory(test)
  endif ()
endif ()
