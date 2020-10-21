# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

find_package(pybind11 CONFIG REQUIRED)

add_library(data_model_adapter_python data_model_python.cpp)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    target_compile_options(data_model_adapter_python PRIVATE -fsized-deallocation)
endif()

target_link_libraries(data_model_adapter_python
  pybind11::embed
  shared_model_proto_backend
  )
