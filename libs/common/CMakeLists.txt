# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(common INTERFACE
  # bind.hpp
  # blob.hpp
  # byteutils.hpp
  # cloneable.hpp
  # default_constructible_unary_fn.hpp
  # instanceof.hpp
  # is_any.hpp
  # obj_utils.hpp
  # result.hpp
  # set.hpp
  # visitor.hpp
  )
target_link_libraries(common INTERFACE
  Boost::boost
  )

add_library(libs_files
  files.cpp
  )
target_link_libraries(libs_files
  logger
  common
  Boost::filesystem
  )

add_library(libs_timeout INTERFACE
  # timeout.hpp
  )
target_link_libraries(libs_timeout INTERFACE
  common
  rxcpp
  )

add_library(irohad_version irohad_version.cpp)

# Get the git repo data
set(GIT_REPO_PRETTY_VER "version info unavailable")
if (EXISTS "${PROJECT_SOURCE_DIR}/.git")
  if(NOT GIT_FOUND)
    find_package(Git QUIET)
  endif()

  if(GIT_EXECUTABLE)
    # Get pretty version
    execute_process(COMMAND
        "${GIT_EXECUTABLE}"
        describe --tags --always
        WORKING_DIRECTORY
        "${PROJECT_SOURCE_DIR}"
        RESULT_VARIABLE
        res
        OUTPUT_VARIABLE
        GIT_REPO_PRETTY_VER
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT res EQUAL 0)
      message(STATUS "Error running `git describe': ${res}")
    endif()
    message(STATUS "Git repo pretty version: ${GIT_REPO_PRETTY_VER}")
  else()
    message(STATUS "Git executable not found!")
  endif()
endif()

target_compile_definitions(irohad_version PRIVATE -DGIT_REPO_PRETTY_VER="${GIT_REPO_PRETTY_VER}")
