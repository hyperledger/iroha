# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(common INTERFACE
  # bind.hpp
  # blob.hpp
  # byteutils.hpp
  # cloneable.hpp
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

add_library(permutation_generator permutation_generator.cpp)

add_library(irohad_version irohad_version.cpp)

add_library(libs_to_string INTERFACE
  # to_string.hpp
  )
target_link_libraries(libs_to_string INTERFACE
  Boost::boost
  )

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

target_compile_definitions(irohad_version
  PRIVATE
    -DGIT_REPO_PRETTY_VER="${GIT_REPO_PRETTY_VER}"
    -DIROHA_MAJOR_VERSION=${PROJECT_VERSION_MAJOR}
    -DIROHA_MINOR_VERSION=${PROJECT_VERSION_MINOR}
    -DIROHA_PATCH_VERSION=${PROJECT_VERSION_PATCH}
  )
