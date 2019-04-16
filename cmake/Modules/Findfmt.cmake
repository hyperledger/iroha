add_library(fmt INTERFACE IMPORTED)

find_path(fmt_INCLUDE_DIR fmt/format.h
  PATHS ${EP_PREFIX}/src/fmtlib_fmt/include)
mark_as_advanced(fmt_INCLUDE_DIR)

# read the fmt version stored in fmt/core.h
unset(fmt_VERSION)
set(fmt_version_file_path ${fmt_INCLUDE_DIR}/fmt/core.h)
if (EXISTS ${fmt_version_file_path})
  file(READ ${fmt_version_file_path} fmt_version_file)
  if (fmt_version_file MATCHES "FMT_VERSION ([0-9]+)([0-9][0-9])([0-9][0-9])")
    # Use math to skip leading zeros if any.
    math(EXPR ver_major ${CMAKE_MATCH_1})
    math(EXPR ver_minor ${CMAKE_MATCH_2})
    math(EXPR ver_patch ${CMAKE_MATCH_3})
    set(fmt_VERSION "${ver_major}.${ver_minor}.${ver_patch}")
  endif ()
endif ()

if (NOT DEFINED fmt_VERSION OR fmt_VERSION VERSION_LESS fmt_FIND_VERSION)
  message(STATUS "Package 'fmt' of version ${fmt_FIND_VERSION} not found. "
          "Will download it from git repo.")

  set(GIT_URL https://github.com/fmtlib/fmt.git)
  set(fmt_VERSION ${fmt_FIND_VERSION})
  set(GIT_TAG "refs/tags/${fmt_VERSION}")
  set_package_properties(fmt
      PROPERTIES
      URL ${GIT_URL}
      DESCRIPTION "String formatting library"
      )

  externalproject_add(fmtlib_fmt
      GIT_REPOSITORY  ${GIT_URL}
      GIT_TAG         ${GIT_TAG}
      GIT_SHALLOW     1
      CONFIGURE_COMMAND "" # remove configure step
      BUILD_COMMAND "" # remove build step
      INSTALL_COMMAND "" # remove install step
      TEST_COMMAND "" # remove test step
      )
  externalproject_get_property(fmtlib_fmt source_dir)
  set(fmt_INCLUDE_DIR ${source_dir}/include)
  file(MAKE_DIRECTORY ${fmt_INCLUDE_DIR})

  add_dependencies(fmt fmtlib_fmt)
endif()

set_target_properties(fmt PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${fmt_INCLUDE_DIR}
    )

target_compile_definitions(fmt INTERFACE FMT_HEADER_ONLY)

find_package_handle_standard_args(fmt
    REQUIRED_VARS
      fmt_INCLUDE_DIR
    VERSION_VAR
      fmt_VERSION
    )

