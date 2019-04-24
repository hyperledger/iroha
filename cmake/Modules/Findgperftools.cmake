add_library(gperftools SHARED IMPORTED)

if(PROFILING STREQUAL "HEAP")
  set(chosen_lib libtcmalloc.a)
elseif(PROFILING STREQUAL "CPU")
  set(chosen_lib libprofiler.a)
elseif(PROFILING STREQUAL "ALL")
  set(chosen_lib libtcmalloc_and_profiler.a)
else()
  message(FATAL_ERROR "PROFILING must be one of 'HEAP', 'CPU' or 'ALL' when enabled!")
endif()

find_path(gperftools_INCLUDE_DIR gperftools/tcmalloc.h
  PATHS ${EP_PREFIX}/src/gperftools_gperftools/include
  )
find_library(gperftools_LIBRARY_PATH ${chosen_lib}
  PATHS ${EP_PREFIX}/src/gperftools_gperftools-build/lib
  )

mark_as_advanced(gperftools_INCLUDE_DIR)
mark_as_advanced(gperftools_LIBRARY_PATH)

unset(gperftools_VERSION)
set(gperftools_version_file_path ${gperftools_INCLUDE_DIR}/gperftools/tcmalloc.h)
if (EXISTS ${gperftools_version_file_path})
  file(READ ${gperftools_version_file_path} gperftools_version_file)
  string(REGEX MATCH "TC_VERSION_MAJOR ([0-9]*)" _ ${gperftools_version_file})
  set(ver_major ${CMAKE_MATCH_1})
  string(REGEX MATCH "TC_VERSION_MINOR ([0-9]*)" _ ${gperftools_version_file})
  set(ver_minor ${CMAKE_MATCH_1})
  string(REGEX MATCH "TC_VERSION_PATCH ([0-9]*)" _ ${gperftools_version_file})
  set(ver_patch ${CMAKE_MATCH_1})
  set(gperftools_VERSION "${ver_major}.${ver_minor}.${ver_patch}")
endif()

if (NOT gperftools_LIBRARY_PATH
    OR NOT DEFINED gperftools_VERSION
    OR gperftools_VERSION VERSION_LESS gperftools_FIND_VERSION)
  message(STATUS "Package 'gperftools' of version ${gperftools_FIND_VERSION} not found. "
          "Will download it from git repo.")

  set(GIT_URL https://github.com/gperftools/gperftools.git)
  set(gperftools_VERSION ${gperftools_FIND_VERSION})
  set(GIT_TAG "gperftools-${gperftools_VERSION}")

  set (gperftools_BUILD_DIR "${EP_PREFIX}/src/gperftools_gperftools-build")
  externalproject_add(gperftools_gperftools
      GIT_REPOSITORY  ${GIT_URL}
      GIT_TAG         ${GIT_TAG}
      GIT_SHALLOW     ON
      CONFIGURE_COMMAND ./autogen.sh COMMAND ./configure --prefix=${gperftools_BUILD_DIR}
      BUILD_IN_SOURCE ON
      BUILD_COMMAND make
      INSTALL_COMMAND make install
      )
  externalproject_get_property(gperftools_gperftools source_dir)
  set(gperftools_INCLUDE_DIR ${EP_PREFIX}/src/gperftools_gperftools-build/include)
  set(gperftools_LIBRARY_PATH ${EP_PREFIX}/src/gperftools_gperftools-build/lib/${chosen_lib})

  # dirty hack to create a directory normally generated during installation
  file(MAKE_DIRECTORY ${gperftools_INCLUDE_DIR})

  add_dependencies(gperftools gperftools_gperftools)
endif ()

set_target_properties(gperftools PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${gperftools_INCLUDE_DIR}
    IMPORTED_LOCATION ${gperftools_LIBRARY_PATH}
    )

find_package_handle_standard_args(gperftools
    REQUIRED_VARS
      gperftools_INCLUDE_DIR
      gperftools_LIBRARY_PATH
    VERSION_VAR
      gperftools_VERSION
    )
