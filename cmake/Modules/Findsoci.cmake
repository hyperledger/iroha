set(_SOCI_REQUIRED_VARS SOCI_INCLUDE_DIR SOCI_LIBRARY SOCI_postgresql_PLUGIN)

add_library(SOCI::core UNKNOWN IMPORTED)
add_library(SOCI::postgresql UNKNOWN IMPORTED)

find_path(
    SOCI_INCLUDE_DIR soci.h
    PATH_SUFFIXES "" "soci"
    DOC "Soci (http://soci.sourceforge.net) include directory")
mark_as_advanced(SOCI_INCLUDE_DIR)
get_filename_component(_SOCI_INCLUDE_PARENT_DIR ${SOCI_INCLUDE_DIR} DIRECTORY)
set(SOCI_INCLUDE_DIRS ${SOCI_INCLUDE_DIR} ${_SOCI_INCLUDE_PARENT_DIR})
mark_as_advanced(SOCI_INCLUDE_DIRS)

find_library(
    SOCI_LIBRARY
    NAMES soci_core soci_core_4_0
    HINTS ${SOCI_INCLUDE_DIR}/..
    PATH_SUFFIXES lib${LIB_SUFFIX})
mark_as_advanced(SOCI_LIBRARY)

find_library(
    SOCI_postgresql_PLUGIN
    NAMES soci_postgresql soci_postgresql_4_0
    HINTS ${SOCI_INCLUDE_DIR}/..
    PATH_SUFFIXES lib${LIB_SUFFIX})
mark_as_advanced(SOCI_postgresql_PLUGIN)

get_filename_component(SOCI_LIBRARY_DIR ${SOCI_LIBRARY} PATH)
mark_as_advanced(SOCI_LIBRARY_DIR)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(soci DEFAULT_MSG ${_SOCI_REQUIRED_VARS})

set_target_properties(SOCI::core PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${SOCI_INCLUDE_DIRS}"
    IMPORTED_LOCATION "${SOCI_LIBRARY}"
    )

if (NOT MSVC)
  set_target_properties(SOCI::core PROPERTIES
      INTERFACE_LINK_LIBRARIES dl
      )
endif ()

set_target_properties(SOCI::postgresql PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${SOCI_INCLUDE_DIRS}"
    IMPORTED_LOCATION "${SOCI_postgresql_PLUGIN}"
    INTERFACE_LINK_LIBRARIES PostgreSQL::PostgreSQL
    )
