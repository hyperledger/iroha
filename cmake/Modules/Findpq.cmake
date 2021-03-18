add_library(pq UNKNOWN IMPORTED)
add_executable(pg_config IMPORTED)

find_path(pq_INCLUDE_DIR libpq-fe.h PATH_SUFFIXES postgresql)
mark_as_advanced(pq_INCLUDE_DIR)

find_path(postgres_INCLUDE_DIR postgres_ext.h PATH_SUFFIXES postgresql)
mark_as_advanced(postgres_INCLUDE_DIR)

# Windows libraries are usually not prefixed with 'lib', however this library
# has such a prefix, therefore we need to search for libpq instead of pq on
# Windows
find_library(pq_LIBRARY NAMES pq libpq)
mark_as_advanced(pq_LIBRARY)

find_library(pgcommon_LIBRARY NAMES pgcommon libpgcommon)
mark_as_advanced(pgcommon_LIBRARY)

find_library(pgport_LIBRARY NAMES pgport libpgport)
mark_as_advanced(pgport_LIBRARY)

# Debug library has 'd' suffix on Windows
if (MSVC)
  find_library(pqd_LIBRARY NAMES pqd libpqd)
  mark_as_advanced(pqd_LIBRARY)
endif ()

find_package_handle_standard_args(pq DEFAULT_MSG
    pq_INCLUDE_DIR
    postgres_INCLUDE_DIR
    pq_LIBRARY
    )

set(URL https://git.postgresql.org/git/postgresql.git)
set(VERSION 029386ccbddd0a33d481b94e511f5219b03e6636)
set_target_description(pq "C postgres client library" ${URL} ${VERSION})

if (NOT pq_FOUND)
  externalproject_add(postgres_postgres
      GIT_REPOSITORY  ${URL}
      GIT_TAG         ${VERSION}
      CONFIGURE_COMMAND
                      ./configure --without-readline --prefix=${EP_PREFIX}
                      CC=${CMAKE_C_COMPILER}

      BUILD_IN_SOURCE 1
      BUILD_COMMAND ${MAKE} COPT=${CMAKE_C_FLAGS} -C ./src/bin/pg_config &&
                    ${MAKE} COPT=${CMAKE_C_FLAGS} -C ./src/interfaces/libpq &&
                    ${MAKE} COPT=${CMAKE_C_FLAGS} -C ./src/backend ../../src/include/utils/fmgroids.h
      BUILD_BYPRODUCTS ${EP_PREFIX}/lib/libpq.a
      INSTALL_COMMAND make -C src/bin/pg_config install &&
                      make -C src/interfaces/libpq install &&
                      make -C src/include install
      TEST_COMMAND "" # remove test step
      UPDATE_COMMAND "" # remove update step
      )
  set(postgres_INCLUDE_DIR ${EP_PREFIX}/include)
  set(pq_INCLUDE_DIR ${EP_PREFIX}/include)
  set(pq_LIBRARY ${EP_PREFIX}/lib/libpq.a)
  set(pg_config_EXECUTABLE ${EP_PREFIX}/bin/pg_config)
  file(MAKE_DIRECTORY ${pq_INCLUDE_DIR} ${postgres_INCLUDE_DIR})

  add_dependencies(pg_config postgres_postgres)
  add_dependencies(pq postgres_postgres pg_config)
endif ()

get_filename_component(pq_LIBRARY_DIR ${pq_LIBRARY} DIRECTORY)
mark_as_advanced(pq_LIBRARY_DIR)

if (MSVC)
  set_target_properties(pq PROPERTIES
      IMPORTED_LOCATION_DEBUG ${pqd_LIBRARY}
      IMPORTED_LOCATION_RELEASE ${pq_LIBRARY}
      )
endif ()

set_target_properties(pq PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${pq_INCLUDE_DIR};${postgres_INCLUDE_DIR}"
    IMPORTED_LOCATION ${pq_LIBRARY}
    )

if (VCPKG_TOOLCHAIN)
  find_package(OpenSSL REQUIRED)
  set_target_properties(pq PROPERTIES
      INTERFACE_LINK_LIBRARIES OpenSSL::SSL
      )
endif ()
if(pgcommon_LIBRARY)
  target_link_libraries(pq
      INTERFACE
      ${pgcommon_LIBRARY}
      )
endif()
if(pgport_LIBRARY)
  target_link_libraries(pq
      INTERFACE
      ${pgport_LIBRARY}
      )
endif()

if(ENABLE_LIBS_PACKAGING)
  add_install_step_for_lib(${pq_LIBRARY})
endif()
