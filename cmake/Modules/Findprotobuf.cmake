add_library(protobuf UNKNOWN IMPORTED)
add_executable(protoc IMPORTED)

if (FIND_PROTOBUF)
  find_path(protobuf_INCLUDE_DIR google/protobuf/service.h)
  mark_as_advanced(protobuf_INCLUDE_DIR)

  find_library(protobuf_LIBRARY protobuf)
  mark_as_advanced(protobuf_LIBRARY)

  find_program(protoc_EXECUTABLE protoc)
  mark_as_advanced(protoc_EXECUTABLE)
endif()

find_package_handle_standard_args(protobuf DEFAULT_MSG
    protobuf_INCLUDE_DIR
    protobuf_LIBRARY
    protoc_EXECUTABLE
    )

set(URL https://github.com/google/protobuf.git)
set(VERSION 09745575a923640154bcf307fba8aedff47f240a) # Protocol Buffers v3.8.0
set_target_description(protobuf "Protocol buffers library" ${URL} ${VERSION})

if (NOT protobuf_FOUND)
  externalproject_add(google_protobuf
      GIT_REPOSITORY  ${URL}
      GIT_TAG         ${VERSION}
      CONFIGURE_COMMAND ${CMAKE_COMMAND}
                      -G${CMAKE_GENERATOR}
                      -H${EP_PREFIX}/src/google_protobuf/cmake -B${EP_PREFIX}/src/google_protobuf-build
                      ${DEPS_CMAKE_ARGS}
                      -Dprotobuf_BUILD_TESTS=OFF
                      -Dprotobuf_BUILD_SHARED_LIBS=ON
      BUILD_BYPRODUCTS ${EP_PREFIX}/src/google_protobuf-build/protoc
                       ${EP_PREFIX}/src/google_protobuf-build/${CMAKE_SHARED_LIBRARY_PREFIX}protobuf${CMAKE_SHARED_LIBRARY_SUFFIX}
      INSTALL_COMMAND ""
      TEST_COMMAND "" # remove test step
      UPDATE_COMMAND "" # remove update step
      )
  externalproject_get_property(google_protobuf source_dir binary_dir)
  set(protobuf_INCLUDE_DIR ${source_dir}/src)
  set(protobuf_LIBRARY ${binary_dir}/${CMAKE_SHARED_LIBRARY_PREFIX}protobuf${CMAKE_SHARED_LIBRARY_SUFFIX})
  set(protoc_EXECUTABLE ${binary_dir}/protoc)
  file(MAKE_DIRECTORY ${protobuf_INCLUDE_DIR})
  link_directories(${binary_dir})

  add_dependencies(protoc google_protobuf)
  add_dependencies(protobuf google_protobuf protoc)
endif ()

get_filename_component(protobuf_LIBRARY_DIR ${protobuf_LIBRARY} DIRECTORY)
mark_as_advanced(protobuf_LIBRARY_DIR)

set_target_properties(protobuf PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${protobuf_INCLUDE_DIR}
    IMPORTED_LOCATION ${protobuf_LIBRARY}
    )

set_target_properties(protoc PROPERTIES
    IMPORTED_LOCATION ${protoc_EXECUTABLE}
    )


if(ENABLE_LIBS_PACKAGING)
  add_install_step_for_lib(${protobuf_LIBRARY})
endif()
