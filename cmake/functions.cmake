# Compile the specified target as a modern, strict C++.
function(strictmode target)
  # Require pure C++14 standard.
  set_target_properties(${target} PROPERTIES
      CXX_STANDARD 14
      CXX_STANDARD_REQUIRED ON
      CXX_EXTENSIONS OFF
      )
  # Enable more warnings and turn them into compile errors.
  if ((CMAKE_CXX_COMPILER_ID STREQUAL "GNU") OR
  (CMAKE_CXX_COMPILER_ID STREQUAL "Clang") OR
  (CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang"))
    target_compile_options(${target} PRIVATE -Wall -Wpedantic -Werror -Wno-potentially-evaluated-expression)
  elseif ((CMAKE_CXX_COMPILER_ID STREQUAL "MSVC") OR
  (CMAKE_CXX_COMPILER_ID STREQUAL "Intel"))
    target_compile_options(${target} PRIVATE /W3 /WX)
  else ()
    message(AUTHOR_WARNING "Unknown compiler: building target ${target} with default options")
  endif ()
endfunction()

# Creates test "test_name", with "SOURCES" (use string as second argument)
function(addtest test_name SOURCES)
  if (COVERAGE)
    set(test_xml_output --gtest_output=xml:${REPORT_DIR}/xunit-${test_name}.xml)
  endif ()
  add_executable(${test_name} ${SOURCES})
  target_link_libraries(${test_name} gtest::main gmock::main)
  target_include_directories(${test_name} PUBLIC ${PROJECT_SOURCE_DIR}/test)

  # fetch directory after test in source dir call
  # for example:
  # "/Users/user/iroha/test/integration/acceptance"
  # match to "integration"
  string(REGEX REPLACE ".*test\\/([a-zA-Z]+).*" "\\1" output ${CMAKE_CURRENT_SOURCE_DIR})

  add_test(
      NAME "${output}_${test_name}"
      COMMAND $<TARGET_FILE:${test_name}> ${test_xml_output}
  )
  if (NOT MSVC)
    # protobuf generates warnings at the moment
    strictmode(${test_name})
  endif ()
  if ((CMAKE_CXX_COMPILER_ID STREQUAL "GNU") OR
  (CMAKE_CXX_COMPILER_ID STREQUAL "Clang") OR
  (CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang"))
    target_compile_options(${test_name} PRIVATE -Wno-inconsistent-missing-override)
  elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # do nothing, but also don't spam warning on each test
  else ()
    message(AUTHOR_WARNING "Unknown compiler: building target ${target} with default options")
  endif ()
endfunction()

# Creates benchmark "bench_name", with "SOURCES" (use string as second argument)
function(addbenchmark bench_name SOURCES)
  add_executable(${bench_name} ${SOURCES})
  target_link_libraries(${bench_name} PRIVATE benchmark)
  strictmode(${bench_name})
endfunction()

function(compile_proto_to_cpp PROTO)
  string(REGEX REPLACE "\\.proto$" ".pb.h" GEN_PB_HEADER ${PROTO})
  string(REGEX REPLACE "\\.proto$" ".pb.cc" GEN_PB ${PROTO})
  if (MSVC OR VCPKG_TOOLCHAIN)
    set(GEN_COMMAND "${Protobuf_PROTOC_EXECUTABLE}")
    set(GEN_ARGS ${Protobuf_INCLUDE_DIR})
  else()
    set(GEN_COMMAND ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=${protobuf_LIBRARY_DIR}:$ENV{LD_LIBRARY_PATH} "${protoc_EXECUTABLE}")
    set(GEN_ARGS ${protobuf_INCLUDE_DIR})
  endif()
  add_custom_command(
      OUTPUT ${SCHEMA_OUT_DIR}/${GEN_PB_HEADER} ${SCHEMA_OUT_DIR}/${GEN_PB}
      COMMAND ${GEN_COMMAND}
      ARGS -I${GEN_ARGS} -I${CMAKE_CURRENT_SOURCE_DIR} ${ARGN} --cpp_out=${SCHEMA_OUT_DIR} ${PROTO}
      DEPENDS protoc ${SCHEMA_PATH}/${PROTO}
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      )
endfunction()

function(compile_proto_only_grpc_to_cpp PROTO)
  string(REGEX REPLACE "\\.proto$" ".grpc.pb.h" GEN_GRPC_PB_HEADER ${PROTO})
  string(REGEX REPLACE "\\.proto$" ".grpc.pb.cc" GEN_GRPC_PB ${PROTO})
  if(TESTING)
    # Generate gRPC mock classes for services
    set(GENERATE_MOCKS "generate_mock_code=true:")
    string(REGEX REPLACE "\\.proto$" "_mock.grpc.pb.h" GEN_GRPC_PB_MOCK_HEADER ${PROTO})
    set(TEST_OUTPUT ${SCHEMA_OUT_DIR}/${GEN_GRPC_PB_MOCK_HEADER})
  endif(TESTING)
  if (MSVC OR VCPKG_TOOLCHAIN)
    set(GEN_COMMAND "${Protobuf_PROTOC_EXECUTABLE}")
    set(GEN_ARGS ${Protobuf_INCLUDE_DIR})
    set(GEN_PLUGIN "${gRPC_CPP_PLUGIN_EXECUTABLE}")
  else()
    set(GEN_COMMAND ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=${protobuf_LIBRARY_DIR}:$ENV{LD_LIBRARY_PATH} "${protoc_EXECUTABLE}")
    set(GEN_ARGS ${protobuf_INCLUDE_DIR})
    set(GEN_PLUGIN "${grpc_CPP_PLUGIN}")
  endif()
  add_custom_command(
      OUTPUT ${SCHEMA_OUT_DIR}/${GEN_GRPC_PB_HEADER} ${SCHEMA_OUT_DIR}/${GEN_GRPC_PB} ${TEST_OUTPUT}
      COMMAND ${GEN_COMMAND}
      ARGS -I${GEN_ARGS} -I${CMAKE_CURRENT_SOURCE_DIR} ${ARGN} --grpc_out=${GENERATE_MOCKS}${SCHEMA_OUT_DIR} --plugin=protoc-gen-grpc=${GEN_PLUGIN} ${PROTO}
      DEPENDS grpc_cpp_plugin ${SCHEMA_PATH}/${PROTO}
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      )
endfunction()

function(compile_proto_to_grpc_cpp PROTO)
  compile_proto_to_cpp(${PROTO} "${ARGN}")
  compile_proto_only_grpc_to_cpp(${PROTO} "${ARGN}")
endfunction()


macro(set_target_description target description url commit)
  set_package_properties(${target}
      PROPERTIES
      URL ${url}
      DESCRIPTION ${description}
      PURPOSE "commit: ${commit}"
      )
endmacro()


macro(add_install_step_for_bin target)
  install(TARGETS ${target}
      RUNTIME DESTINATION bin
      CONFIGURATIONS ${CMAKE_BUILD_TYPE}
      COMPONENT binaries)
endmacro()


macro(add_install_step_for_lib libpath)
  # full path with resolved symlinks:
  # /usr/local/lib/libprotobuf.so -> /usr/local/lib/libprotobuf.so.13.0.0
  get_filename_component(lib_major_minor_patch ${libpath} REALPATH)

  install(FILES ${lib_major_minor_patch}
      DESTINATION lib
      CONFIGURATIONS ${CMAKE_BUILD_TYPE}
      COMPONENT libraries)
endmacro()


macro(remove_line_terminators str output)
  string(REGEX REPLACE "\r|\n" "" ${output} ${str})
endmacro()


macro(get_git_revision commit)
  find_package(Git)
  execute_process(
      COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
      OUTPUT_VARIABLE ${commit}
      WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  )
endmacro()

macro(append_build_flags)
  string(REPLACE ";" " " SPACE_ARGS "${ARGN}")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SPACE_ARGS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SPACE_ARGS}")
endmacro()
