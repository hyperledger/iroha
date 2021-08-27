# Compile the specified target as a modern, strict C++.
function(strictmode target)
  # Require pure C++17 standard.
  set_target_properties(${target} PROPERTIES
      CXX_STANDARD 17
      CXX_STANDARD_REQUIRED ON
      CXX_EXTENSIONS OFF
      )
  #todo target_compile_definitions(${target} PUBLIC GTEST_REMOVE_LEGACY_TEST_CASEAPI_)
  # Enable more warnings and turn them into compile errors.
  if ((CMAKE_CXX_COMPILER_ID STREQUAL "GNU") OR
      (CMAKE_CXX_COMPILER_ID STREQUAL "Clang") OR
      (CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang"))
    #target_compile_options(${target} PRIVATE -Wall -Wpedantic -Werror -Wno-potentially-/evaluated-expression)
    #target_compile_options(${test_name} PRIVATE -Wno-inconsistent-missing-override -Wno-gnu-zero-variadic-macro-arguments)
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
  target_link_libraries(${test_name} GTest::gmock_main)
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
  get_target_property(Protobuf_INCLUDE_DIR protobuf::libprotobuf
    INTERFACE_INCLUDE_DIRECTORIES)
  add_custom_command(
      OUTPUT ${SCHEMA_OUT_DIR}/${GEN_PB_HEADER} ${SCHEMA_OUT_DIR}/${GEN_PB}
      COMMAND protobuf::protoc -I${Protobuf_INCLUDE_DIR} -I${CMAKE_CURRENT_SOURCE_DIR} ${ARGN} --cpp_out=${SCHEMA_OUT_DIR} ${PROTO}
      DEPENDS protobuf::protoc ${SCHEMA_PATH}/${PROTO}
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
  get_target_property(Protobuf_INCLUDE_DIR protobuf::libprotobuf
    INTERFACE_INCLUDE_DIRECTORIES)
  add_custom_command(
      OUTPUT ${SCHEMA_OUT_DIR}/${GEN_GRPC_PB_HEADER} ${SCHEMA_OUT_DIR}/${GEN_GRPC_PB} ${TEST_OUTPUT}
      COMMAND protobuf::protoc -I${Protobuf_INCLUDE_DIR} -I${CMAKE_CURRENT_SOURCE_DIR} ${ARGN} --grpc_out=${GENERATE_MOCKS}${SCHEMA_OUT_DIR} --plugin=protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin> ${PROTO}
      DEPENDS gRPC::grpc_cpp_plugin ${SCHEMA_PATH}/${PROTO}
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      )
endfunction()

function(prepare_generated_schema_go_path)
  if(NOT IS_DIRECTORY "${GO_GENERATED_SCHEMA_PATH}")
    file(MAKE_DIRECTORY "${GO_GENERATED_SCHEMA_PATH}")
  endif()
  configure_file(
    "${SCHEMA_PATH}/generated_go.mod.in"
    "${GO_GENERATED_SCHEMA_PATH}/go.mod"
    @ONLY
    )
endfunction()

macro(get_go_env_path OUTPUT_VAR)
  set(${OUTPUT_VAR} "$ENV{PATH}")
  if(DEFINED ENV{GOBIN})
    set(${OUTPUT_VAR} "${${OUTPUT_VAR}}:$ENV{GOBIN}")
  endif()
  if(DEFINED ENV{GOPATH})
    set(${OUTPUT_VAR} "${${OUTPUT_VAR}}:$ENV{GOPATH}/bin")
  endif()
endmacro()

function(compile_proto_to_go PROTO DEPENDER_TARGET)
    prepare_generated_schema_go_path()
    get_filename_component(PROTO_PATH "${PROTO}" DIRECTORY)
    get_filename_component(GEN_PB_GO_NAME_WE "${PROTO}" NAME_WE)
    set(GEN_PB_GO_PATH "${GO_GENERATED_SCHEMA_PATH}/${GEN_PB_GO_NAME_WE}.pb.go")
    get_target_property(Protobuf_INCLUDE_DIR protobuf::libprotobuf
      INTERFACE_INCLUDE_DIRECTORIES)
    get_go_env_path(ENV_PATH)
    add_custom_command(
        OUTPUT "${GEN_PB_GO_PATH}"
        COMMAND env "PATH=${ENV_PATH}" $<TARGET_FILE:protobuf::protoc>
          -I${Protobuf_INCLUDE_DIR} -I${PROTO_PATH}
          ${ARGN} --go_out=${GO_GENERATED_SCHEMA_PATH} ${PROTO}
          --go_opt=module=iroha.generated/protocol
        DEPENDS protobuf::protoc ${PROTO}
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      )
    set(INTERMEDIATE_TGT "SCHEMA_GO_DEPENDER_${GEN_PB_GO_NAME_WE}")
    add_custom_target(${INTERMEDIATE_TGT} DEPENDS "${GEN_PB_GO_PATH}")
    add_dependencies(${DEPENDER_TARGET} ${INTERMEDIATE_TGT})
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
      COMPONENT irohad)
endmacro()


macro(add_install_step_for_lib libpath)
  # full path with resolved symlinks:
  # /usr/local/lib/libprotobuf.so -> /usr/local/lib/libprotobuf.so.13.0.0
  get_filename_component(lib_major_minor_patch ${libpath} REALPATH)

  install(FILES ${lib_major_minor_patch}
      DESTINATION lib
      CONFIGURATIONS ${CMAKE_BUILD_TYPE}
      COMPONENT irohad)
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
  add_compile_options(${ARGN})
  add_link_options(${ARGN})
endmacro()
