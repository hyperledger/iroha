set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

add_subdirectory(grpc_client)
add_subdirectory(model)
add_subdirectory(examples)

target_include_directories(grpc_client PUBLIC
    ${PROJECT_SOURCE_DIR}/iroha-lib
)
