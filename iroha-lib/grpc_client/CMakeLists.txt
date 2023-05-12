add_library(grpc_client
    GrpcClient.hpp
    GrpcClient.cpp
)

target_link_libraries(grpc_client
    grpc_channel_factory
    model_generators
    command_client
    query_client
)
