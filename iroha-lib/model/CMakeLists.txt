add_library(iroha_lib_model
    Query.hpp
    Query.cpp
    Tx.hpp
    Tx.cpp
    TxBatch.hpp
    generators/CommandGenerator.hpp
    generators/CommandGenerator.cpp
    generators/QueryGenerator.hpp
    generators/QueryGenerator.cpp
    utils/Utils.h
    utils/Utils.cpp
)

target_link_libraries(iroha_lib_model
    grpc_client
)

target_include_directories(iroha_lib_model PUBLIC
    ${PROJECT_SOURCE_DIR}/iroha-lib
)
