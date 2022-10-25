add_executable(tx_example
    TxExample.cpp
)

target_link_libraries(tx_example
    iroha_lib_model
    logger_manager
)

add_install_step_for_bin(tx_example)

add_executable(batch_example
    BatchExample.cpp
)

target_link_libraries(batch_example
    iroha_lib_model
    logger_manager
)

add_install_step_for_bin(batch_example)

add_executable(query_example
    QueryExample.cpp
)

target_link_libraries(query_example
    iroha_lib_model
    logger_manager
)

add_install_step_for_bin(query_example)
