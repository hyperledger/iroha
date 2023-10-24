if (APPLE)
    message("iroha-lib does not support MacOS currently!")
else()
    ###### irohalib_tx_example:
    add_executable(irohalib_tx_example
        TxExample.cpp
    )

    target_link_libraries(irohalib_tx_example
        iroha_lib_model
        logger_manager
    )

    add_install_step_for_bin(irohalib_tx_example)


    ###### irohalib_batch_example:
    add_executable(irohalib_batch_example
        BatchExample.cpp
    )

    target_link_libraries(irohalib_batch_example
        iroha_lib_model
        logger_manager
    )

    add_install_step_for_bin(irohalib_batch_example)


    ###### irohalib_query_example:
    add_executable(irohalib_query_example
        QueryExample.cpp
    )

    target_link_libraries(irohalib_query_example
        iroha_lib_model
        logger_manager
    )

    add_install_step_for_bin(irohalib_query_example)


    ###### irohalib_domainassetcreation_example:
    add_executable(irohalib_domainassetcreation_example
        DomainAssetCreation.cpp
    )

    target_link_libraries(irohalib_domainassetcreation_example
        iroha_lib_model
        logger_manager
        gflags
    )

    add_install_step_for_bin(irohalib_domainassetcreation_example)
endif()
