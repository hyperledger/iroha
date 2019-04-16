# Additional targets to perform clang-format/clang-tidy
# Get all project files
file(GLOB_RECURSE
        ALL_CXX_SOURCE_FILES
        *.[ch]pp
        )

# Adding clang-format target if executable is found
find_program(CLANG_FORMAT "clang-format")
if(CLANG_FORMAT)
    add_custom_target(
            clang-format
            COMMAND "${CLANG_FORMAT}"
            -i
            ${ALL_CXX_SOURCE_FILES}
    )
endif()
