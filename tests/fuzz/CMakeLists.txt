add_executable(rampart_manifest_fuzzer fuzz_manifest.c)

target_link_libraries(rampart_manifest_fuzzer PRIVATE rampart_core)
rampart_apply_common_options(rampart_manifest_fuzzer)
target_link_options(rampart_manifest_fuzzer PRIVATE -fsanitize=fuzzer)

add_executable(rampart_image_fuzzer fuzz_image.c)

target_link_libraries(rampart_image_fuzzer PRIVATE rampart_core)
rampart_apply_common_options(rampart_image_fuzzer)
target_link_options(rampart_image_fuzzer PRIVATE -fsanitize=fuzzer)

if(BUILD_TESTING)
    set(RAMPART_FUZZ_SMOKE_RUNS 100000)
    set(RAMPART_FUZZ_INPUT_TIMEOUT_SECONDS 5)
    set(RAMPART_FUZZ_CTEST_TIMEOUT_SECONDS 30)

    function(rampart_add_fuzz_tests target_name corpus_name seed_pattern)
        set(source_corpus "${CMAKE_CURRENT_SOURCE_DIR}/corpus/${corpus_name}")
        set(work_corpus "${CMAKE_CURRENT_BINARY_DIR}/work/${corpus_name}")
        set(artifact_dir "${CMAKE_CURRENT_BINARY_DIR}/artifacts/${corpus_name}")

        file(GLOB seed_inputs CONFIGURE_DEPENDS "${source_corpus}/${seed_pattern}")
        if(NOT seed_inputs)
            message(FATAL_ERROR "No ${corpus_name} fuzz seeds found in ${source_corpus}")
        endif()
        list(SORT seed_inputs)

        file(MAKE_DIRECTORY "${work_corpus}" "${artifact_dir}")

        add_test(
            NAME "${target_name}_seed_replay"
            COMMAND $<TARGET_FILE:${target_name}> -runs=1 ${seed_inputs})
        add_test(
            NAME "${target_name}_smoke"
            COMMAND
                $<TARGET_FILE:${target_name}>
                -runs=${RAMPART_FUZZ_SMOKE_RUNS}
                -max_len=1048576
                -timeout=${RAMPART_FUZZ_INPUT_TIMEOUT_SECONDS}
                -artifact_prefix=${artifact_dir}/
                "${work_corpus}"
                "${source_corpus}")

        set_tests_properties(
            "${target_name}_seed_replay"
            "${target_name}_smoke"
            PROPERTIES LABELS "fuzz;sanitizer"
                       RUN_SERIAL TRUE
                       TIMEOUT ${RAMPART_FUZZ_CTEST_TIMEOUT_SECONDS})
    endfunction()

    rampart_add_fuzz_tests(rampart_manifest_fuzzer manifest "*.bin")
    rampart_add_fuzz_tests(rampart_image_fuzzer image "*.rampart")
endif()
