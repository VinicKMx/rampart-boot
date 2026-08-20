add_executable(rampart_unit_tests test_core.c)

target_link_libraries(rampart_unit_tests PRIVATE rampart_core rampart_stage0 rampart_stage1)
target_compile_definitions(
    rampart_unit_tests PRIVATE RAMPART_TEST_VECTOR_DIR="${PROJECT_SOURCE_DIR}/tests/vectors/image-v1")
rampart_apply_common_options(rampart_unit_tests)

add_test(NAME rampart_unit_tests COMMAND rampart_unit_tests)

add_executable(rampart_manifest_tests test_manifest.c)

target_link_libraries(rampart_manifest_tests PRIVATE rampart_core)
rampart_apply_common_options(rampart_manifest_tests)

add_test(NAME rampart_manifest_tests COMMAND rampart_manifest_tests)
