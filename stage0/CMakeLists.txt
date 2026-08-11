add_library(rampart_stage0 STATIC src/select.c)

target_include_directories(rampart_stage0 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(rampart_stage0 PUBLIC rampart_core)
rampart_apply_common_options(rampart_stage0)

if(RAMPART_BUILD_EMBEDDED)
    rampart_apply_embedded_compile_options(rampart_stage0)
endif()

if(RAMPART_BUILD_EMBEDDED)
    add_executable(
        rampart_stage0_image
        src/reset.c
        ${PROJECT_SOURCE_DIR}/platform/stm32u5/startup_cortex_m33.S)
    target_link_libraries(rampart_stage0_image PRIVATE rampart_stage0 rampart_core)
    rampart_apply_common_options(rampart_stage0_image)
    rampart_apply_embedded_options(rampart_stage0_image)
    set_target_properties(rampart_stage0_image PROPERTIES OUTPUT_NAME stage0.elf)

    add_custom_command(
        TARGET rampart_stage0_image
        POST_BUILD
        COMMAND ${CMAKE_SIZE} $<TARGET_FILE:rampart_stage0_image>
        COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:rampart_stage0_image>
                $<TARGET_FILE_DIR:rampart_stage0_image>/stage0.bin
        VERBATIM)
endif()
