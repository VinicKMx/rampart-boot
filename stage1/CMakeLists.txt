add_library(rampart_stage1 STATIC src/stage1.c)

target_include_directories(rampart_stage1 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(rampart_stage1 PUBLIC rampart_core)
rampart_apply_common_options(rampart_stage1)

if(RAMPART_BUILD_EMBEDDED)
    rampart_apply_embedded_compile_options(rampart_stage1)
endif()

if(RAMPART_BUILD_EMBEDDED)
    add_executable(
        rampart_stage1_image
        src/reset.c
        ${PROJECT_SOURCE_DIR}/platform/stm32u5/startup_cortex_m33.S)
    target_link_libraries(rampart_stage1_image PRIVATE rampart_stage1 rampart_core)
    rampart_apply_common_options(rampart_stage1_image)
    rampart_apply_embedded_options(rampart_stage1_image)
    set_target_properties(rampart_stage1_image PROPERTIES OUTPUT_NAME stage1.elf)

    add_custom_command(
        TARGET rampart_stage1_image
        POST_BUILD
        COMMAND ${CMAKE_SIZE} $<TARGET_FILE:rampart_stage1_image>
        COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:rampart_stage1_image>
                $<TARGET_FILE_DIR:rampart_stage1_image>/stage1.bin
        VERBATIM)
endif()
