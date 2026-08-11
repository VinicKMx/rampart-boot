add_library(
    rampart_core STATIC
    src/manifest.c
    src/status.c
    src/target.c)

target_include_directories(rampart_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
rampart_apply_common_options(rampart_core)

if(RAMPART_BUILD_EMBEDDED)
    rampart_apply_embedded_compile_options(rampart_core)
endif()
