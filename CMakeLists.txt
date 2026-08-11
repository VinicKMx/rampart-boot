cmake_minimum_required(VERSION 3.24)

project(
    RampartBoot
    VERSION 0.1.0
    DESCRIPTION "Transactional and observable secure firmware lifecycle framework"
    LANGUAGES C ASM)

include(CTest)

option(RAMPART_BUILD_TESTS "Build Rampart host-side C tests" ON)
option(RAMPART_ENABLE_SANITIZERS "Enable ASan/UBSan for host C targets" OFF)
option(RAMPART_ENABLE_CLANG_TIDY "Enable clang-tidy for C targets" OFF)
option(RAMPART_BUILD_EMBEDDED "Build embedded firmware images" ${CMAKE_CROSSCOMPILING})

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

function(rampart_apply_common_options target_name)
    target_compile_features(${target_name} PUBLIC c_std_17)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(
            ${target_name}
            PRIVATE
                $<$<COMPILE_LANGUAGE:C>:-Wall>
                $<$<COMPILE_LANGUAGE:C>:-Wextra>
                $<$<COMPILE_LANGUAGE:C>:-Wpedantic>
                $<$<COMPILE_LANGUAGE:C>:-Wconversion>
                $<$<COMPILE_LANGUAGE:C>:-Wsign-conversion>
                $<$<COMPILE_LANGUAGE:C>:-Wshadow>
                $<$<COMPILE_LANGUAGE:C>:-Wstrict-prototypes>
                $<$<COMPILE_LANGUAGE:C>:-Wmissing-prototypes>
                $<$<COMPILE_LANGUAGE:C>:-Werror>)
    endif()

    if(RAMPART_ENABLE_SANITIZERS AND NOT CMAKE_CROSSCOMPILING)
        target_compile_options(
            ${target_name}
            PRIVATE $<$<COMPILE_LANGUAGE:C>:-fsanitize=address,undefined>
                    $<$<COMPILE_LANGUAGE:C>:-fno-omit-frame-pointer>)
        target_link_options(${target_name} PRIVATE -fsanitize=address,undefined)
    endif()

    if(RAMPART_ENABLE_CLANG_TIDY)
        find_program(RAMPART_CLANG_TIDY_EXE NAMES clang-tidy clang-tidy-18 REQUIRED)
        set_target_properties(
            ${target_name}
            PROPERTIES C_CLANG_TIDY "${RAMPART_CLANG_TIDY_EXE};--warnings-as-errors=*")
    endif()
endfunction()

function(rampart_apply_embedded_compile_options target_name)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "Embedded builds require GCC or Clang-style options")
    endif()

    target_compile_options(
        ${target_name}
        PRIVATE
            $<$<COMPILE_LANGUAGE:C>:-ffreestanding>
            $<$<COMPILE_LANGUAGE:C>:-fno-builtin>
            $<$<COMPILE_LANGUAGE:C>:-fdata-sections>
            $<$<COMPILE_LANGUAGE:C>:-ffunction-sections>
            $<$<COMPILE_LANGUAGE:C>:-mcpu=cortex-m33>
            $<$<COMPILE_LANGUAGE:C>:-mthumb>
            $<$<COMPILE_LANGUAGE:ASM>:-mcpu=cortex-m33>
            $<$<COMPILE_LANGUAGE:ASM>:-mthumb>)
endfunction()

function(rampart_apply_embedded_options target_name)
    rampart_apply_embedded_compile_options(${target_name})

    target_link_options(
        ${target_name}
        PRIVATE
            -nostdlib
            -mcpu=cortex-m33
            -mthumb
            -Wl,--gc-sections
            -Wl,-Map,$<TARGET_FILE_DIR:${target_name}>/$<TARGET_FILE_BASE_NAME:${target_name}>.map
            -T${PROJECT_SOURCE_DIR}/platform/stm32u5/stm32u585_minimal.ld)
endfunction()

add_subdirectory(core)
add_subdirectory(stage0)
add_subdirectory(stage1)

if(BUILD_TESTING AND RAMPART_BUILD_TESTS AND NOT CMAKE_CROSSCOMPILING)
    add_subdirectory(tests/unit)
endif()
