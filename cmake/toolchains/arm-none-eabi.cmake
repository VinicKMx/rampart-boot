set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)
set(CMAKE_AR arm-none-eabi-ar)
set(CMAKE_RANLIB arm-none-eabi-ranlib)
set(CMAKE_OBJCOPY arm-none-eabi-objcopy CACHE FILEPATH "Arm objcopy")
set(CMAKE_SIZE arm-none-eabi-size CACHE FILEPATH "Arm size")

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

