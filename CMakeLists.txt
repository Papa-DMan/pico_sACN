cmake_minimum_required(VERSION 3.12)
set(PICO_SDK_PATH ${CMAKE_CURRENT_LIST_DIR}/../pico-sdk)
set(PICO_BOARD pico_w)

include(pico_sdk_import.cmake)

project(ETC-Pico)

pico_sdk_init()

include(${CMAKE_CURRENT_LIST_DIR}/./FreeRTOS/FreeRTOS-Kernel/portable/ThirdParty/GCC/RP2040/FreeRTOS_Kernel_import.cmake)

add_subdirectory(FreeRTOS/coreJSON)
add_subdirectory(DMX)
add_subdirectory(ProjectFiles)