cmake_minimum_required(VERSION 3.10)
project(Stub C)

if(NOT ANDROID)
    message(FATAL_ERROR "This project is designed for Android NDK.")
endif()

get_filename_component(NDK_BIN_DIR ${CMAKE_C_COMPILER} DIRECTORY)
find_program(OBJCOPY NAMES llvm-objcopy PATHS ${NDK_BIN_DIR} NO_DEFAULT_PATH)


set(EXTRA_FLAGS
        -Oz
        -fPIC
        -fno-stack-protector
        -ffreestanding
        -fno-exceptions
        -fno-asynchronous-unwind-tables
)

set(STUB_FLAGS "")

if(ANDROID_ABI STREQUAL "arm64-v8a")
    list(APPEND STUB_FLAGS "-mbranch-protection=bti")
endif()


set(HELPER_LDS "${CMAKE_CURRENT_SOURCE_DIR}/helper.lds")

set(EXTRA_LINK_ARGS
        "-nostdlib"
        "-Wl,-static"
        "-Wl,--gc-sections"
        "-Wl,-T,${HELPER_LDS}"
)

add_library(stub MODULE stub.c
        stub.h)

target_compile_options(stub PRIVATE ${EXTRA_FLAGS} ${STUB_FLAGS})

target_link_options(stub PRIVATE ${EXTRA_LINK_ARGS})
set_target_properties(stub PROPERTIES
        PREFIX ""
        LINK_DEPENDS "${HELPER_LDS}"
)

set(OBJCOPY_FLAGS "-O" "binary" "-j" ".payload")

add_custom_command(
        OUTPUT stub_bin
        COMMAND ${OBJCOPY} ${OBJCOPY_FLAGS} $<TARGET_FILE:stub> stub.bin
        DEPENDS stub
        COMMENT "Extracting STUB.bin using objcopy"
)

add_custom_command(
        OUTPUT stub_header
        COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/bin2header.py
        STUB.bin ../../stub.h stub_binary
        DEPENDS stub
        COMMENT "Converting STUB.bin to header using Python"
)

add_custom_target(build_stub ALL DEPENDS stub_bin stub_header)
