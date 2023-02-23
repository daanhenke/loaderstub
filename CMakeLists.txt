cmake_minimum_required(VERSION 3.4)
project(loader-stub)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

add_executable(bin2h tools/bin2h.cc)

set(STUB_SOURCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/stub/x86_64-windows.S")
set(STUB_OBJECT_FILE "${CMAKE_CURRENT_BINARY_DIR}/stub.o")
set(STUB_RAW_FILE "${CMAKE_CURRENT_BINARY_DIR}/stub.bin")
set(STUB_GEN_FILE "${CMAKE_CURRENT_BINARY_DIR}/stub.cc")

enable_language(ASM_NASM)
add_custom_command(
    COMMENT "Building shellcode..."
    OUTPUT
        ${STUB_GEN_FILE}
    COMMAND
        ${CMAKE_ASM_NASM_COMPILER} -f bin "${STUB_SOURCE_FILE}" -o "${STUB_RAW_FILE}"
    COMMAND
        bin2h "${STUB_RAW_FILE}" "${STUB_GEN_FILE}" -id=shellcode_win64
    DEPENDS
        bin2h
        ${STUB_SOURCE_FILE}
)

add_executable(stub-host
    tools/stub-host.cc
    ${STUB_GEN_FILE}
)

add_library(modloader SHARED
    source/modloader.cc
)

add_library(target SHARED
    tools/target.cc
)

add_executable(pe-patcher
    source/main.cc
    ${STUB_GEN_FILE}
)
