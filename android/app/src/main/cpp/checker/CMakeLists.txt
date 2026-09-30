project(checker)
cmake_minimum_required(VERSION 3.4.1)

add_definitions(-DDEX_PATH=\"${DEX_PATH}\")

if(NOT DEFINED APP_SIGNER_SHA256)
    message(FATAL_ERROR "APP_SIGNER_SHA256 must be supplied by the Android build")
endif()
string(LENGTH "${APP_SIGNER_SHA256}" APP_SIGNER_SHA256_LENGTH)
if(NOT APP_SIGNER_SHA256_LENGTH EQUAL 64 OR NOT APP_SIGNER_SHA256 MATCHES "^[0-9A-Fa-f]+$")
    message(FATAL_ERROR "APP_SIGNER_SHA256 must be a 64-character SHA-256 hex digest")
endif()

add_library(${PROJECT_NAME} STATIC
        dexfile.c
        checker.cpp
        checker_state.cpp
        checker_runtime.cpp
        checker_forensics.cpp
        checker_cloud.cpp
        checker_findings.cpp
        checker_timing.cpp
        checker_sepolicy.cpp
        checker_environment.cpp
        checker_kernelsu.cpp
        checker_kernelsu_throne.cpp
        checker_readproc.cpp
        checker_security.cpp
        checker_teesim.cpp
        elf_util.cpp
        jni_helper.cpp
        integrity.cpp
        proc_util.cc
)

target_compile_definitions(${PROJECT_NAME} PRIVATE
        APP_SIGNER_SHA256="${APP_SIGNER_SHA256}"
)

target_compile_options(${PROJECT_NAME} PRIVATE
        $<$<COMPILE_LANGUAGE:C>:-O1>
        $<$<COMPILE_LANGUAGE:CXX>:-O1>

        $<$<COMPILE_LANGUAGE:C>:-fno-lto>
        $<$<COMPILE_LANGUAGE:CXX>:-fno-lto>
)


set_source_files_properties(dexfile.c OBJECT_DEPENDS ${DEX_PATH})

# Timing measurements stay outside LTO so code layout does not become part of
# the service-latency signal.
set_source_files_properties(checker_timing.cpp PROPERTIES
        COMPILE_OPTIONS "-fno-inline-functions;-fno-unroll-loops;-fno-vectorize;-fno-slp-vectorize"
)

target_include_directories(${PROJECT_NAME} PUBLIC include)

target_link_libraries(${PROJECT_NAME} PUBLIC
        log
        fmt-header-only
        systemproperties
)
