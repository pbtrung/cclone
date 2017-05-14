cmake_minimum_required(VERSION 3.2)
project(cclone)

set(CMAKE_C_STANDARD 11)

set(CCLONE_VERSION_MAJOR 0)
set(CCLONE_VERSION_MINOR 999999)
set(CCLONE_VERSION_PATCH 0)

set(SRC_PATH "${PROJECT_SOURCE_DIR}/src")
set(INC_PATH "${PROJECT_SOURCE_DIR}/include")
set(TEST_PATH "${PROJECT_SOURCE_DIR}/tests")

set(CURL_INC "${PROJECT_SOURCE_DIR}/build/vendor/curl/include")
set(JANSSON_INC "${PROJECT_SOURCE_DIR}/build/vendor/jansson/include")

set(SSL_LIB "${PROJECT_SOURCE_DIR}/build/vendor/libressl/lib/libssl.a")
set(CRYPTO_LIB "${PROJECT_SOURCE_DIR}/build/vendor/libressl/lib/libcrypto.a")
file(GLOB_RECURSE STATIC_LIBS "${PROJECT_SOURCE_DIR}/build/vendor/*.a")
list(REMOVE_ITEM STATIC_LIBS ${SSL_LIB} ${CRYPTO_LIB})

configure_file(
    "${SRC_PATH}/cclone-cfg.h.in"
    "${INC_PATH}/cclone-cfg.h"
)

# Default is debug build
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

include_directories(
    ${INC_PATH} 
    ${CURL_INC}
    ${JANSSON_INC}
)
file(GLOB_RECURSE CCLONE_SRC "${SRC_PATH}/*.c")
list(REMOVE_ITEM CCLONE_SRC "${SRC_PATH}/main.c")
list(REMOVE_ITEM CCLONE_SRC "${SRC_PATH}/crypt/cryptmt/sse2.c")
list(REMOVE_ITEM CCLONE_SRC "${SRC_PATH}/crypt/cryptmt/altivec.c")

# Build executable binary
option(BUILD_EXE "Build executable binary" ON)
if(BUILD_EXE)
    set(CCLONE_BIN "${PROJECT_NAME}")
    set(CCLONE_BIN_SRC "${SRC_PATH}/main.c")
    add_executable(${CCLONE_BIN} ${CCLONE_BIN_SRC} ${CCLONE_SRC})
    target_link_libraries(${CCLONE_BIN} ${STATIC_LIBS} ${SSL_LIB} ${CRYPTO_LIB})
endif()

# Build test
option(BUILD_TEST "Build test" ON)
if(BUILD_TEST)
    set(CCLONE_TEST "test-${PROJECT_NAME}")
    include_directories(${TEST_PATH})
    set(CCLONE_TEST_SRC "${TEST_PATH}/test-${PROJECT_NAME}.c")
    add_executable(${CCLONE_TEST} ${CCLONE_TEST_SRC} ${CCLONE_SRC})
    target_link_libraries(${CCLONE_TEST} ${STATIC_LIBS} ${SSL_LIB} ${CRYPTO_LIB})   
endif()

# Build flags
set(COMMON_FLAGS "-Wall -pthread -fno-strict-aliasing")
set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native ${COMMON_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb ${COMMON_FLAGS}")

set_target_properties(
    ${CCLONE_BIN}
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG   "${PROJECT_SOURCE_DIR}/bin/debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${PROJECT_SOURCE_DIR}/bin/release"
)
set_target_properties(
    ${CCLONE_TEST}
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG   "${PROJECT_SOURCE_DIR}/bin/debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${PROJECT_SOURCE_DIR}/bin/release"
)

# Helper function to add preprocesor definition of __FILE_BASENAME__
# to pass the filename without directory path for debugging use.
#
# Example:
#
#   define_file_basename_for_sources(my_target)
#
# Will add -D__FILE_BASENAME__="filename" for each source file depended on
# by my_target, where filename is the name of the file.
#
function(define_file_basename_for_sources targetname)
    get_target_property(source_files "${targetname}" SOURCES)
    foreach(sourcefile ${source_files})
        # Get source file's current list of compile definitions.
        get_property(defs SOURCE "${sourcefile}"
            PROPERTY COMPILE_DEFINITIONS)
        # Add the __FILE_BASENAME__=filename compile definition to the list.
        get_filename_component(basename "${sourcefile}" NAME)
        list(APPEND defs "__FILE_BASENAME__=\"${basename}\"")
        # Set the updated compile definitions on the source file.
        set_property(
            SOURCE "${sourcefile}"
            PROPERTY COMPILE_DEFINITIONS ${defs})
    endforeach()
endfunction()

define_file_basename_for_sources(${CCLONE_BIN})
define_file_basename_for_sources(${CCLONE_TEST})