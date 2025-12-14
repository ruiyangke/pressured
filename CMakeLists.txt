cmake_minimum_required(VERSION 3.16)
project(pressured C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

# TLS backend selection (openssl or mbedtls)
set(TLS_BACKEND "openssl" CACHE STRING "TLS backend: openssl or mbedtls")
set_property(CACHE TLS_BACKEND PROPERTY STRINGS "openssl" "mbedtls")

# Find dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(JSON_C REQUIRED json-c)
pkg_check_modules(LUA REQUIRED lua5.4)
pkg_check_modules(ZLIB REQUIRED zlib)

# Find TLS backend
if(TLS_BACKEND STREQUAL "mbedtls")
    pkg_check_modules(MBEDTLS REQUIRED mbedtls)
    message(STATUS "Using mbedTLS for crypto")
    set(CRYPTO_SOURCE "plugins/storage/crypto_mbedtls.c")
    set(CRYPTO_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIRS})
    # mbedtls pkg-config only returns -lmbedtls, but we need all three libs
    set(CRYPTO_LIBRARIES mbedtls mbedx509 mbedcrypto)
    set(CRYPTO_LIBRARY_DIRS ${MBEDTLS_LIBRARY_DIRS})
else()
    pkg_check_modules(OPENSSL REQUIRED openssl)
    message(STATUS "Using OpenSSL for crypto")
    set(CRYPTO_SOURCE "plugins/storage/crypto_openssl.c")
    set(CRYPTO_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIRS})
    set(CRYPTO_LIBRARIES ${OPENSSL_LIBRARIES})
    set(CRYPTO_LIBRARY_DIRS ${OPENSSL_LIBRARY_DIRS})
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CURL_INCLUDE_DIRS}
    ${JSON_C_INCLUDE_DIRS}
    ${LUA_INCLUDE_DIRS}
    ${CRYPTO_INCLUDE_DIRS}
)

# Link directories (needed for Alpine where libs are in non-standard locations)
link_directories(
    ${CURL_LIBRARY_DIRS}
    ${JSON_C_LIBRARY_DIRS}
    ${LUA_LIBRARY_DIRS}
    ${CRYPTO_LIBRARY_DIRS}
)

# Core library (no Lua dependency - Lua is in the plugin)
add_library(pressured_core STATIC
    src/config.c
    src/cgroup.c
    src/kubelet.c
    src/event_generator.c
    src/event.c
    src/log.c
    src/plugin.c
    src/http.c
    src/service_registry.c
)

# Enable Position Independent Code for static library (needed when linking into shared libs)
set_target_properties(pressured_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(pressured_core
    ${CURL_LIBRARIES}
    ${JSON_C_LIBRARIES}
    pthread
    dl
    m
)

# Main executable
add_executable(pressured src/main.c)
target_link_libraries(pressured pressured_core)

# Make the main executable export symbols for plugins
set_target_properties(pressured PROPERTIES ENABLE_EXPORTS ON)

# Tests
enable_testing()

add_executable(test_cgroup src/test_cgroup.c)
target_link_libraries(test_cgroup pressured_core)
add_test(NAME test_cgroup COMMAND test_cgroup)

add_executable(test_plugin src/test_plugin.c)
target_link_libraries(test_plugin pressured_core)
set_target_properties(test_plugin PROPERTIES ENABLE_EXPORTS ON)
add_test(NAME test_plugin COMMAND test_plugin)

add_executable(test_http src/test_http.c)
target_link_libraries(test_http pressured_core)
add_test(NAME test_http COMMAND test_http)

add_executable(test_service_registry src/test_service_registry.c)
target_link_libraries(test_service_registry pressured_core)
add_test(NAME test_service_registry COMMAND test_service_registry)

# Lua plugin shared library
add_library(pressured_plugin_lua SHARED
    plugins/lua/lua_plugin.c
    plugins/lua/binding_log.c
    plugins/lua/binding_http.c
    plugins/lua/binding_storage.c
)

set_target_properties(pressured_plugin_lua PROPERTIES
    OUTPUT_NAME "lua"
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
)

target_include_directories(pressured_plugin_lua PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/plugins/lua
    ${LUA_INCLUDE_DIRS}
)

target_link_libraries(pressured_plugin_lua
    pressured_core
    ${LUA_LIBRARIES}
)

# Local storage plugin shared library
add_library(storage_local SHARED
    plugins/storage/local_storage.c
)

set_target_properties(storage_local PROPERTIES
    OUTPUT_NAME "local-storage"
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
)

target_include_directories(storage_local PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${JSON_C_INCLUDE_DIRS}
)

target_link_libraries(storage_local
    ${JSON_C_LIBRARIES}
)

# Storage plugin test
add_executable(test_storage plugins/storage/test_storage.c)
target_link_libraries(test_storage pressured_core)
set_target_properties(test_storage PROPERTIES ENABLE_EXPORTS ON)
add_test(NAME test_storage COMMAND test_storage)

# S3 storage plugin shared library
set(S3_UPLOAD_MODE "STREAMING" CACHE STRING "S3 upload mode: STREAMING or MULTIPART")
set_property(CACHE S3_UPLOAD_MODE PROPERTY STRINGS "STREAMING" "MULTIPART")

add_library(storage_s3 SHARED
    plugins/storage/s3_storage.c
    ${CRYPTO_SOURCE}
)

if(S3_UPLOAD_MODE STREQUAL "STREAMING")
    target_compile_definitions(storage_s3 PRIVATE S3_UPLOAD_STREAMING)
    message(STATUS "S3 storage: using STREAMING mode (single PUT, max 5GB)")
else()
    target_compile_definitions(storage_s3 PRIVATE S3_UPLOAD_MULTIPART)
    message(STATUS "S3 storage: using MULTIPART mode (unlimited size)")
endif()

set_target_properties(storage_s3 PROPERTIES
    OUTPUT_NAME "s3-storage"
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
)

target_include_directories(storage_s3 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/plugins/storage
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${CRYPTO_INCLUDE_DIRS}
)

target_link_libraries(storage_s3
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
    ${CRYPTO_LIBRARIES}
)

# AWS SigV4 signing unit tests
add_executable(test_sigv4 plugins/storage/test_sigv4.c plugins/storage/sigv4.c ${CRYPTO_SOURCE})
target_include_directories(test_sigv4 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/plugins/storage ${CRYPTO_INCLUDE_DIRS})
target_link_libraries(test_sigv4 ${CRYPTO_LIBRARIES})
add_test(NAME test_sigv4 COMMAND test_sigv4)

# pprof parser plugin
add_library(pprof_plugin SHARED
    plugins/pprof/pprof_plugin.c
)

set_target_properties(pprof_plugin PROPERTIES
    OUTPUT_NAME "pprof"
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
)

target_include_directories(pprof_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/plugins/pprof
    ${ZLIB_INCLUDE_DIRS}
)

target_link_libraries(pprof_plugin
    pressured_core
    ${ZLIB_LIBRARIES}
)

add_executable(test_pprof plugins/pprof/test_pprof.c)
target_include_directories(test_pprof PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/plugins/pprof)
target_link_libraries(test_pprof pressured_core)
set_target_properties(test_pprof PROPERTIES ENABLE_EXPORTS ON)
add_test(NAME test_pprof COMMAND test_pprof)

# Manual tests (not added to ctest - require external services)
add_executable(test_http_e2e src/test_http_e2e.c)
target_link_libraries(test_http_e2e pressured_core)

add_executable(test_lua_http plugins/lua/test_lua_http.c)
target_link_libraries(test_lua_http pressured_core)
set_target_properties(test_lua_http PROPERTIES ENABLE_EXPORTS ON)

add_executable(test_lua_storage plugins/lua/test_lua_storage.c)
target_link_libraries(test_lua_storage pressured_core)
set_target_properties(test_lua_storage PROPERTIES ENABLE_EXPORTS ON)

add_executable(test_lua_multi plugins/lua/test_lua_multi.c)
target_link_libraries(test_lua_multi pressured_core)
set_target_properties(test_lua_multi PROPERTIES ENABLE_EXPORTS ON)

add_executable(test_http_stream_storage src/test_http_stream_storage.c)
target_link_libraries(test_http_stream_storage pressured_core)
set_target_properties(test_http_stream_storage PROPERTIES ENABLE_EXPORTS ON)

add_executable(test_s3_storage plugins/storage/test_s3_storage.c)
target_link_libraries(test_s3_storage pressured_core)
set_target_properties(test_s3_storage PROPERTIES ENABLE_EXPORTS ON)

add_executable(test_large_upload plugins/storage/test_large_upload.c)
target_link_libraries(test_large_upload pressured_core)
set_target_properties(test_large_upload PROPERTIES ENABLE_EXPORTS ON)

add_executable(test_streaming_upload plugins/storage/test_streaming_upload.c)
target_link_libraries(test_streaming_upload pressured_core)
set_target_properties(test_streaming_upload PROPERTIES ENABLE_EXPORTS ON)

add_executable(test_real_aws plugins/storage/test_real_aws.c)
target_link_libraries(test_real_aws pressured_core)
set_target_properties(test_real_aws PROPERTIES ENABLE_EXPORTS ON)

# Install
install(TARGETS pressured DESTINATION bin)
install(TARGETS pressured_plugin_lua DESTINATION lib/pressured/plugins)
install(TARGETS storage_local DESTINATION lib/pressured/plugins)
install(TARGETS storage_s3 DESTINATION lib/pressured/plugins)
install(TARGETS pprof_plugin DESTINATION lib/pressured/plugins)
