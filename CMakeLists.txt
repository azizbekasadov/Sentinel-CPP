cmake_minimum_required(VERSION 3.20)
project(SentinelCPP VERSION 0.3.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(SENTINEL_BUILD_TESTS "Build Sentinel-CPP unit tests" ON)
option(SENTINEL_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(SENTINEL_ENABLE_CLANG_TIDY "Run clang-tidy as part of the build" OFF)
set(SENTINEL_SANITIZER "" CACHE STRING
    "Sanitizer to enable: empty, 'address' (ASan + UBSan) or 'thread' (TSan)")
set_property(CACHE SENTINEL_SANITIZER PROPERTY STRINGS "" address thread)

# ---------------------------------------------------------------------------
# Shared compile settings
# ---------------------------------------------------------------------------
add_library(sentinel_options INTERFACE)
target_compile_features(sentinel_options INTERFACE cxx_std_20)

if(MSVC)
    target_compile_options(sentinel_options INTERFACE /W4 /permissive-)
    if(SENTINEL_WARNINGS_AS_ERRORS)
        target_compile_options(sentinel_options INTERFACE /WX)
    endif()
else()
    target_compile_options(sentinel_options INTERFACE
        -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
        -Wold-style-cast -Wcast-align -Wnon-virtual-dtor -Woverloaded-virtual
        -Wnull-dereference -Wimplicit-fallthrough)
    if(SENTINEL_WARNINGS_AS_ERRORS)
        target_compile_options(sentinel_options INTERFACE -Werror)
    endif()
endif()

if(SENTINEL_SANITIZER STREQUAL "address")
    set(_sentinel_sanitizer_flags -fsanitize=address,undefined -fno-omit-frame-pointer)
elseif(SENTINEL_SANITIZER STREQUAL "thread")
    set(_sentinel_sanitizer_flags -fsanitize=thread -fno-omit-frame-pointer)
elseif(NOT SENTINEL_SANITIZER STREQUAL "")
    message(FATAL_ERROR "Unknown SENTINEL_SANITIZER value '${SENTINEL_SANITIZER}'")
endif()

if(DEFINED _sentinel_sanitizer_flags)
    if(MSVC)
        message(FATAL_ERROR "Sanitizer builds are only supported with GCC or Clang")
    endif()
    target_compile_options(sentinel_options INTERFACE ${_sentinel_sanitizer_flags})
    target_link_options(sentinel_options INTERFACE ${_sentinel_sanitizer_flags})
endif()

if(SENTINEL_ENABLE_CLANG_TIDY)
    find_program(SENTINEL_CLANG_TIDY_EXE NAMES clang-tidy REQUIRED)
    set(_sentinel_clang_tidy_command "${SENTINEL_CLANG_TIDY_EXE}")
    if(APPLE AND CMAKE_OSX_SYSROOT)
        list(APPEND _sentinel_clang_tidy_command
            "--extra-arg=-isysroot" "--extra-arg=${CMAKE_OSX_SYSROOT}")
    endif()
endif()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
add_library(ScannerEngine
    src/engine/Json.cpp
    src/engine/Scanner.cpp
    include/engine/IRule.hpp
    include/engine/Json.hpp
    include/engine/RegexRule.hpp
    include/engine/Scanner.hpp
    include/engine/StringMatch.hpp
    include/engine/ThreadPool.hpp
)
add_library(Sentinel::ScannerEngine ALIAS ScannerEngine)

target_include_directories(ScannerEngine PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(ScannerEngine PUBLIC sentinel_options)

find_package(Threads REQUIRED)
target_link_libraries(ScannerEngine PUBLIC Threads::Threads)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
add_executable(sentinel src/main.cpp)
target_link_libraries(sentinel PRIVATE ScannerEngine)

if(SENTINEL_ENABLE_CLANG_TIDY)
    set_target_properties(ScannerEngine sentinel PROPERTIES
        CXX_CLANG_TIDY "${_sentinel_clang_tidy_command}")
endif()

# ---------------------------------------------------------------------------
# Formatting helpers (no-ops when clang-format is not installed)
# ---------------------------------------------------------------------------
find_program(SENTINEL_CLANG_FORMAT_EXE NAMES clang-format)
if(SENTINEL_CLANG_FORMAT_EXE)
    file(GLOB_RECURSE SENTINEL_FORMAT_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp")

    add_custom_target(format
        COMMAND "${SENTINEL_CLANG_FORMAT_EXE}" -i ${SENTINEL_FORMAT_SOURCES}
        COMMENT "Formatting sources with clang-format"
        VERBATIM)

    add_custom_target(format-check
        COMMAND "${SENTINEL_CLANG_FORMAT_EXE}" --dry-run --Werror ${SENTINEL_FORMAT_SOURCES}
        COMMENT "Checking source formatting with clang-format"
        VERBATIM)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(SENTINEL_BUILD_TESTS)
    include(FetchContent)

    set(SENTINEL_BUNDLED_CATCH2_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build/_deps/catch2-src")

    if(EXISTS "${SENTINEL_BUNDLED_CATCH2_DIR}/CMakeLists.txt")
        message(STATUS "Using bundled Catch2 source from ${SENTINEL_BUNDLED_CATCH2_DIR}")
        add_subdirectory("${SENTINEL_BUNDLED_CATCH2_DIR}" "${CMAKE_BINARY_DIR}/_deps/catch2")
    else()
        FetchContent_Declare(
            Catch2
            GIT_REPOSITORY https://github.com/catchorg/Catch2.git
            GIT_TAG v3.4.0
        )
        FetchContent_MakeAvailable(Catch2)
    endif()

    enable_testing()

    add_executable(unit_tests
        tests/src_tests/JsonTests.cpp
        tests/src_tests/RuleTests.cpp
        tests/src_tests/ScannerTests.cpp
    )

    target_link_libraries(unit_tests PRIVATE Catch2::Catch2WithMain ScannerEngine)

    if(SENTINEL_ENABLE_CLANG_TIDY)
        set_target_properties(unit_tests PROPERTIES
            CXX_CLANG_TIDY "${_sentinel_clang_tidy_command}")
    endif()

    add_test(NAME unit_tests COMMAND unit_tests)
endif()
