cmake_minimum_required(VERSION 3.20)
project(SentinelCPP VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SENTINEL_BUILD_TESTS "Build Sentinel-CPP unit tests" ON)

add_library(ScannerEngine
    src/engine/Scanner.cpp
    include/engine/IRule.hpp
    include/engine/RegexRule.hpp
    include/engine/Scanner.hpp
    include/engine/StringMatch.hpp
    include/engine/ThreadPool.hpp
)

target_include_directories(ScannerEngine PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_features(ScannerEngine PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(ScannerEngine PRIVATE /W4 /permissive-)
else()
    target_compile_options(ScannerEngine PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(sentinel src/main.cpp)
target_link_libraries(sentinel PRIVATE ScannerEngine)

if(SENTINEL_BUILD_TESTS)
    include(FetchContent)

    set(SENTINEL_BUNDLED_CATCH2_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/build/_deps/catch2-src")

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
        tests/test_main.cpp
        tests/src_tests/RuleTests.cpp
        tests/src_tests/ScannerTests.cpp
    )

    target_link_libraries(unit_tests PRIVATE Catch2::Catch2WithMain ScannerEngine)

    if(MSVC)
        target_compile_options(unit_tests PRIVATE /W4 /permissive-)
    else()
        target_compile_options(unit_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(NAME unit_tests COMMAND unit_tests)
endif()
