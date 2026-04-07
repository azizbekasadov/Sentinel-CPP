cmake_minimum_required(VERSION 3.14)
project(Sentinel-CPP)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.4.0 
)
FetchContent_MakeAvailable(Catch2)

add_library(ScannerEngine 
    src/engine/Scanner.cpp
    include/engine/Scanner.hpp
    include/engine/ThreadPool.hpp
    include/engine/IRule.hpp
    include/engine/StringMatch.hpp
    include/engine/RegexRule.hpp
)

target_include_directories(ScannerEngine PUBLIC 
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

add_executable(sentinel src/main.cpp)
target_link_libraries(sentinel PRIVATE ScannerEngine)

## Tests 
enable_testing()

add_executable(unit_tests
    tests/test_main.cpp
    tests/src_tests/ScannerTests.cpp
    tests/src_tests/RuleTests.cpp
)

target_link_libraries(unit_tests PRIVATE 
    Catch2::Catch2WithMain 
    ScannerEngine
)

add_test(NAME AllTests COMMAND $<TARGET_FILE:unit_tests>)

set_tests_properties(AllTests PROPERTIES 
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)