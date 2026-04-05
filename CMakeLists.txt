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

file(GLOB_RECURSE SOURCES "src/*.cpp")
file(GLOB_RECURSE HEADERS "include/*.hpp")

add_executable(sentinel ${SOURCES} ${HEADERS})

target_include_directories(sentinel PUBLIC 
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/engine"
)

enable_testing()
file(GLOB_RECURSE TEST_FILES "tests/*.cpp")

set(LOGIC_SOURCES ${SOURCES})
list(FILTER LOGIC_SOURCES EXCLUDE REGEX "main.cpp")

add_executable(unit_tests ${TEST_FILES} ${LOGIC_SOURCES} ${HEADERS})
target_link_libraries(unit_tests PRIVATE Catch2::Catch2WithMain)

target_include_directories(unit_tests PUBLIC 
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/engine"
)