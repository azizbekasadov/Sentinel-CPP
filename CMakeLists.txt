cmake_minimum_required(VERSION 3.10)
project(Sentinel-CPP)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(sentinel main.cpp ${SOURCES})