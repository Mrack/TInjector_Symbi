cmake_minimum_required(VERSION 3.18.4)

project(test)

set(CMAKE_CXX_STANDARD 20)

add_library(testso SHARED testso.cpp)


target_link_libraries(testso log)

