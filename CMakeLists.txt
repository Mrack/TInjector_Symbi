cmake_minimum_required(VERSION 3.10)
project(tinjector_symbi)

set(CMAKE_C_STANDARD 11)

add_subdirectory(stub)
add_subdirectory(test)

add_executable(tinjector_symbi main.cpp)