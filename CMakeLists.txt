cmake_minimum_required(VERSION 3.15...4.1)

project(secure_hash VERSION 1.0 DESCRIPTION "Implementation of the Secure Hash family algorithms" LANGUAGES CXX)
add_subdirectory(test)

add_library(
    ${PROJECT_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/secure_hash.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/secure_hash.hpp
)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
