cmake_minimum_required(VERSION 3.15...4.1)

project(test_secure_hash VERSION 1.0 DESCRIPTION "Testin of the Secure Hash family algorithms library" LANGUAGES CXX)

add_executable(
    ${PROJECT_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}../include)
target_link_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}../build)
target_link_libraries(${PROJECT_NAME} PUBLIC secure_hash)
