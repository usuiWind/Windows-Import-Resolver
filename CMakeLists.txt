cmake_minimum_required(VERSION 3.16)
project(pe_resolver CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


add_library(resolver STATIC
    src/resolver.cpp
)

target_include_directories(resolver PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(demo
    demo/main.cpp
)

target_include_directories(demo PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(demo PRIVATE resolver)

if (MSVC)
    target_compile_definitions(resolver PRIVATE UNICODE _UNICODE)
    target_compile_definitions(demo PRIVATE UNICODE _UNICODE)
endif()
