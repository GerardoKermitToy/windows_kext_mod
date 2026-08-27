cmake_minimum_required(VERSION 3.24)

project(WindowsNamedPipeDuplexExample LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "This example requires Windows named pipes.")
endif()

if(NOT MSVC)
    message(FATAL_ERROR "This example is intended to be built with MSVC.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "This example targets x64. Configure CMake with -A x64.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CheckIPOSupported)
check_ipo_supported(RESULT IPO_SUPPORTED OUTPUT IPO_ERROR LANGUAGES CXX)
if(NOT IPO_SUPPORTED)
    message(FATAL_ERROR "Release IPO is required but unavailable: ${IPO_ERROR}")
endif()

set(COMMON_SOURCES
    src/duplex_pipe/pipe_transport.cpp
    src/pipe_support.cpp
)

add_executable(pipe_server
    src/server.cpp
    src/duplex_pipe/duplex_pipe_server.cpp
    ${COMMON_SOURCES}
)

add_executable(pipe_client
    src/client.cpp
    src/duplex_pipe/duplex_pipe_client.cpp
    ${COMMON_SOURCES}
)

add_executable(pipe_api_test
    tests/pipe_api_test.cpp
    src/duplex_pipe/duplex_pipe_client.cpp
    src/duplex_pipe/duplex_pipe_server.cpp
    ${COMMON_SOURCES}
)

add_executable(pipe_stress_test
    tests/pipe_stress_test.cpp
    src/duplex_pipe/duplex_pipe_client.cpp
    src/duplex_pipe/duplex_pipe_server.cpp
    ${COMMON_SOURCES}
)

enable_testing()
add_test(NAME pipe_api_no_throw COMMAND pipe_api_test)
add_test(NAME pipe_stress COMMAND pipe_stress_test)
set_tests_properties(pipe_api_no_throw pipe_stress PROPERTIES
    RESOURCE_LOCK named_pipe_service
    TIMEOUT 60
)

foreach(app_target IN ITEMS
        pipe_server
        pipe_client
        pipe_api_test
        pipe_stress_test)
    target_include_directories(${app_target} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    target_compile_definitions(${app_target} PRIVATE
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _WIN32_WINNT=0x0A00
        WINVER=0x0A00
    )
    target_compile_options(${app_target} PRIVATE /W4 /permissive-)
    set_property(TARGET ${app_target} PROPERTY
        INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
    )
endforeach()
