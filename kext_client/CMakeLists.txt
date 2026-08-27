cmake_minimum_required(VERSION 3.15)
project(kext_client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT WIN32)
    message(FATAL_ERROR "kext_client targets Windows only.")
endif()

# Named-pipe server used to bridge raw driver traffic to an attached client.
set(WINRPC_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../winrpc/src")

# Client library for the Portmaster kernel extension.
add_library(pmkext STATIC
    src/PortmasterKext.cpp
    "${WINRPC_SOURCE_DIR}/duplex_pipe/duplex_pipe_server.cpp"
    "${WINRPC_SOURCE_DIR}/duplex_pipe/pipe_transport.cpp"
    "${WINRPC_SOURCE_DIR}/pipe_support.cpp"
)

target_include_directories(pmkext
    PUBLIC include
    PRIVATE "${WINRPC_SOURCE_DIR}"
)

# Advapi32 provides the service-control (SCM) functions.
target_link_libraries(pmkext PUBLIC advapi32)

if(MSVC)
    target_compile_options(pmkext PRIVATE /W4 /permissive-)
    target_compile_definitions(pmkext PUBLIC
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _WIN32_WINNT=0x0A00
        WINVER=0x0A00
        _CRT_SECURE_NO_WARNINGS
    )
else()
    target_compile_options(pmkext PRIVATE -Wall -Wextra)
    target_compile_definitions(pmkext PUBLIC
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _WIN32_WINNT=0x0A00
        WINVER=0x0A00
    )
endif()

# Console monitor.
add_executable(kext_monitor
    src/main.cpp
)

target_link_libraries(kext_monitor PRIVATE pmkext)

# wmain requires the Unicode entry point.
if(MSVC)
    set_target_properties(kext_monitor PROPERTIES
        LINK_FLAGS "/ENTRY:wmainCRTStartup"
    )
else()
    target_link_options(kext_monitor PRIVATE -municode)
endif()

# Request Administrator on launch: the device ACL only admits admins and the
# service functions need SC_MANAGER_CREATE_SERVICE.
# Appended to LINK_FLAGS above (do not repeat /ENTRY here, it would duplicate).
if(MSVC)
    set_target_properties(kext_monitor PROPERTIES
        LINK_FLAGS "/ENTRY:wmainCRTStartup /MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
endif()
