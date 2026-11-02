cmake_minimum_required(VERSION 3.15)
project(kext_client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT WIN32)
    message(FATAL_ERROR "kext_client targets Windows only.")
endif()

# Client library for the Portmaster kernel extension (direct device I/O only).
add_library(pmkext STATIC
    src/PortmasterKext.cpp
    src/ProcessSuspensions.cpp
)

target_include_directories(pmkext PUBLIC include)

# Advapi32 provides SCM functions; Ws2_32 provides IP literal parsing.
target_link_libraries(pmkext PUBLIC advapi32 ws2_32 fwpuclnt)

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

# Import only the read-only NSI query. Configuration changes stay in netsh.
set(NSI_IMPORT_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/nsi.lib")
set(NSI_DEFINITION "${CMAKE_CURRENT_SOURCE_DIR}/src/nsi.def")
if(MSVC)
    if(CMAKE_CXX_COMPILER_ARCHITECTURE_ID STREQUAL "ARM64")
        set(NSI_MACHINE ARM64)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(NSI_MACHINE X64)
    else()
        message(FATAL_ERROR "The monitor's NSI query ABI requires a 64-bit target.")
    endif()
    add_custom_command(OUTPUT "${NSI_IMPORT_LIBRARY}"
        COMMAND "${CMAKE_AR}" /nologo "/def:${NSI_DEFINITION}"
                "/machine:${NSI_MACHINE}" "/out:${NSI_IMPORT_LIBRARY}"
        DEPENDS "${NSI_DEFINITION}"
        BYPRODUCTS "${CMAKE_CURRENT_BINARY_DIR}/nsi.exp"
        VERBATIM)
else()
    if(NOT CMAKE_DLLTOOL OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR "Generating nsi.lib requires a 64-bit target and dlltool.")
    endif()
    add_custom_command(OUTPUT "${NSI_IMPORT_LIBRARY}"
        COMMAND "${CMAKE_DLLTOOL}" --input-def "${NSI_DEFINITION}"
                --output-lib "${NSI_IMPORT_LIBRARY}"
        DEPENDS "${NSI_DEFINITION}"
        VERBATIM)
endif()
add_custom_target(nsi_import_library DEPENDS "${NSI_IMPORT_LIBRARY}")
add_library(nsi_import STATIC IMPORTED)
set_target_properties(nsi_import PROPERTIES IMPORTED_LOCATION "${NSI_IMPORT_LIBRARY}")
add_dependencies(nsi_import nsi_import_library)

# Console monitor.
add_executable(kext_monitor
    src/main.cpp
    src/RoutePolicies.cpp
)

target_link_libraries(kext_monitor PRIVATE pmkext iphlpapi nsi_import)

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

include(CTest)
if(BUILD_TESTING)
    add_executable(route_policy_tests tests/route_policy_tests.cpp src/RoutePolicies.cpp)
    target_include_directories(route_policy_tests PRIVATE src)
    target_link_libraries(route_policy_tests PRIVATE pmkext nsi_import)
    add_test(NAME route_policy_tests COMMAND route_policy_tests)
    set_tests_properties(route_policy_tests PROPERTIES TIMEOUT 10)

    add_test(NAME app_interface_cli_tests
        COMMAND "${CMAKE_COMMAND}" "-DMONITOR=$<TARGET_FILE:kext_monitor>"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/app_interface_cli_tests.cmake")
    set_tests_properties(app_interface_cli_tests PROPERTIES TIMEOUT 30)

    add_executable(app_interface_tests tests/app_interface_tests.cpp)
    target_link_libraries(app_interface_tests PRIVATE pmkext)
    add_test(NAME app_interface_tests COMMAND app_interface_tests)
    set_tests_properties(app_interface_tests PROPERTIES TIMEOUT 15)

    # Explicit bounded administrator-only probe; never load a driver in CTest.
    add_executable(app_interface_runtime tests/app_interface_runtime.cpp)
    target_link_libraries(app_interface_runtime PRIVATE pmkext iphlpapi)
    if(MSVC)
        target_compile_options(app_interface_tests PRIVATE /utf-8)
        target_compile_options(app_interface_runtime PRIVATE /utf-8)
        target_link_options(app_interface_runtime PRIVATE /ENTRY:wmainCRTStartup)
    else()
        target_link_options(app_interface_runtime PRIVATE -municode)
    endif()

    add_executable(verdict_tests tests/verdict_tests.cpp)
    target_link_libraries(verdict_tests PRIVATE pmkext)
    add_test(NAME verdict_tests COMMAND verdict_tests)

    add_executable(connection_record_tests tests/connection_record_tests.cpp)
    target_link_libraries(connection_record_tests PRIVATE pmkext)
    add_test(NAME connection_record_tests COMMAND connection_record_tests)
    set_tests_properties(connection_record_tests PROPERTIES TIMEOUT 10)

    add_executable(process_event_tests tests/process_event_tests.cpp)
    target_link_libraries(process_event_tests PRIVATE pmkext)
    add_test(NAME process_event_tests COMMAND process_event_tests)
    set_tests_properties(process_event_tests PROPERTIES TIMEOUT 10)

    # Explicit Administrator-only runtime probe, launched by process_events.py.
    # Keep service installation and driver loading out of the offline CTest suite.
    add_executable(process_control_runtime tests/process_control_runtime.cpp)
    target_link_libraries(process_control_runtime PRIVATE pmkext)
    if(MSVC)
        target_link_options(process_control_runtime PRIVATE /ENTRY:wmainCRTStartup)
    else()
        target_link_options(process_control_runtime PRIVATE -municode)
    endif()

    add_executable(bandwidth_record_tests tests/bandwidth_record_tests.cpp)
    target_link_libraries(bandwidth_record_tests PRIVATE pmkext)
    add_test(NAME bandwidth_record_tests COMMAND bandwidth_record_tests)
    set_tests_properties(bandwidth_record_tests PROPERTIES TIMEOUT 120)

    add_executable(ip_address_tests tests/ip_address_tests.cpp)
    target_link_libraries(ip_address_tests PRIVATE pmkext)
    add_test(NAME ip_address_tests COMMAND ip_address_tests)

    add_executable(delayed_verdict_tests tests/delayed_verdict_tests.cpp)
    target_link_libraries(delayed_verdict_tests PRIVATE pmkext)
    add_test(NAME delayed_verdict_tests COMMAND delayed_verdict_tests)
    set_tests_properties(delayed_verdict_tests PROPERTIES TIMEOUT 10)

    add_executable(process_suspension_tests tests/process_suspension_tests.cpp)
    target_link_libraries(process_suspension_tests PRIVATE pmkext)
    add_test(NAME process_suspension_tests COMMAND process_suspension_tests)
    set_tests_properties(process_suspension_tests PROPERTIES TIMEOUT 10)

    add_executable(record_output_tests tests/record_output_tests.cpp)
    target_link_libraries(record_output_tests PRIVATE pmkext)
    add_test(NAME record_output_tests COMMAND record_output_tests)
    set_tests_properties(record_output_tests PROPERTIES TIMEOUT 10)

    add_test(NAME verdict_delay_cli_tests
        COMMAND "${CMAKE_COMMAND}" "-DMONITOR=$<TARGET_FILE:kext_monitor>"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/verdict_delay_cli_tests.cmake")
    set_tests_properties(verdict_delay_cli_tests PROPERTIES TIMEOUT 30)

    add_test(NAME process_events_cli_tests
        COMMAND "${CMAKE_COMMAND}" "-DMONITOR=$<TARGET_FILE:kext_monitor>"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/process_events_cli_tests.cmake")
    set_tests_properties(process_events_cli_tests PROPERTIES TIMEOUT 30)
endif()
