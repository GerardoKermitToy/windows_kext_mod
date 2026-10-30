# --help keeps the syntax/documentation checks independent of the driver.
execute_process(
    COMMAND "${MONITOR}" --duration 1 --help --process-events-only --only-logs
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error
    TIMEOUT 5
)
if(NOT "${result}" STREQUAL "0")
    message(FATAL_ERROR "Process-event help: expected exit 0, got ${result}\n${output}${error}")
endif()
foreach(option IN ITEMS "--process-events-only" "--process-events-write" "--process-events-restart-ms")
    if(NOT output MATCHES "${option}")
        message(FATAL_ERROR "Help does not document ${option}")
    endif()
endforeach()
if(NOT output MATCHES "process collection is not started")
    message(FATAL_ERROR "Help does not document the explicit process-collection opt-in")
endif()

function(check_bad_request_options)
    execute_process(
        COMMAND "${MONITOR}" --duration 1 ${ARGN} --help
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error
        TIMEOUT 5
    )
    if(NOT "${result}" STREQUAL "2")
        message(FATAL_ERROR "Args '${ARGN}': expected exit 2, got ${result}\n${output}${error}")
    endif()
endfunction()
check_bad_request_options(--process-events-write)
check_bad_request_options(--process-events-restart-ms 100)
foreach(value IN ITEMS "0" "-1" "+1" "1x" "4294967296")
    check_bad_request_options(--process-events-only --process-events-restart-ms "${value}")
endforeach()
check_bad_request_options(--process-events-only --process-events-restart-ms)

# Use a nonexistent .sys so the monitor cannot load the driver. The process-only
# mode must win over --only-logs in either argument order and leave stdout free of
# startup/status records; its fatal diagnostic remains visible on stderr.
get_filename_component(
    missing_driver "${CMAKE_CURRENT_BINARY_DIR}/definitely-missing-portmaster-kext.sys" ABSOLUTE)
function(check_process_only_precedence)
    execute_process(
        COMMAND "${MONITOR}" --duration 1 ${ARGN} --filter-pid 4242 "${missing_driver}"
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error
        TIMEOUT 5
    )
    if(NOT "${result}" STREQUAL "1")
        message(FATAL_ERROR "Args '${ARGN}': expected missing-driver exit 1, got ${result}\n${output}${error}")
    endif()
    if(NOT "${output}" STREQUAL "")
        message(FATAL_ERROR "Args '${ARGN}': process-only mode emitted stdout startup/status text: ${output}")
    endif()
    if(NOT error MATCHES "ERROR: driver file not found\\.")
        message(FATAL_ERROR "Args '${ARGN}': process-only fatal diagnostic was not on stderr: ${error}")
    endif()
endfunction()

check_process_only_precedence(--process-events-only --only-logs)
check_process_only_precedence(--only-logs --process-events-only)
check_process_only_precedence(--process-events-write --process-events-only --process-events-restart-ms 1)
check_process_only_precedence(--process-events-only --process-events-restart-ms 4294967295)
message(STATUS "PASS: process-event CLI parsing and output-mode precedence")
