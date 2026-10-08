# --help prevents every case from loading the driver, even if parsing regresses.
function(check_parse expected)
    execute_process(
        COMMAND "${MONITOR}" --duration 1 --help ${ARGN}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error
        TIMEOUT 5
    )
    if(NOT "${result}" STREQUAL "${expected}")
        message(FATAL_ERROR "Args '${ARGN}': expected exit ${expected}, got ${result}\n${output}${error}")
    endif()
    if(expected EQUAL 0 AND NOT output MATCHES "With --match, delay only matching connections;")
        message(FATAL_ERROR "Help does not document match-only verdict delay")
    endif()
    if(expected EQUAL 0 AND NOT output MATCHES "V: accept \\| permanent-accept")
        message(FATAL_ERROR "Help does not list permanent-accept")
    endif()
    if(expected EQUAL 0 AND NOT output MATCHES "--suspend-pid-on-verdict-delay")
        message(FATAL_ERROR "Help does not document PID suspension")
    endif()
    if(expected EQUAL 2 AND NOT output MATCHES "ERROR: --verdict-delay-ms")
        message(FATAL_ERROR "Invalid delay did not produce the expected error: ${output}")
    endif()
endfunction()

check_parse(0)
foreach(delay IN ITEMS 0 1 250 4294967295)
    check_parse(0 --verdict-delay-ms "${delay}")
endforeach()
check_parse(0 --verdict-delay-ms 250 --no-verdicts)
check_parse(0 --verdict-delay-ms 250 --verdict accept --match 127.0.0.1)
check_parse(0 --verdict-delay-ms 250 --verdict accept --match 127.0.0.1:9999)
check_parse(0 --verdict permanent-accept)
check_parse(0 --verdict permanent-accept --verdict-delay-ms 250)
check_parse(0 --verdict permanent-accept --match 127.0.0.1 --verdict-delay-ms 0)
check_parse(0 --verdict permanent-accept --match 127.0.0.1:9999 --verdict-delay-ms 250)
check_parse(0 --suspend-pid-on-verdict-delay)
check_parse(0 --suspend-pid-on-verdict-delay --verdict-delay-ms 0)
check_parse(0 --suspend-pid-on-verdict-delay --no-verdicts --verdict-delay-ms 250)
check_parse(0 --suspend-pid-on-verdict-delay --verdict permanent-accept
              --match 127.0.0.1:9999 --verdict-delay-ms 250)

foreach(delay IN ITEMS -1 +1 abc 1.5 250ms " 250" 4294967296 18446744073709551616)
    check_parse(2 --verdict-delay-ms "${delay}")
endforeach()
check_parse(2 --verdict-delay-ms)

# Keep the empty argument explicit rather than losing it through list expansion.
execute_process(
    COMMAND "${MONITOR}" --duration 1 --help --verdict-delay-ms ""
    RESULT_VARIABLE result
    TIMEOUT 5
)
if(NOT "${result}" STREQUAL "2")
    message(FATAL_ERROR "Empty delay: expected exit 2, got ${result}")
endif()
message(STATUS "PASS: verdict delay CLI validation")
