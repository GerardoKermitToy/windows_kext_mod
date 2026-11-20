# Help exits before service installation, device I/O, or route-policy changes.
foreach(extra IN ITEMS "" "--no-inbound-udp-pid-fallback" "--process-events-only")
    execute_process(
        COMMAND "${MONITOR}" --duration 1 --authorize-outbound-udp-at-ale ${extra} --help
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error
        TIMEOUT 5
    )
    if(NOT "${result}" STREQUAL "0")
        message(FATAL_ERROR "UDP-setting help: expected exit 0, got ${result}\n${output}${error}")
    endif()
    foreach(text IN ITEMS "--authorize-outbound-udp-at-ale" "default: disabled" "Registered I/O")
        if(NOT output MATCHES "${text}")
            message(FATAL_ERROR "UDP-setting help does not document ${text}")
        endif()
    endforeach()
endforeach()
message(STATUS "PASS: outbound UDP ALE opt-in CLI parsing and help")
