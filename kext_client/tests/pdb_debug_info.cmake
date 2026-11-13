if(NOT EXISTS "${IMAGE}")
    message(FATAL_ERROR "Monitor executable not found: ${IMAGE}")
endif()
if(NOT EXISTS "${PDB}")
    message(FATAL_ERROR "Monitor PDB not found: ${PDB}")
endif()

# link.exe /dump is dumpbin; inspect the actual PE debug directory rather than
# just searching the executable for a PDB-looking string.
execute_process(
    COMMAND "${DUMP_TOOL}" /dump /headers "${IMAGE}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE headers
    ERROR_VARIABLE error_output
)
if(NOT result STREQUAL "0")
    message(FATAL_ERROR "Could not inspect monitor debug directory: ${error_output}")
endif()

string(REGEX MATCH "Format: RSDS, \\{[^}]+\\}, [0-9]+, ([^\r\n]+)" codeview "${headers}")
if(NOT codeview)
    message(FATAL_ERROR "Monitor has no RSDS CodeView debug record")
endif()
string(STRIP "${CMAKE_MATCH_1}" recorded_pdb)
get_filename_component(expected_pdb "${PDB}" NAME)
if(NOT recorded_pdb STREQUAL expected_pdb)
    message(FATAL_ERROR "Monitor records '${recorded_pdb}' instead of '${expected_pdb}'")
endif()
