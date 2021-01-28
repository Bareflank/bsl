#
# Copyright (C) 2020 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

include(${CMAKE_CURRENT_LIST_DIR}/../colors.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../build_command.cmake)

# Add Info
#
# Creates an info target
#
# NAME: The name of the project
#
macro(bf_add_info NAME)
    add_custom_target(info)

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_MAG}  ___   _   ___ ___ ___ _      _   _  _ _  __        ${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_MAG} | _ ) /_\\ | _ \\ __| __| |    /_\\ | \\| | |/ /    ${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_MAG} | _ \\/ _ \\|   / _|| _|| |__ / _ \\| .` | ' <      ${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_MAG} |___/_/ \\_\\_|_\\___|_| |____/_/ \\_\\_|\\_|_|\\_\\${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo " "
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_GRN} Please give us a star on: ${BF_COLOR_WHT}https://github.com/bareflank/${NAME}  ${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_BLU} -----------------------------------------------------------------${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo " "
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_GRN} Current Build Configuration:${BF_COLOR_RST}"
        VERBATIM
    )

    if(BUILD_EXAMPLES)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   BUILD_EXAMPLES                 ${BF_COLOR_GRN}enabled${BF_COLOR_RST}"
            VERBATIM
        )
    else()
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   BUILD_EXAMPLES                 ${BF_COLOR_RED}disabled${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    if(BUILD_TESTS)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   BUILD_TESTS                    ${BF_COLOR_GRN}enabled${BF_COLOR_RST}"
            VERBATIM
        )
    else()
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   BUILD_TESTS                    ${BF_COLOR_RED}disabled${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    if(ENABLE_CLANG_FORMAT)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   ENABLE_CLANG_FORMAT            ${BF_COLOR_GRN}enabled${BF_COLOR_RST} - ${BF_CLANG_FORMAT}"
            VERBATIM
        )
    else()
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   ENABLE_CLANG_FORMAT            ${BF_COLOR_RED}disabled${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    if(ENABLE_DOXYGEN)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   ENABLE_DOXYGEN                 ${BF_COLOR_GRN}enabled${BF_COLOR_RST} - ${BF_DOXYGEN}"
            VERBATIM
        )
    else()
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   ENABLE_DOXYGEN                 ${BF_COLOR_RED}disabled${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    if(ENABLE_COLOR)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   ENABLE_COLOR                   ${BF_COLOR_GRN}enabled${BF_COLOR_RST}"
            VERBATIM
        )
    else()
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   ENABLE_COLOR                   ${BF_COLOR_RED}disabled${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   BSL_DEBUG_LEVEL                ${BF_COLOR_CYN}${BSL_DEBUG_LEVEL}${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   BSL_PAGE_SIZE                  ${BF_COLOR_CYN}${BSL_PAGE_SIZE}${BF_COLOR_RST}"
        VERBATIM
    )

    if(CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   CMAKE_BUILD_TYPE               ${BF_COLOR_CYN}${CMAKE_BUILD_TYPE}${BF_COLOR_RST} - ${CMAKE_CXX_CLANG_TIDY}"
            VERBATIM
        )
    elseif(CMAKE_BUILD_TYPE STREQUAL CODECOV)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   CMAKE_BUILD_TYPE               ${BF_COLOR_CYN}${CMAKE_BUILD_TYPE}${BF_COLOR_RST} - ${BF_GRCOV}"
            VERBATIM
        )
    else()
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   CMAKE_BUILD_TYPE               ${BF_COLOR_CYN}${CMAKE_BUILD_TYPE}${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo " "
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_GRN} Supported CMake Build Types:${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}  -DCMAKE_BUILD_TYPE=RELEASE      compile in release mode${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}  -DCMAKE_BUILD_TYPE=DEBUG        compile in debug mode${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}  -DCMAKE_BUILD_TYPE=CLANG_TIDY   compile with Clang Tidy checks${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}  -DCMAKE_BUILD_TYPE=ASAN         compile with Google ASAN${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}  -DCMAKE_BUILD_TYPE=UBSAN        compile with Google UBSAN${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}  -DCMAKE_BUILD_TYPE=CODECOV      compile with LLVM coverage${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo " "
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_GRN} Basic Commands:${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   ${BF_BUILD_COMMAND} info                     shows this help info${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   ${BF_BUILD_COMMAND}                          builds the project${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   ${BF_BUILD_COMMAND} clean                    cleans the project${BF_COLOR_RST}"
        COMMAND ${CMAKE_COMMAND} -E echo " "
        COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_GRN} Supported Build Targets:${BF_COLOR_RST}"
        VERBATIM
    )

    if(BUILD_TESTS)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   ${BF_BUILD_COMMAND} unittest                 run the project's unit tests${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    if(ENABLE_CLANG_FORMAT)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   ${BF_BUILD_COMMAND} format                   formats the source code${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    if(ENABLE_DOXYGEN)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   ${BF_BUILD_COMMAND} doxygen                  generates documentation${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL CODECOV)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   ${BF_BUILD_COMMAND} codecov-info            gathers info about unit test coverage${BF_COLOR_RST}"
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_YLW}   ${BF_BUILD_COMMAND} codecov-upload          uploads results of unit test coverage${BF_COLOR_RST}"
            VERBATIM
        )
    endif()

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E echo " "
        VERBATIM
    )
endmacro(bf_add_info)
