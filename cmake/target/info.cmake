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

add_custom_target(BSL_INFO_TARGET)

add_custom_command(TARGET BSL_INFO_TARGET
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta "  ___   _   ___ ___ ___ _      _   _  _ _  __ "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta " | _ ) /_\\ | _ \\ __| __| |    /_\\ | \\| | |/ / "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta " | _ \\/ _ \\|   / _|| _|| |__ / _ \\| .` | ' <  "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta " |___/_/ \\_\\_|_\\___|_| |____/_/ \\_\\_|\\_|_|\\_\\ "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " Please give us a star on: ${BF_COLOR_WHT}https://github.com/bareflank/${BSL_PROJECT_NAME} "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --blue    " ------------------------------------------------------------------------------- "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " Current Build Configuration:"
    VERBATIM
)

# ------------------------------------------------------------------------------
# options
# ------------------------------------------------------------------------------

if(BUILD_EXAMPLES)
    add_custom_command(TARGET BSL_INFO_TARGET
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   BUILD_EXAMPLES                 ${BF_ENABLED}"
        VERBATIM
    )
else()
    add_custom_command(TARGET BSL_INFO_TARGET
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   BUILD_EXAMPLES                 ${BF_DISABLED}"
        VERBATIM
    )
endif()

if(BUILD_TESTS)
    add_custom_command(TARGET BSL_INFO_TARGET
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   BUILD_TESTS                    ${BF_ENABLED}"
        VERBATIM
    )
else()
    add_custom_command(TARGET BSL_INFO_TARGET
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   BUILD_TESTS                    ${BF_DISABLED}"
        VERBATIM
    )
endif()

if(ENABLE_CLANG_FORMAT)
    add_custom_command(TARGET BSL_INFO_TARGET
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ENABLE_CLANG_FORMAT            ${BF_ENABLED} - ${BF_CLANG_FORMAT}"
        VERBATIM
    )
else()
    add_custom_command(TARGET BSL_INFO_TARGET
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ENABLE_CLANG_FORMAT            ${BF_DISABLED}"
        VERBATIM
    )
endif()

if(ENABLE_DOXYGEN)
    add_custom_command(TARGET BSL_INFO_TARGET
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ENABLE_DOXYGEN                 ${BF_ENABLED} - ${BF_DOXYGEN}"
        VERBATIM
    )
else()
    add_custom_command(TARGET BSL_INFO_TARGET
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ENABLE_DOXYGEN                 ${BF_DISABLED}"
        VERBATIM
    )
endif()

# ------------------------------------------------------------------------------
# settings
# ------------------------------------------------------------------------------

add_custom_command(TARGET BSL_INFO_TARGET
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   BSL_DEBUG_LEVEL                ${BF_COLOR_CYN}${BSL_DEBUG_LEVEL}"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   BSL_PAGE_SIZE                  ${BF_COLOR_CYN}${BSL_PAGE_SIZE}"
    VERBATIM
)

# ------------------------------------------------------------------------------
# build type
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY)
    add_custom_command(TARGET BSL_INFO_TARGET
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   CMAKE_BUILD_TYPE               ${BF_COLOR_CYN}${CMAKE_BUILD_TYPE}${BF_COLOR_RST} - ${CMAKE_CXX_CLANG_TIDY}"
        VERBATIM
    )
elseif(CMAKE_BUILD_TYPE STREQUAL CODECOV)
    add_custom_command(TARGET BSL_INFO_TARGET
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   CMAKE_BUILD_TYPE               ${BF_COLOR_CYN}${CMAKE_BUILD_TYPE}${BF_COLOR_RST} - ${BF_GRCOV}"
        VERBATIM
    )
else()
    add_custom_command(TARGET BSL_INFO_TARGET
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   CMAKE_BUILD_TYPE               ${BF_COLOR_CYN}${CMAKE_BUILD_TYPE}"
        VERBATIM
    )
endif()

# ------------------------------------------------------------------------------
# remaining info
# ------------------------------------------------------------------------------

add_custom_command(TARGET BSL_INFO_TARGET
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " Supported CMake Build Types:"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "  -DCMAKE_BUILD_TYPE=RELEASE      compile in release mode"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "  -DCMAKE_BUILD_TYPE=DEBUG        compile in debug mode"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "  -DCMAKE_BUILD_TYPE=CLANG_TIDY   compile with Clang Tidy checks"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "  -DCMAKE_BUILD_TYPE=PERFORCE     compile with Perforce checks"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "  -DCMAKE_BUILD_TYPE=ASAN         compile with Google ASAN"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "  -DCMAKE_BUILD_TYPE=UBSAN        compile with Google UBSAN"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "  -DCMAKE_BUILD_TYPE=CODECOV      compile with LLVM coverage"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " Basic Commands:"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ${BUILD_COMMAND} info                     shows this help info"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ${BUILD_COMMAND}                          builds the project"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ${BUILD_COMMAND} clean                    cleans the project"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " Supported Build Targets:"
    VERBATIM
)

if(BUILD_TESTS)
    add_custom_command(TARGET BSL_INFO_TARGET
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ${BUILD_COMMAND} unittest                 run the project's unit tests"
        VERBATIM
    )
endif()

if(ENABLE_CLANG_FORMAT)
    add_custom_command(TARGET BSL_INFO_TARGET
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ${BUILD_COMMAND} format                   formats the source code"
        VERBATIM
    )
endif()

if(ENABLE_DOXYGEN)
    add_custom_command(TARGET BSL_INFO_TARGET
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ${BUILD_COMMAND} doxygen                  generates documentation"
        VERBATIM
    )
endif()

if(CMAKE_BUILD_TYPE STREQUAL CODECOV)
    add_custom_command(TARGET BSL_INFO_TARGET
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ${BUILD_COMMAND} codecov-info            gathers info about unit test coverage"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   ${BUILD_COMMAND} codecov-upload          uploads results of unit test coverage"
        VERBATIM
    )
endif()

# ------------------------------------------------------------------------------
# done
# ------------------------------------------------------------------------------

add_custom_command(TARGET BSL_INFO_TARGET
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    VERBATIM
)

if(NOT DEFINED BSL_IS_SUBPROJECT)
    add_custom_target(info)
    add_dependencies(info BSL_INFO_TARGET)
endif()
