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

# Add Config
#
# Add a configurable varibale to the CMake build. This function ensures each
# variable is properly set, and ensures it's properly visible in ccmake.
#
# @param ADVANCED Only show this variable in the advanced mode for ccmake
# @param SKIP_VALIDATION do not validate that the varibale is properly set
# @param CONFIG_NAME The name of the variable
# @param CONFIG_TYPE The variable's type: STRING, PATH, FILEPATH, BOOL
# @param DEFAULT_VAL The default value for the variable
# @param DESCRIPTION A description of the variable
# @param OPTIONS Possible values for the the variable. Only applies to STRING
#    type variables.
#
function(bf_add_config)
    set(options ADVANCED SKIP_VALIDATION)
    set(oneVal CONFIG_NAME CONFIG_TYPE DEFAULT_VAL DESCRIPTION)
    set(multiVal OPTIONS)
    cmake_parse_arguments(ARG "${options}" "${oneVal}" "${multiVal}" ${ARGN})

    if(ARG_CONFIG_TYPE STREQUAL "BOOL" AND NOT ARG_DEFAULT_VAL)
        set(ARG_DEFAULT_VAL OFF)
    endif()

    if(NOT DEFINED ${ARG_CONFIG_NAME})
        set(${ARG_CONFIG_NAME} ${ARG_DEFAULT_VAL} CACHE ${ARG_CONFIG_TYPE} ${ARG_DESCRIPTION})
    else()
        set(${ARG_CONFIG_NAME} ${${ARG_CONFIG_NAME}} CACHE ${ARG_CONFIG_TYPE} ${ARG_DESCRIPTION})
    endif()

    if(ARG_OPTIONS AND ARG_CONFIG_TYPE STREQUAL "STRING")
        set_property(CACHE ${ARG_CONFIG_NAME} PROPERTY STRINGS ${ARG_OPTIONS})
    endif()

    if(NOT ARG_SKIP_VALIDATION)
        if(ARG_OPTIONS AND ARG_CONFIG_TYPE STREQUAL "STRING")
            if(NOT ARG_DEFAULT_VAL IN_LIST ARG_OPTIONS)
                message(FATAL_ERROR "${ARG_CONFIG_NAME} invalid option \'${ARG_DEFAULT_VAL}\'")
            endif()
        endif()

        if(ARG_CONFIG_TYPE STREQUAL "PATH")
            if(NOT EXISTS "${ARG_DEFAULT_VAL}")
                message(FATAL_ERROR "${ARG_CONFIG_NAME} path not found: ${ARG_DEFAULT_VAL}")
            endif()
        endif()

        if(ARG_CONFIG_TYPE STREQUAL "FILEPATH")
            if(NOT EXISTS "${ARG_DEFAULT_VAL}")
                message(FATAL_ERROR "${ARG_CONFIG_NAME} file not found: ${ARG_DEFAULT_VAL}")
            endif()
        endif()

        if(ARG_CONFIG_TYPE STREQUAL "BOOL")
            if(NOT ARG_DEFAULT_VAL STREQUAL ON AND NOT ARG_DEFAULT_VAL STREQUAL OFF)
                message(FATAL_ERROR "${ARG_CONFIG_NAME} must be set to ON or OFF")
            endif()
        endif()
    endif()

    if(ARG_ADVANCED)
        mark_as_advanced(${ARG_CONFIG_NAME})
    endif()
endfunction(bf_add_config)

