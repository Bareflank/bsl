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

if(ENABLE_CLANG_FORMAT)
    add_custom_target(
        format
    )

    file(GLOB SUBDIRS RELATIVE ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/*)
    foreach(DIR ${SUBDIRS})
        if(IS_DIRECTORY ${CMAKE_BINARY_DIR}/${DIR} AND NOT DIR MATCHES "build")
            file(GLOB_RECURSE HEADERS RELATIVE ${CMAKE_BINARY_DIR} ${CMAKE_BINARY_DIR}/${DIR}/*.hpp)
            file(GLOB_RECURSE SOURCES RELATIVE ${CMAKE_BINARY_DIR} ${CMAKE_BINARY_DIR}/${DIR}/*.cpp)
            if(NOT "${HEADERS}" STREQUAL "" OR NOT "${SOURCES}" STREQUAL "")
                add_custom_command(TARGET format
                    COMMAND ${BF_CLANG_FORMAT} -i ${HEADERS} ${SOURCES}
                )
            endif()
        endif()
    endforeach()
endif()
