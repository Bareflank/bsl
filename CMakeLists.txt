#
# Copyright (C) 2019 Assured Information Security, Inc.
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

cmake_minimum_required(VERSION 3.13)
project(dynarray CXX)

include(ExternalProject)
set(CMAKE_CXX_STANDARD 17)

# ------------------------------------------------------------------------------
# Initial Setup
# ------------------------------------------------------------------------------

option(BUILD_EXAMPLES "Build example programs" ON)
option(BUILD_TESTS "Build test programs" ON)
option(ENABLE_CLANG_TIDY "Enable the use of clang tidy" OFF)
option(ENABLE_CPPCHECK "Enable the use of cppcheck" OFF)
option(ENABLE_DEVELOPMENT "Enable all development options" OFF)

# ------------------------------------------------------------------------------
# Development Mode
# ------------------------------------------------------------------------------

if(ENABLE_DEVELOPMENT)
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    set(ENABLE_CLANG_TIDY ON)
    set(ENABLE_CPPCHECK ON)
    set(CMAKE_BUILD_TYPE UBSAN)
endif()

# ------------------------------------------------------------------------------
# Sanity Checks
# ------------------------------------------------------------------------------

if(BUILD_EXAMPLES AND CMAKE_BUILD_TYPE STREQUAL "COVERAGE")
    message(FATAL_ERROR "BUILD_EXAMPLES must be OFF if COVERAGE is enabled")
endif()

# ------------------------------------------------------------------------------
# Flags
# ------------------------------------------------------------------------------

set(CMAKE_CXX_FLAGS "-Wall -Wextra -pedantic -Werror")
set(CMAKE_CXX_FLAGS_ASAN "-fno-omit-frame-pointer -fsanitize=address -g")
set(CMAKE_LINKER_FLAGS_ASAN "-fno-omit-frame-pointer -fsanitize=address -g")
set(CMAKE_CXX_FLAGS_UBSAN "-fsanitize=undefined -g")
set(CMAKE_LINKER_FLAGS_UBSAN "-fsanitize=undefined -g")

# ------------------------------------------------------------------------------
# Clang Tidy
# ------------------------------------------------------------------------------

if(ENABLE_CLANG_TIDY AND NOT CMAKE_CXX_CLANG_TIDY)
    list(APPEND CMAKE_CXX_CLANG_TIDY
        clang-tidy
    )
endif()

if(ENABLE_CPPCHECK AND NOT CMAKE_CXX_CPPCHECK)
    list(APPEND CMAKE_CXX_CPPCHECK
        ${CMAKE_BINARY_DIR}/external/bin/cppcheck
        --enable=all
        --error-exitcode=1
        --quiet
        --inline-suppr
        --suppress=missingIncludeSystem
        --template="{file}:{line}: {severity}: {id}: {message}"
    )
endif()

# ------------------------------------------------------------------------------
# Sub Directories
# ------------------------------------------------------------------------------

if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(BUILD_TESTS)
    add_subdirectory(tests)
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(FILES include/bsl.h DESTINATION include/bsl)

# ------------------------------------------------------------------------------
# Package
# ------------------------------------------------------------------------------

add_library(bsl INTERFACE)

target_include_directories(bsl INTERFACE
    ${CMAKE_SOURCE_DIR}/include
)

export(TARGETS bsl FILE bslConfig.cmake APPEND)
export(PACKAGE bsl)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_custom_target(
    format
    COMMAND find ${CMAKE_SOURCE_DIR}/include -iname *.h -o -iname *.cpp | xargs clang-format -i
    COMMAND find ${CMAKE_SOURCE_DIR}/tests -iname *.h -o -iname *.cpp | xargs clang-format -i
)

# ------------------------------------------------------------------------------
# CppCheck
# ------------------------------------------------------------------------------

if(ENABLE_CPPCHECK)
    list(APPEND CPPCHECK_CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/external/
        -DCMAKE_CXX_FLAGS="-w"
        -DCMAKE_BUILD_TYPE=Release
    )

    ExternalProject_Add(
        cppcheck
        URL https://github.com/danmar/cppcheck/archive/1.89.tar.gz
        URL_MD5 3bc61e54f13639c60a3fc698edb18d61
        CMAKE_ARGS ${CPPCHECK_CMAKE_ARGS}
        UPDATE_COMMAND ""
        UPDATE_DISCONNECTED ON
    )
endif()
