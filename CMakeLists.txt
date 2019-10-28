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

set(CMAKE_CXX_STANDARD 17)

# ------------------------------------------------------------------------------
# Initial Setup
# ------------------------------------------------------------------------------

option(BUILD_EXAMPLES "Build example programs" ON)
option(BUILD_TESTS "Build test programs" ON)
option(DISABLE_CLANG_TIDY "Disable the use of clang tidy" OFF)

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

if(NOT DISABLE_CLANG_TIDY AND NOT CMAKE_CXX_CLANG_TIDY)
    set(CMAKE_CXX_CLANG_TIDY "clang-tidy")
endif()

# ------------------------------------------------------------------------------
# Sub Directories
# ------------------------------------------------------------------------------

if(BUILD_TESTS)
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
