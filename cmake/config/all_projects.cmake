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

# ------------------------------------------------------------------------------
# functions
# ------------------------------------------------------------------------------

include(${CMAKE_CURRENT_LIST_DIR}/../function/bf_error.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../function/bf_find_program.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../function/bf_add_config.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../function/bf_add_test.cmake)

# ------------------------------------------------------------------------------
# number of threads
# ------------------------------------------------------------------------------

include(ProcessorCount)
ProcessorCount(NUM_THREADS)

# ------------------------------------------------------------------------------
# standardization
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL PERFORCE)
    set(CMAKE_CXX_STANDARD 17)
else()
    set(CMAKE_CXX_STANDARD 20)
endif()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ------------------------------------------------------------------------------
# compilation database
# ------------------------------------------------------------------------------

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ------------------------------------------------------------------------------
# color
# ------------------------------------------------------------------------------

string(ASCII 27 Esc)
set(BF_COLOR_RST "${Esc}[m")
set(BF_COLOR_RED "${Esc}[91m")
set(BF_COLOR_GRN "${Esc}[92m")
set(BF_COLOR_YLW "${Esc}[93m")
set(BF_COLOR_BLU "${Esc}[94m")
set(BF_COLOR_MAG "${Esc}[95m")
set(BF_COLOR_CYN "${Esc}[96m")
set(BF_COLOR_WHT "${Esc}[97m")

# ------------------------------------------------------------------------------
# color coded words
# ------------------------------------------------------------------------------

set(BF_ENABLED "${BF_COLOR_GRN}enabled${BF_COLOR_RST}")
set(BF_DISABLED "${BF_COLOR_YLW}disabled${BF_COLOR_RST}")

# ------------------------------------------------------------------------------
# build command
# ------------------------------------------------------------------------------

if(CMAKE_GENERATOR STREQUAL "Unix Makefiles")
    set(BUILD_COMMAND "make ")
elseif(CMAKE_GENERATOR STREQUAL "Ninja")
    set(BUILD_COMMAND "ninja")
else()
    bf_error("Unsupported cmake generator: ${CMAKE_GENERATOR}")
endif()

# ------------------------------------------------------------------------------
# build types
# ------------------------------------------------------------------------------

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE DEBUG)
endif()

if(CMAKE_BUILD_TYPE STREQUAL Release)
    set(CMAKE_BUILD_TYPE RELEASE)
endif()

if(CMAKE_BUILD_TYPE STREQUAL Debug)
    set(CMAKE_BUILD_TYPE DEBUG)
endif()

if(NOT CMAKE_BUILD_TYPE STREQUAL RELEASE AND
   NOT CMAKE_BUILD_TYPE STREQUAL DEBUG AND
   NOT CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY AND
   NOT CMAKE_BUILD_TYPE STREQUAL PERFORCE AND
   NOT CMAKE_BUILD_TYPE STREQUAL ASAN AND
   NOT CMAKE_BUILD_TYPE STREQUAL UBSAN AND
   NOT CMAKE_BUILD_TYPE STREQUAL CODECOV)
    bf_error("Unknown CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
endif()

message(STATUS "Build type: ${BF_COLOR_CYN}${CMAKE_BUILD_TYPE}${BF_COLOR_RST}")

# ------------------------------------------------------------------------------
# examples
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL DEBUG OR
   CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY OR
   CMAKE_BUILD_TYPE STREQUAL PERFORCE OR
   CMAKE_BUILD_TYPE STREQUAL ASAN OR
   CMAKE_BUILD_TYPE STREQUAL UBSAN)
    if(NOT DEFINED BUILD_EXAMPLES)
        set(BUILD_EXAMPLES ON)
    endif()
endif()

if(BUILD_EXAMPLES)
    message(STATUS "Build examples: ${BF_ENABLED}")
else()
    message(STATUS "Build examples: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# tests
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL DEBUG OR
   CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY OR
   CMAKE_BUILD_TYPE STREQUAL ASAN OR
   CMAKE_BUILD_TYPE STREQUAL UBSAN OR
   CMAKE_BUILD_TYPE STREQUAL CODECOV)
    if(NOT DEFINED BUILD_TESTS)
        set(BUILD_TESTS ON)
    endif()
endif()

if(BUILD_TESTS)
    include(CTest)
    message(STATUS "Build tests: ${BF_ENABLED}")
else()
    message(STATUS "Build tests: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# clang tidy
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY)
    bf_find_program(CMAKE_CXX_CLANG_TIDY "clang-tidy" "https://clang.llvm.org/extra/clang-tidy/")
    message(STATUS "Tool [Clang Tidy]: ${BF_ENABLED} - ${CMAKE_CXX_CLANG_TIDY}")
endif()

# ------------------------------------------------------------------------------
# clang format
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL DEBUG OR
   CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY OR
   CMAKE_BUILD_TYPE STREQUAL PERFORCE OR
   CMAKE_BUILD_TYPE STREQUAL ASAN OR
   CMAKE_BUILD_TYPE STREQUAL UBSAN OR
   CMAKE_BUILD_TYPE STREQUAL CODECOV)
    if(NOT DEFINED ENABLE_CLANG_FORMAT)
        set(ENABLE_CLANG_FORMAT ON)
    endif()
endif()

if(ENABLE_CLANG_FORMAT)
    bf_find_program(BF_CLANG_FORMAT "clang-format" "https://clang.llvm.org/docs/ClangFormat.html")
    message(STATUS "Tool [Clang Format]: ${BF_ENABLED} - ${BF_CLANG_FORMAT}")
else()
    message(STATUS "Tool [Clang Format]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# grcov
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL CODECOV)
    bf_find_program(BF_GRCOV "grcov" "https://github.com/mozilla/grcov")
    message(STATUS "Tool [grcov]: ${BF_ENABLED} - ${BF_GRCOV}")
else()
    message(STATUS "Tool [grcov]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# doxygen
# ------------------------------------------------------------------------------

if(ENABLE_DOXYGEN)
    bf_find_program(BF_DOXYGEN "doxygen" "http://doxygen.nl/")
    message(STATUS "Tool [Doxygen]: ${BF_ENABLED} - ${BF_DOXYGEN}")
else()
    message(STATUS "Tool [Doxygen]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# asan
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL ASAN)
    message(STATUS "Tool [Google's ASAN]: ${BF_ENABLED}")
else()
    message(STATUS "Tool [Google's ASAN]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# ubsan
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL UBSAN)
    message(STATUS "Tool [Google's UBSAN]: ${BF_ENABLED}")
else()
    message(STATUS "Tool [Google's UBSAN]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# defaults
# ------------------------------------------------------------------------------

if(NOT DEFINED BSL_DEBUG_LEVEL)
    set(BSL_DEBUG_LEVEL "0")
endif()

if(NOT DEFINED BSL_PAGE_SIZE)
    set(BSL_PAGE_SIZE "0x10'00U")
endif()

if(CMAKE_BUILD_TYPE STREQUAL PERFORCE)
    set(BSL_PERFORCE "true")
    set(BSL_CONSTEXPR "")
else()
    set(BSL_PERFORCE "false")
    set(BSL_CONSTEXPR "constexpr")
endif()

# ------------------------------------------------------------------------------
# build type flags
# ------------------------------------------------------------------------------

string(APPEND CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} "
    "-Weverything "
    "-Wno-c++98-compat "
    "-Wno-c++98-compat-pedantic "
    "-Wno-c++20-compat "
    "-Wno-c11-extensions "
    "-Wno-padded "
    "-Wno-weak-vtables "
    "-Wno-ctad-maybe-unsupported "
    "-Wno-enum-compare-conditional "
    "-fcomment-block-commands=include "
    "-fcomment-block-commands=cond "
    "-fcomment-block-commands=endcond "
)

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Werror")
set(CMAKE_LINKER_FLAGS_RELEASE "-O3 -DNDEBUG -Werror")
set(CMAKE_CXX_FLAGS_DEBUG "-Og -g -ftime-trace")
set(CMAKE_LINKER_FLAGS_DEBUG "-Og -g -ftime-trace")
set(CMAKE_CXX_FLAGS_CLANG_TIDY "-O0 -g -ftime-trace -Werror")
set(CMAKE_LINKER_FLAGS_CLANG_TIDY "-O0 -g -ftime-trace -Werror")
set(CMAKE_CXX_FLAGS_PERFORCE "-O0 -Werror")
set(CMAKE_LINKER_FLAGS_PERFORCE "-O0 -Werror")
set(CMAKE_CXX_FLAGS_ASAN "-Og -g -fno-omit-frame-pointer -fsanitize=address")
set(CMAKE_LINKER_FLAGS_ASAN "-Og -g -fno-omit-frame-pointer -fsanitize=address")
set(CMAKE_CXX_FLAGS_UBSAN "-Og -g -fsanitize=undefined")
set(CMAKE_LINKER_FLAGS_UBSAN "-Og -g -fsanitize=undefined")
set(CMAKE_CXX_FLAGS_CODECOV "-O0 -fprofile-arcs -ftest-coverage")
set(CMAKE_LINKER_FLAGS_CODECOV "-O0 -fprofile-arcs -ftest-coverage")

message(STATUS "CXX Flags:${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE}}")
