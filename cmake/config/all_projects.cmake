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

include(${CMAKE_CURRENT_LIST_DIR}/../function/bf_find_program.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../function/bf_add_config.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../function/bf_add_test.cmake)

# ------------------------------------------------------------------------------
# options (user configurable)
# ------------------------------------------------------------------------------

option(BUILD_EXAMPLES "Turns on/off building the examples" OFF)
option(BUILD_TESTS "Turns on/off building the tests" OFF)
option(ENABLE_CLANG_FORMAT "Turns on/off support for clang format" ON)
option(ENABLE_DOXYGEN "Turns on/off support for doxygen" OFF)

# ------------------------------------------------------------------------------
# settings (user configurable)
# ------------------------------------------------------------------------------

bf_add_config(
    CONFIG_NAME BSL_DEBUG_LEVEL
    CONFIG_TYPE STRING
    DEFAULT_VAL 0
    DESCRIPTION "Defines the debug level"
    OPTIONS 0 v vv vvv
)

bf_add_config(
    CONFIG_NAME BSL_PAGE_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL "0x10'00U"
    DESCRIPTION "Defines the size of a page"
    SKIP_VALIDATION
)

# ------------------------------------------------------------------------------
# build types (user configurable)
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
    message(FATAL_ERROR "Unknown CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
endif()

# ------------------------------------------------------------------------------
# validate
# ------------------------------------------------------------------------------

if(NOT CMAKE_GENERATOR STREQUAL "Unix Makefiles" AND NOT CMAKE_GENERATOR STREQUAL "Ninja")
    message(FATAL_ERROR "CMAKE_GENERATOR must be set to \"Unix Makefiles\" or \"Ninja\"")
endif()

if(NOT CMAKE_CXX_COMPILER MATCHES "clang")
    message(FATAL_ERROR "CMAKE_CXX_COMPILER must be set to a clang compiler")
endif()

if(CMAKE_BUILD_TYPE STREQUAL PERFORCE AND BUILD_TESTS)
    message(FATAL_ERROR "BUILD_TESTS is not supported with CMAKE_BUILD_TYPE=PERFORCE")
endif()

if(CMAKE_BUILD_TYPE STREQUAL CODECOV AND BUILD_EXAMPLES)
    message(FATAL_ERROR "BUILD_EXAMPLES is not supported with CMAKE_BUILD_TYPE=CODECOV")
endif()

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
set(BF_DISABLED "${BF_COLOR_RED}disabled${BF_COLOR_RST}")

# ------------------------------------------------------------------------------
# project name
# ------------------------------------------------------------------------------

if(NOT DEFINED BSL_PROJECT_NAME)
    set(BSL_PROJECT_NAME bsl)
endif()

# ------------------------------------------------------------------------------
# build command
# ------------------------------------------------------------------------------

if(CMAKE_GENERATOR STREQUAL "Unix Makefiles")
    set(BUILD_COMMAND "make ")
elseif(CMAKE_GENERATOR STREQUAL "Ninja")
    set(BUILD_COMMAND "ninja")
else()
    message(FATAL_ERROR "Unsupported cmake generator: ${CMAKE_GENERATOR}")
endif()

# ------------------------------------------------------------------------------
# tests
# ------------------------------------------------------------------------------

if(BUILD_TESTS)
    include(CTest)
endif()

# ------------------------------------------------------------------------------
# find programs
# ------------------------------------------------------------------------------

if(ENABLE_CLANG_FORMAT)
    bf_find_program(BF_CLANG_FORMAT "clang-format" "https://clang.llvm.org/docs/ClangFormat.html")
endif()

if(ENABLE_DOXYGEN)
    bf_find_program(BF_DOXYGEN "doxygen" "http://doxygen.nl/")
endif()

if(CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY)
    bf_find_program(CMAKE_CXX_CLANG_TIDY "clang-tidy" "https://clang.llvm.org/extra/clang-tidy/")
endif()

if(CMAKE_BUILD_TYPE STREQUAL CODECOV)
    bf_find_program(BF_GRCOV "grcov" "https://github.com/mozilla/grcov")
endif()

# ------------------------------------------------------------------------------
# perforce
# ------------------------------------------------------------------------------

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

string(APPEND BSL_WARNINGS
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

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Werror ${BSL_WARNINGS}")
set(CMAKE_LINKER_FLAGS_RELEASE "-O3 -DNDEBUG -Werror ${BSL_WARNINGS}")
set(CMAKE_CXX_FLAGS_DEBUG "-Og -g -ftime-trace ${BSL_WARNINGS}")
set(CMAKE_LINKER_FLAGS_DEBUG "-Og -g -ftime-trace ${BSL_WARNINGS}")
set(CMAKE_CXX_FLAGS_CLANG_TIDY "-O0 -g -ftime-trace -Werror ${BSL_WARNINGS}")
set(CMAKE_LINKER_FLAGS_CLANG_TIDY "-O0 -g -ftime-trace -Werror ${BSL_WARNINGS}")
set(CMAKE_CXX_FLAGS_PERFORCE "-O0 -Werror ${BSL_WARNINGS}")
set(CMAKE_LINKER_FLAGS_PERFORCE "-O0 -Werror ${BSL_WARNINGS}")
set(CMAKE_CXX_FLAGS_ASAN "-Og -g -fno-omit-frame-pointer -fsanitize=address ${BSL_WARNINGS}")
set(CMAKE_LINKER_FLAGS_ASAN "-Og -g -fno-omit-frame-pointer -fsanitize=address ${BSL_WARNINGS}")
set(CMAKE_CXX_FLAGS_UBSAN "-Og -g -fsanitize=undefined ${BSL_WARNINGS}")
set(CMAKE_LINKER_FLAGS_UBSAN "-Og -g -fsanitize=undefined ${BSL_WARNINGS}")
set(CMAKE_CXX_FLAGS_CODECOV "-O0 -fprofile-arcs -ftest-coverage ${BSL_WARNINGS}")
set(CMAKE_LINKER_FLAGS_CODECOV "-O0 -fprofile-arcs -ftest-coverage ${BSL_WARNINGS}")
