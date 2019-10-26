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

include(ExternalProject)
enable_testing()

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

list(APPEND CATCH_CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/external/
    -DCATCH_BUILD_TESTING=OFF
)

ExternalProject_Add(
    catch
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_SHALLOW 1
    CMAKE_ARGS ${CATCH_CMAKE_ARGS}
)

include_directories(SYSTEM ${CMAKE_BINARY_DIR}/external/include)

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

if(NOT CMAKE_CXX_CLANG_TIDY)
    set(CMAKE_CXX_CLANG_TIDY "clang-tidy")
endif()

# ------------------------------------------------------------------------------
# Initial Setup
# ------------------------------------------------------------------------------

add_executable(test_dynarray dynarray.cpp)
add_executable(test_random_access_iterator random_access_iterator.cpp)
add_executable(test_farray farray.cpp)

add_dependencies(test_dynarray catch)
add_dependencies(test_random_access_iterator catch)
add_dependencies(test_farray catch)

add_test(test_dynarray test_dynarray)
add_test(test_random_access_iterator test_random_access_iterator)
add_test(test_farray test_farray)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_custom_target(
    format
    COMMAND find ${CMAKE_SOURCE_DIR}/include -iname *.h -o -iname *.cpp | xargs clang-format -i
    COMMAND find ${CMAKE_SOURCE_DIR}/tests -iname *.h -o -iname *.cpp | xargs clang-format -i
)

add_custom_target(
    unittest
    COMMAND ctest --output-on-failure
)
