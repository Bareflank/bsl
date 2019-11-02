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

include(CTest)
enable_testing()

# ------------------------------------------------------------------------------
# Catch
# ------------------------------------------------------------------------------

list(APPEND UT_CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/external/
    -DBUILD_TESTS=OFF
    -DBUILD_EXAMPLES=OFF
    -DBUILD_BENCHMARKS=OFF
)

ExternalProject_Add(
    ut
    GIT_REPOSITORY https://github.com/boost-experimental/ut.git
    GIT_SHALLOW 1
    CMAKE_ARGS ${UT_CMAKE_ARGS}
    UPDATE_COMMAND ""
    UPDATE_DISCONNECTED ON
)

# ------------------------------------------------------------------------------
# External Includes
# ------------------------------------------------------------------------------

include_directories(SYSTEM ${CMAKE_BINARY_DIR}/external/include)

# ------------------------------------------------------------------------------
# Flags
# ------------------------------------------------------------------------------

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-access-control")
set(CMAKE_CXX_FLAGS_COVERAGE "-O0 -g --coverage -fprofile-arcs -ftest-coverage")
set(CMAKE_LINKER_FLAGS_COVERAGE "-O0 -g --coverage -fprofile-arcs -ftest-coverage")

# ------------------------------------------------------------------------------
# Initial Setup
# ------------------------------------------------------------------------------

add_executable(test_dynarray dynarray.cpp)
add_executable(test_random_access_iterator random_access_iterator.cpp)
add_executable(test_ifarray ifarray.cpp)

add_dependencies(test_dynarray ut)
add_dependencies(test_random_access_iterator ut)
add_dependencies(test_ifarray ut)

add_test(test_dynarray test_dynarray)
add_test(test_random_access_iterator test_random_access_iterator)
add_test(test_ifarray test_ifarray)

if(ENABLE_CPPCHECK)
    add_dependencies(test_dynarray cppcheck)
    add_dependencies(test_random_access_iterator cppcheck)
    add_dependencies(test_ifarray cppcheck)
endif()

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL "COVERAGE")
    add_custom_target(
        unittest
        COMMAND lcov --zerocounters --directory . -q
        COMMAND ctest --output-on-failure
    )

    add_custom_target(
        coverage_info
        COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/coverage.info
        COMMAND lcov --zerocounters --directory . -q
        COMMAND ${CMAKE_COMMAND} -E echo "================================================================================"
        COMMAND ctest --output-on-failure
        COMMAND ${CMAKE_COMMAND} -E echo "================================================================================"
        COMMAND lcov --capture --directory . --output-file ${CMAKE_BINARY_DIR}/coverage.info
        COMMAND lcov --remove ${CMAKE_BINARY_DIR}/coverage.info '/usr/*' --output-file ${CMAKE_BINARY_DIR}/coverage.info -q
        COMMAND lcov --remove ${CMAKE_BINARY_DIR}/coverage.info '${CMAKE_BINARY_DIR}/*' --output-file ${CMAKE_BINARY_DIR}/coverage.info -q
    )

    add_custom_target(
        coverage
        COMMAND ${CMAKE_COMMAND} --build . --target coverage_info
        COMMAND ${CMAKE_COMMAND} -E echo "================================================================================"
        COMMAND genhtml -o site ${CMAKE_BINARY_DIR}/coverage.info
        COMMAND ${CMAKE_COMMAND} -E echo "================================================================================"
        COMMAND ${CMAKE_COMMAND} -E chdir site python -m "http.server"
    )

    add_custom_target(
        coverage_upload
        COMMAND ${CMAKE_COMMAND} --build . --target coverage_info
        COMMAND ${CMAKE_COMMAND} -E echo "================================================================================"
        COMMAND curl -s https://codecov.io/bash > ${CMAKE_BINARY_DIR}/codecov.sh
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR}
        bash ${CMAKE_BINARY_DIR}/codecov.sh -t 3127698f-3d70-4a23-a00f-cd7e54768434 -f ${CMAKE_BINARY_DIR}/coverage.info
    )
else()
    add_custom_target(
        unittest
        COMMAND ctest --output-on-failure
    )
endif()
