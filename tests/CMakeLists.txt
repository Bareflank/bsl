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

enable_testing()

# ------------------------------------------------------------------------------
# Catch
# ------------------------------------------------------------------------------

list(APPEND CATCH_CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/external/
    -DCATCH_BUILD_TESTING=OFF
)

ExternalProject_Add(
    catch
    URL https://github.com/catchorg/Catch2/archive/v2.10.2.tar.gz
    URL_MD5 4ea4e4a9ddba9859e06a6f34719c720d
    CMAKE_ARGS ${CATCH_CMAKE_ARGS}
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

add_library(catch_main STATIC catch_main.cpp)
add_dependencies(catch_main catch)

add_executable(test_dynarray dynarray.cpp)
add_executable(test_random_access_iterator random_access_iterator.cpp)
add_executable(test_ifarray ifarray.cpp)

target_link_libraries(test_dynarray catch_main)
target_link_libraries(test_random_access_iterator catch_main)
target_link_libraries(test_ifarray catch_main)

add_test(test_dynarray test_dynarray)
add_test(test_random_access_iterator test_random_access_iterator)
add_test(test_ifarray test_ifarray)

if(ENABLE_CPPCHECK)
    add_dependencies(catch_main cppcheck)
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
        COMMAND lcov --capture --directory . --output-file ${CMAKE_BINARY_DIR}/coverage.info -rc lcov_function_coverage=0
        COMMAND lcov --remove ${CMAKE_BINARY_DIR}/coverage.info '/usr/*' --output-file ${CMAKE_BINARY_DIR}/coverage.info -q
        COMMAND lcov --remove ${CMAKE_BINARY_DIR}/coverage.info '${CMAKE_BINARY_DIR}/*' --output-file ${CMAKE_BINARY_DIR}/coverage.info -q
    )

    add_custom_target(
        coverage
        COMMAND ${CMAKE_COMMAND} --build . --target coverage_info
        COMMAND ${CMAKE_COMMAND} -E echo "================================================================================"
        COMMAND genhtml -o site ${CMAKE_BINARY_DIR}/coverage.info
        COMMAND ${CMAKE_COMMAND} -E echo "================================================================================"
        COMMAND ${CMAKE_COMMAND} -E chdir site python -m "SimpleHTTPServer"
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
