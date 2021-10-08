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

include(${bsl_SOURCE_DIR}/cmake/colors.cmake)

# Check Dependency
#
# Check that a dependency overridden with FETCHCONTENT_SOURCE_DIR_<NAME> is
# pointing to the expected git tag and warn if it isn't.
#
# NAME: The name of the dependency to check in FETCHCONTENT_SOURCE_DIR_<NAME>
# GIT_TAG: The git tag to check against
#
macro(bf_check_dependency NAME GIT_TAG)
    string(TOUPPER ${NAME} NAME_UPPER)
    if (FETCHCONTENT_SOURCE_DIR_HYPERVISOR)
        execute_process(COMMAND ${CMAKE_COMMAND} -E chdir ${FETCHCONTENT_SOURCE_DIR_${NAME_UPPER}} git rev-list -n 1 HEAD
                        OUTPUT_VARIABLE GIT_HEAD_COMMIT_HASH
                        OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        execute_process(COMMAND ${CMAKE_COMMAND} -E chdir ${FETCHCONTENT_SOURCE_DIR_${NAME_UPPER}} git rev-list -n 1 ${GIT_TAG}
                        OUTPUT_VARIABLE GIT_EXPECTED_COMMIT_HASH
                        OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if (NOT ${GIT_EXPECTED_COMMIT_HASH} STREQUAL ${GIT_HEAD_COMMIT_HASH})
            message("-- ${BF_COLOR_YLW}Warning: dependency ${FETCHCONTENT_SOURCE_DIR_${NAME_UPPER}} is not pointing to ${GIT_TAG}${BF_COLOR_RST}")
        endif()
    endif()
endmacro(bf_check_dependency)
