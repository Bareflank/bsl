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

# TODO:
# - Once we have full branch coverage in the BSL, we need to turn branch
#   coverage on for CI. For now, codecov will ignore it's own config settings
#   if you include branch coverage in the uploaded report, so we have it
#   turned off in grcov.
#

if(CMAKE_BUILD_TYPE STREQUAL CODECOV)
    add_custom_target(codecov-upload-ci
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR} cmake --build . --target unittest
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR} ${BF_GRCOV} . -s ${CMAKE_SOURCE_DIR} -t lcov -o ${CMAKE_BINARY_DIR}/codecov.info --ignore '/**'
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR} bash ${CMAKE_BINARY_DIR}/codecov.sh -f ${CMAKE_BINARY_DIR}/codecov.info
    )
endif()
