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

include(${CMAKE_CURRENT_LIST_DIR}/../colors.cmake)

if(CMAKE_BUILD_TYPE STREQUAL CODECOV)
    if(DEFINED BF_GENHTML)
        add_custom_target(codecov-grcov
            COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR} cmake --build . --target unittest
            COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR} ${BF_GRCOV} . -s ${CMAKE_SOURCE_DIR} -t html -o ${CMAKE_SOURCE_DIR}/grcov/ --ignore '/**' --branch
            COMMAND ${CMAKE_COMMAND} -E echo "${BF_COLOR_GRN}success${BF_COLOR_RST}: open ${BF_COLOR_YLW}${CMAKE_SOURCE_DIR}/grcov/index.html${BF_COLOR_RST} in a browser to see the report"
        )
    endif()
endif()
