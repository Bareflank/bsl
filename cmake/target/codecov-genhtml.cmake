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

if(CMAKE_BUILD_TYPE STREQUAL CODECOV)
    if(BF_LCOV AND BF_GENHTML)
        if(ENABLE_BRANCH)
            add_custom_target(codecov-genhtml
                COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/genhtml
                COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/genhtml.info
                COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR} ${BF_LCOV} --zerocounters --directory ${CMAKE_BINARY_DIR}
                COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR} cmake --build . --target unittest
                COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR} ${BF_GRCOV} . -s ${CMAKE_SOURCE_DIR} -t lcov -o ${CMAKE_BINARY_DIR}/genhtml.info --ignore '/**' --branch --excl-line GRCOV_EXCLUDE --excl-br-line GRCOV_EXCLUDE_BR
                COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR} ${BF_GENHTML} -s --function-coverage --branch-coverage --legend --demangle-cpp --highlight -rc genhtml_hi_limit=100 ${CMAKE_BINARY_DIR}/genhtml.info -o ${CMAKE_SOURCE_DIR}/genhtml/ --prefix ${CMAKE_SOURCE_DIR}
            )
        else()
            add_custom_target(codecov-genhtml
                COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/genhtml
                COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/genhtml.info
                COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR} ${BF_LCOV} --zerocounters --directory ${CMAKE_BINARY_DIR}
                COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR} cmake --build . --target unittest
                COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_BINARY_DIR} ${BF_GRCOV} . -s ${CMAKE_SOURCE_DIR} -t lcov -o ${CMAKE_BINARY_DIR}/genhtml.info --ignore '/**' --excl-line GRCOV_EXCLUDE --excl-br-line GRCOV_EXCLUDE_BR
                COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR} ${BF_GENHTML} -s --function-coverage --legend --demangle-cpp --highlight -rc genhtml_hi_limit=100 ${CMAKE_BINARY_DIR}/genhtml.info -o ${CMAKE_SOURCE_DIR}/genhtml/ --prefix ${CMAKE_SOURCE_DIR}
            )
        endif()
    endif()
endif()


