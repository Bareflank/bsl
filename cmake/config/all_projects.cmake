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

include(${CMAKE_CURRENT_LIST_DIR}/../function/bf_add_config.cmake)

option(BUILD_EXAMPLES "Turns on/off building the examples" OFF)
option(BUILD_TESTS "Turns on/off building the tests" OFF)
option(ENABLE_CLANG_FORMAT "Turns on/off support for clang format" OFF)
option(ENABLE_DOXYGEN "Turns on/off support for doxygen" OFF)

bf_add_config(
    CONFIG_NAME BSL_DEBUG_LEVEL
    CONFIG_TYPE STRING
    DEFAULT_VAL "static_cast<bsl::uintmax>(0)"
    DESCRIPTION "Defines the debug level"
    OPTIONS "static_cast<bsl::uintmax>(0)" "bsl::V" "bsl::VV" "bsl::VVV"
)

bf_add_config(
    CONFIG_NAME BSL_PAGE_SIZE
    CONFIG_TYPE STRING
    DEFAULT_VAL "static_cast<bsl::uintmax>(4096)"
    DESCRIPTION "Defines the size of a page"
    SKIP_VALIDATION
)
