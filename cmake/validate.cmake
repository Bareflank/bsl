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
