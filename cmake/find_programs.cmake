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

include(${CMAKE_CURRENT_LIST_DIR}/function/bf_find_program.cmake)

if(ENABLE_CLANG_FORMAT)
    bf_find_program(BF_CLANG_FORMAT "clang-format" "https://clang.llvm.org/docs/ClangFormat.html")
endif()

if(ENABLE_DOXYGEN)
    bf_find_program(BF_DOXYGEN "doxygen" "http://doxygen.nl/")
endif()

if(CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY)
    bf_find_program(CMAKE_CXX_CLANG_TIDY
        "clang-tidy"
        "https://clang.llvm.org/extra/clang-tidy/"
    )

endif()

if(CMAKE_BUILD_TYPE STREQUAL CODECOV)
    bf_find_program(BF_GCOV "gcov" "https://llvm.org/docs/CommandGuide/llvm-cov.html")
    bf_find_program(BF_GRCOV "grcov" "https://github.com/mozilla/grcov")

    # These are optional
    #

    find_program(BF_LCOV "lcov")
    find_program(BF_GENHTML "genhtml")

    # NOTE:
    # - For GRCOV to work, gcov must actually point to llvm-cov. This will
    #   cause llvm-cov to act like GCOV which is needed because you cannot
    #   mix GCOV with Clang.
    #

    execute_process(COMMAND gcov --version OUTPUT_VARIABLE GCOV_OUTPUT)
    if(NOT GCOV_OUTPUT MATCHES "LLVM")
        message(FATAL_ERROR "gcov must be a symlink to, or rename of llvm-cov")
    endif()
endif()

if(NOT TARGET iwyu)
    find_program(IWYU_PATH "include-what-you-use")
    if(IWYU_PATH)
        find_package(PythonInterp)
        if(NOT PYTHONINTERP_FOUND)
            message(FATAL_ERROR "python is required for include-what-you-use")
        endif()
        add_custom_target(iwyu
            COMMAND "${PYTHON_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/utils/iwyu_tool.py" -p "${CMAKE_BINARY_DIR}" -j ${CMAKE_NUM_PROCESSORS} --
                    # -Xiwyu --no_comments
                    -Xiwyu --quoted_includes_first
                    -Xiwyu --cxx17ns
                    -Xiwyu --no_fwd_decls
                    -Xiwyu --check_also=${CMAKE_SOURCE_DIR}/*.hpp
            COMMENT "Running include-what-you-use"
            VERBATIM
        )
    else()
        message(STATUS "${BF_COLOR_YLW}unable to locate 'include-what-you-use'${BF_COLOR_RST}")
    endif()
endif()
