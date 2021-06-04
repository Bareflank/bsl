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

# NOTE:
# - Code coverage using clang is a bit of a mess. Clang and GCC do not stay
#   in sync with eachother on most distrobutions, and this is made worse when
#   you include CI. Clang can produce gcov files, but they are not in the same
#   format that gcov wants as GCC and Clang, again, are likely not compatible.
#   You basically have to constantly determine exactly which version of Clang
#   the currently installed version of GCC will support, which is insane.
# - LLVM comes with llvm-cov which you can ask to run as if it were gcov.
#   For some reason, which works great, except that Codecov doesn't seem to
#   like the output, even though they claim in some GitHub tickets that this
#   should work. The other issue here, is there is not way to see the results
#   in a human readable form (or at least not one that you would want to
#   see).
# - This is where grcov comes into play. It is compatible with Windows (unlike
#   lcov), and will take the output of llvm-cov and convert it into a format
#   that Codecov seems to like. The problem is, grcov will use gcov and there
#   is no flag to tell it to use llvm-cov instead. To solve this, you need to
#   symlink or rename llvm-cov to gcov. Once you do that, llvm-cov will run
#   as gcov (basically the same as running llvm-cov gcov). Once this is done
#   grcov will output an lcov or coveralls report. Since Codecov seems to like
#   lcov a lot, we use the lcov output format.
# - In short, what this means is that we have a Codecov setup that will work on
#   both Windows and Linux as we are only using LLVM binaries along with
#   grcov which is cross platform (and used by Mozilla to perform code coverage
#   reports on Windows). It also means that you can use genhtml to get a local
#   coverage report on Linux instead of constantly having to upload to Codecov
#   which is good as it cuts back on GitHub email traffic.

if(CMAKE_BUILD_TYPE STREQUAL CODECOV)
    if(NOT EXISTS ${CMAKE_BINARY_DIR}/codecov.sh)
        file(DOWNLOAD https://codecov.io/bash ${CMAKE_BINARY_DIR}/codecov.sh)
    endif()
endif()
