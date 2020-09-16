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

list(APPEND BSL_WARNINGS
    -Weverything
    -Wno-c++98-compat
    -Wno-c++98-compat-pedantic
    -Wno-c++20-compat
    -Wno-c11-extensions
    -Wno-padded
    -Wno-weak-vtables
    -Wno-ctad-maybe-unsupported
    -Wno-enum-compare-conditional
    -Wno-return-std-move-in-c++11
    -fcomment-block-commands=include
    -fcomment-block-commands=cond
    -fcomment-block-commands=endcond
)

list(APPEND BSL_ENABLE_CONSOLE_COLORS
    -fdiagnostics-color=always
    -fansi-escape-codes
)

list(APPEND BSL_FLAGS_RELEASE
    -O3
    -DNDEBUG
    -Werror
    ${BSL_WARNINGS}
    ${BSL_ENABLE_CONSOLE_COLORS}
)

list(APPEND BSL_FLAGS_DEBUG
    -Og
    -g
    -ftime-trace
    ${BSL_WARNINGS}
    ${BSL_ENABLE_CONSOLE_COLORS}
)

list(APPEND BSL_FLAGS_CLANG_TIDY
    -O0
    -g
    -ftime-trace
    -Werror
    ${BSL_WARNINGS}
    ${BSL_ENABLE_CONSOLE_COLORS}
)

list(APPEND BSL_FLAGS_ASAN
    -Og
    -g
    -fno-omit-frame-pointer
    -fsanitize=address
    ${BSL_WARNINGS}
    ${BSL_ENABLE_CONSOLE_COLORS}
)

list(APPEND BSL_FLAGS_UBSAN
    -Og
    -g
    -fsanitize=undefined
    ${BSL_WARNINGS}
    ${BSL_ENABLE_CONSOLE_COLORS}
)

list(APPEND BSL_FLAGS_CODECOV
    -O0
    -fprofile-arcs
    -ftest-coverage
    ${BSL_WARNINGS}
    ${BSL_ENABLE_CONSOLE_COLORS}
)
