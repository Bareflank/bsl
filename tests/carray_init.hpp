/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef TESTS_CARRAY_INIT_HPP
#define TESTS_CARRAY_INIT_HPP

#include <bsl/carray.hpp>
#include <bsl/convert.hpp>

namespace test
{
    constexpr bsl::carray CARRAY_INIT{
        bsl::to_i32(4),
        bsl::to_i32(8),
        bsl::to_i32(15),
        bsl::to_i32(16),
        bsl::to_i32(23),
        bsl::to_i32(42)};

    constexpr bsl::carray CARRAY_INIT_INT_23{23, 23, 23, 23, 23, 23};
    constexpr bsl::carray CARRAY_INIT_INT_42{42, 42, 42, 42, 42, 42};

    constexpr bsl::carray CARRAY_INIT_STR_42{"42"};
    constexpr bsl::carray CARRAY_INIT_STR_42_SPACE{"42 "};
    constexpr bsl::carray CARRAY_INIT_STR_APP{"app"};
    constexpr bsl::carray CARRAY_INIT_STR_DASH_APP{"-app"};
    constexpr bsl::carray CARRAY_INIT_STR_DASH_APP_EQ{"-app="};
    constexpr bsl::carray CARRAY_INIT_STR_DASH_APP_EQ_42{"-app=42"};
    constexpr bsl::carray CARRAY_INIT_STR_DASH_APP_EQ_42_SPACE{"-app=42 "};
    constexpr bsl::carray CARRAY_INIT_STR_DASH_APP_EQ_HELLO{"-app=hello"};

    constexpr bsl::carray CARRAY_INIT_STR_ARGS{
        "-app=ignored",
        "pos1",
        "-4=16",
        "-8=23",
        "pos2",
        "-15=42",
        "-app=42",
        "-app=42",
        "-app=42"};
    constexpr bsl::carray CARRAY_INIT_STR_ARGS_POS{
        "4", "-opt1", "8", "15", "16", "-opt2", "23", "42", "42"};
    constexpr bsl::carray CARRAY_INIT_STR_ARGS_BOOL{
        "true", "-opt1", "false", "1", "0", "42", "-opt2", "hello", "42 "};
}

#endif
