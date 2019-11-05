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

#include <bsl/cstring.hpp>
#include <bsl/array.hpp>
#include <bsl/string_view.hpp>
#include <bsl/ut.hpp>

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
bsl::exit_code
main() noexcept
{
    // clang-format off

    bsl::ut_scenario{"builtin_memset"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr{4, 8, 15, 16, 23, 42};
            bsl::ut_then{} = [&arr]() {
                bsl::ut_check(bsl::builtin_memset(nullptr, 42, arr.size_bytes()) == nullptr);
                bsl::ut_check(bsl::builtin_memset(arr.data(), 42, 0) == nullptr);
                bsl::ut_check(bsl::builtin_memset(arr.data(), 42, arr.size_bytes()) == arr.data());
            };
        };
    };

    bsl::ut_scenario{"builtin_memcmp"} = []() {
        bsl::ut_given{} = []() {
            bsl::array<bsl::uintmax, 6> arr1{4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 6> arr2{4, 8, 15, 16, 23, 42};
            bsl::array<bsl::uintmax, 6> arr3{4, 8, 15, 16, 23, 0};
            bsl::ut_then{} = [&arr1, &arr2, &arr3]() {
                bsl::ut_check(bsl::builtin_memcmp(nullptr, arr2.data(), arr1.size_bytes()) == 0);
                bsl::ut_check(bsl::builtin_memcmp(arr1.data(), nullptr, arr1.size_bytes()) == 0);
                bsl::ut_check(bsl::builtin_memcmp(arr1.data(), arr2.data(), arr1.size_bytes()) == 0);
                bsl::ut_check(bsl::builtin_memcmp(arr1.data(), arr3.data(), arr1.size_bytes()) != 0);
            };
        };
    };

    bsl::ut_scenario{"builtin_strncmp"} = []() {
        bsl::ut_given{} = []() {
            bsl::string_view msg1{"Hello World"};
            bsl::string_view msg2{"Hello World"};
            bsl::string_view msg3{"Something Else"};
            bsl::ut_then{} = [&msg1, &msg2, &msg3]() {
                bsl::ut_check(bsl::builtin_strncmp(nullptr, msg2.data(), msg1.size_bytes()) == 0);
                bsl::ut_check(bsl::builtin_strncmp(msg1.data(), nullptr, msg1.size_bytes()) == 0);
                bsl::ut_check(bsl::builtin_strncmp(msg1.data(), msg2.data(), msg1.size_bytes()) == 0);
                bsl::ut_check(bsl::builtin_strncmp(msg1.data(), msg3.data(), msg1.size_bytes()) != 0);
            };
        };
    };

    bsl::ut_scenario{"builtin_strlen"} = []() {
        bsl::ut_given{} = []() {
            bsl::string_view msg1{};
            bsl::string_view msg2{""};
            bsl::string_view msg3{"Hello"};
            bsl::ut_then{} = [&msg1, &msg2, &msg3]() {
                bsl::ut_check(bsl::builtin_strlen(nullptr) == 0);
                bsl::ut_check(bsl::builtin_strlen(msg1.data()) == 0);
                bsl::ut_check(bsl::builtin_strlen(msg2.data()) == 0);
                bsl::ut_check(bsl::builtin_strlen(msg3.data()) == 5);
            };
        };
    };

    bsl::ut_scenario{"builtin_strnchr"} = []() {
        bsl::ut_given{} = []() {
            bsl::string_view msg{"Hello World"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(bsl::builtin_strnchr(nullptr, 'o', msg.size_bytes()) == nullptr);
                bsl::ut_check(bsl::builtin_strnchr(msg.data(), 'o', 0) == nullptr);
                bsl::ut_check(bsl::builtin_strnchr(msg.data(), 'o', msg.size_bytes()) == msg.at_if(4));
                bsl::ut_check(bsl::builtin_strnchr(msg.data(), 'z', msg.size_bytes()) == nullptr);
            };
        };
    };

    // clang-format on

    return bsl::ut_success();
}
