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
#include <bsl/cstr_type.hpp>
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
    using namespace bsl;

    bsl::ut_scenario{"builtin_strncmp"} = []() {
        bsl::ut_given{} = []() {
            bsl::cstr_type msg1{"Hello World"};
            bsl::cstr_type msg2{"Hello World"};
            bsl::cstr_type msg3{"Something Else"};
            bsl::ut_then{} = [&msg1, &msg2, &msg3]() {
                bsl::ut_check(builtin_strncmp(nullptr, msg2, builtin_strlen(msg1)) == 0);
                bsl::ut_check(builtin_strncmp(msg1, nullptr, builtin_strlen(msg1)) == 0);
                bsl::ut_check(builtin_strncmp(msg1, msg2, safe_uintmax::zero(true)) == 0);
                bsl::ut_check(builtin_strncmp(msg1, msg2, builtin_strlen(msg1)) == 0);
                bsl::ut_check(builtin_strncmp(msg1, msg3, builtin_strlen(msg1)) != 0);
            };
        };
    };

    bsl::ut_scenario{"builtin_strlen"} = []() {
        bsl::ut_given{} = []() {
            bsl::cstr_type msg1{};
            bsl::cstr_type msg2{""};
            bsl::cstr_type msg3{"Hello"};
            bsl::ut_then{} = [&msg1, &msg2, &msg3]() {
                bsl::ut_check(builtin_strlen(nullptr) == to_umax(0));
                bsl::ut_check(builtin_strlen(msg1) == to_umax(0));
                bsl::ut_check(builtin_strlen(msg2) == to_umax(0));
                bsl::ut_check(builtin_strlen(msg3) == to_umax(5));
            };
        };
    };

    bsl::ut_scenario{"builtin_strnchr"} = []() {
        bsl::ut_given{} = []() {
            bsl::cstr_type msg{"Hello World"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(builtin_strnchr(nullptr, 'o', builtin_strlen(msg)) == nullptr);
                bsl::ut_check(builtin_strnchr(msg, 'o', to_umax(0)) == nullptr);
                bsl::ut_check(builtin_strnchr(msg, 'o', safe_uintmax::zero(true)) == nullptr);
                bsl::ut_check(builtin_strnchr(msg, 'o', builtin_strlen(msg)) == &msg[4]);
                bsl::ut_check(builtin_strnchr(msg, 'z', builtin_strlen(msg)) == nullptr);
            };
        };
    };

    return bsl::ut_success();
}
