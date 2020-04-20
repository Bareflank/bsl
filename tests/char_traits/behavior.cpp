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

#include <bsl/char_traits.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/npos.hpp>
#include <bsl/ut.hpp>

/// <!-- description -->
///   @brief Used to execute the actual checks. We put the checks in this
///     function so that we can validate the tests both at compile-time
///     and at run-time. If a bsl::ut_check fails, the tests will either
///     fail fast at run-time, or will produce a compile-time error.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
constexpr bsl::exit_code
tests() noexcept
{
    using namespace bsl;
    using traits = bsl::char_traits<bsl::char_type>;

    bsl::ut_scenario{"eq"} = []() {
        bsl::ut_given{} = []() {
            bsl::char_type a{42};
            bsl::char_type b{42};
            bsl::ut_then{} = [&a, &b]() {
                bsl::ut_check(traits::eq(a, b));
            };
        };
    };

    bsl::ut_scenario{"lt"} = []() {
        bsl::ut_given{} = []() {
            bsl::char_type a{23};
            bsl::char_type b{42};
            bsl::ut_then{} = [&a, &b]() {
                bsl::ut_check(traits::lt(a, b));
            };
        };
    };

    bsl::ut_scenario{"compare"} = []() {
        bsl::ut_then{} = []() {
            bsl::ut_check(traits::compare(nullptr, "42", to_umax(2)) == 0);
            bsl::ut_check(traits::compare("42", nullptr, to_umax(2)) == 0);
            bsl::ut_check(traits::compare("42", "42", to_umax(0)) == 0);
            bsl::ut_check(traits::compare("42", "42", to_umax(1)) == 0);
            bsl::ut_check(traits::compare("42", "42", to_umax(2)) == 0);
            bsl::ut_check(traits::compare("42", "23", to_umax(1)) != 0);
            bsl::ut_check(traits::compare("42", "23", to_umax(2)) != 0);
        };
    };

    bsl::ut_scenario{"length"} = []() {
        bsl::ut_then{} = []() {
            bsl::ut_check(traits::length(nullptr) == to_umax(0));
            bsl::ut_check(traits::length("") == to_umax(0));
            bsl::ut_check(traits::length("42") == to_umax(2));
            bsl::ut_check(traits::length("4\0 2") == to_umax(1));
        };
    };

    bsl::ut_scenario{"find"} = []() {
        bsl::ut_given{} = []() {
            cstr_type const msg{"Hello World"};
            bsl::ut_then{} = [&msg]() {
                bsl::ut_check(traits::find(nullptr, to_umax(5), 'l') == nullptr);
                bsl::ut_check(traits::find(msg, to_umax(0), 'l') == nullptr);
                bsl::ut_check(traits::find(msg, to_umax(5), 'l') == &msg[2]);
                bsl::ut_check(traits::find(msg, npos, 'l') == &msg[2]);
                bsl::ut_check(traits::find(msg, to_umax(1), 'z') == nullptr);
                bsl::ut_check(traits::find(msg, npos, 'z') == nullptr);
            };
        };
    };

    bsl::ut_scenario{"to_char_type"} = []() {
        bsl::ut_then{} = []() {
            constexpr bsl::intmax big{4242};
            bsl::ut_check(traits::to_char_type(42) == 42);
            bsl::ut_check(traits::to_char_type(big) != big);
        };
    };

    bsl::ut_scenario{"to_int_type"} = []() {
        bsl::ut_then{} = []() {
            bsl::ut_check(traits::to_int_type(42) == 42);
        };
    };

    bsl::ut_scenario{"eq_int_type"} = []() {
        bsl::ut_then{} = []() {
            bsl::ut_check(traits::eq_int_type(42, 42));
            bsl::ut_check(traits::eq_int_type(traits::eof(), traits::eof()));
            bsl::ut_check(!traits::eq_int_type(42, traits::eof()));
            bsl::ut_check(!traits::eq_int_type(traits::eof(), 42));
        };
    };

    bsl::ut_scenario{"eof"} = []() {
        bsl::ut_then{} = []() {
            bsl::ut_check(traits::eof() == -1);
        };
    };

    bsl::ut_scenario{"not_eof"} = []() {
        bsl::ut_then{} = []() {
            bsl::ut_check(traits::not_eof(42) == 42);
            bsl::ut_check(traits::not_eof(0) == 0);
            bsl::ut_check(traits::not_eof(traits::eof()) == 0);
        };
    };

    return bsl::ut_success();
}

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
    static_assert(tests() == bsl::ut_success());
    return tests();
}
