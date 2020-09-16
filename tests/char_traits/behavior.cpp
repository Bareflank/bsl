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

namespace
{
    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        using traits = bsl::char_traits<bsl::char_type>;

        bsl::ut_scenario{"eq"} = []() {
            bsl::ut_given{} = []() {
                bsl::char_type a{static_cast<bsl::char_type>(42)};
                bsl::char_type b{static_cast<bsl::char_type>(42)};
                bsl::ut_then{} = [&a, &b]() {
                    bsl::ut_check(traits::eq(a, b));
                };
            };
        };

        bsl::ut_scenario{"lt"} = []() {
            bsl::ut_given{} = []() {
                bsl::char_type a{static_cast<bsl::char_type>(23)};
                bsl::char_type b{static_cast<bsl::char_type>(42)};
                bsl::ut_then{} = [&a, &b]() {
                    bsl::ut_check(traits::lt(a, b));
                };
            };
        };

        bsl::ut_scenario{"compare"} = []() {
            bsl::ut_then{} = []() {
                bsl::ut_check(traits::compare(nullptr, "42", bsl::to_umax(2)) == 0);
                bsl::ut_check(traits::compare("42", nullptr, bsl::to_umax(2)) == 0);
                bsl::ut_check(traits::compare("42", nullptr, bsl::safe_uintmax::zero(true)) == 0);
                bsl::ut_check(traits::compare("42", "42", bsl::to_umax(0)) == 0);
                bsl::ut_check(traits::compare("42", "42", bsl::to_umax(1)) == 0);
                bsl::ut_check(traits::compare("42", "42", bsl::to_umax(2)) == 0);
                bsl::ut_check(traits::compare("42", "23", bsl::to_umax(1)) != 0);
                bsl::ut_check(traits::compare("42", "23", bsl::to_umax(2)) != 0);
            };
        };

        bsl::ut_scenario{"length"} = []() {
            bsl::ut_then{} = []() {
                bsl::ut_check(traits::length(nullptr) == bsl::to_umax(0));
                bsl::ut_check(traits::length("") == bsl::to_umax(0));
                bsl::ut_check(traits::length("42") == bsl::to_umax(2));
                bsl::ut_check(traits::length("4\0 2") == bsl::to_umax(1));
            };
        };

        bsl::ut_scenario{"find"} = []() {
            bsl::ut_given{} = []() {
                bsl::cstr_type const msg{"Hello World"};
                bsl::ut_then{} = [&msg]() {
                    bsl::ut_check(traits::find(nullptr, bsl::to_umax(5), 'l') == nullptr);
                    bsl::ut_check(traits::find(msg, bsl::to_umax(0), 'l') == nullptr);
                    bsl::ut_check(traits::find(msg, bsl::safe_uintmax::zero(true), 'l') == nullptr);
                    bsl::ut_check(traits::find(msg, bsl::to_umax(5), 'l') == &msg[2]);
                    bsl::ut_check(traits::find(msg, bsl::npos, 'l') == &msg[2]);
                    bsl::ut_check(traits::find(msg, bsl::to_umax(1), 'z') == nullptr);
                    bsl::ut_check(traits::find(msg, bsl::npos, 'z') == nullptr);
                };
            };
        };

        bsl::ut_scenario{"to_char_type"} = []() {
            bsl::ut_then{} = []() {
                constexpr bsl::safe_intmax s{bsl::to_imax(42)};
                constexpr bsl::safe_intmax b{bsl::to_imax(4242)};
                bsl::ut_check(bsl::to_imax(traits::to_char_type(s.get())) == s);
                bsl::ut_check(bsl::to_imax(traits::to_char_type(b.get())) != b);
            };
        };

        bsl::ut_scenario{"to_int_type"} = []() {
            bsl::ut_then{} = []() {
                bsl::ut_check(traits::to_int_type('*') == bsl::to_imax(42));
            };
        };

        bsl::ut_scenario{"eq_int_type"} = []() {
            bsl::ut_then{} = []() {
                constexpr bsl::safe_intmax i{bsl::to_imax(42)};
                bsl::ut_check(traits::eq_int_type(i.get(), i.get()));
                bsl::ut_check(traits::eq_int_type(traits::eof(), traits::eof()));
                bsl::ut_check(!traits::eq_int_type(i.get(), traits::eof()));
                bsl::ut_check(!traits::eq_int_type(traits::eof(), i.get()));
            };
        };

        bsl::ut_scenario{"eof"} = []() {
            bsl::ut_then{} = []() {
                bsl::ut_check(traits::eof() == bsl::to_imax(-1));
            };
        };

        bsl::ut_scenario{"not_eof"} = []() {
            bsl::ut_then{} = []() {
                constexpr bsl::safe_intmax i1{};
                constexpr bsl::safe_intmax i2{bsl::to_imax(42)};
                bsl::ut_check(traits::not_eof(i1.get()) == i1);
                bsl::ut_check(traits::not_eof(i2.get()) == i2);
                bsl::ut_check(traits::not_eof(traits::eof()) == i1);
            };
        };

        return bsl::ut_success();
    }
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to bsl::ut_check() fails
///     the application will fast fail. If all calls to bsl::ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    static_assert(tests() == bsl::ut_success());
    return tests();
}
