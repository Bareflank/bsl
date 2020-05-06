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

#include <bsl/basic_errc_type.hpp>
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
    bsl::ut_scenario{"constructor / get"} = []() {
        bsl::ut_given{} = []() {
            bsl::basic_errc_type<> errc{};
            bsl::ut_then{} = [&errc]() {
                bsl::ut_check(errc.get() == 0);
            };
        };

        bsl::ut_given{} = []() {
            bsl::basic_errc_type<> errc{42};
            bsl::ut_then{} = [&errc]() {
                bsl::ut_check(errc.get() == 42);
            };
        };
    };

    bsl::ut_scenario{"operator bool"} = []() {
        bsl::ut_check(!!bsl::errc_success);
        bsl::ut_check(!bsl::errc_failure);
        bsl::ut_check(!bsl::errc_precondition);
        bsl::ut_check(!bsl::errc_postcondition);
        bsl::ut_check(!bsl::errc_assetion);
        bsl::ut_check(!bsl::errc_invalid_argument);
        bsl::ut_check(!bsl::errc_index_out_of_bounds);
        bsl::ut_check(!bsl::errc_bad_function);
        bsl::ut_check(!bsl::errc_unsigned_wrap);
        bsl::ut_check(!bsl::errc_narrow_overflow);
        bsl::ut_check(!bsl::errc_signed_overflow);
        bsl::ut_check(!bsl::errc_divide_by_zero);
        bsl::ut_check(!bsl::errc_nullptr_dereference);
    };

    bsl::ut_scenario{"success"} = []() {
        bsl::ut_check(bsl::errc_success.success());
        bsl::ut_check(!bsl::errc_failure.success());
        bsl::ut_check(!bsl::errc_precondition.success());
        bsl::ut_check(!bsl::errc_postcondition.success());
        bsl::ut_check(!bsl::errc_assetion.success());
        bsl::ut_check(!bsl::errc_invalid_argument.success());
        bsl::ut_check(!bsl::errc_index_out_of_bounds.success());
        bsl::ut_check(!bsl::errc_bad_function.success());
        bsl::ut_check(!bsl::errc_unsigned_wrap.success());
        bsl::ut_check(!bsl::errc_narrow_overflow.success());
        bsl::ut_check(!bsl::errc_signed_overflow.success());
        bsl::ut_check(!bsl::errc_divide_by_zero.success());
        bsl::ut_check(!bsl::errc_nullptr_dereference.success());
    };

    bsl::ut_scenario{"failure"} = []() {
        bsl::ut_check(!bsl::errc_success.failure());
        bsl::ut_check(bsl::errc_failure.failure());
        bsl::ut_check(bsl::errc_precondition.failure());
        bsl::ut_check(bsl::errc_postcondition.failure());
        bsl::ut_check(bsl::errc_assetion.failure());
        bsl::ut_check(bsl::errc_invalid_argument.failure());
        bsl::ut_check(bsl::errc_index_out_of_bounds.failure());
        bsl::ut_check(bsl::errc_bad_function.failure());
        bsl::ut_check(bsl::errc_unsigned_wrap.failure());
        bsl::ut_check(bsl::errc_narrow_overflow.failure());
        bsl::ut_check(bsl::errc_signed_overflow.failure());
        bsl::ut_check(bsl::errc_divide_by_zero.failure());
        bsl::ut_check(bsl::errc_nullptr_dereference.failure());
    };

    bsl::ut_scenario{"is_checked"} = []() {
        bsl::ut_check(!bsl::errc_success.is_checked());
        bsl::ut_check(!bsl::errc_failure.is_checked());
        bsl::ut_check(!bsl::errc_precondition.is_checked());
        bsl::ut_check(!bsl::errc_postcondition.is_checked());
        bsl::ut_check(!bsl::errc_assetion.is_checked());
        bsl::ut_check(!bsl::errc_invalid_argument.is_checked());
        bsl::ut_check(!bsl::errc_index_out_of_bounds.is_checked());
        bsl::ut_check(!bsl::errc_bad_function.is_checked());
        bsl::ut_check(!bsl::errc_unsigned_wrap.is_checked());
        bsl::ut_check(!bsl::errc_narrow_overflow.is_checked());
        bsl::ut_check(!bsl::errc_signed_overflow.is_checked());
        bsl::ut_check(!bsl::errc_divide_by_zero.is_checked());
        bsl::ut_check(!bsl::errc_nullptr_dereference.is_checked());
    };

    bsl::ut_scenario{"is_unchecked"} = []() {
        bsl::ut_check(!bsl::errc_success.is_unchecked());
        bsl::ut_check(bsl::errc_failure.is_unchecked());
        bsl::ut_check(bsl::errc_precondition.is_unchecked());
        bsl::ut_check(bsl::errc_postcondition.is_unchecked());
        bsl::ut_check(bsl::errc_assetion.is_unchecked());
        bsl::ut_check(bsl::errc_invalid_argument.is_unchecked());
        bsl::ut_check(bsl::errc_index_out_of_bounds.is_unchecked());
        bsl::ut_check(bsl::errc_bad_function.is_unchecked());
        bsl::ut_check(bsl::errc_unsigned_wrap.is_unchecked());
        bsl::ut_check(bsl::errc_narrow_overflow.is_unchecked());
        bsl::ut_check(bsl::errc_signed_overflow.is_unchecked());
        bsl::ut_check(bsl::errc_divide_by_zero.is_unchecked());
        bsl::ut_check(bsl::errc_nullptr_dereference.is_unchecked());
    };

    bsl::ut_scenario{"message"} = []() {
        bsl::ut_check(!bsl::errc_success.message().empty());
        bsl::ut_check(!bsl::errc_failure.message().empty());
        bsl::ut_check(!bsl::errc_precondition.message().empty());
        bsl::ut_check(!bsl::errc_postcondition.message().empty());
        bsl::ut_check(!bsl::errc_assetion.message().empty());
        bsl::ut_check(!bsl::errc_invalid_argument.message().empty());
        bsl::ut_check(!bsl::errc_index_out_of_bounds.message().empty());
        bsl::ut_check(!bsl::errc_bad_function.message().empty());
        bsl::ut_check(!bsl::errc_unsigned_wrap.message().empty());
        bsl::ut_check(!bsl::errc_narrow_overflow.message().empty());
        bsl::ut_check(!bsl::errc_signed_overflow.message().empty());
        bsl::ut_check(!bsl::errc_divide_by_zero.message().empty());
        bsl::ut_check(!bsl::errc_nullptr_dereference.message().empty());
    };

    bsl::ut_scenario{"message with user defined"} = []() {
        bsl::ut_given{} = []() {
            bsl::basic_errc_type<> errc{42};
            bsl::ut_then{} = [&errc]() {
                bsl::ut_check(errc.message().empty());
            };
        };
    };

    bsl::ut_scenario{"equals"} = []() {
        bsl::ut_given{} = []() {
            bsl::basic_errc_type<> errc1{42};
            bsl::basic_errc_type<> errc2{42};
            bsl::ut_then{} = [&errc1, &errc2]() {
                bsl::ut_check(errc1 == errc2);
            };
        };
    };

    bsl::ut_scenario{"not equals"} = []() {
        bsl::ut_given{} = []() {
            bsl::basic_errc_type<> errc1{23};
            bsl::basic_errc_type<> errc2{42};
            bsl::ut_then{} = [&errc1, &errc2]() {
                bsl::ut_check(errc1 != errc2);
            };
        };
    };

    bsl::ut_scenario{"output doesn't crash"} = []() {
        bsl::debug() << bsl::errc_success << '\n';
        bsl::debug() << bsl::errc_failure << '\n';
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
