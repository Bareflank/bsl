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

#include <bsl/forward.hpp>
#include <bsl/is_const.hpp>
#include <bsl/is_lvalue_reference.hpp>
#include <bsl/is_rvalue_reference.hpp>
#include <bsl/remove_reference.hpp>
#include <bsl/ut.hpp>

namespace
{
    template<typename T>
    [[nodiscard]] constexpr bsl::safe_int32
    detector(T &&t) noexcept
    {
        using namespace bsl;

        if constexpr (is_const<remove_reference_t<T>>::value) {
            return bsl::to_i32(1);
        }

        if constexpr (is_lvalue_reference<decltype(t)>::value) {
            return bsl::to_i32(2);
        }

        if constexpr (is_rvalue_reference<decltype(t)>::value) {
            return bsl::to_i32(3);
        }

        return bsl::to_i32(0);
    }

    template<typename T>
    [[nodiscard]] constexpr bsl::safe_int32
    forwarder(T &&t) noexcept
    {
        return detector(bsl::forward<T>(t));
    }
}

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
    bsl::ut_scenario{"exchange"} = []() {
        bsl::ut_given{} = []() {
            bsl::safe_int32 const val{42};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(forwarder(val) == 1);
            };
        };

        bsl::ut_given{} = []() {
            bsl::safe_int32 val{42};
            bsl::ut_then{} = [&val]() {
                bsl::ut_check(forwarder(val) == 2);
            };
        };

        bsl::ut_given{} = []() {
            bsl::ut_then{} = []() {
                bsl::ut_check(forwarder(42) == 3);
            };
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
