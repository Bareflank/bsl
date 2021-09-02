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

#include "../class_base.hpp"
#include "../class_pod.hpp"
#include "../class_subclass.hpp"
#include "../func.hpp"
#include "../func_might_throw.hpp"

#include <bsl/invoke.hpp>
#include <bsl/reference_wrapper.hpp>
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
        constexpr test::class_base base{};
        constexpr test::class_subclass subclass{};
        constexpr test::class_pod pod{true, true};

        bsl::reference_wrapper<test::class_base const> const rw_base{base};
        bsl::reference_wrapper<test::class_subclass const> const rw_subclass{subclass};
        bsl::reference_wrapper<test::class_pod const> const rw_pod{pod};

        bsl::ut_scenario{"1.1"} = [&]() noexcept {
            bsl::ut_check(bsl::invoke(&test::class_base::get, base));
            bsl::ut_check(bsl::invoke(&test::class_base::get, subclass));
            bsl::ut_check(bsl::invoke(&test::class_subclass::get, subclass));
        };

        bsl::ut_scenario{"1.2"} = [&]() noexcept {
            bsl::ut_check(bsl::invoke(&test::class_base::get, rw_base));
            bsl::ut_check(bsl::invoke(&test::class_base::get, rw_subclass));
            bsl::ut_check(bsl::invoke(&test::class_subclass::get, rw_subclass));
        };

        bsl::ut_scenario{"1.3"} = [&]() noexcept {
            bsl::ut_check(bsl::invoke(&test::class_base::get, &base));
            bsl::ut_check(bsl::invoke(&test::class_base::get, &subclass));
            bsl::ut_check(bsl::invoke(&test::class_subclass::get, &subclass));
        };

        bsl::ut_scenario{"2.1"} = [&]() noexcept {
            bsl::ut_check(bsl::invoke(&test::class_pod::val1, pod));
        };

        bsl::ut_scenario{"2.2"} = [&]() noexcept {
            bsl::ut_check(bsl::invoke(&test::class_pod::val1, rw_pod));
        };

        bsl::ut_scenario{"2.3"} = [&]() noexcept {
            bsl::ut_check(bsl::invoke(&test::class_pod::val1, &pod));
        };

        bsl::ut_scenario{"3.1"} = [&]() noexcept {
            bsl::ut_check(bsl::invoke(&test::func, true));
            bsl::ut_check(bsl::invoke(&test::func_might_throw, true));
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
