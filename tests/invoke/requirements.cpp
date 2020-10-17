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
    constexpr test::class_base g_class_base{};
    constexpr test::class_subclass g_class_subclass{};
    constexpr test::class_pod g_class_pod{true, true};

    constexpr bsl::reference_wrapper<test::class_base const> g_rw_class_base{g_class_base};
    constexpr bsl::reference_wrapper<test::class_subclass const> g_rw_class_subclass{
        g_class_subclass};
    constexpr bsl::reference_wrapper<test::class_pod const> g_rw_class_pod{g_class_pod};
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
    bsl::ut_scenario{"1.1 noexceptness"} = []() {
        static_assert(noexcept(bsl::invoke(&test::class_base::get, g_class_base)));
        static_assert(noexcept(bsl::invoke(&test::class_base::get, g_class_subclass)));
        static_assert(
            !noexcept(bsl::invoke(&test::class_subclass::get_might_throw, g_class_subclass)));
    };

    bsl::ut_scenario{"1.2 noexceptness"} = []() {
        static_assert(noexcept(bsl::invoke(&test::class_base::get, g_rw_class_base)));
        static_assert(noexcept(bsl::invoke(&test::class_base::get, g_rw_class_subclass)));
        static_assert(
            !noexcept(bsl::invoke(&test::class_subclass::get_might_throw, g_rw_class_subclass)));
    };

    bsl::ut_scenario{"1.3 noexceptness"} = []() {
        static_assert(noexcept(bsl::invoke(&test::class_base::get, &g_class_base)));
        static_assert(noexcept(bsl::invoke(&test::class_base::get, &g_class_subclass)));
        static_assert(
            !noexcept(bsl::invoke(&test::class_subclass::get_might_throw, &g_class_subclass)));
    };

    bsl::ut_scenario{"2.1 noexceptness"} = []() {
        static_assert(noexcept(bsl::invoke(&test::class_pod::val1, g_class_pod)));
    };

    bsl::ut_scenario{"2.2 noexceptness"} = []() {
        static_assert(noexcept(bsl::invoke(&test::class_pod::val1, g_rw_class_pod)));
    };

    bsl::ut_scenario{"2.3 noexceptness"} = []() {
        static_assert(noexcept(bsl::invoke(&test::class_pod::val1, &g_class_pod)));
    };

    bsl::ut_scenario{"3.1 noexceptness"} = []() {
        static_assert(noexcept(bsl::invoke(&test::func, true)));
        static_assert(!noexcept(bsl::invoke(&test::func_might_throw, true)));
    };

    return bsl::ut_success();
}
