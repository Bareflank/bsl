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

#include <bsl/invoke.hpp>
#include <bsl/reference_wrapper.hpp>
#include <bsl/ut.hpp>

namespace
{
    [[nodiscard]] constexpr bool
    test_func(bool val)
    {
        return val;
    }

    [[nodiscard]] constexpr bool
    test_func_noexcept(bool val)
    {
        return val;
    }

    class test_base
    {
    public:
        constexpr test_base() noexcept = default;

        [[nodiscard]] constexpr bool
        operator()(bool val) const
        {
            return val;
        }

        bsl::int32 data{42};    // NOLINT
    };

    class test_final final : public test_base
    {
    public:
        constexpr test_final() noexcept = default;
    };

    class test_noexcept final
    {
    public:
        constexpr test_noexcept() noexcept = default;

        [[nodiscard]] constexpr bool
        operator()(bool val) const noexcept
        {
            return val;
        }

        bsl::int32 data{42};    // NOLINT
    };

    constexpr test_final g_test_final{};
    constexpr test_noexcept g_test_noexcept{};

    constexpr bsl::reference_wrapper<test_final const> g_rw_test_final{g_test_final};
    constexpr bsl::reference_wrapper<test_noexcept const> g_rw_test_noexcept{g_test_noexcept};
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
    bsl::ut_scenario{"1.1"} = []() {
        bsl::ut_check(bsl::invoke(&test_base::operator(), g_test_final, true));
        bsl::ut_check(bsl::invoke(&test_final::operator(), g_test_final, true));
        bsl::ut_check(bsl::invoke(&test_noexcept::operator(), g_test_noexcept, true));
    };

    bsl::ut_scenario{"1.2"} = []() {
        bsl::ut_check(bsl::invoke(&test_base::operator(), g_rw_test_final, true));
        bsl::ut_check(bsl::invoke(&test_final::operator(), g_rw_test_final, true));
        bsl::ut_check(bsl::invoke(&test_noexcept::operator(), g_rw_test_noexcept, true));
    };

    bsl::ut_scenario{"1.3"} = []() {
        bsl::ut_check(bsl::invoke(&test_base::operator(), &g_test_final, true));
        bsl::ut_check(bsl::invoke(&test_final::operator(), &g_test_final, true));
        bsl::ut_check(bsl::invoke(&test_noexcept::operator(), &g_test_noexcept, true));
    };

    bsl::ut_scenario{"2.1"} = []() {
        bsl::ut_check(bsl::invoke(&test_base::data, g_test_final) == 42);
        bsl::ut_check(bsl::invoke(&test_final::data, g_test_final) == 42);
        bsl::ut_check(bsl::invoke(&test_noexcept::data, g_test_noexcept) == 42);
    };

    bsl::ut_scenario{"2.2"} = []() {
        bsl::ut_check(bsl::invoke(&test_base::data, g_rw_test_final) == 42);
        bsl::ut_check(bsl::invoke(&test_final::data, g_rw_test_final) == 42);
        bsl::ut_check(bsl::invoke(&test_noexcept::data, g_rw_test_noexcept) == 42);
    };

    bsl::ut_scenario{"2.3"} = []() {
        bsl::ut_check(bsl::invoke(&test_base::data, &g_test_final) == 42);
        bsl::ut_check(bsl::invoke(&test_final::data, &g_test_final) == 42);
        bsl::ut_check(bsl::invoke(&test_noexcept::data, &g_test_noexcept) == 42);
    };

    bsl::ut_scenario{"3.1"} = []() {
        bsl::ut_check(bsl::invoke(&test_func, true));
        bsl::ut_check(bsl::invoke(&test_func_noexcept, true));
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
