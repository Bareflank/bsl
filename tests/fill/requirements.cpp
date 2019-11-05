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

#include <bsl/fill.hpp>
#include <bsl/array.hpp>
#include <bsl/ut.hpp>

namespace
{
    class copy_except final
    {
    public:
        constexpr copy_except() noexcept = default;
        ~copy_except() noexcept = default;
        constexpr copy_except(copy_except const &) noexcept(false) = default;
        constexpr copy_except &operator=(copy_except const &) &noexcept(false) = default;
        constexpr copy_except(copy_except &&) noexcept = delete;
        constexpr copy_except &operator=(copy_except &&) &noexcept = delete;
    };

    class copy_noexcept final
    {
    public:
        constexpr copy_noexcept() noexcept = default;
        ~copy_noexcept() noexcept = default;
        constexpr copy_noexcept(copy_noexcept const &) noexcept = default;
        constexpr copy_noexcept &operator=(copy_noexcept const &) &noexcept = default;
        constexpr copy_noexcept(copy_noexcept &&) noexcept = delete;
        constexpr copy_noexcept &operator=(copy_noexcept &&) &noexcept = delete;
    };

    constexpr bsl::array<copy_except, 42> g_arr1{};
    constexpr bsl::array<copy_noexcept, 42> g_arr2{};
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
    using namespace bsl;

    bsl::ut_scenario{"verify except"} = []() {
        static_assert(!noexcept(bsl::fill(g_arr1, copy_except{})));
        static_assert(!noexcept(bsl::fill(g_arr1.begin(), g_arr1.end(), copy_except{})));
    };

    bsl::ut_scenario{"verify noexcept"} = []() {
        static_assert(noexcept(bsl::fill(g_arr2, copy_noexcept{})));
        static_assert(noexcept(bsl::fill(g_arr2.begin(), g_arr2.end(), copy_noexcept{})));
    };

    return bsl::ut_success();
}
