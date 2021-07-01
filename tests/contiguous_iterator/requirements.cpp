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

#include <bsl/array.hpp>
#include <bsl/contiguous_iterator.hpp>
#include <bsl/convert.hpp>
#include <bsl/ut.hpp>

namespace
{
    constexpr bsl::array TEST_INIT{
        bsl::to_i32(4),
        bsl::to_i32(8),
        bsl::to_i32(15),
        bsl::to_i32(16),
        bsl::to_i32(23),
        bsl::to_i32(42)};
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
    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            bsl::contiguous_iterator mut_ci1{TEST_INIT.data(), TEST_INIT.size(), bsl::to_umax(0)};
            bsl::contiguous_iterator mut_ci2{TEST_INIT.data(), TEST_INIT.size(), bsl::to_umax(0)};
            bsl::contiguous_iterator const ci1{TEST_INIT.data(), TEST_INIT.size(), bsl::to_umax(0)};
            bsl::contiguous_iterator const ci2{TEST_INIT.data(), TEST_INIT.size(), bsl::to_umax(0)};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(
                    bsl::contiguous_iterator{TEST_INIT.data(), TEST_INIT.size(), bsl::to_umax(0)}));

                static_assert(noexcept(mut_ci1.data()));
                static_assert(noexcept(mut_ci1.size()));
                static_assert(noexcept(mut_ci1.index()));
                static_assert(noexcept(mut_ci1.empty()));
                static_assert(noexcept(!!mut_ci1));
                static_assert(noexcept(mut_ci1.is_end()));
                static_assert(noexcept(mut_ci1.get_if()));
                static_assert(noexcept(*mut_ci1));
                static_assert(noexcept(++mut_ci1));
                static_assert(noexcept(--mut_ci1));
                static_assert(noexcept(mut_ci1 == mut_ci2));
                static_assert(noexcept(mut_ci1 != mut_ci2));
                static_assert(noexcept(mut_ci1 < mut_ci2));
                static_assert(noexcept(mut_ci1 > mut_ci2));

                static_assert(noexcept(ci1.data()));
                static_assert(noexcept(ci1.size()));
                static_assert(noexcept(ci1.index()));
                static_assert(noexcept(ci1.empty()));
                static_assert(noexcept(!!ci1));
                static_assert(noexcept(ci1.is_end()));
                static_assert(noexcept(ci1.get_if()));
                static_assert(noexcept(*ci1));
                static_assert(noexcept(ci1 == ci2));
                static_assert(noexcept(ci1 != ci2));
                static_assert(noexcept(ci1 < ci2));
                static_assert(noexcept(ci1 > ci2));
            };
        };
    };

    return bsl::ut_success();
}
