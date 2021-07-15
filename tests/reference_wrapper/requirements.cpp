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

#include <bsl/convert.hpp>
#include <bsl/reference_wrapper.hpp>
#include <bsl/ut.hpp>

namespace
{
    [[nodiscard]] constexpr auto
    func(bsl::safe_int32 const val) noexcept -> bsl::safe_int32
    {
        return val;
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
    // clang-format off
    bsl::ut_scenario{"quiet the func"} = []() noexcept {
        bsl::discard(func(42_i32));
    };

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            // BUG: Need to figure out why we cannot use & here
            // NOLINTNEXTLINE(bsl-function-name-use)
            bsl::reference_wrapper<bsl::safe_int32(bsl::safe_int32)> mut_rw{func};
            // BUG: Need to figure out why we cannot use & here
            // NOLINTNEXTLINE(bsl-function-name-use)
            bsl::reference_wrapper<bsl::safe_int32(bsl::safe_int32)> const rw{func};
            bsl::ut_then{} = []() noexcept {
                // BUG: Need to figure out why we cannot use & here
                // NOLINTNEXTLINE(bsl-function-name-use)
                static_assert(noexcept(bsl::reference_wrapper<bsl::safe_int32(bsl::safe_int32)>{func}));

                static_assert(noexcept(mut_rw.get()));
                static_assert(!noexcept(mut_rw(bsl::to_i32(42))));

                static_assert(noexcept(rw.get()));
                static_assert(!noexcept(rw(bsl::to_i32(42))));
            };
        };
    };

    return bsl::ut_success();
}
