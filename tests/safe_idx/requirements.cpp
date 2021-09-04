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
#include <bsl/discard.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace
{
    constinit bsl::safe_idx const g_verify_constinit{};
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
    bsl::ut_scenario{"verify supports constinit"} = []() noexcept {
        bsl::discard(g_verify_constinit);
    };

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            auto mut_val1{42_idx};    // NOLINT
            auto mut_val2{42_idx};    // NOLINT
            constexpr auto val1{42_idx};
            constexpr auto val2{42_idx};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(bsl::safe_idx{}));
                static_assert(noexcept(bsl::safe_idx{static_cast<bsl::uintmx>(42)}));
                static_assert(noexcept(bsl::safe_idx{bsl::safe_umx{}, bsl::here()}));

                static_assert(noexcept(mut_val1 = static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(mut_val1.max_value()));
                static_assert(noexcept(mut_val1.min_value()));
                static_assert(noexcept(mut_val1.magic_0()));
                static_assert(noexcept(mut_val1.magic_1()));
                static_assert(noexcept(mut_val1.magic_2()));
                static_assert(noexcept(mut_val1.magic_3()));
                static_assert(noexcept(mut_val1.data_as_ref()));
                static_assert(noexcept(mut_val1.data()));
                static_assert(noexcept(mut_val1.get()));
                static_assert(noexcept(mut_val1.data()));
                static_assert(noexcept(mut_val1.is_pos()));
                static_assert(noexcept(mut_val1.is_zero()));
                static_assert(noexcept(mut_val1.is_invalid()));
                static_assert(noexcept(mut_val1.is_valid()));
                static_assert(noexcept(mut_val1 += mut_val2));
                static_assert(noexcept(mut_val1 += static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(mut_val1 -= mut_val2));
                static_assert(noexcept(mut_val1 -= static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(++mut_val1));
                static_assert(noexcept(--mut_val1));
                static_assert(noexcept(mut_val1 == mut_val2));
                static_assert(noexcept(mut_val1 == static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(static_cast<bsl::uintmx>(42) == mut_val1));
                static_assert(noexcept(mut_val1 != mut_val2));
                static_assert(noexcept(mut_val1 != static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(static_cast<bsl::uintmx>(42) != mut_val1));
                static_assert(noexcept(mut_val1 < mut_val2));
                static_assert(noexcept(mut_val1 < static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(static_cast<bsl::uintmx>(42) < mut_val1));
                static_assert(noexcept(mut_val1 > mut_val2));
                static_assert(noexcept(mut_val1 > static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(static_cast<bsl::uintmx>(42) > mut_val1));
                static_assert(noexcept(mut_val1 + mut_val2));
                static_assert(noexcept(mut_val1 + static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(static_cast<bsl::uintmx>(42) + mut_val1));
                static_assert(noexcept(mut_val1 - mut_val2));
                static_assert(noexcept(mut_val1 - static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(static_cast<bsl::uintmx>(42) - mut_val1));

                static_assert(noexcept(val1.max_value()));
                static_assert(noexcept(val1.min_value()));
                static_assert(noexcept(val1.magic_0()));
                static_assert(noexcept(val1.magic_1()));
                static_assert(noexcept(val1.magic_2()));
                static_assert(noexcept(val1.magic_3()));
                static_assert(noexcept(val1.data_as_ref()));
                static_assert(noexcept(val1.cdata_as_ref()));
                static_assert(noexcept(val1.data()));
                static_assert(noexcept(val1.cdata()));
                static_assert(noexcept(val1.get()));
                static_assert(noexcept(val1.data()));
                static_assert(noexcept(val1.is_pos()));
                static_assert(noexcept(val1.is_zero()));
                static_assert(noexcept(val1.is_invalid()));
                static_assert(noexcept(val1.is_valid()));
                static_assert(noexcept(val1 == val2));
                static_assert(noexcept(val1 == static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(static_cast<bsl::uintmx>(42) == val1));
                static_assert(noexcept(val1 != val2));
                static_assert(noexcept(val1 != static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(static_cast<bsl::uintmx>(42) != val1));
                static_assert(noexcept(val1 < val2));
                static_assert(noexcept(val1 < static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(static_cast<bsl::uintmx>(42) < val1));
                static_assert(noexcept(val1 > val2));
                static_assert(noexcept(val1 > static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(static_cast<bsl::uintmx>(42) > val1));
                static_assert(noexcept(val1 <= val2));
                static_assert(noexcept(val1 <= static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(static_cast<bsl::uintmx>(42) <= val1));
                static_assert(noexcept(val1 >= val2));
                static_assert(noexcept(val1 >= static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(static_cast<bsl::uintmx>(42) >= val1));
                static_assert(noexcept(val1 + val2));
                static_assert(noexcept(val1 + static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(static_cast<bsl::uintmx>(42) + val1));
                static_assert(noexcept(val1 - val2));
                static_assert(noexcept(val1 - static_cast<bsl::uintmx>(42)));
                static_assert(noexcept(static_cast<bsl::uintmx>(42) - val1));
            };
        };
    };

    return bsl::ut_success();
}
